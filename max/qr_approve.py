#!/usr/bin/env python3
"""
qr_approve.py — подтверждение QR авторизации в MAX.

Использование:
    # Терминал 1 — ГОСТ туннель:
    sudo stunnel-gost

    # Терминал 2:
    python3 qr_approve.py "https://max.ru/:auth/<UUID>"

Конфиг (client.conf или phone_auth.conf рядом с файлом):
    TOKEN     = <токен>
    VIEWER_ID = <viewerId>
    DEVICE_ID = <deviceId>

Зависимости:
    pip install msgpack lz4
"""

import asyncio
import logging
import struct
import sys
import time
from pathlib import Path

try:
    import cv2
    from pyzbar.pyzbar import decode as zbar_decode
    HAS_QR_SCAN = True
except ImportError:
    HAS_QR_SCAN = False

import lz4.block
import msgpack

# ══════════════════════════════════════════════════════════════════════════════
# КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════

def _load_config(account_idx: int = None):
    """
    Загружает конфиг аккаунта из phone_auth.conf (TOKEN_1, VIEWER_ID_1, DEVICE_ID_1 ...)
    account_idx: номер аккаунта (1, 2, 3...) или None — берёт первый
    """
    p = Path(__file__).parent / "phone_auth.conf"
    if p.exists():
        accounts = {}
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, val = line.partition("=")
            key = key.strip(); val = val.strip()
            for prefix in ("TOKEN", "VIEWER_ID", "DEVICE_ID"):
                if key.startswith(prefix):
                    suffix = key[len(prefix):]
                    idx = int(suffix.lstrip("_")) if suffix.lstrip("_").isdigit() else 1
                    if idx not in accounts:
                        accounts[idx] = {}
                    accounts[idx][prefix] = val
                    break

        if accounts:
            if account_idx is not None:
                if account_idx not in accounts:
                    raise KeyError(f"Аккаунт _{account_idx} не найден. "
                                   f"Доступны: {sorted(accounts.keys())}")
                return accounts[account_idx]
            return accounts[min(accounts.keys())]

    # Fallback: client.conf
    p = Path(__file__).parent / "client.conf"
    if p.exists():
        cfg = {}
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            key, _, val = line.partition("=")
            cfg[key.strip()] = val.strip()
        if "TOKEN" in cfg:
            return cfg

    raise FileNotFoundError("Не найден phone_auth.conf или client.conf с TOKEN")

# Загружаем после парсинга аргументов в main()
TOKEN     = None
VIEWER_ID = 0
DEVICE_ID = None

TUNNEL_HOST = "127.0.0.1"
TUNNEL_PORT = 8443

SESSION_INIT     = 6
LOGIN            = 19
AUTH_QR_APPROVE  = 0x122  # 290

CMD_REQUEST  = 0
CMD_RESPONSE = 1
CMD_ERROR    = 3

PROTO_VERSION = 10

# ══════════════════════════════════════════════════════════════════════════════
# ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("qr_approve")

# ══════════════════════════════════════════════════════════════════════════════
# ПРОТОКОЛ
# ══════════════════════════════════════════════════════════════════════════════

def build_packet(opcode: int, seq: int, payload: dict) -> bytes:
    payload_bytes = msgpack.packb(payload, use_bin_type=True)
    payload_len   = len(payload_bytes)
    header = struct.pack(
        ">BBHHI",
        PROTO_VERSION,
        CMD_REQUEST,
        seq,
        opcode,
        payload_len & 0x00FFFFFF,
    )
    log.debug(f"→ SEND  opcode=0x{opcode:04X}({opcode})  seq={seq}  "
              f"payload_len={payload_len}  header={header.hex()}")
    log.debug(f"  payload={payload}")
    return header + payload_bytes


def parse_header(data: bytes) -> tuple:
    ver, cmd, seq, opcode, payload_info = struct.unpack(">BBHHI", data)
    payload_len  = payload_info & 0x00FFFFFF
    compression  = (payload_info >> 24) & 0xFF
    log.debug(f"← HEADER  opcode=0x{opcode:04X}({opcode})  cmd={cmd}  seq={seq}  "
              f"payload_len={payload_len}  compression={compression}")
    return ver, cmd, seq, opcode, payload_len, compression


def decompress_payload(raw: bytes, compression: int) -> dict:
    if compression > 0:
        try:
            decompressed = lz4.block.decompress(raw, uncompressed_size=compression * len(raw))
            log.debug(f"  LZ4 decompressed: {len(raw)} → {len(decompressed)} bytes")
            return msgpack.unpackb(decompressed, raw=False)
        except Exception:
            try:
                decompressed = lz4.block.decompress(raw, uncompressed_size=len(raw) * 16)
                return msgpack.unpackb(decompressed, raw=False)
            except Exception:
                try:
                    return msgpack.unpackb(raw, raw=False)
                except Exception as e:
                    log.warning(f"  decompress error: {e}")
                    return {}
    try:
        return msgpack.unpackb(raw, raw=False)
    except Exception as e:
        log.warning(f"  msgpack error: {e}")
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# КЛИЕНТ
# ══════════════════════════════════════════════════════════════════════════════

class QrApproveClient:
    def __init__(self, token: str, device_id: str):
        self.token     = token
        self.device_id = device_id
        self.seq       = 0
        self.reader    = None
        self.writer    = None
        self._once: dict[str, asyncio.Future] = {}

    def _next_seq(self) -> int:
        s = self.seq; self.seq += 1; return s

    async def _send(self, opcode: int, payload: dict):
        seq    = self._next_seq()
        packet = build_packet(opcode, seq, payload)
        self.writer.write(packet)
        await self.writer.drain()
        return seq

    async def _recv_packet(self) -> dict | None:
        try:
            header_data = await self.reader.readexactly(10)
        except asyncio.IncompleteReadError as e:
            log.warning(f"Соединение закрыто: {e}")
            return None

        ver, cmd, seq, opcode, payload_len, compression = parse_header(header_data)

        payload = {}
        if payload_len > 0:
            try:
                raw     = await self.reader.readexactly(payload_len)
                payload = decompress_payload(raw, compression)
            except asyncio.IncompleteReadError as e:
                log.warning(f"Соединение закрыто при чтении payload: {e}")
                return None

        log.info(f"← RECV  opcode=0x{opcode:04X}({opcode})  cmd={cmd}  seq={seq}  payload={payload}")
        return {"ver": ver, "cmd": cmd, "seq": seq, "opcode": opcode, "payload": payload}

    async def _recv_loop(self):
        while True:
            pkt = await self._recv_packet()
            if pkt is None:
                for key, fut in list(self._once.items()):
                    if not fut.done():
                        fut.set_exception(ConnectionError("Соединение закрыто"))
                break

            op  = pkt["opcode"]
            cmd = pkt["cmd"]
            pl  = pkt["payload"]

            key = None
            if   op == SESSION_INIT    and cmd in (CMD_RESPONSE, CMD_ERROR): key = "op6"
            elif op == LOGIN           and cmd in (CMD_RESPONSE, CMD_ERROR): key = "op19"
            elif op == AUTH_QR_APPROVE and cmd in (CMD_RESPONSE, CMD_ERROR): key = "op_qr"

            if key and key in self._once:
                f = self._once.pop(key)
                f.done() or f.set_result({"payload": pl, "cmd": cmd})
            else:
                log.info(f"← UNHANDLED  opcode=0x{op:04X}({op})  cmd={cmd}")

    async def _wait_once(self, key: str, timeout: float = 5.0):
        fut = asyncio.get_event_loop().create_future()
        self._once[key] = fut
        log.debug(f"  Жду key={key} timeout={timeout}s ...")
        return await asyncio.wait_for(fut, timeout=timeout)

    async def _session_init(self):
        log.info("═══ Шаг 1: SESSION_INIT (opcode=6) ═══")
        await self._send(SESSION_INIT, {
            "userAgent": {
                "deviceType":    "ANDROID",
                "pushDeviceType": "GCM",
                "appVersion":    "26.11.0",
                "arch":          "arm64-v8a",
                "buildNumber":   6657,
                "osVersion":     "Android 14",
                "locale":        "ru",
                "deviceLocale":  "ru_RU",
                "deviceName":    "Samsung SM-S921B",
                "screen":        "1080x2400",
                "timezone":      "Europe/Moscow",
            },
            "deviceId":        self.device_id,
            "clientSessionId": int(time.time() * 1000),
        })
        resp = await self._wait_once("op6", timeout=5.0)
        if resp["cmd"] == CMD_ERROR:
            raise RuntimeError(f"SESSION_INIT ошибка: {resp['payload']}")
        log.info(f"SESSION_INIT OK")

    async def _login(self):
        log.info("═══ Шаг 2: LOGIN (opcode=19) ═══")
        await self._send(LOGIN, {
            "token":        self.token,
            "interactive":  False,
            "chatsCount":   0,
            "chatsSync":    0,
            "contactsSync": 0,
            "presenceSync": 0,
            "draftsSync":   0,
        })
        resp = await self._wait_once("op19", timeout=15.0)
        if resp["cmd"] == CMD_ERROR:
            raise RuntimeError(f"LOGIN ошибка: {resp['payload']}")
        log.info("LOGIN OK")

    async def _qr_approve(self, qr_link: str):
        log.info(f"═══ Шаг 3: AUTH_QR_APPROVE (opcode=0x{AUTH_QR_APPROVE:04X}) ═══")
        log.info(f"   qrLink = {qr_link}")

        fut = asyncio.get_event_loop().create_future()
        self._once["op_qr"] = fut

        await self._send(AUTH_QR_APPROVE, {"qrLink": qr_link})

        try:
            resp = await asyncio.wait_for(fut, timeout=10.0)
            if resp["cmd"] == CMD_ERROR:
                log.error(f"AUTH_QR_APPROVE ошибка: {resp['payload']}")
                return False
            log.info(f"✓ AUTH_QR_APPROVE успех! payload={resp['payload']}")
            return True
        except asyncio.TimeoutError:
            self._once.pop("op_qr", None)
            log.info("✓ AUTH_QR_APPROVE: нет ответа (пустой ответ = успех)")
            return True

    async def run(self, qr_link: str):
        # Автоповтор подключения
        recv_task = None
        attempt   = 0
        while True:
            attempt += 1
            try:
                log.info(f"Попытка {attempt}: подключаемся к {TUNNEL_HOST}:{TUNNEL_PORT} ...")
                self.seq   = 0
                self._once = {}
                self.reader, self.writer = await asyncio.open_connection(TUNNEL_HOST, TUNNEL_PORT)
                log.info("TCP подключён")
                recv_task = asyncio.create_task(self._recv_loop())
                await self._session_init()
                break
            except Exception as e:
                log.warning(f"Попытка {attempt} неудачна: {e}, повтор через 2с ...")
                if recv_task:
                    recv_task.cancel()
                    try: await recv_task
                    except: pass
                    recv_task = None
                if self.writer:
                    self.writer.close()
                await asyncio.sleep(2)

        try:
            await self._login()
            await asyncio.sleep(0.3)
            success = await self._qr_approve(qr_link)
            await asyncio.sleep(2.0)
            if success:
                log.info("✓ QR авторизация выполнена")
            else:
                log.error("✗ QR авторизация не удалась")
        except Exception as e:
            log.error(f"Ошибка: {e}", exc_info=True)
        finally:
            if recv_task:
                recv_task.cancel()
                try: await recv_task
                except asyncio.CancelledError: pass
            if self.writer:
                self.writer.close()
                try: await self.writer.wait_closed()
                except: pass

        log.info("Соединение закрыто")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def scan_qr(image_path: str) -> str | None:
    """Сканирует QR код из файла изображения."""
    if not HAS_QR_SCAN:
        log.error("Установи зависимости: pip install opencv-python pyzbar && sudo apt install libzbar0")
        return None

    img = cv2.imread(image_path)
    if img is None:
        log.error(f"Не удалось загрузить изображение: {path}")
        return None

    qrs = zbar_decode(img)
    for qr in qrs:
        data = qr.data.decode("utf-8")
        log.info(f"QR найден: {data}")
        if "/:auth/" in data:
            return data

    log.warning("QR с /:auth/ не найден на изображении")
    return None


async def main():
    if len(sys.argv) != 3:
        print('Использование: python3 qr_approve.py /path/to/image.png <номер_аккаунта>')
        print('Пример:        python3 qr_approve.py /tmp/qr.png 1')
        print()
        print("Перед запуском убедись что ГОСТ туннель запущен:")
        print("  sudo stunnel-gost")
        sys.exit(1)

    image_path  = sys.argv[1]
    account_idx = int(sys.argv[2])

    qr_link = scan_qr(image_path)
    if not qr_link:
        log.error("QR код не найден в изображении")
        sys.exit(1)

    # Загружаем конфиг
    global TOKEN, VIEWER_ID, DEVICE_ID
    cfg       = _load_config(account_idx)
    TOKEN     = cfg["TOKEN"]
    VIEWER_ID = int(cfg.get("VIEWER_ID", 0))
    DEVICE_ID = cfg["DEVICE_ID"]

    if "/:auth/" not in qr_link:
        log.warning(f"Подозрительная ссылка (нет /:auth/): {qr_link}")

    idx_str = f"[{account_idx}]" if account_idx else "[1]"
    log.info(f"Аккаунт:  {idx_str}  VIEWER_ID={VIEWER_ID}")
    log.info(f"QR ссылка: {qr_link}")

    await QrApproveClient(token=TOKEN, device_id=DEVICE_ID).run(qr_link)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Прервано")