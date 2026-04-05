#!/usr/bin/env python3
"""
phone_auth.py — авторизация в MAX по номеру телефона через SMS код.

Использование:
    # Терминал 1 — ГОСТ туннель (держать открытым):
    OPENSSL_MODULES=/opt/openssl34/lib64/ossl-modules \
    LD_LIBRARY_PATH=/opt/openssl34/lib64 \
    sudo -E stunnel /etc/stunnel/gost.conf

    # Терминал 2 — авторизация:
    python3 phone_auth.py +79067951822

Зависимости:
    pip install msgpack lz4
"""

import asyncio
import logging
import struct
import sys
import time
import uuid
from pathlib import Path

def _input(prompt: str) -> str:
    """input() с явной поддержкой UTF-8."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return sys.stdin.buffer.readline().decode("utf-8").rstrip("\n")

import lz4.block
import msgpack

# ══════════════════════════════════════════════════════════════════════════════
# КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════

TUNNEL_HOST = "127.0.0.1"
TUNNEL_PORT = 8443

SESSION_INIT  = 6
AUTH_REQUEST  = 17
AUTH          = 18
AUTH_CONFIRM  = 23  # для регистрации нового аккаунта
LOGIN         = 19  # для входа в существующий

CMD_REQUEST      = 0
CMD_RESPONSE     = 1
CMD_NOTIFICATION = 2
CMD_ERROR        = 3

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
log = logging.getLogger("phone_auth")

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
        except Exception as e1:
            log.debug(f"  LZ4 attempt 1 failed: {e1}, trying larger buffer...")
            try:
                decompressed = lz4.block.decompress(raw, uncompressed_size=len(raw) * 16)
                return msgpack.unpackb(decompressed, raw=False)
            except Exception as e2:
                log.warning(f"  LZ4 decompress failed: {e2}, trying raw msgpack...")
                try:
                    return msgpack.unpackb(raw, raw=False)
                except Exception as e3:
                    log.warning(f"  msgpack parse error: {e3}")
                    return {}
    try:
        return msgpack.unpackb(raw, raw=False)
    except Exception as e:
        log.warning(f"  msgpack parse error: {e}")
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# КЛИЕНТ
# ══════════════════════════════════════════════════════════════════════════════

class PhoneAuthClient:
    def __init__(self, device_id: str):
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
            log.warning(f"Соединение закрыто при чтении заголовка: {e}")
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
            if   op == SESSION_INIT and cmd in (CMD_RESPONSE, CMD_ERROR): key = "op6"
            elif op == AUTH_REQUEST and cmd in (CMD_RESPONSE, CMD_ERROR): key = "op17"
            elif op == AUTH         and cmd in (CMD_RESPONSE, CMD_ERROR): key = "op18"
            elif op == AUTH_CONFIRM and cmd in (CMD_RESPONSE, CMD_ERROR): key = "op23"

            if key and key in self._once:
                f = self._once.pop(key)
                f.done() or f.set_result({"payload": pl, "cmd": cmd})
            else:
                log.info(f"← UNHANDLED  opcode=0x{op:04X}({op})  cmd={cmd}  payload={pl}")

    async def _wait_once(self, key: str, timeout: float = 30.0):
        fut = asyncio.get_event_loop().create_future()
        self._once[key] = fut
        log.debug(f"  Жду key={key} timeout={timeout}s ...")
        result = await asyncio.wait_for(fut, timeout=timeout)
        log.debug(f"  Получил key={key}")
        return result

    # ── Шаг 1: SESSION_INIT ──────────────────────────────────────────────────

    async def session_init(self):
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
                "deviceName": "Samsung SM-S921B",
                "screen":     "1080x2400",
                "timezone":      "Europe/Moscow",
            },
            "deviceId":        "6b4370f6-2169-4f64-a1c6-54e1bcb6a26a",
            "clientSessionId": int(time.time() * 1000),
        })
        resp = await self._wait_once("op6", timeout=5.0)
        pl   = resp["payload"]
        log.info(f"SESSION_INIT ответ: {pl}")
        if resp["cmd"] == CMD_ERROR:
            raise RuntimeError(f"SESSION_INIT ошибка: {pl}")
        return pl

    # ── Шаг 2: AUTH_REQUEST ──────────────────────────────────────────────────

    async def request_sms(self, phone: str) -> str:
        log.info(f"═══ Шаг 2: AUTH_REQUEST (opcode=17)  phone={phone} ═══")
        await self._send(AUTH_REQUEST, {
            "phone":    phone,
            "type":     "START_AUTH",
            "language": "ru",
        })
        resp = await self._wait_once("op17", timeout=5.0)
        cmd  = resp["cmd"]
        pl   = resp["payload"]

        if cmd == CMD_ERROR:
            raise RuntimeError(f"AUTH_REQUEST ошибка: {pl.get('error') or pl}")

        token = pl.get("token") or pl.get("verifyToken") or pl.get("authToken")
        if not token:
            log.warning(f"Полный ответ: {pl}")
            raise RuntimeError("AUTH_REQUEST: токен не получен")

        log.info(f"AUTH_REQUEST успех, token: {token[:20]}...")
        return token

    # ── Шаг 3: AUTH ──────────────────────────────────────────────────────────

    async def verify_code(self, token: str, code: str) -> dict:
        log.info(f"═══ Шаг 3: AUTH (opcode=18)  code={code} ═══")
        await self._send(AUTH, {
            "token":         token,
            "verifyCode":    code,
            "authTokenType": "CHECK_CODE",
        })
        resp = await self._wait_once("op18", timeout=30.0)
        cmd  = resp["cmd"]
        pl   = resp["payload"]

        if cmd == CMD_ERROR:
            raise RuntimeError(f"AUTH ошибка: {pl.get('error') or pl}")

        login_token   = None
        register_token = None
        token_attrs = pl.get("tokenAttrs", {})
        if token_attrs:
            login_token    = token_attrs.get("LOGIN",    {}).get("token")
            register_token = token_attrs.get("REGISTER", {}).get("token")
        if not login_token:
            login_token = pl.get("token")

        if register_token and not login_token:
            log.info("AUTH: новый аккаунт — требуется регистрация (REGISTER token получен)")
            log.info(f"  register_token: {register_token[:20]}...")
            return {"login_token": register_token, "raw": pl, "is_new": True}

        if not login_token:
            log.warning(f"Полный ответ AUTH: {pl}")
            raise RuntimeError("AUTH: login token не получен")

        log.info(f"AUTH успех! login_token: {login_token[:20]}...")
        return {"login_token": login_token, "raw": pl, "is_new": False}

    # ── Шаг 3б: AUTH_CONFIRM — регистрация нового аккаунта ──────────────────

    async def register(self, register_token: str, first_name: str, last_name: str = "") -> dict:
        log.info(f"═══ Шаг 3б: AUTH_CONFIRM (opcode=19)  name={first_name} {last_name} ═══")
        payload = {
            "token":     register_token,
            "firstName": first_name,
            "tokenType": "REGISTER",
        }
        if last_name:
            payload["lastName"] = last_name
        await self._send(AUTH_CONFIRM, payload)
        resp = await self._wait_once("op23", timeout=30.0)
        cmd  = resp["cmd"]
        pl   = resp["payload"]

        if cmd == CMD_ERROR:
            raise RuntimeError(f"AUTH_CONFIRM ошибка: {pl.get('error') or pl}")

        login_token = None
        token_attrs = pl.get("tokenAttrs", {})
        if token_attrs:
            login_token = token_attrs.get("LOGIN", {}).get("token")
        if not login_token:
            login_token = pl.get("token")

        viewer_id = None
        profile = pl.get("profile", {})
        if profile:
            contact   = profile.get("contact", {})
            viewer_id = contact.get("id")

        log.info(f"✓ Регистрация завершена! viewerId={viewer_id}")
        return {"login_token": login_token, "viewer_id": viewer_id, "raw": pl}

    # ── Основной флоу ────────────────────────────────────────────────────────

    async def _open_connection(self):
        """Открывает TCP соединение."""
        self.reader, self.writer = await asyncio.open_connection(TUNNEL_HOST, TUNNEL_PORT)

    async def run(self, phone: str):
        # Автоповтор SESSION_INIT пока сервер не ответит
        recv_task = None
        attempt   = 0
        while True:
            attempt += 1
            try:
                log.info(f"Попытка {attempt}: подключаемся к {TUNNEL_HOST}:{TUNNEL_PORT} ...")
                self.seq   = 0
                self._once = {}
                await self._open_connection()
                log.info("TCP подключён")
                recv_task = asyncio.create_task(self._recv_loop())
                await self.session_init()
                break
            except Exception as e:
                log.warning(f"Попытка {attempt} неудачна: {e}, повтор через 2с ...")
                if recv_task:
                    recv_task.cancel()
                    try: await recv_task
                    except: pass
                    recv_task = None
                if hasattr(self, 'writer') and self.writer:
                    self.writer.close()
                await asyncio.sleep(2)

        try:
            token = await self.request_sms(phone)

            print()
            print("═" * 50)
            code = _input(f"  Введи SMS код для {phone}: ").strip()
            print("═" * 50)
            print()

            if not code:
                log.error("Код не введён")
                return

            auth_result = await self.verify_code(token, code)
            login_token = auth_result["login_token"]
            is_new      = auth_result.get("is_new", False)

            if is_new:
                log.info("Новый аккаунт — требуется регистрация")
                print()
                print("═" * 50)
                first_name = _input("  Введи имя: ").strip()
                last_name  = _input("  Введи фамилию (Enter чтобы пропустить): ").strip()
                print("═" * 50)
                print()

                if not first_name:
                    log.error("Имя не введено")
                    return

                reg_result  = await self.register(login_token, first_name, last_name)
                login_token = reg_result.get("login_token") or login_token
                viewer_id   = reg_result.get("viewer_id")

                log.info("✓ Регистрация и авторизация завершены!")
                log.info(f"  viewerId:    {viewer_id}")
                log.info(f"  login_token: {login_token[:30]}...")
                _save_config(login_token, viewer_id, self.device_id)
                return

            # Берём viewer_id прямо из ответа AUTH
            viewer_id = None
            raw_pl = auth_result.get("raw", {})
            profile = raw_pl.get("profile", {})
            if profile:
                contact   = profile.get("contact", {})
                viewer_id = contact.get("id")

            log.info("✓ Авторизация завершена!")
            log.info(f"  viewerId:    {viewer_id}")
            log.info(f"  login_token: {login_token[:30]}...")

            _save_config(login_token, viewer_id, self.device_id)
            await asyncio.sleep(1.0)

        except RuntimeError as e:
            log.error(str(e))
        except asyncio.TimeoutError:
            log.error("Таймаут ожидания ответа от сервера")
        except EOFError:
            log.error("Ввод прерван")
        except Exception as e:
            log.error(f"Ошибка: {e}", exc_info=True)
        finally:
            recv_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

        log.info("Соединение закрыто")


# ══════════════════════════════════════════════════════════════════════════════
# СОХРАНЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════

def _load_accounts(path: Path) -> dict:
    """Читает phone_auth.conf формата TOKEN_1=... VIEWER_ID_1=... DEVICE_ID_1=..."""
    accounts = {}
    if not path.exists():
        return accounts
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        # Парсим суффикс: TOKEN_1 -> ("TOKEN", 1)
        for prefix in ("TOKEN", "VIEWER_ID", "DEVICE_ID"):
            if key.startswith(prefix):
                suffix = key[len(prefix):]
                idx = int(suffix.lstrip("_")) if suffix.lstrip("_").isdigit() else 1
                if idx not in accounts:
                    accounts[idx] = {}
                accounts[idx][prefix] = val
                break
    return accounts


def _write_accounts(path: Path, accounts: dict):
    lines = [f"# phone_auth.conf — {time.strftime('%Y-%m-%d %H:%M:%S')}"]
    for idx in sorted(accounts.keys()):
        acc = accounts[idx]
        suffix = f"_{idx}"
        lines.append(f"TOKEN{suffix}={acc.get('TOKEN', '')}")
        lines.append(f"VIEWER_ID{suffix}={acc.get('VIEWER_ID', '')}")
        lines.append(f"DEVICE_ID{suffix}={acc.get('DEVICE_ID', '')}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _save_config(token: str, viewer_id, device_id: str):
    out        = Path(__file__).parent / "phone_auth.conf"
    accounts   = _load_accounts(out)
    new_viewer = str(viewer_id or "")

    # Ищем существующий аккаунт по VIEWER_ID (только если viewer_id не пустой)
    if new_viewer:
        for idx, acc in accounts.items():
            if acc.get("VIEWER_ID") == new_viewer:
                accounts[idx]["TOKEN"]     = token
                accounts[idx]["DEVICE_ID"] = device_id
                _write_accounts(out, accounts)
                print(f"\n✓ Аккаунт _{idx} VIEWER_ID={new_viewer} обновлён\n")
                return

    # Новый аккаунт — всегда новый индекс
    idx = max(accounts.keys(), default=0) + 1
    accounts[idx] = {"TOKEN": token, "VIEWER_ID": new_viewer, "DEVICE_ID": device_id}
    _write_accounts(out, accounts)
    print(f"\n✓ Аккаунт _{idx} VIEWER_ID={new_viewer} сохранён (всего: {len(accounts)})\n")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    if len(sys.argv) < 2:
        print("Использование: python3 phone_auth.py +79067951822")
        print()
        print("Перед запуском убедись что ГОСТ туннель запущен:")
        print("  OPENSSL_MODULES=/opt/openssl34/lib64/ossl-modules \\")
        print("  LD_LIBRARY_PATH=/opt/openssl34/lib64 \\")
        print("  sudo -E stunnel /etc/stunnel/gost.conf")
        sys.exit(1)

    phone = sys.argv[1]
    if not phone.startswith("+"):
        phone = "+" + phone

    # Читаем device_id из conf если есть, иначе генерируем новый
    conf_path = Path(__file__).parent / "client.conf"
    device_id = None
    if conf_path.exists():
        for line in conf_path.read_text().splitlines():
            if line.startswith("DEVICE_ID="):
                device_id = line.split("=", 1)[1].strip()
                break
    if not device_id:
        conf_path2 = Path(__file__).parent / "phone_auth.conf"
        if conf_path2.exists():
            for line in conf_path2.read_text().splitlines():
                if line.startswith("DEVICE_ID="):
                    device_id = line.split("=", 1)[1].strip()
                    break
    if not device_id:
        device_id = str(uuid.uuid4())
        log.info("device_id: сгенерирован новый")
    else:
        log.info(f"device_id: загружен из conf")

    log.info(f"Телефон:   {phone}")
    log.info(f"device_id: {device_id}")

    await PhoneAuthClient(device_id=device_id).run(phone)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Прервано")