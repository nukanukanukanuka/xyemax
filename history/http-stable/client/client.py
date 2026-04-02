#!/usr/bin/env python3
"""
client.py — HTTP/HTTPS прокси с батч-транспортом через MAX файловый канал.

Архитектура:
  Браузер → HTTP/HTTPS прокси (localhost:8080)
          → батч запросов (JSON + тела)     → MAX файл →
          ← батч ответов (JSON + тела)      ← MAX файл ←
          → браузер получает ответы

Ключевые отличия от TCP-туннеля:
  - Через WS проходит 2 файла на сессию (запросы + ответы), а не десятки TCP-чанков
  - client.py делает TLS termination локально (self-signed CA)
  - Накапливает запросы за окно BATCH_WINDOW_MS и шлёт одним файлом
  - server.py выполняет все запросы параллельно и шлёт одним файлом назад

Конфиг (client.conf):
    TOKEN     = <токен>
    VIEWER_ID = <viewerId>
    DEVICE_ID = <deviceId>
    HTTP_PORT = 8080   # порт HTTP/HTTPS прокси (опционально)

Зависимости:
    pip install websockets aiohttp cryptography
"""

import asyncio
import base64
import json
import logging
import ssl
import sys
import time
import uuid
import zlib
from collections import deque
from pathlib import Path

import aiohttp
import websockets

# ══════════════════════════════════════════════════════════════════════════════
# КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════

def _load_config():
    cfg_path = Path(__file__).parent / "client.conf"
    if not cfg_path.exists():
        raise FileNotFoundError(f"client.conf не найден: {cfg_path}")
    cfg = {}
    for line in cfg_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        key, _, val = line.partition("=")
        cfg[key.strip()] = val.strip()
    return cfg

_cfg = _load_config()

def _load_accounts(cfg: dict) -> list[dict]:
    accounts = []
    idx = 1
    while True:
        suffix = "" if idx == 1 else f"_{idx}"
        token  = cfg.get(f"TOKEN{suffix}")
        viewer = cfg.get(f"VIEWER_ID{suffix}")
        device = cfg.get(f"DEVICE_ID{suffix}")
        if token and viewer and device:
            accounts.append({
                "token": token,
                "viewer_id": int(viewer),
                "device_id": device,
                "label": f"acc{idx}",
            })
            idx += 1
            continue
        if idx == 1:
            raise KeyError("В client.conf нужны TOKEN/VIEWER_ID/DEVICE_ID")
        break
    return accounts

ACCOUNTS    = _load_accounts(_cfg)
TOKEN       = ACCOUNTS[0]["token"]
VIEWER_ID   = ACCOUNTS[0]["viewer_id"]
DEVICE_ID   = ACCOUNTS[0]["device_id"]
HTTP_HOST   = "127.0.0.1"
HTTP_PORT   = int(_cfg.get("HTTP_PORT", "8080"))
SELF_CHAT_ID = 0

# Батчинг: ждём до BATCH_WINDOW_MS после первого запроса в окне
BATCH_WINDOW_MS = int(_cfg.get("BATCH_WINDOW_MS", "80"))
# Максимальный размер батча (байт) перед принудительным сбросом
BATCH_MAX_BYTES = int(_cfg.get("BATCH_MAX_BYTES", str(8 * 1024 * 1024)))  # 8 МБ
# Таймаут ожидания ответа от server.py (секунд)
RESPONSE_TIMEOUT = float(_cfg.get("RESPONSE_TIMEOUT", "60"))
# Минимальный интервал между загрузками файлов (секунд), защита от rate limit
UPLOAD_MIN_INTERVAL = float(_cfg.get("UPLOAD_MIN_INTERVAL", "0.5"))

_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE  = _LOGS_DIR / f"client_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"

# ══════════════════════════════════════════════════════════════════════════════
# ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════

class _SpeedFilter(logging.Filter):
    def filter(self, record):
        return record.getMessage().startswith("BATCH ")

def _setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(fh)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S"))
    ch.addFilter(_SpeedFilter())
    root.addHandler(ch)
    for noisy in ("websockets", "asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

_setup_logging()
log = logging.getLogger(__name__)

def _console(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"{ts}  {msg}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
# TLS / CA — генерируем self-signed CA для HTTPS MITM
# ══════════════════════════════════════════════════════════════════════════════

_CA_KEY_FILE  = Path("mitm_ca.key")
_CA_CERT_FILE = Path("mitm_ca.crt")
_CERT_CACHE: dict[str, tuple[bytes, bytes]] = {}  # host → (cert_pem, key_pem)

def _ensure_ca():
    """Создать CA ключ+сертификат при первом запуске."""
    if _CA_KEY_FILE.exists() and _CA_CERT_FILE.exists():
        return
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "MAX Proxy MITM CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MAX Proxy"),
        ])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        _CA_KEY_FILE.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        _CA_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _console(f"CA создан: {_CA_CERT_FILE}  (добавьте в доверенные браузера)")
    except ImportError:
        log.warning("cryptography не установлена, HTTPS MITM недоступен. pip install cryptography")

def _get_server_cert(hostname: str) -> ssl.SSLContext:
    """Вернуть SSLContext с сертификатом для hostname (кэшируется)."""
    if hostname not in _CERT_CACHE:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        ca_key_pem  = _CA_KEY_FILE.read_bytes()
        ca_cert_pem = _CA_CERT_FILE.read_bytes()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.x509 import load_pem_x509_certificate
        ca_key  = load_pem_private_key(ca_key_pem, password=None)
        ca_cert = load_pem_x509_certificate(ca_cert_pem)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        _CERT_CACHE[hostname] = (cert_pem, key_pem)

    cert_pem, key_pem = _CERT_CACHE[hostname]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem); cf_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem); kf_path = kf.name
    try:
        ctx.load_cert_chain(cf_path, kf_path)
    finally:
        os.unlink(cf_path); os.unlink(kf_path)
    return ctx

# ══════════════════════════════════════════════════════════════════════════════
# ТРАНСПОРТ — переиспользован почти без изменений из оригинала
# ══════════════════════════════════════════════════════════════════════════════

_WS_URL = "wss://ws-api.oneme.ru/websocket"
_WS_HEADERS = {
    "Origin": "https://web.max.ru",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
}


def _pack_file(data: bytes) -> bytes:
    """zlib compress если выгодно, иначе raw. Возвращает (payload, is_compressed)."""
    c = zlib.compress(data, level=1)
    if len(c) < len(data):
        return b"\x01" + c   # первый байт = флаг сжатия
    return b"\x00" + data

def _unpack_file(payload: bytes) -> bytes:
    if not payload: return b""
    if payload[0] == 1: return zlib.decompress(payload[1:])
    return payload[1:]


class MaxTransport:
    def __init__(self, token: str, viewer_id: int, device_id: str, chat_id: int, label: str = "acc1"):
        self.label      = label
        self.token      = token
        self.viewer_id  = viewer_id
        self.device_id  = device_id
        self.chat_id    = chat_id
        self.seq        = 0
        self.ws         = None
        self._once: dict[str, asyncio.Future] = {}
        self._send_queue: asyncio.Queue = asyncio.Queue()
        self._http: aiohttp.ClientSession | None = None
        self._recent_outgoing_file_ids: set[int] = set()
        self._seen_file_ids: set[int] = set()
        self._seen_file_ids_order = deque(maxlen=4096)
        self._op88_sem = asyncio.Semaphore(4)
        # Колбэк: вызывается когда пришёл файл с ответами (bytes)
        self.on_batch_response: callable = None
        # Колбэк: вызывается при разрыве WS
        self.on_disconnect: callable = None
        # Время последней успешной отправки файла (для rate limiting)
        self._last_upload_time: float = 0.0

    def _next_seq(self):
        s = self.seq; self.seq += 1; return s

    async def _send_raw(self, opcode: int, payload: dict):
        frame = {"ver": 11, "cmd": 0, "seq": self._next_seq(),
                 "opcode": opcode, "payload": payload}
        await self.ws.send(json.dumps(frame, ensure_ascii=False, separators=(",", ":")))

    async def _wait_once(self, key: str, timeout: float = 15.0):
        fut = asyncio.get_event_loop().create_future()
        self._once[key] = fut
        return await asyncio.wait_for(fut, timeout=timeout)

    def _mark_seen_file(self, file_id: int):
        if file_id in self._seen_file_ids: return
        if len(self._seen_file_ids_order) >= self._seen_file_ids_order.maxlen:
            old = self._seen_file_ids_order.popleft()
            self._seen_file_ids.discard(old)
        self._seen_file_ids.add(file_id)
        self._seen_file_ids_order.append(file_id)

    async def send_file(self, file_body: bytes):
        """Поставить файл в очередь отправки."""
        await self._send_queue.put(file_body)

    async def _send_worker(self):
        while True:
            file_body = await self._send_queue.get()
            if file_body is None: break
            try:
                await self._upload_and_publish(file_body)
            except Exception as e:
                log.error(f"[transport:{self.label}] send_worker error: {e}", exc_info=True)

    async def _upload_and_publish(self, file_body: bytes):
        http = self._http
        loop = asyncio.get_event_loop()

        # Rate limiting: выдерживаем минимальный интервал между загрузками
        now = loop.time()
        wait = self._last_upload_time + UPLOAD_MIN_INTERVAL - now
        if wait > 0:
            await asyncio.sleep(wait)

        # Запрос upload-слота с повторной попыткой при таймауте
        slot = None
        for attempt in range(3):
            fut87 = loop.create_future()
            self._once["op87"] = fut87
            await self._send_raw(87, {"count": 1})
            try:
                slot = await asyncio.wait_for(fut87, timeout=10.0)
                break
            except asyncio.TimeoutError:
                self._once.pop("op87", None)
                log.warning(f"[transport:{self.label}] op87 timeout attempt={attempt+1}/3")
                if attempt < 2:
                    await asyncio.sleep(2.0 * (attempt + 1))
        if slot is None:
            log.error(f"[transport:{self.label}] upload slot timeout after 3 attempts, dropping batch")
            return

        info    = slot["info"][0]
        up_url  = info["url"]
        file_id = int(info["fileId"])

        fut136 = loop.create_future()
        self._once[f"op136_{file_id}"] = fut136
        await self._send_raw(65, {"chatId": self.chat_id, "type": "FILE"})

        form = aiohttp.FormData()
        form.add_field("file", file_body,
                       filename="batch.bin",
                       content_type="application/octet-stream")
        async with http.post(up_url, data=form) as resp:
            if resp.status != 200:
                body = await resp.text()
                self._once.pop(f"op136_{file_id}", None)
                log.error(f"[transport:{self.label}] upload failed {resp.status}: {body}"); return
            self._last_upload_time = loop.time()
            log.debug(f"[transport:{self.label}] upload ok  fileId={file_id}  size={len(file_body)}")

        try:
            await asyncio.wait_for(fut136, timeout=20.0)
        except asyncio.TimeoutError:
            self._once.pop(f"op136_{file_id}", None)
            log.warning(f"[transport:{self.label}] op136 timeout fileId={file_id}")

        self._recent_outgoing_file_ids.add(file_id)
        await self._send_raw(64, {
            "chatId": self.chat_id,
            "message": {
                "cid": -int(time.time() * 1000),
                "attaches": [{"_type": "FILE", "fileId": file_id}],
            },
            "notify": True,
        })

    async def _handshake(self):
        await self._send_raw(6, {
            "userAgent": {
                "deviceType": "WEB", "locale": "ru", "deviceLocale": "ru",
                "osVersion": "Linux", "deviceName": "Chrome",
                "headerUserAgent": _WS_HEADERS["User-Agent"],
                "appVersion": "26.3.7", "screen": "1920x1080 1.0x",
                "timezone": "Europe/Moscow",
            },
            "deviceId": self.device_id,
        })
        await self._wait_once("op6")
        await self._send_raw(19, {
            "token": self.token, "chatsCount": 50, "interactive": True,
            "chatsSync": 0, "contactsSync": 0, "presenceSync": -1, "draftsSync": 0,
        })
        await self._wait_once("op19")
        await self._send_raw(48, {"chatIds": [self.chat_id]})
        await self._send_raw(75, {"chatId": self.chat_id, "subscribe": True})
        log.info(f"Авторизован [client:{self.label}], chatId={self.chat_id}")

    async def _recv_loop(self):
        async for raw in self.ws:
            try: frame = json.loads(raw)
            except Exception: continue
            op, cmd, pl = frame.get("opcode"), frame.get("cmd"), frame.get("payload", {})

            if cmd == 1 and op == 6   and "op6"  in self._once:
                f = self._once.pop("op6");  f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 19  and "op19" in self._once:
                f = self._once.pop("op19"); f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 87  and "op87" in self._once:
                f = self._once.pop("op87"); f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 88:
                fid = pl.get("fileId") or pl.get("id")
                key = f"op88_{fid}" if fid and f"op88_{fid}" in self._once else None
                if key is None:
                    key = next((k for k in list(self._once) if k.startswith("op88_")), None)
                if key:
                    f = self._once.pop(key); f.done() or f.set_result(pl); continue
            if cmd == 0 and op == 136:
                fid = pl.get("fileId") or pl.get("id")
                key = f"op136_{int(fid)}" if fid is not None else None
                if key and key in self._once:
                    f = self._once.pop(key); f.done() or f.set_result(pl); continue
            if cmd == 0 and op in (292, 48, 180, 177, 65, 130):
                continue

            if (op == 128 and cmd == 0) or (op == 64 and cmd == 1 and isinstance(pl, dict) and "message" in pl):
                msg      = pl.get("message", {})
                attaches = msg.get("attaches", [])
                if not attaches: continue
                attach   = attaches[0]
                if attach.get("_type") != "FILE": continue
                file_id  = attach.get("fileId") or attach.get("id")
                msg_id   = msg.get("msgId") or msg.get("id") or ""
                if not file_id: continue
                file_id = int(file_id)
                if file_id in self._recent_outgoing_file_ids:
                    self._recent_outgoing_file_ids.discard(file_id)
                    continue
                if file_id in self._seen_file_ids: continue
                self._mark_seen_file(file_id)
                chat_id = pl.get("chatId")
                asyncio.create_task(self._recv_file(file_id, str(msg_id), chat_id))

    async def _recv_file(self, file_id: int, msg_id: str, chat_id: int):
        async with self._op88_sem:
            key = f"op88_{file_id}"
            fut = asyncio.get_event_loop().create_future()
            self._once[key] = fut
            await self._send_raw(88, {"fileId": file_id, "chatId": chat_id, "messageId": msg_id})
            try:
                pl = await asyncio.wait_for(fut, timeout=22.0)
            except asyncio.TimeoutError:
                self._once.pop(key, None)
                log.error(f"[transport:{self.label}] op88 timeout fileId={file_id}"); return
            url = pl.get("url")
            if not url: return
            try:
                async with self._http.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        log.error(f"[transport:{self.label}] download {resp.status}"); return
                    payload = await resp.read()
            except Exception as e:
                log.error(f"[transport:{self.label}] download error: {e}"); return

        data = _unpack_file(payload)
        log.debug(f"[transport:{self.label}] recv_file fileId={file_id} size={len(data)}")
        if self.on_batch_response:
            asyncio.create_task(self.on_batch_response(data))

    async def _keepalive(self):
        """
        Keepalive по образцу нативного клиента MAX:
          - opcode 1 {"interactive": true/false} каждые ~30 сек
          - opcode 48 (подписка на чат) каждые ~60 сек
        """
        tick = 0
        interactive = True
        while True:
            await asyncio.sleep(30)
            tick += 1
            try:
                # op1: activity ping, чередуем interactive true/false как нативный клиент
                await self._send_raw(1, {"interactive": interactive})
                interactive = not interactive
                # op48: переподписка на чат раз в 2 тика (~60 сек)
                if tick % 2 == 0:
                    await self._send_raw(48, {"chatIds": [self.chat_id]})
            except Exception:
                break

    async def connect(self):
        async with websockets.connect(
            _WS_URL, additional_headers=_WS_HEADERS,
            ping_interval=20, ping_timeout=30, close_timeout=5,
        ) as ws:
            self.ws = ws
            connector = aiohttp.TCPConnector(limit_per_host=4, keepalive_timeout=30)
            self._http = aiohttp.ClientSession(connector=connector)
            recv_task      = asyncio.create_task(self._recv_loop())
            keepalive_task = asyncio.create_task(self._keepalive())
            send_task      = asyncio.create_task(self._send_worker())
            await self._handshake()
            try:
                await recv_task
            finally:
                keepalive_task.cancel()
                await self._send_queue.put(None)
                try: await asyncio.wait_for(send_task, timeout=5)
                except Exception: send_task.cancel()
                if self._http and not self._http.closed:
                    await self._http.close()
                self._http = None
                if self.on_disconnect:
                    asyncio.create_task(self.on_disconnect())



# ══════════════════════════════════════════════════════════════════════════════
# MULTI TRANSPORT — round-robin по нескольким аккаунтам
# ══════════════════════════════════════════════════════════════════════════════

class MultiTransport:
    """
    Обёртка над несколькими MaxTransport.
    - Каждый транспорт коннектится и реконнектится независимо
    - send_file() отправляет через следующий живой транспорт (round-robin)
    - on_batch_response вызывается для любого входящего файла
    - on_disconnect вызывается когда ВСЕ транспорты отвалились одновременно
    """
    def __init__(self, transports: list):
        self._transports = transports
        self._alive: set[int] = set()   # индексы живых транспортов
        self._rr_idx = 0
        self._lock = asyncio.Lock()
        self.on_batch_response: callable = None
        self.on_disconnect: callable = None
        for i, t in enumerate(transports):
            t.on_batch_response = self._make_recv_cb(i)
            t.on_disconnect     = self._make_disc_cb(i)

    def _make_recv_cb(self, idx: int):
        async def _cb(data: bytes):
            if self.on_batch_response:
                await self.on_batch_response(data)
        return _cb

    def _make_disc_cb(self, idx: int):
        async def _cb():
            async with self._lock:
                self._alive.discard(idx)
                log.warning(f"[multi] транспорт {self._transports[idx].label} отвалился, живых: {len(self._alive)}/{len(self._transports)}")
            if not self._alive and self.on_disconnect:
                await self.on_disconnect()
        return _cb

    async def send_file(self, file_body: bytes):
        """Round-robin по живым транспортам."""
        async with self._lock:
            alive = [i for i in range(len(self._transports)) if i in self._alive]
        if not alive:
            log.error("[multi] нет живых транспортов, батч дропается")
            return
        # round-robin
        self._rr_idx = (self._rr_idx + 1) % len(alive)
        idx = alive[self._rr_idx % len(alive)]
        t = self._transports[idx]
        log.debug(f"[multi] send via {t.label}")
        await t.send_file(file_body)

    async def _run_one(self, idx: int):
        """Запустить один транспорт с бесконечным реконнектом."""
        t = self._transports[idx]
        delay = 5
        while True:
            try:
                async with self._lock:
                    self._alive.add(idx)
                await t.connect()
            except Exception as e:
                log.error(f"[multi] {t.label} разрыв: {e}. Reconnect in {delay}s...")
            finally:
                async with self._lock:
                    self._alive.discard(idx)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)

    async def connect(self):
        """Запустить все транспорты параллельно."""
        tasks = [asyncio.create_task(self._run_one(i)) for i in range(len(self._transports))]
        _console(f"[multi] запущено {len(tasks)} транспортов: {[t.label for t in self._transports]}")
        await asyncio.gather(*tasks)


# ══════════════════════════════════════════════════════════════════════════════
# BATCH MANAGER — накапливает HTTP запросы и отправляет батчами
# ══════════════════════════════════════════════════════════════════════════════

class BatchManager:
    """
    Собирает HTTP запросы в течение BATCH_WINDOW_MS, упаковывает в один файл,
    отправляет через transport. Ждёт ответного файла и раздаёт ответы обратно
    ожидающим coroutine через Future.
    """
    def __init__(self, transport: MaxTransport):
        self.t = transport
        self.t.on_batch_response = self._on_batch_response
        self.t.on_disconnect = self._on_disconnect
        # Текущий накапливаемый батч
        self._pending: list[dict] = []       # список {"id", "method", "url", "headers", "body_b64"}
        self._pending_bytes = 0
        self._flush_task: asyncio.Task | None = None
        # Ожидающие ответа: batch_id → {req_id → Future}
        self._waiting: dict[str, dict[str, asyncio.Future]] = {}
        self._lock = asyncio.Lock()

    async def fetch(self, method: str, url: str, headers: dict, body: bytes) -> dict:
        """
        Добавить запрос в батч. Вернёт {"status", "headers", "body"} когда придёт ответ.
        """
        req_id = uuid.uuid4().hex[:8]
        fut = asyncio.get_event_loop().create_future()

        body_b64 = base64.b64encode(body).decode() if body else ""
        # Убираем заголовки которые мешают (keep-alive, proxy-*)
        clean_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in ("proxy-connection", "proxy-authenticate",
                                  "proxy-authorization", "connection",
                                  "keep-alive", "te", "trailers",
                                  "transfer-encoding", "upgrade")
        }
        req = {
            "id": req_id,
            "method": method,
            "url": url,
            "headers": clean_headers,
            "body_b64": body_b64,
        }

        async with self._lock:
            # Найти или создать batch_id для этой волны запросов
            batch_id = self._current_batch_id()
            if batch_id not in self._waiting:
                self._waiting[batch_id] = {}
            self._waiting[batch_id][req_id] = fut
            req["batch_id"] = batch_id
            self._pending.append(req)
            self._pending_bytes += len(body)

            # Запустить таймер флаша если не запущен
            if self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(
                    self._flush_after(BATCH_WINDOW_MS / 1000.0))

            # Принудительный флаш если батч слишком большой
            if self._pending_bytes >= BATCH_MAX_BYTES:
                if self._flush_task and not self._flush_task.done():
                    self._flush_task.cancel()
                await self._flush_now()

        try:
            return await asyncio.wait_for(fut, timeout=RESPONSE_TIMEOUT)
        except asyncio.TimeoutError:
            return {"status": 504, "headers": {}, "body": b"Gateway Timeout (batch)"}

    def _current_batch_id(self) -> str:
        """Вернуть ID текущего открытого батча (или создать новый)."""
        if self._pending:
            return self._pending[0]["batch_id"]
        return uuid.uuid4().hex[:12]

    async def _flush_after(self, delay: float):
        await asyncio.sleep(delay)
        async with self._lock:
            await self._flush_now()

    async def _flush_now(self):
        if not self._pending: return
        reqs = self._pending[:]
        self._pending.clear()
        self._pending_bytes = 0

        batch_id = reqs[0]["batch_id"]
        payload_obj = {"batch_id": batch_id, "requests": reqs}
        payload_json = json.dumps(payload_obj, ensure_ascii=False).encode()
        file_body = _pack_file(payload_json)

        n_req = len(reqs)
        urls  = [r["url"] for r in reqs[:3]]
        log.debug(f"[batch] flush batch_id={batch_id} reqs={n_req} size={len(file_body)}")
        t0 = time.time()
        await self.t.send_file(file_body)
        log.info(f"BATCH sent  id={batch_id}  reqs={n_req}  {len(file_body)//1024}КБ  urls={urls}")

    async def _on_batch_response(self, data: bytes):
        """Вызывается когда пришёл файл с ответами."""
        try:
            resp_obj = json.loads(data)
        except Exception as e:
            log.error(f"[batch] ошибка парсинга ответа: {e}"); return

        batch_id  = resp_obj.get("batch_id", "")
        responses = resp_obj.get("responses", [])

        waiting = self._waiting.pop(batch_id, {})
        for r in responses:
            req_id = r.get("id")
            fut    = waiting.pop(req_id, None)
            if not fut or fut.done(): continue
            body = base64.b64decode(r.get("body_b64", ""))
            fut.set_result({
                "status":  r.get("status", 200),
                "headers": r.get("headers", {}),
                "body":    body,
            })
        # Если какие-то запросы не пришли — ошибка
        for req_id, fut in waiting.items():
            if not fut.done():
                fut.set_result({"status": 502, "headers": {}, "body": b"No response in batch"})
        n = len(responses)
        log.info(f"BATCH recv  id={batch_id}  reqs={n}")

    async def _on_disconnect(self):
        """Вызывается при разрыве WS — сбрасываем все зависшие Future."""
        all_waiting = list(self._waiting.items())
        self._waiting.clear()
        n = 0
        for batch_id, futs in all_waiting:
            for req_id, fut in futs.items():
                if not fut.done():
                    fut.set_result({"status": 502, "headers": {}, "body": b"WS disconnected"})
                    n += 1
        if n:
            log.warning(f"[batch] on_disconnect: сброшено {n} зависших запросов")


# ══════════════════════════════════════════════════════════════════════════════
# HTTP/HTTPS ПРОКСИ
# ══════════════════════════════════════════════════════════════════════════════

class HttpProxyHandler:
    """
    Обрабатывает входящие HTTP/HTTPS соединения от браузера.
    - Обычный HTTP: перехватывает запрос, отдаёт в BatchManager
    - HTTPS (CONNECT): делает TLS handshake как MITM, читает HTTP внутри
    """
    def __init__(self, batch_mgr: BatchManager):
        self.bm = batch_mgr

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=15)
        except asyncio.TimeoutError:
            writer.close(); return
        if not first_line:
            writer.close(); return

        try:
            method, target, proto = first_line.decode(errors="replace").rstrip().split(" ", 2)
        except ValueError:
            writer.close(); return

        if method.upper() == "CONNECT":
            await self._handle_connect(reader, writer, target)
        else:
            await self._handle_plain_http(reader, writer, method, target, proto)

    async def _handle_connect(self, reader, writer, target: str):
        """
        HTTPS MITM: делаем TLS termination локально с self-signed CA,
        читаем HTTP внутри и отправляем батчем на server.py.
        Браузеру/curl нужно доверять mitm_ca.crt.
        """
        host, _, port_s = target.rpartition(":")
        port = int(port_s or 443)

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        log.debug(f"[tunnel] CONNECT {host}:{port} (MITM)")

        try:
            ssl_ctx = _get_server_cert(host)
        except Exception as e:
            log.warning(f"[tunnel] cert error {host}: {e}")
            try: writer.close()
            except Exception: pass
            return

        raw_sock = writer.get_extra_info("socket")
        if raw_sock is None:
            try: writer.close()
            except Exception: pass
            return

        # Закрываем asyncio-обёртку, забираем сырой сокет
        writer.transport.pause_reading()
        raw_sock = raw_sock.dup()
        writer.transport.close()
        # Поднимаем plain-соединение, потом накладываем TLS через start_tls()
        raw_sock.setblocking(False)

        loop = asyncio.get_event_loop()
        tls_reader = asyncio.StreamReader()
        tls_protocol = asyncio.StreamReaderProtocol(tls_reader)
        try:
            plain_transport, _ = await loop.create_connection(
                lambda: tls_protocol, sock=raw_sock
            )
            tls_transport = await loop.start_tls(
                plain_transport, tls_protocol, ssl_ctx, server_side=True
            )
        except Exception as e:
            log.debug(f"[tunnel] TLS handshake failed {host}: {e}")
            try: raw_sock.close()
            except Exception: pass
            return

        tls_writer = asyncio.StreamWriter(tls_transport, tls_protocol, tls_reader, loop)
        await self._read_http_requests(tls_reader, tls_writer, host, port)

    async def _read_http_requests(self, reader, writer, host: str, port: int, transport=None):
        """Читать HTTP запросы из установленного (возможно TLS) соединения."""
        scheme = "https" if port == 443 else f"http+{port}"
        while True:
            try:
                req = await asyncio.wait_for(self._read_one_request(reader), timeout=30)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                break
            if req is None: break
            method, path, headers, body = req
            url = f"https://{host}{path}" if scheme.startswith("https") else f"http://{host}:{port}{path}"
            response = await self.bm.fetch(method, url, headers, body)
            try:
                await self._write_response(writer, response)
            except Exception:
                break
            # Проверяем Connection: keep-alive
            if headers.get("connection", "").lower() == "close":
                break
        try:
            if transport: transport.close()
            else: writer.close()
        except Exception: pass

    async def _handle_plain_http(self, reader, writer, method: str, target: str, proto: str):
        """Обычный HTTP запрос (не CONNECT)."""
        headers, body = await self._read_headers_body(reader)
        url = target if target.startswith("http") else f"http://{headers.get('host', 'unknown')}{target}"
        response = await self.bm.fetch(method, url, headers, body)
        try:
            await self._write_response(writer, response)
        except Exception:
            pass
        finally:
            try: writer.close()
            except Exception: pass

    async def _read_one_request(self, reader) -> tuple | None:
        """Прочитать один HTTP запрос из потока."""
        first_line = await reader.readline()
        if not first_line: return None
        try:
            method, path, _ = first_line.decode(errors="replace").rstrip().split(" ", 2)
        except ValueError:
            return None
        headers, body = await self._read_headers_body(reader)
        return method, path, headers, body

    async def _read_headers_body(self, reader) -> tuple[dict, bytes]:
        headers = {}
        while True:
            line = await reader.readline()
            if not line or line == b"\r\n": break
            decoded = line.decode(errors="replace").rstrip()
            if ":" in decoded:
                k, _, v = decoded.partition(":")
                headers[k.strip().lower()] = v.strip()

        body = b""
        content_length = int(headers.get("content-length", 0))
        if content_length > 0:
            body = await reader.read(content_length)
        return headers, body

    async def _write_response(self, writer, response: dict):
        status  = response["status"]
        hdrs    = response["headers"]
        body    = response["body"]

        status_text = {200: "OK", 301: "Moved Permanently", 302: "Found",
                       304: "Not Modified", 400: "Bad Request", 403: "Forbidden",
                       404: "Not Found", 500: "Internal Server Error",
                       502: "Bad Gateway", 504: "Gateway Timeout"}.get(status, "OK")

        lines = [f"HTTP/1.1 {status} {status_text}\r\n"]
        # Нормализуем заголовки
        response_headers = dict(hdrs)
        response_headers["content-length"] = str(len(body))
        response_headers["connection"] = "keep-alive"
        for k, v in response_headers.items():
            if k.lower() in ("transfer-encoding",): continue
            lines.append(f"{k}: {v}\r\n")
        lines.append("\r\n")
        writer.write("".join(lines).encode())
        if body: writer.write(body)
        await writer.drain()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    _ensure_ca()

    transports = [
        MaxTransport(
            token=acc["token"],
            viewer_id=acc["viewer_id"],
            device_id=acc["device_id"],
            chat_id=SELF_CHAT_ID,
            label=acc["label"],
        )
        for acc in ACCOUNTS
    ]

    multi = MultiTransport(transports)
    batch_mgr = BatchManager(multi)
    proxy     = HttpProxyHandler(batch_mgr)

    http_server = await asyncio.start_server(
        proxy.handle, HTTP_HOST, HTTP_PORT)

    _console("=" * 55)
    _console(f"MAX HTTP Proxy (batch mode)  аккаунтов: {len(ACCOUNTS)}")
    _console(f"HTTP/HTTPS прокси: {HTTP_HOST}:{HTTP_PORT}")
    _console(f"Батч окно: {BATCH_WINDOW_MS} мс  макс. батч: {BATCH_MAX_BYTES//1024} КБ")
    if _CA_CERT_FILE.exists():
        _console(f"CA сертификат: {_CA_CERT_FILE.absolute()} (добавьте в браузер)")
    _console(f"Настройте браузер: HTTP proxy = localhost:{HTTP_PORT}")
    _console(f"Лог: {LOG_FILE}")
    _console("=" * 55)

    async with http_server:
        await multi.connect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass