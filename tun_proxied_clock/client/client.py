#!/usr/bin/env python3
"""
client.py — TUN-туннель через MAX файловый канал.

Архитектура:
  Создаёт виртуальный сетевой интерфейс tun0.
  Читает IP-пакеты из tun0, накапливает за BATCH_WINDOW_MS мс,
  упаковывает в один файл и шлёт на server.py.
  server.py инжектирует пакеты в сеть (NAT), собирает ответные пакеты
  и шлёт обратно одним файлом.

Использование:
  sudo python3 client.py
  # Весь трафик через tun0 автоматически идёт через туннель.
  # Для конкретного приложения: ip route add <dst> dev tun0

Конфиг (client.conf):
    TOKEN     = <токен>
    VIEWER_ID = <viewerId>
    DEVICE_ID = <deviceId>
    TUN_NAME  = tun0          # имя интерфейса (опционально)
    TUN_ADDR  = 10.0.0.1      # локальный адрес tun (опционально)
    TUN_PEER  = 10.0.0.2      # адрес сервера в туннеле (опционально)
    TUN_MTU   = 1400           # MTU (опционально)
    DEFAULT_ROUTE = 0          # 1 = весь трафик через туннель (опционально)

Зависимости:
    pip install websockets aiohttp
    apt install iproute2
"""

import asyncio
import base64
import fcntl
import json
import logging
import os
import struct
import subprocess
import sys
import time
import uuid
import zstandard as _zstd
_zstd_cctx = _zstd.ZstdCompressor(level=1)
_zstd_dctx = _zstd.ZstdDecompressor()
from collections import deque
from pathlib import Path

import socket
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

ACCOUNTS         = _load_accounts(_cfg)
SELF_CHAT_ID     = 0
TUN_NAME         = _cfg.get("TUN_NAME",  "tun0")
TUN_ADDR         = _cfg.get("TUN_ADDR",  "10.0.0.1")
TUN_PEER         = _cfg.get("TUN_PEER",  "10.0.0.2")
TUN_MTU          = int(_cfg.get("TUN_MTU", "1400"))
DEFAULT_ROUTE    = _cfg.get("DEFAULT_ROUTE", "0") == "1"
HTTP_IFACE       = _cfg.get("HTTP_IFACE", "")  # интерфейс для HTTP трафика скрипта (upload/download)

# Батчинг
BATCH_WINDOW_MS = int(_cfg.get("BATCH_WINDOW_MS", "500"))
RESPONSE_TIMEOUT = float(_cfg.get("RESPONSE_TIMEOUT", "30"))

# Rate limit: максимум RATE_LIMIT_COUNT файлов за RATE_LIMIT_WINDOW_10MINS секунд на аккаунт
RATE_LIMIT_COUNT  = int(_cfg.get("RATE_LIMIT_COUNT", "100"))
RATE_LIMIT_WINDOW_10MINS = float(_cfg.get("RATE_LIMIT_WINDOW_10MINS", "600"))  # 10 минут

_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE = _LOGS_DIR / f"client_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"

# ══════════════════════════════════════════════════════════════════════════════
# ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════

class _SpeedFilter(logging.Filter):
    def filter(self, record):
        return "BATCH" in record.getMessage() or "TUN" in record.getMessage()

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
# TUN интерфейс
# ══════════════════════════════════════════════════════════════════════════════

TUNSETIFF   = 0x400454ca
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000

def tun_open(name: str) -> int:
    """Открыть TUN устройство, вернуть fd."""
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    ifr = struct.pack("16sH22x", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd

# Хосты WebSocket которые должны идти через реальный интерфейс, а не через тоннель
_WS_HOSTS = ["ws-api.oneme.ru", "fu.oneme.ru", "telegram.mooner.pro"]


def _get_real_gateway() -> tuple[str, str] | tuple[None, None]:
    """Возвращает (gateway, iface) текущего дефолтного маршрута."""
    r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        parts = line.split()
        try:
            gw  = parts[parts.index("via") + 1]
            dev = parts[parts.index("dev") + 1]
            return gw, dev
        except (ValueError, IndexError):
            continue
    return None, None


def tun_setup(name: str, addr: str, peer: str, mtu: int, default_route: bool):
    """Поднять интерфейс и настроить маршруты."""
    cmds = [
        ["ip", "link", "set", name, "up", "mtu", str(mtu)],
        ["ip", "addr", "add", f"{addr}/30", "dev", name],
    ]
    if default_route:
        gw, dev = _get_real_gateway()
        if gw is None:
            log.warning("[tun] не удалось определить реальный шлюз, DEFAULT_ROUTE может не работать")
        else:
            import socket as _socket

            # Защищаем DNS (systemd-resolved и публичные)
            for dns in ["127.0.0.53", "8.8.8.8", "1.1.1.1"]:
                cmds.append(["ip", "route", "add", dns, "via", gw, "dev", dev])
                log.debug(f"[tun] защита DNS {dns} через {gw} dev {dev}")

            # Защищаем всю CDN подсеть Max напрямую
            cdn_subnets = ["155.212.204.0/24", "155.212.0.0/16"]
            for subnet in cdn_subnets:
                cmds.append(["ip", "route", "add", subnet, "via", gw, "dev", dev])
                log.debug(f"[tun] защита CDN подсети {subnet} через {gw} dev {dev}")

            # Добавляем маршруты для WS хостов (только IPv4) через реальный интерфейс
            for host in _WS_HOSTS:
                try:
                    ips = set(i[4][0] for i in _socket.getaddrinfo(host, 443)
                              if i[0] == _socket.AF_INET)
                    for ip in ips:
                        cmds.append(["ip", "route", "add", ip, "via", gw, "dev", dev])
                        log.debug(f"[tun] защита WS хоста {host} ({ip}) через {gw} dev {dev}")
                except Exception as e:
                    log.warning(f"[tun] не удалось резолвить {host}: {e}")

        # Направляем весь остальной трафик через туннель
        cmds += [
            ["ip", "route", "add", "0.0.0.0/1",  "dev", name],
            ["ip", "route", "add", "128.0.0.0/1", "dev", name],
        ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log.warning(f"[tun] {' '.join(cmd)}: {r.stderr.strip()}")
        else:
            log.debug(f"[tun] {' '.join(cmd)}: OK")

def tun_teardown(name: str, default_route: bool):
    """Убрать интерфейс при выходе."""
    subprocess.run(["ip", "link", "set", name, "down"], capture_output=True)
    if default_route:
        subprocess.run(["ip", "route", "del", "0.0.0.0/1"],  capture_output=True)
        subprocess.run(["ip", "route", "del", "128.0.0.0/1"], capture_output=True)
        import socket as _socket
        for dns in ["127.0.0.53", "8.8.8.8", "1.1.1.1"]:
            subprocess.run(["ip", "route", "del", dns], capture_output=True)
        for subnet in ["155.212.204.0/24", "155.212.0.0/16"]:
            subprocess.run(["ip", "route", "del", subnet], capture_output=True)
        for host in _WS_HOSTS:
            try:
                ips = set(i[4][0] for i in _socket.getaddrinfo(host, 443)
                          if i[0] == _socket.AF_INET)
                for ip in ips:
                    subprocess.run(["ip", "route", "del", ip], capture_output=True)
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# HTTP CONNECTOR — привязка HTTP трафика к конкретному интерфейсу
# ══════════════════════════════════════════════════════════════════════════════

class BoundTCPConnector(aiohttp.TCPConnector):
    """Привязывает HTTP соединения к интерфейсу через SO_BINDTODEVICE."""
    def __init__(self, iface: str, **kwargs):
        super().__init__(**kwargs)
        self._iface = iface.encode()

    async def _wrap_create_connection(self, *args, addr_infos, req, timeout, client_error=Exception, **kwargs):
        import ssl as _ssl
        loop = asyncio.get_event_loop()
        connect_timeout = timeout.sock_connect if timeout and timeout.sock_connect else 30.0
        last_exc = None
        for af, socktype, proto, canonname, sockaddr in addr_infos:
            sock = socket.socket(af, socktype, proto)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self._iface)
                sock.setblocking(False)
                await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout=connect_timeout)
            except Exception as e:
                sock.close()
                last_exc = e
                continue
            ssl_val = req.ssl if hasattr(req, "ssl") else None
            if ssl_val is not False and ssl_val is not None:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                try:
                    return await loop.create_connection(args[0], sock=sock, ssl=ctx, server_hostname=req.url.host)
                except Exception as e:
                    sock.close(); last_exc = e; continue
            else:
                try:
                    return await loop.create_connection(args[0], sock=sock)
                except Exception as e:
                    sock.close(); last_exc = e; continue
        raise last_exc or OSError(f"Could not connect via {self._iface.decode()}")


def _make_http_connector(**kwargs) -> aiohttp.TCPConnector:
    """Создать HTTP connector — с привязкой к интерфейсу если HTTP_IFACE задан."""
    if HTTP_IFACE:
        log.info(f"[net] HTTP трафик скрипта привязан к интерфейсу: {HTTP_IFACE}")
        return BoundTCPConnector(HTTP_IFACE, **kwargs)
    return aiohttp.TCPConnector(**kwargs)


_WS_URL = "wss://ws-api.oneme.ru/websocket"
_WS_HEADERS = {
    "Origin": "https://web.max.ru",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
}

def _pack(data: bytes) -> bytes:
    c = _zstd_cctx.compress(data)
    return (b"\x02" + c) if len(c) < len(data) else (b"\x00" + data)

def _unpack(payload: bytes) -> bytes:
    if not payload: return b""
    if payload[0] == 0x02: return _zstd_dctx.decompress(payload[1:])
    if payload[0] == 0x01: import zlib; return zlib.decompress(payload[1:])
    return payload[1:]


_JPEG_TEMPLATE = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q=="
)
_JPEG_MAGIC = b"MXVPNJ1"
_JPEG_CHUNK = 60000


def _jpeg_wrap(payload: bytes) -> bytes:
    """Упаковать payload в валидный JPEG через APP15-сегменты."""
    total = max(1, (len(payload) + _JPEG_CHUNK - 1) // _JPEG_CHUNK)
    parts = [b"\xFF\xD8"]
    for idx in range(total):
        chunk = payload[idx * _JPEG_CHUNK:(idx + 1) * _JPEG_CHUNK]
        meta = _JPEG_MAGIC + struct.pack(">HH", idx, total) + chunk
        parts.append(b"\xFF\xEF" + struct.pack(">H", len(meta) + 2) + meta)
    parts.append(_JPEG_TEMPLATE[2:])
    return b"".join(parts)


def _jpeg_unwrap(blob: bytes) -> bytes:
    """Извлечь payload из JPEG APP15-сегментов; для legacy вернуть blob как есть."""
    if not blob.startswith(b"\xFF\xD8"):
        return blob
    parts: dict[int, bytes] = {}
    expected = None
    pos = 2
    n = len(blob)
    found = False
    while pos + 4 <= n:
        if blob[pos] != 0xFF:
            break
        while pos < n and blob[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = blob[pos]
        pos += 1
        if marker in (0xD9, 0xDA):
            break
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if pos + 2 > n:
            break
        seglen = int.from_bytes(blob[pos:pos + 2], "big")
        if seglen < 2 or pos + seglen > n:
            break
        seg = blob[pos + 2:pos + seglen]
        if marker == 0xEF and seg.startswith(_JPEG_MAGIC):
            if len(seg) < len(_JPEG_MAGIC) + 4:
                raise ValueError("broken jpeg tunnel segment")
            idx, total = struct.unpack(">HH", seg[len(_JPEG_MAGIC):len(_JPEG_MAGIC) + 4])
            if expected is None:
                expected = total
            elif expected != total:
                raise ValueError("jpeg tunnel segment count mismatch")
            parts[idx] = seg[len(_JPEG_MAGIC) + 4:]
            found = True
        pos += seglen
    if not found:
        return blob
    if expected is None:
        return b""
    if len(parts) != expected:
        raise ValueError(f"jpeg tunnel incomplete: {len(parts)}/{expected}")
    return b"".join(parts[i] for i in range(expected))


# ══════════════════════════════════════════════════════════════════════════════
# ТРАНСПОРТ (MaxTransport + MultiTransport) — без изменений
# ══════════════════════════════════════════════════════════════════════════════

class MaxTransport:
    def __init__(self, token: str, viewer_id: int, device_id: str,
                 chat_id: int, label: str = "acc1"):
        self.label     = label
        self.token     = token
        self.viewer_id = viewer_id
        self.device_id = device_id
        self.chat_id   = chat_id
        self.seq       = 0
        self.ws        = None
        self._once: dict[str, asyncio.Future] = {}
        self._send_queue: asyncio.Queue = asyncio.Queue()
        self._http: aiohttp.ClientSession | None = None
        self._recent_outgoing_file_ids: set[int] = set()
        self._seen_file_ids: set[int] = set()
        self._seen_file_ids_order = deque(maxlen=4096)
        self._op88_sem = asyncio.Semaphore(1)
        self.on_batch_response: callable = None
        self.on_disconnect: callable = None
        self._last_activity_time: float = 0.0
        self._last_event: str = "recv"       # "send" или "recv"
        self._recv_count: int = 0            # входящих за текущие 5 минут
        self._recv_count_reset: float = 0.0  # время последнего сброса счётчика
        self._upload_busy: bool = False      # идёт ли сейчас upload
        self._sent_times: deque = deque()    # времена отправок за скользящее окно
        # Статистика для dashboard
        self._pkts_sent_total:  int = 0
        self._pkts_recv_total:  int = 0
        self._bytes_sent_total: int = 0
        self._bytes_recv_total: int = 0
        self._speed_bytes:      int = 0      # байт за последнюю секунду
        self._speed_ts:       float = 0.0    # начало текущей секунды

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
            log.error(f"[transport:{self.label}] upload slot timeout, dropping")
            self._upload_busy = False
            return
        info    = slot["info"][0]
        up_url  = info["url"]
        file_id = int(info["fileId"])
        fut136  = loop.create_future()
        self._once[f"op136_{file_id}"] = fut136
        await self._send_raw(65, {"chatId": self.chat_id, "type": "FILE"})
        jpeg_body = _jpeg_wrap(file_body)
        form = aiohttp.FormData()
        form.add_field("file", jpeg_body, filename="tun.jpg",
                       content_type="image/jpeg")
        log.debug(f"[transport:{self.label}] jpeg-wrap raw={len(file_body)} jpeg={len(jpeg_body)}")
        async with http.post(up_url, data=form) as resp:
            if resp.status != 200:
                body = await resp.text()
                self._once.pop(f"op136_{file_id}", None)
                log.error(f"[transport:{self.label}] upload failed {resp.status}: {body}")
                self._upload_busy = False
                return
            now = loop.time()
            self._last_activity_time = now
            self._last_event = "send"
            self._pkts_sent_total  += 1
            self._bytes_sent_total += len(file_body)
            self._speed_bytes      += len(file_body)
            log.debug(f"[transport:{self.label}] upload ok fileId={file_id} size={len(file_body)}")
        try:
            await asyncio.wait_for(fut136, timeout=20.0)
        except asyncio.TimeoutError:
            self._once.pop(f"op136_{file_id}", None)
        self._upload_busy = False
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
            log.debug(f"[transport:{self.label}] ws msg op={op} cmd={cmd}")
            if cmd == 1 and op == 6   and "op6"  in self._once:
                f = self._once.pop("op6");  f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 19  and "op19" in self._once:
                f = self._once.pop("op19"); f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 87  and "op87" in self._once:
                f = self._once.pop("op87"); f.done() or f.set_result(pl); continue
            if op == 88:
                fid = pl.get("fileId") or pl.get("id")
                key = f"op88_{fid}" if fid and f"op88_{fid}" in self._once else None
                if key is None:
                    key = next((k for k in list(self._once) if k.startswith("op88_")), None)
                if key:
                    f = self._once.pop(key)
                    if cmd == 3:
                        # cmd=3 — ошибка от сервера (файл не найден и т.п.)
                        log.warning(f"[transport:{self.label}] op88 error cmd=3 fileId={fid}: {pl}")
                        f.done() or f.set_exception(Exception(f"op88 error: {pl}"))
                    else:
                        f.done() or f.set_result(pl)
                    continue
            if cmd == 0 and op == 136:
                fid = pl.get("fileId") or pl.get("id")
                key = f"op136_{int(fid)}" if fid is not None else None
                if key and key in self._once:
                    f = self._once.pop(key); f.done() or f.set_result(pl); continue
            if cmd == 0 and op in (292, 48, 180, 177, 65, 130):
                continue
            if (op == 128 and cmd == 0) or (op == 64 and cmd == 1
                    and isinstance(pl, dict) and "message" in pl):
                msg      = pl.get("message", {})
                attaches = msg.get("attaches", [])
                log.debug(f"[transport:{self.label}] msg op={op} attaches={len(attaches)}")
                if not attaches: continue
                attach   = attaches[0]
                if attach.get("_type") != "FILE":
                    log.debug(f"[transport:{self.label}] skip non-FILE attach type={attach.get('_type')}")
                    continue
                file_id  = attach.get("fileId") or attach.get("id")
                msg_id   = msg.get("msgId") or msg.get("id") or ""
                if not file_id: continue
                file_id = int(file_id)
                if file_id in self._recent_outgoing_file_ids:
                    log.debug(f"[transport:{self.label}] skip own fileId={file_id}")
                    self._recent_outgoing_file_ids.discard(file_id)
                    continue
                if file_id in self._seen_file_ids:
                    log.debug(f"[transport:{self.label}] skip seen fileId={file_id}")
                    continue
                log.debug(f"[transport:{self.label}] incoming fileId={file_id} msgId={msg_id}")
                self._mark_seen_file(file_id)
                asyncio.create_task(self._recv_file(file_id, str(msg_id),
                                                    pl.get("chatId", self.chat_id)))

    async def _recv_file(self, file_id: int, msg_id: str, chat_id: int):
        async with self._op88_sem:
            key = f"op88_{file_id}"
            fut = asyncio.get_event_loop().create_future()
            self._once[key] = fut
            await self._send_raw(88, {"fileId": file_id, "chatId": chat_id,
                                      "messageId": msg_id})
            try:
                pl = await asyncio.wait_for(fut, timeout=22.0)
            except asyncio.TimeoutError:
                self._once.pop(key, None)
                log.error(f"[transport:{self.label}] op88 timeout fileId={file_id}")
                return
            except Exception as e:
                log.warning(f"[transport:{self.label}] op88 failed fileId={file_id}: {e}")
                return
            url = pl.get("url")
            if not url: return
            try:
                async with self._http.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        log.error(f"[transport:{self.label}] download {resp.status}")
                        return
                    payload = await resp.read()
            except Exception as e:
                log.error(f"[transport:{self.label}] download error: {e}", exc_info=True)
                return
        data = _unpack(_jpeg_unwrap(payload))
        now = asyncio.get_event_loop().time()
        self._last_activity_time = now
        self._last_event = "recv"
        if now - self._recv_count_reset >= 300.0:
            self._recv_count = 0
            self._recv_count_reset = now
        self._recv_count += 1
        self._pkts_recv_total  += 1
        self._bytes_recv_total += len(data)
        self._speed_bytes      += len(data)
        log.debug(f"[transport:{self.label}] recv_file fileId={file_id} size={len(data)}")
        if self.on_batch_response:
            asyncio.create_task(self.on_batch_response(data))

    async def _keepalive(self):
        tick = 0
        interactive = True
        while True:
            await asyncio.sleep(30)
            tick += 1
            try:
                await self._send_raw(1, {"interactive": interactive})
                interactive = not interactive
                if tick % 2 == 0:
                    await self._send_raw(48, {"chatIds": [self.chat_id]})
            except Exception:
                break

    async def connect(self):
        # Сброс счётчиков при каждом переподключении
        self._recv_count = 0
        self._recv_count_reset = asyncio.get_event_loop().time()
        self._last_event = "recv"
        async with websockets.connect(
            _WS_URL, additional_headers=_WS_HEADERS,
            ping_interval=20, ping_timeout=30, close_timeout=5,
        ) as ws:
            self.ws = ws
            # Сбрасываем статистику при каждом переподключении
            self._recv_count       = 0
            self._recv_count_reset = asyncio.get_event_loop().time()
            self._last_event       = "recv"
            self._last_activity_time = 0.0
            self._upload_busy      = False
            self._speed_bytes = 0
            self._speed_ts    = 0.0
            connector = _make_http_connector(limit_per_host=4, keepalive_timeout=30)
            self._http = aiohttp.ClientSession(connector=connector)
            recv_task      = asyncio.create_task(self._recv_loop())
            keepalive_task = asyncio.create_task(self._keepalive())
            await self._handshake()
            send_task      = asyncio.create_task(self._send_worker())
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


class MultiTransport:
    def __init__(self, transports: list):
        self._transports = transports
        self._alive: set[int] = set()
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
                log.warning(f"[multi] {self._transports[idx].label} отвалился, "
                             f"живых: {len(self._alive)}/{len(self._transports)}")
            if not self._alive and self.on_disconnect:
                await self.on_disconnect()
        return _cb

    def _rate_limit_remaining(self, t, now: float) -> int:
        """Скользящее окно: убираем отправки старше RATE_LIMIT_WINDOW_10MINS секунд."""
        cutoff = now - RATE_LIMIT_WINDOW_10MINS
        while t._sent_times and t._sent_times[0] < cutoff:
            t._sent_times.popleft()
        return RATE_LIMIT_COUNT - len(t._sent_times)

    def _consume_token(self, t, now: float):
        """Записываем время отправки в скользящее окно."""
        t._sent_times.append(now)

    def _rank_transports(self, ready: list, now: float) -> int:
        """Ранжирует аккаунты по среднему месту в 3 приоритетах.
        Аккаунты с одинаковым значением получают одинаковое среднее место (tied rank).
        Возвращает idx победителя."""
        ts = [self._transports[i] for i in ready]
        n  = len(ready)

        def tied_ranks(values):
            """Назначает одинаковое место аккаунтам с одинаковым значением."""
            sorted_vals = sorted(set(values))
            val_to_rank = {}
            for rank, val in enumerate(sorted_vals, 1):
                val_to_rank[val] = rank
            return [val_to_rank[v] for v in values]

        # Приоритет 1: меньше recv_count — лучше
        rank1 = tied_ranks([ts[j]._recv_count for j in range(n)])

        # Приоритет 2: больше remaining — лучше (инвертируем)
        remainings = [self._rate_limit_remaining(ts[j], now) for j in range(n)]
        rank2 = tied_ranks([-r for r in remainings])  # минус чтобы больше = лучше место

        # Приоритет 3: last_event=="recv" лучше
        rank3 = tied_ranks([0 if ts[j]._last_event == "recv" else 1 for j in range(n)])

        # Среднее место — победитель с минимальным значением
        scores = [(rank1[j] + rank2[j] + rank3[j]) / 3.0 for j in range(n)]
        min_score = min(scores)

        # Среди победителей с одинаковым score — round-robin
        winners = [j for j in range(n) if scores[j] == min_score]
        self._rr_idx = (self._rr_idx + 1) % len(winners)
        best_j = winners[self._rr_idx % len(winners)]

        # Лог
        score_info = {ts[j].label: {
            "recv_count": ts[j]._recv_count,
            "remaining":  remainings[j],
            "last_event": ts[j]._last_event,
            "r1": rank1[j], "r2": rank2[j], "r3": rank3[j],
            "score": f"{scores[j]:.2f}",
        } for j in range(n)}
        log.debug(f"[multi] ранжирование: {score_info}")

        return ready[best_j]

    async def send_file(self, file_body: bytes):
        loop = asyncio.get_event_loop()
        best_idx = None

        while True:
            now = loop.time()
            async with self._lock:
                alive = [i for i in range(len(self._transports)) if i in self._alive]
                if not alive:
                    log.error("[multi] нет живых транспортов, пакеты дропаются")
                    return

                # Фильтр: не занятые и не исчерпавшие лимит
                ready = [i for i in alive
                         if not self._transports[i]._upload_busy
                         and self._rate_limit_remaining(self._transports[i], now) > 0]

                if not ready:
                    min_wait_val = 0.05
                else:
                    best_idx = self._rank_transports(ready, now)
                    best_t   = self._transports[best_idx]
                    best_t._upload_busy = True
                    self._consume_token(best_t, now)
                    # Предзапрашиваем op87 слот пока батч ещё в очереди

                    stats = {self._transports[i].label: {
                        "recv_count": self._transports[i]._recv_count,
                        "remaining":  self._rate_limit_remaining(self._transports[i], now),
                        "last_event": self._transports[i]._last_event,
                        "busy":       self._transports[i]._upload_busy,
                    } for i in alive}
                    log.debug(
                        f"[multi] выбор: {best_t.label} "
                        f"(recv_count={best_t._recv_count}, "
                        f"remaining={self._rate_limit_remaining(best_t, now) + 1}, "
                        f"last_event={best_t._last_event}) "
                        f"| stats={stats}"
                    )
                    min_wait_val = 0

            if min_wait_val > 0:
                log.debug(f"[multi] все аккаунты заняты или лимит исчерпан, ждём {min_wait_val:.3f}s")
                await asyncio.sleep(min_wait_val)
                continue
            break

        await self._transports[best_idx].send_file(file_body)

    async def _run_one(self, idx: int):
        t = self._transports[idx]
        delay = 0
        while True:
            try:
                async with self._lock:
                    self._alive.add(idx)
                await t.connect()
                delay = 0  # успешное подключение — сбрасываем задержку
            except asyncio.CancelledError:
                raise
            except Exception as e:
                if delay > 0:
                    log.error(f"[multi] {t.label} разрыв: {e}. Reconnect in {delay}s...")
                else:
                    log.warning(f"[multi] {t.label} разрыв: {e}. Reconnect немедленно...")
            finally:
                async with self._lock:
                    self._alive.discard(idx)
            if delay > 0:
                await asyncio.sleep(delay)
            delay = min(max(delay, 1) * 2, 60)

    async def connect(self):
        tasks = [asyncio.create_task(self._run_one(i))
                 for i in range(len(self._transports))]
        _console(f"[multi] запущено {len(tasks)} транспортов: "
                 f"{[t.label for t in self._transports]}")
        await asyncio.gather(*tasks)


# ══════════════════════════════════════════════════════════════════════════════
# TUN MANAGER — читает пакеты из tun, батчует, пишет ответы обратно
# ══════════════════════════════════════════════════════════════════════════════

class TunManager:
    """
    Читает IP-пакеты из tun-интерфейса, накапливает за BATCH_WINDOW_MS,
    упаковывает msgpack-подобным форматом и шлёт через transport.
    Если аккаунты заняты — продолжает копить и ждёт освобождения.
    Входящие пакеты от server.py пишет обратно в tun.

    Формат файла (бинарный, компактный):
      [4 байта BE: кол-во пакетов]
      для каждого пакета:
        [2 байта BE: длина][N байт: IP пакет]
    """
    def __init__(self, tun_fd: int, transport: MultiTransport):
        self.fd        = tun_fd
        self.transport = transport
        self.transport.on_batch_response = self._on_response
        self._pending: list[bytes] = []
        self._pending_bytes  = 0
        self._batch_ready    = asyncio.Event()  # сигнал: батч готов к отправке
        self._lock = asyncio.Lock()
        self._pkts_sent = 0
        self._pkts_recv = 0
        self._bytes_sent = 0
        self._bytes_recv = 0
        self._t0 = time.time()

    # ── Encode / Decode ───────────────────────────────────────────────────────

    @staticmethod
    def _encode(packets: list[bytes]) -> bytes:
        import struct
        parts = [struct.pack(">I", len(packets))]
        for pkt in packets:
            parts.append(struct.pack(">H", len(pkt)))
            parts.append(pkt)
        return b"".join(parts)

    @staticmethod
    def _decode(data: bytes) -> list[bytes]:
        import struct
        if len(data) < 4: return []
        count = struct.unpack_from(">I", data, 0)[0]
        offset = 4
        packets = []
        for _ in range(count):
            if offset + 2 > len(data): break
            plen = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            if offset + plen > len(data): break
            packets.append(data[offset:offset + plen])
            offset += plen
        return packets

    # ── Чтение из TUN → батч → отправка ─────────────────────────────────────

    async def read_loop(self):
        """Читаем пакеты из tun, накапливаем за BATCH_WINDOW_MS, затем сигналим send_loop."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                pkt = await loop.run_in_executor(None, os.read, self.fd, TUN_MTU + 4)
            except OSError as e:
                if e.errno == 11:  # EAGAIN — нет данных, норма для O_NONBLOCK
                    await asyncio.sleep(0.01)
                    continue
                log.error(f"[tun] read error: {e}")
                await asyncio.sleep(0.1)
                continue
            if not pkt:
                continue
            async with self._lock:
                was_empty = len(self._pending) == 0
                self._pending.append(pkt)
                self._pending_bytes += len(pkt)
                # Запускаем таймер только при первом пакете в батче
                if was_empty:
                    asyncio.create_task(self._arm_batch())

    async def _arm_batch(self):
        """Ждём BATCH_WINDOW_MS, затем сигналим send_loop что батч готов."""
        await asyncio.sleep(BATCH_WINDOW_MS / 1000.0)
        self._batch_ready.set()

    async def send_loop(self):
        """Ждём готовности батча, затем отправляем как только аккаунт свободен."""
        while True:
            await self._batch_ready.wait()
            self._batch_ready.clear()
            async with self._lock:
                if not self._pending:
                    continue
                pkts = self._pending[:]
                self._pending.clear()
                self._pending_bytes = 0
            raw    = self._encode(pkts)
            packed = _pack(raw)
            self._pkts_sent  += len(pkts)
            self._bytes_sent += len(raw)
            log.debug(f"[tun] → {len(pkts)} pkts  raw={len(raw)}B  packed={len(packed)}B")
            # send_file ждёт свободный аккаунт сам — данные не теряются
            await self.transport.send_file(packed)

    # ── Приём ответов от сервера → запись в TUN ───────────────────────────────

    async def _on_response(self, data: bytes):
        pkts  = self._decode(data)
        if not pkts:
            return
        self._pkts_recv  += len(pkts)
        self._bytes_recv += len(data)
        log.debug(f"[tun] ← {len(pkts)} pkts  raw={len(data)}B")
        loop = asyncio.get_event_loop()
        for pkt in pkts:
            try:
                await loop.run_in_executor(None, os.write, self.fd, pkt)
            except OSError as e:
                log.warning(f"[tun] write error: {e}")

    # ── Статистика / Dashboard ───────────────────────────────────────────────

    async def stats_loop(self):
        """Живой dashboard — обновляет строки на месте через ANSI escape."""
        transports = self.transport._transports
        n = len(transports)
        # Резервируем n строк
        print("\n" * n, end="", flush=True)
        speed_window: dict[int, float] = {}  # idx -> байт за текущую секунду
        speed_ts:     dict[int, float] = {}
        speed_kbps:   dict[int, float] = {}  # idx -> кбит/с (сглаженная)

        now_ts = time.time()
        for i in range(n):
            speed_window[i] = 0.0
            speed_ts[i]     = now_ts
            speed_kbps[i]   = 0.0

        while True:
            await asyncio.sleep(0.5)
            now_ts = time.time()
            now_ev = asyncio.get_event_loop().time()

            lines = []
            for i, t in enumerate(transports):
                # Скорость: байт накоплено за последние 0.5с → кбит/с
                elapsed = now_ts - speed_ts[i]
                if elapsed >= 0.5:
                    instant = (t._speed_bytes * 8 / 1000) / elapsed  # кбит/с
                    # EMA сглаживание
                    speed_kbps[i] = speed_kbps[i] * 0.4 + instant * 0.6
                    t._speed_bytes = 0
                    speed_ts[i]    = now_ts

                # Остаток лимита
                cutoff = now_ev - RATE_LIMIT_WINDOW_10MINS
                while t._sent_times and t._sent_times[0] < cutoff:
                    t._sent_times.popleft()
                remaining = RATE_LIMIT_COUNT - len(t._sent_times)

                busy_mark = "●" if t._upload_busy else " "
                line = (
                    f"  {busy_mark} {t.label:<6} "
                    f"↓{t._pkts_recv_total:>5}  "
                    f"↑{t._pkts_sent_total:>5}  "
                    f"{speed_kbps[i]:>7.1f} кбит/с  "
                    f"лимит: {remaining:>3}/{RATE_LIMIT_COUNT}"
                )
                lines.append(line)

            # Перемещаемся вверх на n строк и перезаписываем
            sys.stdout.write("\033[" + str(n) + "A")
            for line in lines:
                sys.stdout.write("\033[2K" + line + "\n")
            sys.stdout.flush()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    if os.geteuid() != 0:
        print("Ошибка: нужен root (sudo python3 client.py)")
        sys.exit(1)

    _console("=" * 55)
    _console(f"MAX TUN клиент  аккаунтов: {len(ACCOUNTS)}")
    _console(f"Интерфейс: {TUN_NAME}  {TUN_ADDR} ↔ {TUN_PEER}  MTU={TUN_MTU}")
    _console(f"DEFAULT_ROUTE={'да' if DEFAULT_ROUTE else 'нет'}")
    _console(f"Батч окно: {BATCH_WINDOW_MS}мс  лимит: {RATE_LIMIT_COUNT} файлов/{int(RATE_LIMIT_WINDOW_10MINS//60)}мин")
    _console(f"Лог: {LOG_FILE}")
    _console("=" * 55)

    # Открываем TUN
    try:
        tun_fd = tun_open(TUN_NAME)
    except PermissionError:
        _console("Ошибка: нет прав на /dev/net/tun. Нужен root.")
        sys.exit(1)
    except FileNotFoundError:
        _console("Ошибка: /dev/net/tun не найден. modprobe tun")
        sys.exit(1)

    tun_setup(TUN_NAME, TUN_ADDR, TUN_PEER, TUN_MTU, DEFAULT_ROUTE)
    _console(f"TUN {TUN_NAME} поднят: {TUN_ADDR}/30")

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
    multi   = MultiTransport(transports)
    tun_mgr = TunManager(tun_fd, multi)

    try:
        await asyncio.gather(
            multi.connect(),
            tun_mgr.read_loop(),
            tun_mgr.send_loop(),
            tun_mgr.stats_loop(),
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        _console("Завершение, убираем маршруты...")
        tun_teardown(TUN_NAME, DEFAULT_ROUTE)
        os.close(tun_fd)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass