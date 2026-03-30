#!/usr/bin/env python3
"""
client.py — TUN-туннель через MAX файловый канал.

Архитектура:
  Создаёт виртуальный сетевой интерфейс tun0.
  Читает IP-пакеты из tun0, накапливает до BATCH_MIN_KB КБ,
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
import zlib
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
BATCH_WINDOW_MS = int(_cfg.get("BATCH_WINDOW_MS", "200"))
BATCH_MIN_KB    = int(_cfg.get("BATCH_MIN_KB", "8"))
RESPONSE_TIMEOUT = float(_cfg.get("RESPONSE_TIMEOUT", "30"))
UPLOAD_MIN_INTERVAL = float(_cfg.get("UPLOAD_MIN_INTERVAL", "0.3"))

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
    c = zlib.compress(data, level=1)
    return (b"\x01" + c) if len(c) < len(data) else (b"\x00" + data)

def _unpack(payload: bytes) -> bytes:
    if not payload: return b""
    return zlib.decompress(payload[1:]) if payload[0] == 1 else payload[1:]


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
        self._op88_sem = asyncio.Semaphore(4)
        self.on_batch_response: callable = None
        self.on_disconnect: callable = None
        self._last_activity_time: float = 0.0
        self._last_event: str = "recv"       # "send" или "recv"
        self._recv_count: int = 0            # входящих за текущие 5 минут
        self._recv_count_reset: float = 0.0  # время последнего сброса счётчика

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
                return
            self._last_activity_time = loop.time()
            self._last_event = "send"
            log.debug(f"[transport:{self.label}] upload ok fileId={file_id} size={len(file_body)}")
            _console(f"↑ {self.label}  {len(file_body)/1024:,.1f} КБ")
        try:
            await asyncio.wait_for(fut136, timeout=20.0)
        except asyncio.TimeoutError:
            self._once.pop(f"op136_{file_id}", None)
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
        log.debug(f"[transport:{self.label}] recv_file fileId={file_id} size={len(data)}")
        _console(f"↓ {self.label}  {len(data)/1024:,.1f} КБ")
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

    async def send_file(self, file_body: bytes):
        async with self._lock:
            alive = [i for i in range(len(self._transports)) if i in self._alive]
        if not alive:
            log.error("[multi] нет живых транспортов, пакеты дропаются")
            return

        loop = asyncio.get_event_loop()
        now  = loop.time()

        # Шаг 1: фильтруем по UPLOAD_MIN_INTERVAL, находим минимальный wait
        waits = {}
        for i in alive:
            t = self._transports[i]
            waits[i] = max(0.0, t._last_activity_time + UPLOAD_MIN_INTERVAL - now)

        min_wait = min(waits.values())

        # Если все заняты — ждём самого раннего
        if min_wait > 0:
            log.debug(f"[multi] все аккаунты заняты, ждём {min_wait:.3f}s")
            await asyncio.sleep(min_wait)
            now = loop.time()
            for i in alive:
                t = self._transports[i]
                waits[i] = max(0.0, t._last_activity_time + UPLOAD_MIN_INTERVAL - now)

        # Шаг 2: кандидаты — у кого таймер истёк (wait == 0)
        ready = [i for i in alive if waits[i] == 0.0]

        # Шаг 3: приоритет 1 — минимальный recv_count за 5 минут
        min_recv = min(self._transports[i]._recv_count for i in ready)
        p1 = [i for i in ready if self._transports[i]._recv_count == min_recv]

        # Шаг 4: приоритет 2 — последнее событие "recv" (противоположная сторона отправила последней)
        p2 = [i for i in p1 if self._transports[i]._last_event == "recv"]
        candidates = p2 if p2 else p1

        # Tiebreaker — round-robin среди финальных кандидатов
        self._rr_idx = (self._rr_idx + 1) % len(candidates)
        best_idx = candidates[self._rr_idx % len(candidates)]
        best_t   = self._transports[best_idx]

        # Лог выбора
        stats = {self._transports[i].label: {
            "recv_count": self._transports[i]._recv_count,
            "last_event": self._transports[i]._last_event,
            "wait": f"{waits[i]:.3f}s"
        } for i in alive}
        log.debug(
            f"[multi] выбор: {best_t.label} "
            f"(recv_count={best_t._recv_count}, last_event={best_t._last_event}) "
            f"| ready={[self._transports[i].label for i in ready]} "
            f"| p1={[self._transports[i].label for i in p1]} "
            f"| p2={[self._transports[i].label for i in p2]} "
            f"| stats={stats}"
        )

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
    Читает IP-пакеты из tun-интерфейса, накапливает до BATCH_MIN_BYTES,
    упаковывает msgpack-подобным форматом и шлёт через transport.
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
        self._flush_task: asyncio.Task | None = None
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
        """Читаем пакеты из tun — отправляем по BATCH_MIN_KB или по таймауту BATCH_WINDOW_MS."""
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
                self._pending.append(pkt)
                self._pending_bytes += len(pkt)
                if self._flush_task is None or self._flush_task.done():
                    self._flush_task = asyncio.create_task(
                        self._flush_after(BATCH_WINDOW_MS / 1000.0))
                if self._pending_bytes >= BATCH_MIN_KB * 1024:
                    if self._flush_task and not self._flush_task.done():
                        self._flush_task.cancel()
                    await self._flush_now()

    async def _flush_after(self, delay: float):
        await asyncio.sleep(delay)
        async with self._lock:
            await self._flush_now()

    async def _flush_now(self):
        if not self._pending:
            return
        pkts = self._pending[:]
        self._pending.clear()
        self._pending_bytes = 0
        raw    = self._encode(pkts)
        packed = _pack(raw)
        self._pkts_sent  += len(pkts)
        self._bytes_sent += len(raw)
        log.debug(f"[tun] → {len(pkts)} pkts  raw={len(raw)}B  packed={len(packed)}B")
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

    # ── Статистика ────────────────────────────────────────────────────────────

    async def stats_loop(self):
        while True:
            await asyncio.sleep(60)
            elapsed = time.time() - self._t0
            log.info(
                f"[tun] stats: "
                f"sent={self._pkts_sent}pkts/{self._bytes_sent//1024}КБ  "
                f"recv={self._pkts_recv}pkts/{self._bytes_recv//1024}КБ  "
                f"uptime={elapsed:.0f}s"
            )


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
    _console(f"Батч мин: {BATCH_MIN_KB}КБ")
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