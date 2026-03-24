#!/usr/bin/env python3
"""
server.py — серверная сторона TUN-туннеля через MAX файловый канал.

Архитектура:
  Получает файл с IP-пакетами от client.py.
  Инжектирует пакеты в TUN-интерфейс (tun0 на сервере).
  Linux делает NAT и маршрутизацию — пакеты уходят в интернет.
  Ответные пакеты читаются из tun0 и отправляются обратно клиенту.

Настройка сервера (один раз):
  # Включить IP forwarding
  echo 1 > /proc/sys/net/ipv4/ip_forward
  # NAT: заменить eth0 на ваш внешний интерфейс
  iptables -t nat -A POSTROUTING -s 10.0.0.0/30 -o eth0 -j MASQUERADE

Конфиг (server.conf):
    TOKEN     = <токен>
    VIEWER_ID = <viewerId>
    DEVICE_ID = <deviceId>
    TOKEN_2   = ...  # мультиаккаунт
    TUN_NAME  = tun0
    TUN_ADDR  = 10.0.0.2      # адрес сервера в туннеле
    TUN_PEER  = 10.0.0.1      # адрес клиента в туннеле
    TUN_MTU   = 1400

Зависимости:
    pip install websockets aiohttp
    apt install iproute2 iptables
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
import zlib
from collections import deque
from pathlib import Path

import aiohttp
import websockets

# ══════════════════════════════════════════════════════════════════════════════
# КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════

def _load_config():
    cfg_path = Path(__file__).parent / "server.conf"
    if not cfg_path.exists():
        raise FileNotFoundError(f"server.conf не найден: {cfg_path}")
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
            raise KeyError("В server.conf нужны TOKEN/VIEWER_ID/DEVICE_ID")
        break
    return accounts

ACCOUNTS     = _load_accounts(_cfg)
VIEWER_ID    = ACCOUNTS[0]["viewer_id"]
SELF_CHAT_ID = 0

TUN_NAME  = _cfg.get("TUN_NAME", "tun0")
TUN_ADDR  = _cfg.get("TUN_ADDR", "10.0.0.2")
TUN_PEER  = _cfg.get("TUN_PEER", "10.0.0.1")
TUN_MTU   = int(_cfg.get("TUN_MTU", "1400"))

UPLOAD_MIN_INTERVAL = float(_cfg.get("UPLOAD_MIN_INTERVAL", "0.3"))

STATUS_URL    = "https://telegram.mooner.pro/api/max/status"
SESSIONS_FILE = Path("sessions.json")
POLL_INTERVAL = 30

_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE = _LOGS_DIR / f"server_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"

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
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

_WS_URL = "wss://ws-api.oneme.ru/websocket"
_WS_HEADERS = {
    "Origin": "https://web.max.ru",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
}

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

def _pack(data: bytes) -> bytes:
    c = zlib.compress(data, level=1)
    return (b"\x01" + c) if len(c) < len(data) else (b"\x00" + data)

def _unpack(payload: bytes) -> bytes:
    if not payload: return b""
    return zlib.decompress(payload[1:]) if payload[0] == 1 else payload[1:]

def _encode_packets(packets: list[bytes]) -> bytes:
    parts = [struct.pack(">I", len(packets))]
    for pkt in packets:
        parts.append(struct.pack(">H", len(pkt)))
        parts.append(pkt)
    return b"".join(parts)

def _decode_packets(data: bytes) -> list[bytes]:
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

def tun_open(name: str) -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    ifr = struct.pack("16sH22x", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd

def tun_setup(name: str, addr: str, peer: str, mtu: int):
    cmds = [
        ["ip", "link", "set", name, "up", "mtu", str(mtu)],
        ["ip", "addr", "add", f"{addr}/30", "dev", name],
        ["ip", "route", "add", f"{peer}/32", "dev", name],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log.warning(f"[tun] {' '.join(cmd)}: {r.stderr.strip()}")
        else:
            log.debug(f"[tun] {' '.join(cmd)}: OK")

def _check_nat(iface: str):
    """Проверить что NAT настроен, подсказать если нет."""
    r = subprocess.run(
        ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n"],
        capture_output=True, text=True)
    if "MASQUERADE" not in r.stdout and "SNAT" not in r.stdout:
        _console(f"⚠️  NAT не настроен! Выполни:")
        _console(f"   echo 1 > /proc/sys/net/ipv4/ip_forward")
        _console(f"   iptables -t nat -A POSTROUTING -s {TUN_PEER}/30 -o {iface} -j MASQUERADE")

def _get_default_iface() -> str:
    r = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                       capture_output=True, text=True)
    for token in r.stdout.split():
        if token == "dev":
            return r.stdout.split()[r.stdout.split().index("dev") + 1]
    return "eth0"

# ══════════════════════════════════════════════════════════════════════════════
# ТРАНСПОРТ
# ══════════════════════════════════════════════════════════════════════════════

class MaxTransport:
    def __init__(self, role: str, token: str, viewer_id: int,
                 device_id: str, chat_id: int, label: str = "acc1"):
        self.label     = label
        self.role      = role
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
        self.on_batch_request: callable = None
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
        now  = loop.time()
        wait = self._last_upload_time + UPLOAD_MIN_INTERVAL - now
        if wait > 0:
            await asyncio.sleep(wait)
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
        form = aiohttp.FormData()
        form.add_field("file", file_body, filename="tun_resp.bin",
                       content_type="application/octet-stream")
        async with http.post(up_url, data=form) as resp:
            if resp.status != 200:
                body = await resp.text()
                self._once.pop(f"op136_{file_id}", None)
                log.error(f"[transport:{self.label}] upload failed {resp.status}: {body}")
                return
            self._last_upload_time = loop.time()
            log.debug(f"[transport:{self.label}] upload ok fileId={file_id} size={len(file_body)}")
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
        log.debug(f"[transport:{self.label}] published fileId={file_id} size={len(file_body)}")

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
        log.info(f"Авторизован [server:{self.label}], chatId={self.chat_id}")

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
            if (op == 128 and cmd == 0) or (op == 64 and cmd == 1
                    and isinstance(pl, dict) and "message" in pl):
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
                asyncio.create_task(self._recv_file(
                    file_id, str(msg_id), pl.get("chatId", self.chat_id)))

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
                async with self._http.get(
                        url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        log.error(f"[transport:{self.label}] download {resp.status}")
                        return
                    payload = await resp.read()
            except Exception as e:
                log.error(f"[transport:{self.label}] download error: {e}")
                return
        data = _unpack(payload)
        log.debug(f"[transport:{self.label}] recv_file fileId={file_id} size={len(data)}")
        if self.on_batch_request:
            asyncio.create_task(self.on_batch_request(data))

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
        async with websockets.connect(
            _WS_URL, extra_headers=_WS_HEADERS,
            ping_interval=20, ping_timeout=30, close_timeout=5,
        ) as ws:
            self.ws = ws
            connector = aiohttp.TCPConnector(limit=32, limit_per_host=8,
                                              keepalive_timeout=30)
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
            raise RuntimeError("recv_loop завершился")


# ══════════════════════════════════════════════════════════════════════════════
# TUN FORWARDER — получает пакеты от клиента, пишет в tun, читает ответы
# ══════════════════════════════════════════════════════════════════════════════

class TunForwarder:
    """
    Получает батч IP-пакетов от клиента → пишет в tun (Linux делает NAT).
    Читает ответные пакеты из tun → накапливает → шлёт клиенту обратно.
    """
    def __init__(self, tun_fd: int):
        self.fd = tun_fd
        # transport привязывается после создания
        self.transport: MaxTransport | None = None
        self._pending: list[bytes] = []
        self._pending_bytes = 0
        self._flush_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        # Батч окно для ответных пакетов (меньше чем у клиента — быстрее ответ)
        self._resp_window_ms = 50

    def attach(self, transport: MaxTransport):
        self.transport = transport
        transport.on_batch_request = self._on_packets_from_client

    async def _on_packets_from_client(self, data: bytes):
        """Получили батч от клиента — пишем пакеты в tun."""
        pkts  = _decode_packets(data)
        if not pkts:
            return
        log.debug(f"[tun] ← клиент: {len(pkts)} pkts  raw={len(data)}B")
        log.info(f"BATCH TUN←  pkts={len(pkts)}  {len(data)//1024}КБ")
        loop = asyncio.get_event_loop()
        for pkt in pkts:
            try:
                await loop.run_in_executor(None, os.write, self.fd, pkt)
            except OSError as e:
                log.warning(f"[tun] write error: {e}")

    async def read_loop(self):
        """Читаем ответные пакеты из tun → батчуем → шлём клиенту."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                pkt = await loop.run_in_executor(None, os.read, self.fd, TUN_MTU + 4)
            except OSError as e:
                if e.errno == 11:  # EAGAIN — нет данных
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
                        self._flush_after(self._resp_window_ms / 1000.0))
                if self._pending_bytes >= 4 * 1024 * 1024:
                    if self._flush_task and not self._flush_task.done():
                        self._flush_task.cancel()
                    await self._flush_now()

    async def _flush_after(self, delay: float):
        await asyncio.sleep(delay)
        async with self._lock:
            await self._flush_now()

    async def _flush_now(self):
        if not self._pending or not self.transport:
            return
        pkts = self._pending[:]
        self._pending.clear()
        self._pending_bytes = 0
        raw    = _encode_packets(pkts)
        packed = _pack(raw)
        log.debug(f"[tun] → клиент: {len(pkts)} pkts  raw={len(raw)}B  packed={len(packed)}B")
        log.info(f"BATCH TUN→  pkts={len(pkts)}  {len(raw)//1024}КБ  packed={len(packed)//1024}КБ")
        await self.transport.send_file(packed)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        try: return json.loads(SESSIONS_FILE.read_text())
        except Exception: pass
    return {}

def _save_sessions(sessions: dict):
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2, ensure_ascii=False))


class SessionManager:
    def __init__(self, forwarder: TunForwarder):
        self.sessions: dict[str, dict] = _load_sessions()
        self._tasks:   dict[str, asyncio.Task] = {}
        self._forwarder = forwarder

    async def start(self):
        migrated = False
        for url, info in list(self.sessions.items()):
            if info.get("chat_id") != 0 or info.get("name") != "self-chat":
                self.sessions[url] = {"chat_id": 0, "user_id": VIEWER_ID,
                                       "name": "self-chat"}
                migrated = True
        if migrated:
            _save_sessions(self.sessions)
        for url, info in self.sessions.items():
            self._tasks[url] = asyncio.create_task(
                self._run_proxy(url, info["chat_id"], info.get("name", url)))
        if self.sessions:
            log.info(f"Восстановлено {len(self.sessions)} сессий")

    async def sync(self, active_links: list[str]):
        current, wanted = set(self.sessions), set(active_links)
        for url in current - wanted:
            task = self._tasks.pop(url, None)
            if task:
                task.cancel()
                try: await task
                except (asyncio.CancelledError, Exception): pass
            self.sessions.pop(url, None)
        if current - wanted:
            _save_sessions(self.sessions)
        for url in wanted - current:
            log.info(f"[sync] добавляем: {url}")
            try:
                info = {"chat_id": 0, "user_id": VIEWER_ID, "name": "self-chat"}
                self.sessions[url] = info
                _save_sessions(self.sessions)
                self._tasks[url] = asyncio.create_task(
                    self._run_proxy(url, info["chat_id"], info["name"]))
            except Exception as e:
                log.error(f"[sync] не удалось добавить {url}: {e}")
        for url, info in list(self.sessions.items()):
            task = self._tasks.get(url)
            if task is None or task.done():
                self._tasks[url] = asyncio.create_task(
                    self._run_proxy(url, info["chat_id"], info.get("name", url)))

    async def _run_proxy(self, url: str, chat_id: int, name: str):
        async def _run_one(acc: dict):
            delay = 5
            while True:
                transport = MaxTransport(
                    "server", acc["token"], acc["viewer_id"], acc["device_id"],
                    chat_id, label=acc["label"],
                )
                self._forwarder.attach(transport)
                try:
                    log.info(f"[proxy:{name}] WS подключение ({acc['label']}, "
                             f"chat_id={chat_id})")
                    await transport.connect()
                    delay = 5
                except asyncio.CancelledError:
                    log.info(f"[proxy:{name}] {acc['label']} остановлен")
                    return
                except Exception as e:
                    log.error(f"[proxy:{name}] {acc['label']} разрыв: {e!r}. "
                              f"Reconnect in {delay}s...")
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 60)

        await asyncio.gather(*[_run_one(acc) for acc in ACCOUNTS])


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    if os.geteuid() != 0:
        print("Ошибка: нужен root (sudo python3 server.py)")
        sys.exit(1)

    _console("=" * 55)
    _console(f"MAX TUN сервер  аккаунтов: {len(ACCOUNTS)}")
    _console(f"Интерфейс: {TUN_NAME}  {TUN_ADDR} ↔ {TUN_PEER}  MTU={TUN_MTU}")
    _console(f"API: {STATUS_URL}  poll={POLL_INTERVAL}s")
    _console(f"Лог: {LOG_FILE}")
    _console("=" * 55)

    if os.geteuid() == 0:
        iface = _get_default_iface()
        _check_nat(iface)

    try:
        tun_fd = tun_open(TUN_NAME)
    except (PermissionError, FileNotFoundError) as e:
        _console(f"Ошибка открытия TUN: {e}")
        sys.exit(1)

    tun_setup(TUN_NAME, TUN_ADDR, TUN_PEER, TUN_MTU)
    _console(f"TUN {TUN_NAME} поднят: {TUN_ADDR}/30, peer={TUN_PEER}")

    forwarder = TunForwarder(tun_fd)
    manager   = SessionManager(forwarder)
    await manager.start()

    async with aiohttp.ClientSession() as http:
        poll_task = asyncio.create_task(_poll_loop(http, manager))
        read_task = asyncio.create_task(forwarder.read_loop())
        try:
            await asyncio.gather(poll_task, read_task)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            poll_task.cancel()
            read_task.cancel()
            subprocess.run(["ip", "link", "set", TUN_NAME, "down"],
                           capture_output=True)
            os.close(tun_fd)
            _console("Завершено.")


async def _poll_loop(http: aiohttp.ClientSession, manager: SessionManager):
    while True:
        try:
            async with http.get(STATUS_URL,
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
                data  = await resp.json(content_type=None)
                links = data.get("links", [])
                log.info(f"[poll] активных ссылок: {len(links)}")
                await manager.sync(links)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error(f"[poll] ошибка: {e}")
        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass