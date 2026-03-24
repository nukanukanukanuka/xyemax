#!/usr/bin/env python3
"""
client.py — клиентская сторона. Самодостаточный файл.

Запуск:
    python3 client.py

Конфиг (client.conf):
    TOKEN     = <токен>
    VIEWER_ID = <viewerId>
    DEVICE_ID = <deviceId>
    SOCKS5_PORT = 1080   # опционально

Сценарий:
    1. Читаем client.conf
    2. Self-chat: chatId = viewerId (личка — файлы себе)
    3. Запускаем SOCKS5 прокси на localhost:SOCKS5_PORT

Логи:
  - подробный DEBUG → logs/client_YYYY-MM-DD_HH-MM-SS.log
  - краткий INFO    → консоль (только статистика соединений)

Зависимости:
    pip install websockets aiohttp
    (playwright нужен только для первичного получения токена)
"""

import asyncio
import base64
import json
import logging
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
        token = cfg.get(f"TOKEN{suffix}")
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
SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = int(_cfg.get("SOCKS5_PORT", "1080"))

# Self-chat в MAX работает через chatId = 0
SELF_CHAT_ID = 0

_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE  = _LOGS_DIR / f"client_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"

# ══════════════════════════════════════════════════════════════════════════════
# ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════

class _SpeedFilter(logging.Filter):
    def filter(self, record):
        return record.getMessage().startswith("DONE ")

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
# TRANSPORT
# ══════════════════════════════════════════════════════════════════════════════

_WS_URL = "wss://ws-api.oneme.ru/websocket"
_WS_HEADERS = {
    "Origin": "https://web.max.ru",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
}

# Тег в имени файла чтобы отличать свои исходящие от входящих в self-chat
_OUTGOING_TAG = b"OUT:"


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
        self.on_frame   = None
        self._send_buffer: list[bytes] = []
        self._flush_task: asyncio.Task | None = None
        self._send_queue: asyncio.Queue = asyncio.Queue()
        self._BATCH_DELAY = 0.0
        self._BATCH_MAX   = 32
        self._http: aiohttp.ClientSession | None = None
        self._recent_outgoing_file_ids: set[int] = set()
        self._seen_file_ids: set[int] = set()
        self._seen_file_ids_order = deque(maxlen=4096)
        self._op88_sem = asyncio.Semaphore(4)
        self._recent_outgoing_file_ids: set[int] = set()

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
        if file_id in self._seen_file_ids:
            return
        if len(self._seen_file_ids_order) >= self._seen_file_ids_order.maxlen:
            old = self._seen_file_ids_order.popleft()
            self._seen_file_ids.discard(old)
        self._seen_file_ids.add(file_id)
        self._seen_file_ids_order.append(file_id)


    async def send(self, obj: dict):
        """Сериализовать фрейм туннеля в байты и добавить в буфер отправки."""
        obj = dict(obj)
        raw_data = b""
        if "d" in obj:
            raw_data = base64.b64decode(obj.pop("d"))
            if obj.get("z"):
                obj.pop("z")
                raw_data = zlib.decompress(raw_data)

        hdr = json.dumps(obj, separators=(",", ":")).encode()
        frame_bytes = len(hdr).to_bytes(4, "big") + hdr + raw_data
        self._send_buffer.append(frame_bytes)

        if len(self._send_buffer) >= self._BATCH_MAX:
            if self._flush_task and not self._flush_task.done():
                self._flush_task.cancel()
            await self._flush_buffer()
        elif self._flush_task is None or self._flush_task.done():
            total_buffered = sum(len(f) for f in self._send_buffer)
            if not self._send_queue.empty():
                delay = self._BATCH_DELAY
            elif total_buffered < 512:
                # Маленький/контрольный фрейм — ждём 25мс, вдруг следом data
                delay = 0.025
            else:
                delay = 0.0
            self._flush_task = asyncio.create_task(self._flush_after(delay))

    async def _flush_after(self, delay: float):
        await asyncio.sleep(delay)
        await self._flush_buffer()

    async def _flush_buffer(self):
        if not self._send_buffer:
            return
        frames = self._send_buffer[:]
        self._send_buffer.clear()
        n = len(frames)
        parts = [n.to_bytes(4, "big")]
        for f in frames:
            parts.append(len(f).to_bytes(4, "big") + f)
        file_body = b"".join(parts)
        log.debug(f"[transport:{self.label}] batch flush  frames={n}  total={len(file_body)}B")
        await self._send_queue.put(file_body)

    async def _send_worker(self):
        """Отправляет батчи строго по одному — MAX поддерживает один op87 слот за раз."""
        current: asyncio.Task | None = None
        try:
            while True:
                file_body = await self._send_queue.get()
                if file_body is None:
                    break
                current = asyncio.create_task(self._send_file(file_body))
                try:
                    await current
                except Exception as e:
                    log.error(f"[transport:{self.label}] send_worker error: {e}", exc_info=True)
                current = None
        finally:
            if current and not current.done():
                current.cancel()
                await asyncio.gather(current, return_exceptions=True)

    async def _send_file(self, file_body: bytes):
        """Загрузить батч как файл в self-chat и опубликовать attachment строго после op136."""
        http = self._http
        loop = asyncio.get_event_loop()

        # 1. Запросить upload slot
        fut87 = loop.create_future()
        self._once["op87"] = fut87
        await self._send_raw(87, {"count": 1})
        try:
            slot = await asyncio.wait_for(fut87, timeout=10.0)
        except asyncio.TimeoutError:
            log.error(f"[transport:{self.label}] upload slot timeout"); return
        info    = slot["info"][0]
        up_url  = info["url"]
        file_id = int(info["fileId"])

        # 2. Уведомить чат о готовящейся загрузке и заранее ждать op136
        fut136 = loop.create_future()
        self._once[f"op136_{file_id}"] = fut136
        await self._send_raw(65, {"chatId": self.chat_id, "type": "FILE"})

        # 3. Загрузить файл
        form = aiohttp.FormData()
        form.add_field("file", file_body,
                       filename="OUT_data.bin",
                       content_type="application/octet-stream")
        async with http.post(up_url, data=form) as resp:
            if resp.status != 200:
                body = await resp.text()
                self._once.pop(f"op136_{file_id}", None)
                log.error(f"[transport:{self.label}] upload failed {resp.status}: {body}"); return
            log.debug(f"[transport:{self.label}] upload ok  fileId={file_id}  size={len(file_body)}")

        # 4. Дождаться op136 — MAX должен подтвердить приём файла
        try:
            pl136 = await asyncio.wait_for(fut136, timeout=20.0)
            got_file_id = pl136.get("fileId") or pl136.get("id")
            if got_file_id is not None and int(got_file_id) != file_id:
                log.debug(f"[transport:{self.label}] op136 fileId mismatch: expected={file_id} got={got_file_id}")
        except asyncio.TimeoutError:
            self._once.pop(f"op136_{file_id}", None)
            # Файл уже загружен на сервер MAX — отправляем op64 в любом случае,
            # иначе MAX держит незакрытый слот и рвёт WS-соединение
            log.warning(f"[transport:{self.label}] op136 timeout fileId={file_id}, sending op64 anyway")
        self._recent_outgoing_file_ids.add(file_id)

        # 5. Отправить сообщение с вложением себе
        await self._send_raw(64, {
            "chatId": self.chat_id,
            "message": {
                "cid": -int(time.time() * 1000),
                "attaches": [{"_type": "FILE", "fileId": file_id, "name": "OUT_data.bin"}],
            },
            "notify": True,
        })

    async def _handshake(self):
        await self._send_raw(6, {
            "userAgent": {
                "deviceType": "WEB", "locale": "ru", "deviceLocale": "ru",
                "osVersion": "Windows", "deviceName": "Chrome",
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
        log.info(f"Авторизован [{self.label}], chatId={self.chat_id} (self-chat)")

    async def _recv_loop(self):
        async for raw in self.ws:
            try: frame = json.loads(raw)
            except Exception: continue
            op, cmd, pl = frame.get("opcode"), frame.get("cmd"), frame.get("payload", {})

            if cmd == 1 and op == 6  and "op6"  in self._once:
                f = self._once.pop("op6");  f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 19 and "op19" in self._once:
                f = self._once.pop("op19"); f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 87 and "op87" in self._once:
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

            # В self-chat сообщение с вложением приходит как ack op64/cmd1,
            # а не только как отдельный event op128/cmd0.
            if (op == 128 and cmd == 0) or (op == 64 and cmd == 1 and isinstance(pl, dict) and "message" in pl):
                msg      = pl.get("message", {})
                attaches = msg.get("attaches", [])
                chat_id  = pl.get("chatId")
                log.debug(f"[transport] msg-event op={op} cmd={cmd} chat={chat_id} attaches={len(attaches)}")

                if not attaches:
                    continue

                attach = attaches[0]
                log.debug(f"[transport] attach full={attach}")
                if attach.get("_type") != "FILE":
                    continue

                file_id = attach.get("fileId") or attach.get("id")
                msg_id  = msg.get("msgId") or msg.get("id") or ""
                if not file_id:
                    log.warning(f"[transport] нет fileId в attach: {attach}"); continue
                file_id = int(file_id)
                if file_id in self._recent_outgoing_file_ids:
                    self._recent_outgoing_file_ids.discard(file_id)
                    log.debug(f"[transport:{self.label}] пропускаем свой исходящий файл fileId={file_id}")
                    continue
                if file_id in self._seen_file_ids:
                    log.debug(f"[transport:{self.label}] пропускаем уже обработанный fileId={file_id}")
                    continue
                self._mark_seen_file(file_id)
                asyncio.create_task(self._recv_file(file_id, str(msg_id), chat_id))

    async def _resolve_download_url(self, file_id: int, msg_id: str, chat_id: int) -> str | None:
        for attempt in range(3):
            key = f"op88_{file_id}"
            fut = asyncio.get_event_loop().create_future()
            self._once[key] = fut
            await self._send_raw(88, {"fileId": file_id, "chatId": chat_id, "messageId": msg_id})
            timeout = 12.0 + attempt * 10.0  # 12s, 22s, 32s
            try:
                pl = await asyncio.wait_for(fut, timeout=timeout)
                url = pl.get("url")
                log.debug(f"[transport] op88 fileId={file_id} url={url}")
                return url
            except asyncio.TimeoutError:
                self._once.pop(key, None)
                if attempt < 2:
                    log.warning(f"[transport] op88 timeout fileId={file_id} attempt={attempt+1}, retrying...")
                    await asyncio.sleep(0.5)
                else:
                    log.error(f"[transport] op88 timeout fileId={file_id} all retries exhausted")
                    return None

    async def _recv_file(self, file_id: int, msg_id: str, chat_id: int):
        async with self._op88_sem:
            url = await self._resolve_download_url(file_id, msg_id, chat_id)
            if not url:
                return
            try:
                async with self._http.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        log.error(f"[transport:{self.label}] download failed {resp.status} fileId={file_id}"); return
                    file_body = await resp.read()
            except Exception as e:
                log.error(f"[transport:{self.label}] download error: {e}"); return

        frames = _unpack_batch(file_body)
        if not frames:
            log.warning(f"[transport:{self.label}] не удалось распарсить батч fileId={file_id}"); return
        log.debug(f"[transport:{self.label}] recv_file  fileId={file_id}  frames={len(frames)}")
        for obj in frames:
            if self.on_frame:
                asyncio.create_task(self.on_frame(obj))

    async def connect(self):
        async with websockets.connect(
            _WS_URL, additional_headers=_WS_HEADERS,
            ping_interval=None,
            close_timeout=5,
        ) as ws:
            self.ws = ws
            connector = aiohttp.TCPConnector(
                limit_per_host=4,
                keepalive_timeout=30,
                enable_cleanup_closed=True,
            )
            self._http = aiohttp.ClientSession(connector=connector)
            self._send_queue  = asyncio.Queue()
            recv_task         = asyncio.create_task(self._recv_loop())
            keepalive_task    = asyncio.create_task(self._keepalive())
            send_worker_task  = asyncio.create_task(self._send_worker())
            await self._handshake()
            try:
                await recv_task
            finally:
                keepalive_task.cancel()
                try: await keepalive_task
                except BaseException: pass
                await self._send_queue.put(None)
                try:
                    await asyncio.wait_for(send_worker_task, timeout=5.0)
                except Exception:
                    send_worker_task.cancel()
                    try: await send_worker_task
                    except BaseException: pass
                if self._http and not self._http.closed:
                    await self._http.close()
                self._http = None

    async def _keepalive(self):
        while True:
            await asyncio.sleep(25)
            try:
                await self._send_raw(48, {"chatIds": [self.chat_id]})
                log.debug("[transport] keepalive sent")
            except Exception as e:
                log.debug(f"[transport] keepalive error: {e}"); break


class MultiTransport:
    CONTROL_ACTIONS = {"connect", "ok", "err", "close", "closed"}

    def __init__(self, transports: list[MaxTransport]):
        if not transports:
            raise ValueError("MultiTransport требует хотя бы один transport")
        self.transports = transports
        self.control = transports[0]
        self.on_frame = None
        self._rr = 0
        self._cid_control: dict[str, MaxTransport] = {}
        for t in self.transports:
            t.on_frame = self._make_frame_dispatcher(t)

    def _make_frame_dispatcher(self, transport: MaxTransport):
        async def _dispatch(obj):
            cid = obj.get("id")
            if cid and obj.get("a") in self.CONTROL_ACTIONS:
                self._cid_control[cid] = transport
            if self.on_frame:
                await self.on_frame(obj)
        return _dispatch

    def _next_transport(self) -> MaxTransport:
        t = self.transports[self._rr % len(self.transports)]
        self._rr += 1
        return t

    def _pick_transport(self, obj: dict) -> MaxTransport:
        action = obj.get("a")
        cid = obj.get("id")

        if action in self.CONTROL_ACTIONS:
            if cid:
                t = self._cid_control.get(cid)
                if t is None:
                    if action == "connect":
                        t = self._next_transport()
                    else:
                        t = self.control
                    self._cid_control[cid] = t
                return t
            return self.control

        seq = obj.get("seq")
        if isinstance(seq, int) and self.transports:
            return self.transports[seq % len(self.transports)]
        return self._next_transport()

    async def send(self, obj: dict):
        t = self._pick_transport(obj)
        cid = obj.get("id")
        if cid and obj.get("a") in self.CONTROL_ACTIONS and cid not in self._cid_control:
            self._cid_control[cid] = t
        await t.send(obj)

    def forget_cid(self, cid: str):
        self._cid_control.pop(cid, None)

    async def connect(self):
        tasks = [asyncio.create_task(t.connect()) for t in self.transports]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        exc = None
        for d in done:
            try:
                await d
            except Exception as e:
                exc = e
                break
        for p in pending:
            p.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        if exc:
            raise exc

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _unpack_batch(file_body: bytes) -> list[dict]:
    if len(file_body) < 4:
        log.warning("[unpack] файл слишком короткий"); return []
    n = int.from_bytes(file_body[:4], "big")
    if n == 0 or n > 256:
        log.warning(f"[unpack] неверное кол-во фреймов: {n}"); return []
    pos = 4
    frames = []
    for i in range(n):
        if pos + 4 > len(file_body):
            log.warning(f"[unpack] обрыв на фрейме {i}"); break
        flen = int.from_bytes(file_body[pos:pos+4], "big")
        pos += 4
        if pos + flen > len(file_body):
            log.warning(f"[unpack] фрейм {i} выходит за пределы файла"); break
        frame_bytes = file_body[pos:pos+flen]
        pos += flen
        if len(frame_bytes) < 4:
            continue
        hdr_len = int.from_bytes(frame_bytes[:4], "big")
        if len(frame_bytes) < 4 + hdr_len:
            log.warning(f"[unpack] фрейм {i}: повреждённый заголовок"); continue
        try:
            obj = json.loads(frame_bytes[4:4+hdr_len])
        except Exception as e:
            log.warning(f"[unpack] фрейм {i}: ошибка парсинга JSON: {e}"); continue
        raw_data = frame_bytes[4+hdr_len:]
        if raw_data:
            obj["d"] = base64.b64encode(raw_data).decode()
        frames.append(obj)
    return frames


def _pack(data: bytes) -> tuple[str, bool]:
    c = zlib.compress(data, level=1)
    if len(c) < len(data): return base64.b64encode(c).decode(), True
    return base64.b64encode(data).decode(), False


def _fmt_speed(total_bytes: float, elapsed: float) -> str:
    if elapsed <= 0: return "—"
    bps = total_bytes / elapsed
    if bps >= 1_048_576: return f"{bps/1_048_576:.1f} МБ/с"
    return f"{bps/1024:.1f} КБ/с"

# ══════════════════════════════════════════════════════════════════════════════
# SOCKS5 ПРОКСИ
# ══════════════════════════════════════════════════════════════════════════════

class ProxyClient:
    def __init__(self, transport: MaxTransport):
        self.t              = transport
        self.queues:        dict[str, asyncio.Queue]  = {}
        self.status:        dict[str, str]            = {}
        self._connect_futs: dict[str, asyncio.Future] = {}
        self._stats:        dict[str, dict]           = {}
        self._next_seq:     dict[str, int]            = {}
        self._buf:          dict[str, dict]           = {}
        self._send_seq:     dict[str, int]            = {}
        transport.on_frame = self._on_frame

    def _stat(self, cid):
        if cid not in self._stats:
            self._stats[cid] = {"rx": 0, "tx": 0, "frames_rx": 0, "frames_tx": 0,
                                "t0": time.time(), "host": "", "port": 0}
        return self._stats[cid]

    async def _on_frame(self, obj):
        a, cid = obj.get("a"), obj.get("id", "")
        if a == "ok":
            log.debug(f"[{cid}] <- ok")
            self.status[cid] = "ok"
            fut = self._connect_futs.pop(cid, None)
            if fut and not fut.done(): fut.set_result("ok")
        elif a == "err":
            log.info(f"[{cid}] <- ошибка сервера: {obj.get('msg')}")
            self.status[cid] = "err"
            fut = self._connect_futs.pop(cid, None)
            if fut and not fut.done(): fut.set_result("err")
            await self._push(cid, None)
        elif a == "data":
            raw = base64.b64decode(obj["d"])
            if obj.get("z"): raw = zlib.decompress(raw)
            st = self._stat(cid); st["rx"] += len(raw); st["frames_rx"] += 1
            log.debug(f"[{cid}] <- data #{st['frames_rx']}  {len(raw)}B  seq={obj.get('seq')}  (rx={st['rx']}B)")
            await self._push_ordered(cid, obj.get("seq"), raw)
        elif a == "closed":
            log.debug(f"[{cid}] <- closed by server")
            self.status[cid] = "closed"; await self._push(cid, None)
        else:
            log.warning(f"[{cid}] <- неизвестный action={a!r}")

    async def _push(self, cid, chunk):
        if cid in self.queues: await self.queues[cid].put(chunk)

    async def _push_ordered(self, cid, seq, raw):
        if seq is None:
            await self._push(cid, raw); return
        exp = self._next_seq.get(cid, 0)
        if seq == exp:
            await self._push(cid, raw)
            self._next_seq[cid] = exp + 1
            buf = self._buf.setdefault(cid, {})
            while True:
                nxt = self._next_seq[cid]
                if nxt in buf:
                    await self._push(cid, buf.pop(nxt))
                    self._next_seq[cid] = nxt + 1
                else: break
        elif seq > exp:
            self._buf.setdefault(cid, {})[seq] = raw
        else:
            log.debug(f"[{cid}] dup seq={seq}")

    async def open_tunnel(self, host: str, port: int) -> str | None:
        cid = uuid.uuid4().hex[:8]
        self.queues[cid]    = asyncio.Queue()
        self.status[cid]    = "pending"
        self._next_seq[cid] = self._send_seq[cid] = 0
        self._buf[cid]      = {}
        st = self._stat(cid); st["host"] = host; st["port"] = port

        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._connect_futs[cid] = fut

        t0 = time.monotonic()
        await self.t.send({"a": "connect", "id": cid, "host": host, "port": port})
        try:
            result = await asyncio.wait_for(fut, timeout=20.0)
        except asyncio.TimeoutError:
            self._connect_futs.pop(cid, None)
            log.info(f"tunnel {host}:{port} [{cid}]  TIMEOUT")
            self._cleanup(cid); return None

        elapsed_ms = (time.monotonic() - t0) * 1000
        if result == "ok":
            log.info(f"tunnel {host}:{port} [{cid}]  открыт за ~{elapsed_ms:.0f} мс")
            return cid
        self._cleanup(cid); return None

    def _cleanup(self, cid):
        self._connect_futs.pop(cid, None)
        if hasattr(self.t, "forget_cid"):
            self.t.forget_cid(cid)
        for d in (self.queues, self.status, self._stats,
                  self._next_seq, self._buf, self._send_seq):
            d.pop(cid, None)

    async def handle_socks5(self, reader, writer):
        try:
            host, port = await _socks5_handshake(reader, writer)
        except Exception as e:
            log.warning(f"SOCKS5 handshake error: {e}"); writer.close(); return

        sock = writer.transport.get_extra_info("socket")
        if sock:
            import socket as _socket
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)

        log.info(f"SOCKS5 → {host}:{port}")
        cid = await self.open_tunnel(host, port)
        if not cid:
            writer.close(); return

        q = self.queues[cid]; t0 = time.time()

        async def local_to_remote():
            try:
                while True:
                    try:
                        chunk = await asyncio.wait_for(reader.read(65536), timeout=120)
                    except asyncio.TimeoutError:
                        log.debug(f"[{cid}] local read timeout (120s idle)"); break
                    if not chunk:
                        log.debug(f"[{cid}] local EOF"); break
                    buf = bytearray(chunk)
                    for _ in range(16):
                        if len(buf) >= 65536: break
                        try:
                            more = await asyncio.wait_for(
                                reader.read(min(16384, 65536 - len(buf))), timeout=0.005)
                            if not more: break
                            buf.extend(more)
                        except asyncio.TimeoutError: break
                    data = bytes(buf)
                    st = self._stat(cid); st["tx"] += len(data); st["frames_tx"] += 1
                    seq = self._send_seq.get(cid, 0); self._send_seq[cid] = seq + 1
                    d, compressed = _pack(data)
                    frame = {"a": "data", "id": cid, "seq": seq, "d": d}
                    if compressed: frame["z"] = 1
                    log.debug(f"[{cid}] -> #{st['frames_tx']}  {len(data)}B  seq={seq}")
                    await self.t.send(frame)
            except Exception as e:
                log.warning(f"[{cid}] local read error: {type(e).__name__}: {e}")
            finally:
                self.status[cid] = "closed"
                last_seq = self._send_seq.get(cid, 0) - 1
                await self.t.send({"a": "close", "id": cid, "last_seq": last_seq})

        async def remote_to_local():
            try:
                while True:
                    if self.status.get(cid) in ("closed", "err"): break
                    try:
                        chunk = await asyncio.wait_for(q.get(), timeout=1.0)
                    except asyncio.TimeoutError: continue
                    if chunk is None: break
                    writer.write(chunk); await writer.drain()
            except Exception as e:
                log.warning(f"[{cid}] remote_to_local error: {type(e).__name__}: {e}")

        await asyncio.gather(local_to_remote(), remote_to_local())

        st = self._stat(cid); elapsed = time.time() - t0
        line = (
            f"↑{_fmt_speed(st['tx'], elapsed)} ({st['tx']}B)  "
            f"↓{_fmt_speed(st['rx'], elapsed)} ({st['rx']}B)  "
            f"{elapsed:.1f}s"
        )
        log.info(
            f"DONE {host}:{port} [{cid}] | "
            f"↑{st['tx']}B/{st['frames_tx']}f ({_fmt_speed(st['tx'], elapsed)})  "
            f"↓{st['rx']}B/{st['frames_rx']}f ({_fmt_speed(st['rx'], elapsed)})  "
            f"{elapsed:.1f}s"
        )
        _console(line)
        try: writer.close()
        except Exception: pass
        self._cleanup(cid)


async def _socks5_handshake(reader, writer) -> tuple[str, int]:
    data = await reader.read(257)
    if not data or data[0] != 5: raise ValueError("not SOCKS5")
    writer.write(b"\x05\x00"); await writer.drain()

    hdr = await reader.read(4)
    if len(hdr) < 4 or hdr[1] != 1:
        writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6); await writer.drain()
        raise ValueError("only CONNECT supported")

    atyp = hdr[3]
    if atyp == 1:
        host = ".".join(str(b) for b in await reader.read(4))
    elif atyp == 3:
        n = (await reader.read(1))[0]; host = (await reader.read(n)).decode()
    elif atyp == 4:
        await reader.read(16)
        writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6); await writer.drain()
        raise ValueError("IPv6 not supported")
    else:
        raise ValueError(f"unknown atyp={atyp}")

    port = int.from_bytes(await reader.read(2), "big")
    writer.write(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
    await writer.drain()
    return host, port

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main():
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
    transport = MultiTransport(transports)
    proxy = ProxyClient(transport)

    socks_server = await asyncio.start_server(proxy.handle_socks5, SOCKS5_HOST, SOCKS5_PORT)
    _console("=" * 50)
    _console(f"MAX Self-Chat Proxy  viewer_id={VIEWER_ID}  transports={len(ACCOUNTS)}")
    _console(f"SOCKS5: {SOCKS5_HOST}:{SOCKS5_PORT}")
    _console(f"Тест: curl --socks5 localhost:{SOCKS5_PORT} https://2ip.ru")
    _console(f"Лог:  {LOG_FILE}")
    _console("=" * 50)
    log.info(f"SOCKS5 запущен  {SOCKS5_HOST}:{SOCKS5_PORT}  chat_id={SELF_CHAT_ID}  transports={len(ACCOUNTS)}")

    _reconnect_delay = 5

    async def run():
        async with socks_server:
            await transport.connect()

    while True:
        try:
            await run()
            _reconnect_delay = 5
        except Exception as e:
            delay = min(_reconnect_delay, 60)
            log.error(f"WS разрыв: {e}. Reconnect in {delay}s...")
            await asyncio.sleep(delay)
            _reconnect_delay = delay * 2


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass