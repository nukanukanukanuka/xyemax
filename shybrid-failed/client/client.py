#!/usr/bin/env python3
"""
client.py — клиентская сторона. Самодостаточный файл.

Запуск:
    python3 client.py https://max.ru/u/TOKEN

Конфиг (client.conf):
    TOKEN     = <токен>
    VIEWER_ID = <viewerId>
    DEVICE_ID = <deviceId>
    SOCKS5_PORT = 1080   # опционально

Транспорт — гибридный:
  - Фреймы ≤ TEXT_THRESHOLD байт → текстовое сообщение (RTT ~100ms)
  - Фреймы > TEXT_THRESHOLD байт → файловый upload (RTT ~1.5s)
  - Несколько аккаунтов (TOKEN/TOKEN_2/…) — параллельные WS, round-robin

Логи:
  - подробный DEBUG → logs/client_YYYY-MM-DD_HH-MM-SS.log
  - краткий INFO    → консоль (только статистика DONE)
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
        token  = cfg.get(f"TOKEN{suffix}")
        viewer = cfg.get(f"VIEWER_ID{suffix}")
        device = cfg.get(f"DEVICE_ID{suffix}")
        if token and viewer and device:
            accounts.append({"token": token, "viewer_id": int(viewer),
                              "device_id": device, "label": f"acc{idx}"})
            idx += 1; continue
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

# Порог для переключения на файловый транспорт.
# 2100 байт бинарных данных → ~2800 символов base64 → ~3900 символов JSON — влезает в лимит 4000.
TEXT_THRESHOLD = 800

SELF_CHAT_ID = 0

_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE = _LOGS_DIR / f"client_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"

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


class WsConn:
    """Одно WS-соединение к MAX. MaxTransport держит пул из N таких объектов."""
    _FAIL_THRESHOLD = 3

    def __init__(self, transport: "MaxTransport", idx: int):
        self.t      = transport
        self.idx    = idx
        self.label  = f"{transport.label}#ws{idx}"
        self.ws     = None
        self._once: dict[str, asyncio.Future] = {}
        self._seq   = 0
        self._fail_count = 0
        self._healthy    = False
        self._keepalive_task = None

    def _next_seq(self):
        s = self._seq; self._seq += 1; return s

    async def send_raw(self, opcode: int, payload: dict):
        frame = {"ver": 11, "cmd": 0, "seq": self._next_seq(),
                 "opcode": opcode, "payload": payload}
        await self.ws.send(json.dumps(frame, ensure_ascii=False, separators=(",", ":")))

    def mark_fail(self):
        self._fail_count += 1
        if self._fail_count >= self._FAIL_THRESHOLD:
            self._healthy = False
            log.warning(f"[{self.label}] marked unhealthy after {self._fail_count} failures")

    def mark_ok(self):
        self._fail_count = 0
        self._healthy = True

    @property
    def usable(self) -> bool:
        return self.ws is not None and self._healthy

    async def connect_and_run(self):
        while True:
            try:
                async with websockets.connect(
                    _WS_URL, additional_headers=_WS_HEADERS,
                    ping_interval=None, close_timeout=5,
                ) as ws:
                    self.ws = ws
                    self._once.clear()
                    self._seq = 0
                    try:
                        recv_task = asyncio.create_task(self._recv_loop())
                        try:
                            await self._handshake()
                        except Exception as e:
                            log.warning(f"[{self.label}] handshake failed: {e!r}")
                            recv_task.cancel()
                            try: await recv_task
                            except Exception: pass
                            raise
                        self.mark_ok()
                        log.info(f"[{self.label}] подключён")
                        self._keepalive_task = asyncio.create_task(self._keepalive())
                        await recv_task
                    except Exception as e:
                        log.warning(f"[{self.label}] ошибка: {e!r}")
                    finally:
                        self._healthy = False
                        if self._keepalive_task:
                            self._keepalive_task.cancel()
                            try: await self._keepalive_task
                            except Exception: pass
                        self.ws = None
            except Exception as e:
                log.warning(f"[{self.label}] connect failed: {e!r}")
            self._healthy = False
            await asyncio.sleep(3)

    async def _handshake(self):
        t = self.t
        fut6 = asyncio.get_event_loop().create_future()
        self._once["op6"] = fut6
        await self.send_raw(6, {
            "userAgent": {
                "deviceType": "WEB", "locale": "ru", "deviceLocale": "ru",
                "osVersion": "Windows", "deviceName": "Chrome",
                "headerUserAgent": _WS_HEADERS["User-Agent"],
                "appVersion": "26.3.7", "screen": "1920x1080 1.0x",
                "timezone": "Europe/Moscow",
            },
            "deviceId": t.device_id,
        })
        await asyncio.wait_for(fut6, timeout=15.0)
        fut19 = asyncio.get_event_loop().create_future()
        self._once["op19"] = fut19
        await self.send_raw(19, {
            "token": t.token, "chatsCount": 50, "interactive": True,
            "chatsSync": 0, "contactsSync": 0, "presenceSync": -1, "draftsSync": 0,
        })
        await asyncio.wait_for(fut19, timeout=15.0)
        await self.send_raw(48, {"chatIds": [t.chat_id]})
        await self.send_raw(75, {"chatId": t.chat_id, "subscribe": True})
        log.info(f"Авторизован [{self.label}], chatId={t.chat_id} (self-chat)")

    async def _keepalive(self):
        while True:
            await asyncio.sleep(25)
            try:
                await self.send_raw(48, {"chatIds": [self.t.chat_id]})
                log.debug(f"[{self.label}] keepalive sent")
            except Exception as e:
                log.debug(f"[{self.label}] keepalive error: {e}"); break

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
            if cmd == 0 and op in (292, 48, 180, 177, 65, 130): continue

            if (op == 128 and cmd == 0) or (op == 64 and cmd == 1 and isinstance(pl, dict) and "message" in pl):
                msg      = pl.get("message", {})
                text     = msg.get("text", "")
                attaches = msg.get("attaches", [])
                chat_id  = pl.get("chatId")

                if not attaches:
                    if text.startswith("{"):
                        try: obj = json.loads(text)
                        except Exception: continue
                        if obj.get("src") == "client": continue
                        if self.t.on_frame:
                            asyncio.create_task(self.t.on_frame(obj))
                    continue

                attach = attaches[0]
                if attach.get("_type") != "FILE": continue
                file_id = attach.get("fileId") or attach.get("id")
                msg_id  = msg.get("msgId") or msg.get("id") or ""
                if not file_id: continue
                file_id = int(file_id)
                if file_id in self.t._recent_outgoing_file_ids:
                    self.t._recent_outgoing_file_ids.discard(file_id)
                    log.debug(f"[{self.label}] пропускаем свой исходящий файл fileId={file_id}")
                    continue
                if file_id in self.t._seen_file_ids: continue
                self.t._mark_seen_file(file_id)
                asyncio.create_task(self._recv_file(file_id, str(msg_id), chat_id))

    async def _recv_file(self, file_id: int, msg_id: str, chat_id: int):
        async with self.t._op88_sem:
            key = f"op88_{file_id}"
            fut = asyncio.get_event_loop().create_future()
            self._once[key] = fut
            await self.send_raw(88, {"fileId": file_id, "chatId": chat_id, "messageId": msg_id})
            url = None
            for attempt in range(3):
                try:
                    pl = await asyncio.wait_for(asyncio.shield(fut) if attempt else fut,
                                                timeout=12.0 + attempt * 10.0)
                    url = pl.get("url"); break
                except asyncio.TimeoutError:
                    self._once.pop(key, None)
                    if attempt < 2:
                        log.warning(f"[{self.label}] op88 timeout fileId={file_id} attempt={attempt+1}")
                        fut = asyncio.get_event_loop().create_future()
                        self._once[key] = fut
                        await self.send_raw(88, {"fileId": file_id, "chatId": chat_id, "messageId": msg_id})
                    else:
                        log.error(f"[{self.label}] op88 exhausted fileId={file_id}"); return
            if not url: return
            try:
                async with self.t._http_shared.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        log.error(f"[{self.label}] download failed {resp.status}"); return
                    file_body = await resp.read()
            except Exception as e:
                log.error(f"[{self.label}] download error: {e}"); return

            if len(file_body) < 4: return
            hdr_len = int.from_bytes(file_body[:4], "big")
            if len(file_body) < 4 + hdr_len: return
            try: obj = json.loads(file_body[4:4 + hdr_len])
            except Exception: return
            raw_data = file_body[4 + hdr_len:]
            if raw_data:
                obj["d"] = base64.b64encode(raw_data).decode()
            log.debug(f"[{self.label}] file-recv  fileId={file_id}  action={obj.get('a')}")
            # Фильтруем своё эхо (файлы которые мы сами отправили)
            if obj.get("src") == "client": return
            if self.t.on_frame:
                asyncio.create_task(self.t.on_frame(obj))


class MaxTransport:
    """Транспорт с пулом WS-соединений для клиента."""
    _RETRANSMIT_BUF    = 512
    _MAX_RETX_PER_NACK = 5
    _POOL_SIZE         = 3
    _RL_MAX = 5.0; _RL_MIN = 1.0
    _RL_STEP_UP = 0.5; _RL_STEP_DOWN = 2.0; _RL_PROBE_INTERVAL = 10.0

    def __init__(self, token: str, viewer_id: int, device_id: str,
                 chat_id: int, label: str = "acc1"):
        self.label      = label
        self.token      = token
        self.viewer_id  = viewer_id
        self.device_id  = device_id
        self.chat_id    = chat_id
        self.on_frame   = None
        self._pool: list[WsConn] = [WsConn(self, i) for i in range(self._POOL_SIZE)]
        self._pool_idx  = 0
        self._http_shared: aiohttp.ClientSession | None = None
        self._ctrl_queue: asyncio.Queue = asyncio.Queue()
        self._text_queue: asyncio.Queue = asyncio.Queue()
        self._file_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._recent_outgoing_file_ids: set[int] = set()
        self._seen_file_ids: set[int] = set()
        self._seen_file_ids_order = deque(maxlen=4096)
        self._op88_sem = asyncio.Semaphore(4)
        self._ms_send: int = 0
        self._ms_recv_expected: int = 0
        self._retransmit_buf: dict[int, str] = {}
        self._retransmit_order: deque = deque()
        self._ms_ooo: dict[int, str] = {}
        self._ms_nack_sent_at: float = 0.0
        self._ms_nack_count: int = 0
        self._rl_rate: float = self._RL_MAX
        self._rl_tokens: float = 1.0
        self._rl_last_refill: float = 0.0
        self._rl_last_problem: float = 0.0
        self._rl_last_probe: float = 0.0
        self._rl_ctrl_tokens: float = 1.0
        self._rl_ctrl_last_refill: float = 0.0

    def _best_conn(self) -> "WsConn | None":
        healthy = [c for c in self._pool if c.usable]
        if not healthy:
            connected = [c for c in self._pool if c.ws is not None]
            return connected[self._pool_idx % len(connected)] if connected else None
        conn = healthy[self._pool_idx % len(healthy)]
        self._pool_idx += 1
        return conn

    def _mark_seen_file(self, file_id: int):
        if file_id in self._seen_file_ids: return
        if len(self._seen_file_ids_order) >= self._seen_file_ids_order.maxlen:
            old = self._seen_file_ids_order.popleft()
            self._seen_file_ids.discard(old)
        self._seen_file_ids.add(file_id)
        self._seen_file_ids_order.append(file_id)

    _CTRL_ACTIONS = frozenset({"connect", "ok", "err", "close", "closed"})
    _file_seq: int = 0

    @staticmethod
    def _frame_priority(action: str, seq: int) -> int:
        if action in ("connect", "ok", "err", "closed"):
            return 0
        if action == "close":
            return 1
        if seq == 0: return 0
        if seq < 5:  return 1
        return 2

    async def send(self, obj: dict):
        """Отправить фрейм туннеля — всё через файлы для максимальной надёжности."""
        obj = dict(obj); obj["src"] = "client"
        raw_data = b""
        if "d" in obj:
            raw_data = base64.b64decode(obj["d"])
            if obj.get("z"):
                raw_data = zlib.decompress(raw_data)

        meta = {k: v for k, v in obj.items() if k not in ("d", "z")}
        if raw_data:
            meta["d"] = base64.b64encode(raw_data).decode()

        action = obj.get("a", "")
        seq    = obj.get("seq", 999)
        priority = self._frame_priority(action, seq)

        hdr_meta = {k: v for k, v in meta.items() if k != "d"}
        hdr = json.dumps(hdr_meta, separators=(",", ":")).encode()
        file_body = len(hdr).to_bytes(4, "big") + hdr + raw_data

        MaxTransport._file_seq += 1
        await self._file_queue.put((priority, MaxTransport._file_seq, file_body))

    async def _ctrl_worker(self):
        """Control-фреймы (ok/err/close/connect): с мягким rate limit (_MAX_CTRL_PER_SEC)."""
        try:
            while True:
                text = await self._ctrl_queue.get()
                if text is None: break
                try:
                    ms = self._ms_send; self._ms_send += 1
                    stamped = text[:-1] + f',"ms":{ms}}}'
                    self._retransmit_buf[ms] = stamped
                    self._retransmit_order.append(ms)
                    if len(self._retransmit_order) > self._RETRANSMIT_BUF:
                        old_ms = self._retransmit_order.popleft()
                        self._retransmit_buf.pop(old_ms, None)
                    log.debug(f"[transport:{self.label}] ctrl-send  len={len(stamped)}  action={json.loads(text).get('a')}  ms={ms}")
                    await self._rl_ctrl_acquire()
                    await self._send_raw(64, {
                        "chatId": self.chat_id,
                        "message": {"text": stamped, "cid": -int(time.time() * 1000),
                                    "elements": [], "attaches": []},
                        "notify": False,
                    })
                except Exception as e:
                    log.error(f"[transport:{self.label}] ctrl_worker error: {e}", exc_info=True)
        finally:
            pass

    async def _text_worker(self):
        """Отправляет текстовые фреймы немедленно, нумерует ms для ACK/retransmit."""
        retransmit_last_sent: dict[int, float] = {}
        try:
            while True:
                item = await self._text_queue.get()
                if item is None: break
                try:
                    if isinstance(item, tuple) and item[0] == "_retransmit":
                        _, ms_from, ms_to = item
                        now = time.monotonic()
                        sent_count = 0
                        for ms in range(ms_from, ms_to + 1):
                            if sent_count >= self._MAX_RETX_PER_NACK:
                                log.debug(f"[transport:{self.label}] retransmit capped at {self._MAX_RETX_PER_NACK}/nack")
                                break
                            if now - retransmit_last_sent.get(ms, 0) < 1.0:
                                continue
                            cached = self._retransmit_buf.get(ms)
                            if cached:
                                retransmit_last_sent[ms] = now
                                sent_count += 1
                                log.debug(f"[transport:{self.label}] retransmit ms={ms}")
                                await self._ws_send_text(cached)
                            else:
                                log.warning(f"[transport:{self.label}] retransmit ms={ms} NOT IN BUFFER")
                        if ms_from > 100:
                            cutoff = ms_from - 100
                            for k in [k for k in retransmit_last_sent if k < cutoff]:
                                del retransmit_last_sent[k]
                        continue

                    text = item
                    ms = self._ms_send; self._ms_send += 1
                    stamped = text[:-1] + f',"ms":{ms}}}'
                    self._retransmit_buf[ms] = stamped
                    self._retransmit_order.append(ms)
                    if len(self._retransmit_order) > self._RETRANSMIT_BUF:
                        old_ms = self._retransmit_order.popleft()
                        self._retransmit_buf.pop(old_ms, None)

                    action = json.loads(text).get('a') if log.isEnabledFor(10) else '?'
                    log.debug(f"[transport:{self.label}] text-send  len={len(stamped)}  action={action}  ms={ms}")
                    await self._ws_send_text(stamped)
                except Exception as e:
                    log.error(f"[transport:{self.label}] text_worker error: {e}", exc_info=True)
        finally:
            pass

    async def _ws_send_text(self, text: str):
        await self._rl_acquire()
        await self._send_raw(64, {
            "chatId": self.chat_id,
            "message": {"text": text, "cid": -int(time.time() * 1000),
                        "elements": [], "attaches": []},
            "notify": False,
        })

    async def _rl_acquire(self):
        """Token bucket: ровно 1 сообщение в секунду. Burst = 1."""
        now = time.monotonic()
        elapsed = now - self._rl_last_refill
        self._rl_tokens = min(1.0, self._rl_tokens + elapsed * 1.0)
        self._rl_last_refill = now
        if self._rl_tokens >= 1.0:
            self._rl_tokens -= 1.0
        else:
            wait = 1.0 - self._rl_tokens
            await asyncio.sleep(wait)
            self._rl_tokens = 0.0
            self._rl_last_refill = time.monotonic()

    def _rl_on_problem(self):
        pass  # адаптивность отключена

    async def _rl_ctrl_acquire(self):
        """Token bucket для control-фреймов: 1/сек."""
        now = time.monotonic()
        elapsed = now - self._rl_ctrl_last_refill
        self._rl_ctrl_tokens = min(1.0, self._rl_ctrl_tokens + elapsed * 1.0)
        self._rl_ctrl_last_refill = now
        if self._rl_ctrl_tokens >= 1.0:
            self._rl_ctrl_tokens -= 1.0
        else:
            wait = 1.0 - self._rl_ctrl_tokens
            await asyncio.sleep(wait)
            self._rl_ctrl_tokens = 0.0
            self._rl_ctrl_last_refill = time.monotonic()

    async def _send_worker(self):
        """Загружает файлы в порядке приоритета (seq=0 первыми)."""
        try:
            while True:
                item = await self._file_queue.get()
                if item is None: break
                try:
                    _priority, _seq, file_body = item
                    if file_body is None: break
                    hdr_len = int.from_bytes(file_body[:4], "big")
                    hdr = json.loads(file_body[4:4+hdr_len])
                    log.debug(f"[transport:{self.label}] file-send  size={len(file_body)}  action={hdr.get('a','?')}  seq={hdr.get('seq','?')}  prio={_priority}")
                    await self._send_file(file_body)
                except Exception as e:
                    log.error(f"[transport:{self.label}] send_worker error: {e}", exc_info=True)
        finally:
            pass

    async def _send_file(self, file_body: bytes):
        """Загрузить данные как файл через лучшее доступное соединение из пула."""
        conn = self._best_conn()
        if conn is None:
            log.error(f"[transport:{self.label}] нет доступных WS-соединений"); return

        loop = asyncio.get_event_loop()
        http = self._http_shared

        fut87 = loop.create_future()
        conn._once["op87"] = fut87
        try:
            await conn.send_raw(87, {"count": 1})
        except Exception as e:
            conn.mark_fail(); log.error(f"[{conn.label}] send op87 failed: {e}"); return
        try:
            slot = await asyncio.wait_for(fut87, timeout=10.0)
        except asyncio.TimeoutError:
            conn.mark_fail(); log.error(f"[{conn.label}] upload slot timeout"); return
        conn.mark_ok()

        info    = slot["info"][0]
        up_url  = info["url"]
        file_id = int(info["fileId"])

        fut136 = loop.create_future()
        conn._once[f"op136_{file_id}"] = fut136
        try:
            await conn.send_raw(65, {"chatId": self.chat_id, "type": "FILE"})
        except Exception as e:
            conn.mark_fail(); conn._once.pop(f"op136_{file_id}", None)
            log.error(f"[{conn.label}] send op65 failed: {e}"); return

        form = aiohttp.FormData()
        form.add_field("file", file_body, filename="OUT_data.bin",
                       content_type="application/octet-stream")
        try:
            async with http.post(up_url, data=form) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    conn._once.pop(f"op136_{file_id}", None)
                    log.error(f"[{conn.label}] upload failed {resp.status}: {body}"); return
                log.debug(f"[{conn.label}] upload ok  fileId={file_id}  size={len(file_body)}")
        except Exception as e:
            conn._once.pop(f"op136_{file_id}", None)
            log.error(f"[{conn.label}] upload error: {e}"); return

        try:
            await asyncio.wait_for(fut136, timeout=20.0)
        except asyncio.TimeoutError:
            conn._once.pop(f"op136_{file_id}", None)
            log.warning(f"[{conn.label}] op136 timeout, sending op64 anyway")
        self._recent_outgoing_file_ids.add(file_id)

        try:
            await conn.send_raw(64, {
                "chatId": self.chat_id,
                "message": {
                    "cid": -int(time.time() * 1000),
                    "attaches": [{"_type": "FILE", "fileId": file_id, "name": "OUT_data.bin"}],
                },
                "notify": True,
            })
        except Exception as e:
            conn.mark_fail(); log.error(f"[{conn.label}] send op64 failed: {e}")

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

            # Входящее сообщение — текст (малые фреймы) или файл (большие)
            if (op == 128 and cmd == 0) or (op == 64 and cmd == 1 and isinstance(pl, dict) and "message" in pl):
                msg      = pl.get("message", {})
                text     = msg.get("text", "")
                attaches = msg.get("attaches", [])
                chat_id  = pl.get("chatId")

                if not attaches:
                    # Текстовое сообщение
                    if text.startswith("{"):
                        try:
                            obj = json.loads(text)
                        except Exception:
                            continue
                        # Фильтруем своё эхо
                        if obj.get("src") == "client":
                            continue

                        # Обработка NACK — ретранслируем запрошенные ms
                        if obj.get("a") == "nack":
                            ms_from = obj.get("from", 0)
                            ms_to   = obj.get("to", ms_from)
                            log.debug(f"[transport:{self.label}] got nack ms={ms_from}..{ms_to}")
                            self._rl_on_problem()
                            await self._text_queue.put(("_retransmit", ms_from, ms_to))
                            continue

                        # Проверяем ms-номер
                        ms = obj.pop("ms", None)
                        if ms is not None:
                            exp = self._ms_recv_expected
                            if ms < exp:
                                log.debug(f"[transport:{self.label}] dup ms={ms}, skip")
                                continue
                            elif ms > exp:
                                self._ms_ooo[ms] = obj
                                now = time.monotonic()
                                if now - self._ms_nack_sent_at >= 1.0:
                                    self._ms_nack_sent_at = now
                                    self._ms_nack_count += 1
                                    self._rl_on_problem()
                                    if self._ms_nack_count >= 5:
                                        # 5 безуспешных NACK — пропускаем gap, разблокируем ooo
                                        log.warning(f"[transport:{self.label}] giving up on ms={exp}..{ms-1} after {self._ms_nack_count} NACKs, skipping")
                                        self._ms_nack_count = 0
                                        frames_to_deliver = [obj]
                                        self._ms_recv_expected = ms + 1
                                        while self._ms_recv_expected in self._ms_ooo:
                                            frames_to_deliver.append(self._ms_ooo.pop(self._ms_recv_expected))
                                            self._ms_recv_expected += 1
                                        for frame in frames_to_deliver:
                                            log.debug(f"[transport:{self.label}] text-recv (after skip)  action={frame.get('a')}  id={frame.get('id')}")
                                            if self.on_frame:
                                                asyncio.create_task(self.on_frame(frame))
                                        continue
                                    nack_text = json.dumps({"a":"nack","src":"client","from":exp,"to":ms-1}, separators=(",",":"))
                                    log.debug(f"[transport:{self.label}] gap ms={exp}..{ms-1}, sending nack (attempt {self._ms_nack_count})")
                                    asyncio.create_task(self._ws_send_text(nack_text))
                                continue
                            else:
                                # Ожидаемый ms — сбрасываем счётчик
                                self._ms_nack_count = 0
                                self._ms_recv_expected = ms + 1
                                frames_to_deliver = [obj]
                                while self._ms_recv_expected in self._ms_ooo:
                                    frames_to_deliver.append(self._ms_ooo.pop(self._ms_recv_expected))
                                    self._ms_recv_expected += 1
                                for frame in frames_to_deliver:
                                    log.debug(f"[transport:{self.label}] text-recv  action={frame.get('a')}  id={frame.get('id')}")
                                    if self.on_frame:
                                        asyncio.create_task(self.on_frame(frame))
                                continue

                        log.debug(f"[transport:{self.label}] text-recv  action={obj.get('a')}  id={obj.get('id')}")
                        if self.on_frame:
                            asyncio.create_task(self.on_frame(obj))
                    continue

                # Файловое вложение (большие чанки)
                attach = attaches[0]
                if attach.get("_type") != "FILE": continue
                file_id = attach.get("fileId") or attach.get("id")
                msg_id  = msg.get("msgId") or msg.get("id") or ""
                if not file_id: continue
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

    async def _recv_file(self, file_id: int, msg_id: str, chat_id: int):
        """Скачать файл и распарсить фрейм туннеля."""
        async with self._op88_sem:
            key = f"op88_{file_id}"
            fut = asyncio.get_event_loop().create_future()
            self._once[key] = fut
            await self._send_raw(88, {"fileId": file_id, "chatId": chat_id, "messageId": msg_id})
            url = None
            for attempt in range(3):
                timeout = 12.0 + attempt * 10.0
                try:
                    pl = await asyncio.wait_for(fut if attempt == 0 else asyncio.get_event_loop().create_future(),
                                                timeout=timeout)
                    url = pl.get("url"); break
                except asyncio.TimeoutError:
                    self._once.pop(key, None)
                    if attempt < 2:
                        log.warning(f"[transport:{self.label}] op88 timeout fileId={file_id} attempt={attempt+1}, retrying...")
                        fut = asyncio.get_event_loop().create_future()
                        self._once[key] = fut
                        await self._send_raw(88, {"fileId": file_id, "chatId": chat_id, "messageId": msg_id})
                    else:
                        log.error(f"[transport:{self.label}] op88 timeout fileId={file_id} all retries exhausted")
                        return
            if not url: return

            try:
                async with self._http.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        log.error(f"[transport:{self.label}] download failed {resp.status}"); return
                    file_body = await resp.read()
            except Exception as e:
                log.error(f"[transport:{self.label}] download error: {e}"); return

        # Формат: [4B: len(hdr)][JSON hdr][binary data]
        if len(file_body) < 4: return
        hdr_len = int.from_bytes(file_body[:4], "big")
        if len(file_body) < 4 + hdr_len: return
        try:
            obj = json.loads(file_body[4:4 + hdr_len])
        except Exception: return
        raw_data = file_body[4 + hdr_len:]
        if raw_data:
            obj["d"] = base64.b64encode(raw_data).decode()
        log.debug(f"[transport:{self.label}] file-recv  fileId={file_id}  action={obj.get('a')}")
        if self.on_frame:
            asyncio.create_task(self.on_frame(obj))

    async def connect(self):
        """Запустить пул WS-соединений и _send_worker."""
        connector = aiohttp.TCPConnector(limit_per_host=8, keepalive_timeout=30,
                                          enable_cleanup_closed=True)
        self._http_shared = aiohttp.ClientSession(connector=connector)
        self._file_queue  = asyncio.PriorityQueue()
        self._ms_recv_expected = 0
        self._ms_ooo.clear()

        pool_tasks = [asyncio.create_task(conn.connect_and_run()) for conn in self._pool]
        send_worker_task = asyncio.create_task(self._send_worker())

        try:
            for _ in range(30):
                if any(c.usable for c in self._pool):
                    break
                await asyncio.sleep(0.5)
            await asyncio.gather(*pool_tasks)
        except asyncio.CancelledError:
            raise
        finally:
            for task in pool_tasks:
                task.cancel()
                try: await task
                except Exception: pass
            await self._file_queue.put((999, 0, None))
            try: await asyncio.wait_for(send_worker_task, timeout=5.0)
            except Exception: send_worker_task.cancel()
            if self._http_shared and not self._http_shared.closed:
                await self._http_shared.close()
            self._http_shared = None


class MultiTransport:
    """Round-robin по нескольким MaxTransport."""
    CONTROL_ACTIONS = {"connect", "ok", "err", "close", "closed"}

    def __init__(self, transports: list[MaxTransport]):
        if not transports:
            raise ValueError("MultiTransport требует хотя бы один transport")
        self.transports = transports
        self.control    = transports[0]
        self.on_frame   = None
        self._rr = 0
        self._cid_transport: dict[str, MaxTransport] = {}
        for t in self.transports:
            t.on_frame = self._make_frame_dispatcher(t)

    def _make_frame_dispatcher(self, transport: MaxTransport):
        async def _dispatch(obj):
            cid = obj.get("id")
            if cid and obj.get("a") in self.CONTROL_ACTIONS:
                self._cid_transport[cid] = transport
            if self.on_frame:
                await self.on_frame(obj)
        return _dispatch

    def _next_transport(self) -> MaxTransport:
        t = self.transports[self._rr % len(self.transports)]
        self._rr += 1
        return t

    def _pick_transport(self, obj: dict) -> MaxTransport:
        action = obj.get("a")
        cid    = obj.get("id")
        if action in self.CONTROL_ACTIONS:
            if cid:
                t = self._cid_transport.get(cid)
                if t is None:
                    t = self._next_transport() if action == "connect" else self.control
                    self._cid_transport[cid] = t
                return t
            return self.control
        seq = obj.get("seq")
        if isinstance(seq, int):
            return self.transports[seq % len(self.transports)]
        return self._next_transport()

    async def send(self, obj: dict):
        t   = self._pick_transport(obj)
        cid = obj.get("id")
        if cid and obj.get("a") in self.CONTROL_ACTIONS and cid not in self._cid_transport:
            self._cid_transport[cid] = t
        await t.send(obj)

    def forget_cid(self, cid: str):
        self._cid_transport.pop(cid, None)

    async def connect(self):
        tasks = [asyncio.create_task(t.connect()) for t in self.transports]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        exc = None
        for d in done:
            try: await d
            except Exception as e: exc = e; break
        for p in pending: p.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        if exc: raise exc

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _pack(data: bytes) -> tuple[str, bool]:
    c = zlib.compress(data, level=1)
    if len(c) < len(data): return base64.b64encode(c).decode(), True
    return base64.b64encode(data).decode(), False


def _fmt_speed(total_bytes: float, elapsed: float) -> str:
    if elapsed <= 0: return "—"
    bps = total_bytes / elapsed
    if bps >= 1_048_576: return f"{bps/1_048_576:.1f} МБ/с"
    return f"{bps/1024:.1f} КБ/с"


def _extract_link_token(raw: str) -> str:
    for prefix in ("https://max.ru/", "http://max.ru/", "/"):
        if raw.startswith(prefix): raw = raw[len(prefix):]
    return raw

# ══════════════════════════════════════════════════════════════════════════════
# SOCKS5 ПРОКСИ
# ══════════════════════════════════════════════════════════════════════════════

class ProxyClient:
    _REORDER_TIMEOUT = 30.0

    def __init__(self, transport, server_name: str = "?"):
        self.t           = transport
        self.server_name = server_name
        self.queues:    dict[str, asyncio.Queue] = {}
        self.status:    dict[str, str]           = {}
        self._stats:    dict[str, dict]          = {}
        self._next_seq: dict[str, int]           = {}
        self._buf:      dict[str, dict]          = {}
        self._send_seq: dict[str, int]           = {}
        self._connect_futs: dict[str, asyncio.Future] = {}
        self._stall_tasks: dict[str, asyncio.Task] = {}
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
            log.debug(f"[{cid}] <- data #{st['frames_rx']}  {len(raw)}B  seq={obj.get('seq')}")
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
            self._cancel_stall(cid)
            await self._push(cid, raw)
            self._next_seq[cid] = exp + 1
            buf = self._buf.setdefault(cid, {})
            while True:
                nxt = self._next_seq[cid]
                if nxt in buf:
                    await self._push(cid, buf.pop(nxt))
                    self._next_seq[cid] = nxt + 1
                else: break
            if buf:
                self._arm_stall(cid)
        elif seq > exp:
            self._buf.setdefault(cid, {})[seq] = raw
            if cid not in self._stall_tasks or self._stall_tasks[cid].done():
                self._arm_stall(cid)
        else:
            log.debug(f"[{cid}] dup seq={seq}")

    def _arm_stall(self, cid: str):
        self._cancel_stall(cid)
        self._stall_tasks[cid] = asyncio.create_task(self._stall_timeout(cid))

    def _cancel_stall(self, cid: str):
        t = self._stall_tasks.pop(cid, None)
        if t and not t.done(): t.cancel()

    async def _stall_timeout(self, cid: str):
        await asyncio.sleep(self._REORDER_TIMEOUT)
        exp = self._next_seq.get(cid, 0)
        buf_size = len(self._buf.get(cid, {}))
        log.warning(f"[{cid}] reorder stall: seq={exp} missing for {self._REORDER_TIMEOUT:.0f}s, buf={buf_size} frames — closing")
        self.status[cid] = "closed"
        await self._push(cid, None)

    async def open_tunnel(self, host: str, port: int) -> str | None:
        cid = uuid.uuid4().hex[:8]
        self.queues[cid]    = asyncio.Queue()
        self.status[cid]    = "pending"
        self._next_seq[cid] = self._send_seq[cid] = 0
        self._buf[cid]      = {}
        st = self._stat(cid); st["host"] = host; st["port"] = port

        fut = asyncio.get_event_loop().create_future()
        self._connect_futs[cid] = fut

        t0 = time.monotonic()
        connect_obj = {"a": "connect", "id": cid, "host": host, "port": port}
        await self.t.send(connect_obj)

        # Retry connect если ok не пришёл: MAX может дропнуть connect-фрейм.
        # Успешные туннели открываются за ~300-500ms, так что 2s = гарантированная потеря.
        retry_delays = [2.0, 3.0, 4.0, 5.0]  # суммарно 14s, бюджет 15s
        deadline = t0 + 15.0
        for delay in retry_delays:
            try:
                result = await asyncio.wait_for(
                    asyncio.shield(fut), timeout=delay)
                break
            except asyncio.TimeoutError:
                if time.monotonic() >= deadline - 0.5:
                    break
                remaining = deadline - time.monotonic()
                if remaining < 1.0:
                    break
                log.debug(f"tunnel {host}:{port} [{cid}]  no ok in {delay:.0f}s, retrying connect")
                await self.t.send(connect_obj)
        else:
            # Последний шанс — ждём оставшееся время
            try:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    result = await asyncio.wait_for(asyncio.shield(fut), timeout=remaining)
                else:
                    raise asyncio.TimeoutError
            except asyncio.TimeoutError:
                result = None

        if fut.done() and not fut.cancelled():
            result = fut.result()
        elif not fut.done():
            result = None

        self._connect_futs.pop(cid, None)
        elapsed_ms = (time.monotonic() - t0) * 1000
        if result == "ok":
            log.info(f"tunnel {host}:{port} [{cid}]  открыт за ~{elapsed_ms:.0f} мс")
            return cid
        log.info(f"tunnel {host}:{port} [{cid}]  TIMEOUT")
        self._cleanup(cid); return None

    def _cleanup(self, cid):
        self._cancel_stall(cid)
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

        log.info(f"SOCKS5 → {host}:{port}")
        cid = await self.open_tunnel(host, port)
        if not cid:
            writer.close(); return

        q = self.queues[cid]; t0 = time.time()

        async def local_to_remote():
            _BULK_MAX  = 40_000
            _BULK_WAIT = 0.05

            async def _send_frame(data: bytes):
                st = self._stat(cid); st["tx"] += len(data); st["frames_tx"] += 1
                seq = self._send_seq.get(cid, 0); self._send_seq[cid] = seq + 1
                d, z = _pack(data)
                frame = {"a": "data", "id": cid, "seq": seq, "d": d}
                if z: frame["z"] = 1
                log.debug(f"[{cid}] -> #{st['frames_tx']}  {len(data)}B  seq={seq}")
                await self.t.send(frame)

            try:
                bulk_buf = bytearray()
                bulk_deadline = None

                while True:
                    read_timeout = 120.0
                    if bulk_buf and bulk_deadline is not None:
                        read_timeout = max(0.001, bulk_deadline - time.monotonic())

                    try:
                        chunk = await asyncio.wait_for(reader.read(32768), timeout=read_timeout)
                    except asyncio.TimeoutError:
                        if bulk_buf:
                            await _send_frame(bytes(bulk_buf))
                            bulk_buf.clear(); bulk_deadline = None
                            continue
                        else:
                            log.debug(f"[{cid}] local read timeout (120s idle)"); break

                    if not chunk:
                        if bulk_buf:
                            await _send_frame(bytes(bulk_buf))
                        log.debug(f"[{cid}] local EOF"); break

                    if len(chunk) <= TEXT_THRESHOLD:
                        if bulk_buf:
                            await _send_frame(bytes(bulk_buf))
                            bulk_buf.clear(); bulk_deadline = None
                        await _send_frame(chunk)
                        continue

                    if not bulk_buf:
                        bulk_deadline = time.monotonic() + _BULK_WAIT
                    bulk_buf.extend(chunk)

                    if len(bulk_buf) >= _BULK_MAX:
                        await _send_frame(bytes(bulk_buf))
                        bulk_buf.clear(); bulk_deadline = None

            except Exception as e:
                if bulk_buf:
                    try: await _send_frame(bytes(bulk_buf))
                    except Exception: pass
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
            f"[{self.server_name}]  "
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
            token=acc["token"], viewer_id=acc["viewer_id"],
            device_id=acc["device_id"], chat_id=SELF_CHAT_ID,
            label=acc["label"],
        )
        for acc in ACCOUNTS
    ]
    transport = MultiTransport(transports) if len(transports) > 1 else transports[0]
    proxy = ProxyClient(transport, server_name="server")

    socks_server = await asyncio.start_server(proxy.handle_socks5, SOCKS5_HOST, SOCKS5_PORT)
    _console("=" * 50)
    _console(f"MAX Self-Chat Proxy  viewer_id={VIEWER_ID}  transports={len(ACCOUNTS)}")
    _console(f"SOCKS5: {SOCKS5_HOST}:{SOCKS5_PORT}")
    _console(f"TEXT_THRESHOLD: {TEXT_THRESHOLD}B  (≤{TEXT_THRESHOLD} → WS текст, > → файл)")
    _console(f"Тест: curl --socks5 localhost:{SOCKS5_PORT} https://2ip.ru")
    _console(f"Лог:  {LOG_FILE}")
    _console("=" * 50)
    log.info(f"SOCKS5 запущен  {SOCKS5_HOST}:{SOCKS5_PORT}  transports={len(ACCOUNTS)}")

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