#!/usr/bin/env python3
"""
server.py — запускается на VPS. Самодостаточный файл.

Каждые POLL_INTERVAL секунд опрашивает:
    GET https://telegram.mooner.pro/api/max/status
    → {"links": ["https://max.ru/u/TOKEN1", ...]}

Новая ссылка  → резолвим chatId, шлём '.', поднимаем прокси
Ссылка ушла  → останавливаем прокси, удаляем из sessions.json

Логи:
  - подробный DEBUG → proxy_server.log (ротация 10 МБ × 5)
  - краткий INFO    → консоль (только значимые события)
"""

import asyncio
import base64
import json
import logging
import logging.handlers
import sys
import time
import zlib
from pathlib import Path

import aiohttp
import websockets

# ══════════════════════════════════════════════════════════════════════════════
# ФАЙЛОВЫЙ ТРАНСПОРТ — константы
# ══════════════════════════════════════════════════════════════════════════════
# Формат файла: [4 байта BE: длина JSON-заголовка][JSON заголовок][бинарные данные]
# Заголовок содержит все поля фрейма кроме "d" (тело идёт как бинарь после)
# Для управляющих фреймов (connect/ok/err/close/closed) тело пустое.
_FILE_DOWNLOAD_URL = "https://fu.oneme.ru/api/download.do"

# ══════════════════════════════════════════════════════════════════════════════
# КОНФИГ — читается из config.py (рядом с server.py)
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

TOKEN     = _cfg["TOKEN"]
VIEWER_ID = int(_cfg["VIEWER_ID"])
DEVICE_ID = _cfg["DEVICE_ID"]

STATUS_URL    = "https://telegram.mooner.pro/api/max/status"
SESSIONS_FILE = Path("sessions.json")
POLL_INTERVAL = 30
LOG_FILE      = "proxy_server.log"

# ══════════════════════════════════════════════════════════════════════════════
# ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════

class _SpeedFilter(logging.Filter):
    """Пропускает в консоль только строки со статистикой соединений (pipe done)."""
    def filter(self, record):
        return "pipe done" in record.getMessage()


def _setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Файл — всё, DEBUG и выше
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(fh)

    # Консоль — только строки статистики туннеля (клиент + скорость)
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
    """Вывести строку в консоль напрямую, минуя фильтры логгера."""
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


class MaxTransport:
    def __init__(self, role: str, token: str, viewer_id: int,
                 device_id: str, chat_id: int):
        self.role       = role
        self.token      = token
        self.viewer_id  = viewer_id
        self.device_id  = device_id
        self.chat_id    = chat_id
        self.seq        = 0
        self.ws         = None
        self._once: dict[str, asyncio.Future] = {}
        self.on_frame   = None
        self.on_message = None
        # Батчинг: накапливаем фреймы и отправляем одним файлом
        self._send_buffer: list[bytes] = []
        self._flush_task: asyncio.Task | None = None
        self._BATCH_DELAY = 0.04   # секунд ждём перед отправкой
        self._BATCH_MAX   = 16     # не более N фреймов в одном файле

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

    async def send(self, obj: dict):
        """Отправить фрейм туннеля — добавляет в буфер и флашит через BATCH_DELAY."""
        obj = dict(obj); obj["src"] = self.role
        raw_data = b""
        if "d" in obj:
            raw_data = base64.b64decode(obj.pop("d"))
            if obj.get("z"):
                obj.pop("z")
                raw_data = zlib.decompress(raw_data)

        hdr = json.dumps(obj, separators=(",", ":")).encode()
        frame_bytes = len(hdr).to_bytes(4, "big") + hdr + raw_data
        self._send_buffer.append(frame_bytes)

        # Если буфер достиг максимума — флашим немедленно
        if len(self._send_buffer) >= self._BATCH_MAX:
            if self._flush_task and not self._flush_task.done():
                self._flush_task.cancel()
            await self._flush_buffer()
        elif self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush_after(self._BATCH_DELAY))

    async def _flush_after(self, delay: float):
        """Ждём delay секунд, затем отправляем накопленное."""
        await asyncio.sleep(delay)
        await self._flush_buffer()

    async def _flush_buffer(self):
        """Упаковать все накопленные фреймы в один файл и отправить."""
        if not self._send_buffer:
            return
        frames = self._send_buffer[:]
        self._send_buffer.clear()
        n = len(frames)
        # Формат: [4B: кол-во фреймов][4B: len(frame1)][frame1][4B: len(frame2)][frame2]...
        parts = [n.to_bytes(4, "big")]
        for f in frames:
            parts.append(len(f).to_bytes(4, "big") + f)
        file_body = b"".join(parts)
        log.debug(f"[transport] batch flush  frames={n}  total={len(file_body)}B")
        await self._send_file(file_body)

    async def _send_file(self, file_body: bytes):
        """Загрузить файл через MAX File API и отправить сообщением с вложением."""
        async with aiohttp.ClientSession() as http:
            # 1. Запросить upload slot через WS opcode 87
            fut = asyncio.get_event_loop().create_future()
            self._once["op87"] = fut
            await self._send_raw(87, {"count": 1})
            try:
                slot = await asyncio.wait_for(fut, timeout=10.0)
            except asyncio.TimeoutError:
                log.error("[transport] upload slot timeout"); return
            info     = slot["info"][0]
            up_url   = info["url"]
            file_id  = info["fileId"]

            # 2. Уведомление о загрузке файла (opcode 65)
            await self._send_raw(65, {"chatId": self.chat_id, "type": "FILE"})

            # 3. Загрузить файл — multipart/form-data (как клиент)
            form = aiohttp.FormData()
            form.add_field("file", file_body,
                           filename="data.bin",
                           content_type="application/octet-stream")
            async with http.post(up_url, data=form) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    log.error(f"[transport] upload failed {resp.status}: {body}"); return
                log.debug(f"[transport] upload ok  fileId={file_id}  size={len(file_body)}")

            # 4. Ждём opcode 136 — подтверждение от сервера MAX
            fut136 = asyncio.get_event_loop().create_future()
            self._once["op136"] = fut136
            try:
                await asyncio.wait_for(fut136, timeout=10.0)
            except asyncio.TimeoutError:
                log.warning("[transport] op136 timeout — отправляем сообщение без подтверждения")

            # 5. Отправить сообщение с вложением
            await self._send_raw(64, {
                "chatId": self.chat_id,
                "message": {
                    "cid": -int(time.time() * 1000),
                    "attaches": [{"_type": "FILE", "fileId": file_id}],
                },
                "notify": False,
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
        log.info(f"Авторизован [server], chatId={self.chat_id}")

    async def _recv_loop(self):
        async for raw in self.ws:
            try: frame = json.loads(raw)
            except Exception: continue
            op, cmd, pl = frame.get("opcode"), frame.get("cmd"), frame.get("payload", {})

            if cmd == 1 and op == 6   and "op6"   in self._once:
                f = self._once.pop("op6");   f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 19  and "op19"  in self._once:
                f = self._once.pop("op19");  f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 87  and "op87"  in self._once:
                f = self._once.pop("op87");  f.done() or f.set_result(pl); continue
            if cmd == 1 and op == 88:
                # ключ хранится как op88_{fileId}; fileId берём из запроса через seq —
                # но проще: ищем совпадающий ключ, т.к. запросы обычно не параллельны
                key = next((k for k in list(self._once) if k.startswith("op88_")), None)
                if key:
                    f = self._once.pop(key); f.done() or f.set_result(pl); continue
            if cmd == 0 and op == 136 and "op136" in self._once:
                f = self._once.pop("op136"); f.done() or f.set_result(pl); continue
            if cmd == 0 and op in (292, 48, 180, 177, 65, 130):
                continue

            if op == 128 and cmd == 0:
                msg      = pl.get("message", {})
                text     = msg.get("text", "")
                attaches = msg.get("attaches", [])
                sender   = msg.get("sender")
                chat_id  = pl.get("chatId")
                log.debug(f"[transport] op128 chat={chat_id} sender={sender} attaches={len(attaches)}")

                # Текстовое сообщение (сигналинг: ".")
                if not attaches:
                    if self.on_message:
                        asyncio.create_task(self.on_message(chat_id, sender, text))
                    continue

                # Файловое вложение — скачиваем и парсим фрейм
                attach = attaches[0]
                log.debug(f"[transport] attach full={attach}")
                if attach.get("_type") != "FILE":
                    continue
                file_id = attach.get("fileId") or attach.get("id")
                msg_id  = msg.get("msgId") or msg.get("id") or ""
                if not file_id:
                    log.warning(f"[transport] нет fileId в attach: {attach}"); continue
                asyncio.create_task(self._recv_file(int(file_id), str(msg_id), chat_id, sender))

    async def _resolve_download_url(self, file_id: int, msg_id: str, chat_id: int) -> str | None:
        """Получить прямой URL для скачивания файла через opcode 88."""
        key = f"op88_{file_id}"
        fut = asyncio.get_event_loop().create_future()
        self._once[key] = fut
        await self._send_raw(88, {"fileId": file_id, "chatId": chat_id, "messageId": msg_id})
        try:
            pl = await asyncio.wait_for(fut, timeout=10.0)
            url = pl.get("url")
            log.debug(f"[transport] op88 fileId={file_id} url={url}")
            return url
        except asyncio.TimeoutError:
            log.error(f"[transport] op88 timeout fileId={file_id}")
            return None

    async def _recv_file(self, file_id: int, msg_id: str, chat_id: int, sender):
        """Получить URL через opcode 88, скачать файл и распарсить фреймы туннеля."""
        url = await self._resolve_download_url(file_id, msg_id, chat_id)
        if not url:
            return
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        log.error(f"[transport] download failed {resp.status} fileId={file_id}"); return
                    file_body = await resp.read()
        except Exception as e:
            log.error(f"[transport] download error: {e}"); return

        frames = _unpack_batch(file_body)
        if not frames:
            log.warning("[transport] не удалось распарсить батч"); return
        log.debug(f"[transport] recv_file  fileId={file_id}  frames={len(frames)}")
        for obj in frames:
            if obj.get("src") == self.role:
                continue  # наш собственный фрейм, игнорируем
            log.debug(f"[transport] frame  action={obj.get('a')}  id={obj.get('id')}  size={len(obj.get('d',''))}")
            if self.on_frame:
                asyncio.create_task(self.on_frame(obj))

    async def connect(self):
        try:
            async with websockets.connect(
                _WS_URL, additional_headers=_WS_HEADERS,
                ping_interval=None,   # отключаем встроенные пинги — MAX не отвечает на WS ping
                close_timeout=5,
            ) as ws:
                self.ws = ws
                recv_task = asyncio.create_task(self._recv_loop())
                keepalive_task = asyncio.create_task(self._keepalive())
                await self._handshake()
                try:
                    await recv_task
                finally:
                    keepalive_task.cancel()
        except Exception as e:
            log.error(f"[transport:{self.role}] connect завершился: {type(e).__name__}: {e!r}", exc_info=True)
            raise

    async def _keepalive(self):
        """Отправляем опрос подписки каждые 25с чтобы не получить таймаут от MAX."""
        while True:
            await asyncio.sleep(25)
            try:
                # opcode 48 — переподписка на чат, MAX точно понимает и не рвёт соединение
                await self._send_raw(48, {"chatIds": [self.chat_id]})
                log.debug(f"[transport:{self.role}] keepalive sent")
            except Exception as e:
                log.debug(f"[transport:{self.role}] keepalive error: {e}")
                break

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _unpack_batch(file_body: bytes) -> list[dict]:
    """Распаковать батч-файл в список объектов фреймов.

    Формат: [4B: кол-во фреймов N]
              ([4B: len(frame)][frame_bytes]) × N
    Каждый frame_bytes: [4B: len(hdr)][JSON hdr][binary data]
    """
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


def _extract_link_token(url: str) -> str:
    for prefix in ("https://max.ru/", "http://max.ru/", "/"):
        if url.startswith(prefix): url = url[len(prefix):]
    return url

# ══════════════════════════════════════════════════════════════════════════════
# SESSIONS
# ══════════════════════════════════════════════════════════════════════════════

def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        try: return json.loads(SESSIONS_FILE.read_text())
        except Exception: pass
    return {}


def _save_sessions(sessions: dict):
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2, ensure_ascii=False))

# ══════════════════════════════════════════════════════════════════════════════
# RESOLVE + PING
# ══════════════════════════════════════════════════════════════════════════════

async def _resolve_and_ping(link_url: str) -> dict:
    link_token = _extract_link_token(link_url)
    transport  = MaxTransport("server", TOKEN, VIEWER_ID, DEVICE_ID, 0)
    once: dict = {}

    async def recv_loop(ws):
        async for raw in ws:
            try: frame = json.loads(raw)
            except Exception: continue
            op, cmd, pl = frame.get("opcode"), frame.get("cmd"), frame.get("payload", {})
            if   cmd==1 and op==6  and "op6"  in once: f=once.pop("op6");  f.done() or f.set_result(pl)
            elif cmd==1 and op==19 and "op19" in once: f=once.pop("op19"); f.done() or f.set_result(pl)
            elif cmd==1 and op==89 and "op89" in once: f=once.pop("op89"); f.done() or f.set_result(pl)
            elif cmd==1 and op==64 and "op64" in once: f=once.pop("op64"); f.done() or f.set_result(pl)

    async with websockets.connect(
        _WS_URL, additional_headers=_WS_HEADERS, ping_interval=20, ping_timeout=30,
    ) as ws:
        transport.ws = ws; transport._once = once
        recv_task = asyncio.create_task(recv_loop(ws))
        await asyncio.sleep(0)
        await transport._handshake()

        loop = asyncio.get_event_loop()

        fut89 = loop.create_future(); once["op89"] = fut89
        await transport._send_raw(89, {"link": link_token})
        resp89  = await asyncio.wait_for(fut89, timeout=10.0)
        contact = resp89.get("user", {}).get("contact", {})
        user_id = contact["id"]
        name    = (contact.get("names") or [{}])[0].get("name", "?")
        chat_id = VIEWER_ID ^ user_id
        log.info(f"[resolve] {name}  uid={user_id}  chat_id={chat_id}")

        await transport._send_raw(48, {"chatIds": [chat_id]})
        await asyncio.sleep(0.3)
        await transport._send_raw(75, {"chatId": chat_id, "subscribe": True})

        fut64 = loop.create_future(); once["op64"] = fut64
        await transport._send_raw(64, {
            "chatId": chat_id,
            "message": {"text": ".", "cid": -int(time.time() * 1000),
                        "elements": [], "attaches": []},
            "notify": True,
        })
        await asyncio.wait_for(fut64, timeout=10.0)
        log.info(f"[resolve] '.' отправлен → {name}  chat_id={chat_id}")
        recv_task.cancel()

    return {"chat_id": chat_id, "user_id": user_id, "name": name}

# ══════════════════════════════════════════════════════════════════════════════
# PROXY SERVER
# ══════════════════════════════════════════════════════════════════════════════

class ProxyServer:
    def __init__(self, transport: MaxTransport, name: str = "?"):
        self.t          = transport
        self.name       = name
        self.conns:     dict[str, tuple] = {}
        self._stats:    dict[str, dict]  = {}
        self._seq:      dict[str, int]   = {}
        self._next_seq: dict[str, int]   = {}
        self._buf:      dict[str, dict]  = {}
        transport.on_frame = self._on_frame

    def _stat(self, cid):
        if cid not in self._stats:
            self._stats[cid] = {"rx": 0, "tx": 0, "frames_rx": 0, "frames_tx": 0, "t0": time.time()}
        return self._stats[cid]

    async def _on_frame(self, obj):
        a, cid = obj.get("a"), obj.get("id", "")
        if a == "connect":
            log.info(f"[{cid}] CONNECT → {obj.get('host')}:{obj.get('port')}")
            await self._do_connect(cid, obj["host"], obj["port"])
        elif a == "data":
            raw = base64.b64decode(obj["d"])
            if obj.get("z"): raw = zlib.decompress(raw)
            st = self._stat(cid); st["rx"] += len(raw); st["frames_rx"] += 1
            log.debug(f"[{cid}] <- data #{st['frames_rx']}  {len(raw)}B  seq={obj.get('seq')}  (rx={st['rx']}B)")
            await self._do_write_ordered(cid, obj.get("seq"), raw)
        elif a == "close":
            log.info(f"[{cid}] закрытие по запросу клиента")
            await self._do_close(cid, notify=False)
        else:
            log.warning(f"[{cid}] неизвестный action={a!r}")

    async def _do_connect(self, cid, host, port):
        t0 = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10)
        except asyncio.TimeoutError:
            log.info(f"[{cid}] TCP connect TIMEOUT → {host}:{port}")
            await self.t.send({"a": "err", "id": cid, "msg": "timeout"}); return
        except Exception as e:
            log.info(f"[{cid}] TCP connect FAILED → {host}:{port}  ({e})")
            await self.t.send({"a": "err", "id": cid, "msg": str(e)}); return

        log.info(f"[{cid}] TCP connected → {host}:{port}  ({(time.time()-t0)*1000:.0f} мс)")
        self.conns[cid] = (reader, writer)
        self._seq[cid] = self._next_seq[cid] = 0
        self._buf[cid] = {}
        self._stat(cid)["t0"] = time.time()
        await self.t.send({"a": "ok", "id": cid})
        asyncio.create_task(self._pipe(cid, reader))

    async def _pipe(self, cid, reader):
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(2900), timeout=60)
                except asyncio.TimeoutError:
                    log.debug(f"[{cid}] pipe timeout (60s idle)"); break
                if not chunk:
                    log.debug(f"[{cid}] remote EOF"); break
                buf = bytearray(chunk)
                for _ in range(8):
                    if len(buf) >= 2900: break
                    try:
                        more = await asyncio.wait_for(
                            reader.read(min(4096, 2900 - len(buf))), timeout=0.005)
                        if not more: break
                        buf.extend(more)
                    except asyncio.TimeoutError: break
                data = bytes(buf)
                st = self._stat(cid); st["tx"] += len(data); st["frames_tx"] += 1
                seq = self._seq.get(cid, 0); self._seq[cid] = seq + 1
                frame = {"a": "data", "id": cid, "seq": seq, "d": base64.b64encode(data).decode()}
                log.debug(f"[{cid}] -> #{st['frames_tx']}  {len(data)}B  seq={seq}  (tx={st['tx']}B)")
                await self.t.send(frame)
                await asyncio.sleep(0.5 if st["frames_tx"] % 20 == 0 else 0.03)
        except Exception as e:
            log.warning(f"[{cid}] pipe error: {type(e).__name__}: {e}")
        finally:
            st = self._stat(cid); elapsed = time.time() - st["t0"]
            line = (
                f"[{self.name}]  "
                f"↑{_fmt_speed(st['tx'], elapsed)} ({st['tx']}B)  "
                f"↓{_fmt_speed(st['rx'], elapsed)} ({st['rx']}B)  "
                f"{elapsed:.1f}s"
            )
            log.info(
                f"[{cid}] pipe done | "
                f"rx={st['rx']}B/{st['frames_rx']}f ({_fmt_speed(st['rx'], elapsed)})  "
                f"tx={st['tx']}B/{st['frames_tx']}f ({_fmt_speed(st['tx'], elapsed)})  "
                f"{elapsed:.1f}s"
            )
            _console(line)
            await self._do_close(cid, notify=True)

    async def _do_write_ordered(self, cid, seq, raw):
        if seq is None:
            await self._do_write(cid, raw); return
        exp = self._next_seq.get(cid, 0)
        if seq == exp:
            await self._do_write(cid, raw)
            self._next_seq[cid] = exp + 1
            buf = self._buf.setdefault(cid, {})
            while True:
                nxt = self._next_seq[cid]
                if nxt in buf:
                    await self._do_write(cid, buf.pop(nxt))
                    self._next_seq[cid] = nxt + 1
                else: break
        elif seq > exp:
            self._buf.setdefault(cid, {})[seq] = raw

    async def _do_write(self, cid, raw):
        if cid not in self.conns: return
        _, writer = self.conns[cid]
        try:
            writer.write(raw); await writer.drain()
            log.debug(f"[{cid}] wrote {len(raw)}B to remote")
        except Exception as e:
            log.error(f"[{cid}] write FAILED: {e}")
            await self._do_close(cid, notify=True)

    async def _do_close(self, cid, notify):
        if cid not in self.conns: return
        _, writer = self.conns.pop(cid)
        for d in (self._stats, self._seq, self._next_seq, self._buf): d.pop(cid, None)
        try: writer.close(); await writer.wait_closed()
        except Exception: pass
        log.debug(f"[{cid}] socket closed")
        if notify:
            try: await self.t.send({"a": "closed", "id": cid})
            except Exception as e: log.debug(f"[{cid}] не удалось отправить 'closed': {e}")

# ══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class SessionManager:
    def __init__(self):
        self.sessions: dict[str, dict]         = _load_sessions()
        self._tasks:   dict[str, asyncio.Task] = {}

    async def start(self):
        for url, info in self.sessions.items():
            self._tasks[url] = asyncio.create_task(
                self._run_proxy(url, info["chat_id"], info.get("name", url)))
        if self.sessions:
            log.info(f"Восстановлено {len(self.sessions)} сессий из {SESSIONS_FILE}")

    async def sync(self, active_links: list[str]):
        current, wanted = set(self.sessions), set(active_links)

        for url in current - wanted:
            log.info(f"[sync] убираем: {url}")
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
                info = await _resolve_and_ping(url)
                self.sessions[url] = info
                _save_sessions(self.sessions)
                self._tasks[url] = asyncio.create_task(
                    self._run_proxy(url, info["chat_id"], info["name"]))
            except Exception as e:
                log.error(f"[sync] не удалось добавить {url}: {e}")

        for url, info in list(self.sessions.items()):
            task = self._tasks.get(url)
            if task is None or task.done():
                log.info(f"[sync] перезапуск: {info.get('name', url)}")
                self._tasks[url] = asyncio.create_task(
                    self._run_proxy(url, info["chat_id"], info.get("name", url)))

    async def _run_proxy(self, url: str, chat_id: int, name: str):
        while True:
            transport = MaxTransport("server", TOKEN, VIEWER_ID, DEVICE_ID, chat_id)
            ProxyServer(transport, name=name)

            async def on_message(inc_chat_id, sender_id, text,
                                 _t=transport, _name=name, _chat_id=chat_id):
                log.debug(f"[proxy:{_name}] msg chat={inc_chat_id} sender={sender_id} text={text!r}")
                if text.strip() != "." or sender_id == VIEWER_ID: return
                log.info(f"[proxy:{_name}] получили '.' от {sender_id}, отвечаем '.'")
                try:
                    await _t._send_raw(64, {
                        "chatId": inc_chat_id,
                        "message": {"text": ".", "cid": -int(time.time() * 1000),
                                    "elements": [], "attaches": []},
                        "notify": True,
                    })
                except Exception as e:
                    log.error(f"[proxy:{_name}] не удалось отправить '.': {e}")

            transport.on_message = on_message
            try:
                log.info(f"[proxy:{name}] WS подключение (chat_id={chat_id})")
                await transport.connect()
            except asyncio.CancelledError:
                log.info(f"[proxy:{name}] остановлен"); return
            except Exception as e:
                log.error(f"[proxy:{name}] разрыв: {e!r}. Reconnect in 5s...", exc_info=True)
                await asyncio.sleep(5)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    _console("=" * 50)
    _console(f"MAX Proxy SERVER  viewer_id={VIEWER_ID}")
    _console(f"API: {STATUS_URL}  poll={POLL_INTERVAL}s")
    _console(f"Лог: {LOG_FILE}")
    _console("=" * 50)
    log.info(f"MAX Proxy SERVER запущен  viewer_id={VIEWER_ID}  api={STATUS_URL}  poll={POLL_INTERVAL}s")

    manager = SessionManager()
    await manager.start()

    async with aiohttp.ClientSession() as http:
        while True:
            try:
                async with http.get(STATUS_URL, timeout=aiohttp.ClientTimeout(total=10)) as resp:
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
    asyncio.run(main())