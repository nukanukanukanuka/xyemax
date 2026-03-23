#!/usr/bin/env python3
"""
get_session.py — клиентская сторона. Самодостаточный файл.

Запуск:
    python3 get_session.py https://max.ru/u/TOKEN

Сценарий:
    1. Если session.json не найден — открываем браузер, ждём QR, сохраняем сессию
    2. Резолвим ссылку → получаем имя и userId собеседника
    3. Вычисляем chatId = viewerId XOR userId
    4. Отправляем '.' собеседнику
    5. Ждём '.' в ответ
    6. Запускаем SOCKS5 прокси на localhost:1080

Логи:
  - подробный DEBUG → proxy_client.log (ротация 10 МБ × 5)
  - краткий INFO    → консоль (только значимые события)

Зависимости:
    pip install websockets playwright
    playwright install chromium
"""

import asyncio
import base64
import json
import logging
import logging.handlers
import sys
import time
import uuid
import zlib
from pathlib import Path

import aiohttp
import websockets

# ══════════════════════════════════════════════════════════════════════════════
# ФАЙЛОВЫЙ ТРАНСПОРТ — константы
# ══════════════════════════════════════════════════════════════════════════════
_FILE_DOWNLOAD_URL = "https://fu.oneme.ru/api/download.do"

# ══════════════════════════════════════════════════════════════════════════════
# НАСТРОЙКИ
# ══════════════════════════════════════════════════════════════════════════════

SESSION_FILE = Path("session.json")
SOCKS5_HOST  = "127.0.0.1"
SOCKS5_PORT  = 1080

_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE  = _LOGS_DIR / f"client_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"

# ══════════════════════════════════════════════════════════════════════════════
# ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════

class _SpeedFilter(logging.Filter):
    """Пропускает в консоль только строки со статистикой соединений (DONE)."""
    def filter(self, record):
        return record.getMessage().startswith("DONE ")


def _setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Файл — всё, DEBUG и выше (каждый запуск — новый файл в logs/)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(fh)

    # Консоль — только строки статистики туннеля (сервер + скорость)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S"))
    ch.addFilter(_SpeedFilter())
    root.addHandler(ch)

    for noisy in ("websockets", "asyncio"):
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
        self._op88_lock = asyncio.Lock()   # сериализует запросы op88 — MAX не эхоит fileId
        # Батчинг: накапливаем фреймы и отправляем одним файлом строго по очереди
        self._send_buffer: list[bytes] = []
        self._flush_task: asyncio.Task | None = None
        self._send_queue: asyncio.Queue = asyncio.Queue()   # сериализует _send_file
        self._send_worker_task: asyncio.Task | None = None
        self._BATCH_DELAY = 0.015  # секунд ждём перед отправкой
        self._BATCH_MAX   = 32     # не более N фреймов в одном файле
        self._http: aiohttp.ClientSession | None = None  # persistent HTTP session

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
        """Упаковать все накопленные фреймы в один файл и поставить в очередь отправки."""
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
        await self._send_queue.put(file_body)

    async def _send_worker(self):
        """Отправляет батчи строго по одному — гарантирует порядок доставки."""
        while True:
            file_body = await self._send_queue.get()
            if file_body is None:  # сигнал остановки
                break
            try:
                await self._send_file(file_body)
            except Exception as e:
                log.error(f"[transport] send_worker error: {e}", exc_info=True)

    async def _send_file(self, file_body: bytes):
        """Загрузить файл через MAX File API и отправить сообщением с вложением."""
        http = self._http
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

        # 3. Подписываемся на op136 ДО upload — MAX шлёт подтверждение сразу
        # после обработки файла, подписка заранее убирает лишний round-trip
        fut136 = asyncio.get_event_loop().create_future()
        self._once["op136"] = fut136

        # 4. Загрузить файл — multipart/form-data
        form = aiohttp.FormData()
        form.add_field("file", file_body,
                       filename="data.bin",
                       content_type="application/octet-stream")
        async with http.post(up_url, data=form) as resp:
            if resp.status != 200:
                body = await resp.text()
                log.error(f"[transport] upload failed {resp.status}: {body}"); return
            log.debug(f"[transport] upload ok  fileId={file_id}  size={len(file_body)}")

        # 5. Ждём op136 — к этому моменту часто уже пришёл во время upload
        try:
            await asyncio.wait_for(fut136, timeout=5.0)
        except asyncio.TimeoutError:
            log.warning("[transport] op136 timeout — всё равно отправляем")

        # 6. Отправить сообщение с вложением
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
        log.info(f"Авторизован [client], chatId={self.chat_id}")

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
                # Матчим по fileId из payload — поддерживает параллельные запросы
                fid = pl.get("fileId") or pl.get("id")
                key = f"op88_{fid}" if fid and f"op88_{fid}" in self._once else None
                if key is None:
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
        """Получить прямой URL для скачивания файла через opcode 88 (строго по одному)."""
        async with self._op88_lock:
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
                self._once.pop(key, None)
                log.error(f"[transport] op88 timeout fileId={file_id}")
                return None

    async def _recv_file(self, file_id: int, msg_id: str, chat_id: int, sender):
        """Получить URL через opcode 88, скачать файл и распарсить фреймы туннеля."""
        url = await self._resolve_download_url(file_id, msg_id, chat_id)
        if not url:
            return
        try:
            http = self._http
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
        async with websockets.connect(
            _WS_URL, additional_headers=_WS_HEADERS,
            ping_interval=None,   # отключаем встроенные пинги — MAX не отвечает на WS ping
            close_timeout=5,
        ) as ws:
            self.ws = ws
            connector = aiohttp.TCPConnector(
                limit_per_host=4,
                keepalive_timeout=30,
                enable_cleanup_closed=True,
            )
            self._http = aiohttp.ClientSession(connector=connector)
            self._send_queue     = asyncio.Queue()
            recv_task            = asyncio.create_task(self._recv_loop())
            keepalive_task       = asyncio.create_task(self._keepalive())
            send_worker_task     = asyncio.create_task(self._send_worker())
            await self._handshake()
            try:
                await recv_task
            finally:
                keepalive_task.cancel()
                await self._send_queue.put(None)  # останавливаем воркер
                try:
                    await send_worker_task
                except Exception:
                    pass
                if self._http and not self._http.closed:
                    await asyncio.shield(self._http.close())
                self._http = None

    async def _keepalive(self):
        """Отправляем переподписку на чат каждые 25с — MAX точно понимает и не рвёт соединение."""
        while True:
            await asyncio.sleep(25)
            try:
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


def _extract_link_token(raw: str) -> str:
    for prefix in ("https://max.ru/", "http://max.ru/", "/"):
        if raw.startswith(prefix): raw = raw[len(prefix):]
    return raw

# ══════════════════════════════════════════════════════════════════════════════
# ШАГ 1: ПОЛУЧИТЬ СЕССИЮ ЧЕРЕЗ БРАУЗЕР
# ══════════════════════════════════════════════════════════════════════════════

def acquire_session() -> dict:
    if SESSION_FILE.exists():
        session = json.loads(SESSION_FILE.read_text())
        if session.get("token") and session.get("viewerId") and session.get("deviceId"):
            log.info(f"Сессия загружена из {SESSION_FILE}  (viewerId={session['viewerId']})")
            return session

    log.info("session.json не найден — запускаем браузер для авторизации")

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        print("[!] Playwright не установлен. Запусти:")
        print("    pip install playwright && playwright install chromium")
        sys.exit(1)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False, args=["--start-maximized"])
        ctx  = browser.new_context(viewport=None, user_agent=_WS_HEADERS["User-Agent"])
        page = ctx.new_page()

        print("[*] Открываем web.max.ru ...")
        page.goto("https://web.max.ru", wait_until="domcontentloaded")

        print("[*] Ждём QR-код ...")
        try:
            page.wait_for_selector("canvas", timeout=30_000)
            print()
            print("=" * 50)
            print("  📱 Отсканируй QR-код в приложении MAX")
            print("     Профиль → QR-код / Войти по QR")
            print("=" * 50)
        except PWTimeout:
            print("[*] QR не найден — возможно уже авторизован")

        print("[*] Ожидаем авторизации (до 2 минут) ...")
        token, deadline = None, time.time() + 120
        while time.time() < deadline:
            try:
                auth_raw = page.evaluate("() => localStorage.getItem('__oneme_auth')")
                auth  = json.loads(auth_raw) if auth_raw else {}
                token = auth.get("token") or auth.get("authToken")
            except Exception: pass
            if token: break
            print(f"\r[*] Ждём токен... {int(deadline - time.time())}s  ", end="", flush=True)
            time.sleep(1)
        print()

        if not token:
            print("[!] Токен не получен. Попробуй снова.")
            browser.close(); sys.exit(1)

        auth_raw  = page.evaluate("() => localStorage.getItem('__oneme_auth')")
        auth      = json.loads(auth_raw)
        viewer_id = auth.get("viewerId") or auth.get("userId")
        device_id = page.evaluate("() => localStorage.getItem('__oneme_device_id')")
        time.sleep(2)
        browser.close()

    session = {"token": token, "viewerId": int(viewer_id), "deviceId": device_id}
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    log.info(f"Сессия загружена из {SESSION_FILE}  (viewerId={viewer_id})")
    print(f"[✓] Сессия сохранена в {SESSION_FILE}")
    return session

# ══════════════════════════════════════════════════════════════════════════════
# ШАГИ 2-5: РЕЗОЛВ + ОБМЕН ТОЧКАМИ
# ══════════════════════════════════════════════════════════════════════════════

class _SetupClient:
    def __init__(self, transport: MaxTransport):
        self.t = transport
        transport.on_frame = lambda _: asyncio.sleep(0)

    async def _recv_loop(self):
        async for raw in self.t.ws:
            try: frame = json.loads(raw)
            except Exception: continue
            op, cmd, pl = frame.get("opcode"), frame.get("cmd"), frame.get("payload", {})

            if   cmd==1 and op==6  and "op6"  in self.t._once: f=self.t._once.pop("op6");  f.done() or f.set_result(pl)
            elif cmd==1 and op==19 and "op19" in self.t._once: f=self.t._once.pop("op19"); f.done() or f.set_result(pl)
            elif cmd==1 and op==89 and "op89" in self.t._once: f=self.t._once.pop("op89"); f.done() or f.set_result(pl)
            elif cmd==1 and op==64 and "op64" in self.t._once: f=self.t._once.pop("op64"); f.done() or f.set_result(pl)
            elif op==128 and cmd==0:
                msg  = pl.get("message", {})
                text = msg.get("text", "").strip()
                if text == "." and "dot_received" in self.t._once:
                    f = self.t._once.pop("dot_received")
                    f.done() or f.set_result({"chatId": pl.get("chatId"), "msg": msg})

    async def run(self, link_token: str) -> int:
        async with websockets.connect(
            _WS_URL, additional_headers=_WS_HEADERS,
            ping_interval=20, ping_timeout=30,
        ) as ws:
            self.t.ws = ws
            recv_task = asyncio.create_task(self._recv_loop())
            await asyncio.sleep(0)
            await self.t._handshake()

            loop = asyncio.get_event_loop()

            fut89 = loop.create_future(); self.t._once["op89"] = fut89
            await self.t._send_raw(89, {"link": link_token})
            resp89  = await asyncio.wait_for(fut89, timeout=10.0)
            contact = resp89.get("user", {}).get("contact", {})
            user_id = contact.get("id")
            name    = (contact.get("names") or [{}])[0].get("name", "?")
            log.info(f"Собеседник: {name}  (userId={user_id})")
            _console(f"Собеседник: {name}  (userId={user_id})")

            chat_id = self.t.viewer_id ^ user_id
            log.info(f"chatId = {self.t.viewer_id} XOR {user_id} = {chat_id}")

            await self.t._send_raw(48, {"chatIds": [chat_id]})
            await asyncio.sleep(0.3)
            await self.t._send_raw(75, {"chatId": chat_id, "subscribe": True})

            fut64 = loop.create_future(); self.t._once["op64"] = fut64
            await self.t._send_raw(64, {
                "chatId": chat_id,
                "message": {"text": ".", "cid": -int(time.time() * 1000),
                            "elements": [], "attaches": []},
                "notify": True,
            })
            await asyncio.wait_for(fut64, timeout=10.0)
            log.info(f"Отправили '.' → {name}")

            _console(f"⏳ Ждём '.' в ответ от {name} ...")

            fut_dot = loop.create_future(); self.t._once["dot_received"] = fut_dot
            await asyncio.wait_for(fut_dot, timeout=300.0)
            log.info(f"Получили '.' от {name} — запускаем прокси!")
            _console(f"Получили '.' от {name} — запускаем прокси!")

            recv_task.cancel()
            return chat_id, name

# ══════════════════════════════════════════════════════════════════════════════
# ШАГ 6: SOCKS5 ПРОКСИ
# ══════════════════════════════════════════════════════════════════════════════

class ProxyClient:
    def __init__(self, transport: MaxTransport, server_name: str = "?"):
        self.t           = transport
        self.server_name = server_name
        self.queues:          dict[str, asyncio.Queue]   = {}
        self.status:          dict[str, str]             = {}
        self._connect_futs:   dict[str, asyncio.Future] = {}  # cid → Future[str]
        self._stats:          dict[str, dict]            = {}
        self._next_seq:       dict[str, int]             = {}
        self._buf:            dict[str, dict]            = {}
        self._send_seq:       dict[str, int]             = {}
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
        for d in (self.queues, self.status, self._stats,
                  self._next_seq, self._buf, self._send_seq):
            d.pop(cid, None)

    async def handle_socks5(self, reader, writer):
        try:
            host, port = await _socks5_handshake(reader, writer)
        except Exception as e:
            log.warning(f"SOCKS5 handshake error: {e}"); writer.close(); return

        # TCP_NODELAY — отключаем алгоритм Нагла для интерактивного трафика
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
                        chunk = await asyncio.wait_for(reader.read(8192), timeout=60)
                    except asyncio.TimeoutError:
                        log.debug(f"[{cid}] local read timeout"); break
                    if not chunk:
                        log.debug(f"[{cid}] local EOF"); break
                    buf = bytearray(chunk)
                    for _ in range(8):
                        if len(buf) >= 8192: break
                        try:
                            more = await asyncio.wait_for(
                                reader.read(min(4096, 8192 - len(buf))), timeout=0.02)
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
                await self.t.send({"a": "close", "id": cid})

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

async def _run_proxy(session: dict, chat_id: int, server_name: str = "?"):
    transport = MaxTransport(
        role="client", token=session["token"],
        viewer_id=session["viewerId"], device_id=session["deviceId"],
        chat_id=chat_id,
    )
    proxy = ProxyClient(transport, server_name=server_name)

    socks_server = await asyncio.start_server(proxy.handle_socks5, SOCKS5_HOST, SOCKS5_PORT)
    _console("=" * 50)
    _console(f"SOCKS5 прокси запущен  {SOCKS5_HOST}:{SOCKS5_PORT}  сервер={server_name}")
    _console(f"   Тест: curl --socks5 localhost:{SOCKS5_PORT} https://2ip.ru")
    _console(f"   Лог:  {LOG_FILE}")
    _console("=" * 50)
    log.info(f"SOCKS5 прокси запущен  {SOCKS5_HOST}:{SOCKS5_PORT}  server={server_name}  chat_id={chat_id}")

    async def run():
        async with socks_server:
            await transport.connect()

    while True:
        try:
            await run()
        except Exception as e:
            log.error(f"WS разрыв: {e}. Reconnect in 5s...")
            await asyncio.sleep(5)


async def _setup_and_run(link_token: str, session: dict):
    transport = MaxTransport(
        role="client", token=session["token"],
        viewer_id=session["viewerId"], device_id=session["deviceId"],
        chat_id=0,
    )
    chat_id, server_name = await _SetupClient(transport).run(link_token)
    await _run_proxy(session, chat_id, server_name)


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 get_session.py <ссылка>")
        print("Пример:        python3 get_session.py https://max.ru/u/TOKEN")
        sys.exit(1)

    link_token = _extract_link_token(sys.argv[1])
    session    = acquire_session()
    asyncio.run(_setup_and_run(link_token, session))


if __name__ == "__main__":
    main()