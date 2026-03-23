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
LOG_FILE     = "proxy_client.log"

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
        """Отправить фрейм туннеля через файл в MAX-чате."""
        obj = dict(obj); obj["src"] = self.role
        # Извлекаем бинарные данные если есть (поле "d" — base64)
        raw_data = b""
        if "d" in obj:
            raw_data = base64.b64decode(obj.pop("d"))
            if obj.get("z"):
                obj.pop("z")
                raw_data = zlib.decompress(raw_data)

        # Формируем файл: [4B длина заголовка][JSON заголовок][бинарные данные]
        hdr = json.dumps(obj, separators=(",", ":")).encode()
        file_body = len(hdr).to_bytes(4, "big") + hdr + raw_data

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

            # 3. Загрузить файл — raw binary POST
            headers = {"Content-Type": "application/octet-stream"}
            async with http.post(up_url, data=file_body, headers=headers) as resp:
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
                if attach.get("_type") != "FILE":
                    continue
                token = attach.get("token")
                if not token:
                    log.warning("[transport] нет token в attach"); continue
                asyncio.create_task(self._recv_file(token, sender))

    async def _recv_file(self, token: str, sender):
        """Скачать файл по token и распарсить фрейм туннеля."""
        url = f"{_FILE_DOWNLOAD_URL}?token={token}"
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        log.error(f"[transport] download failed {resp.status} token={token}"); return
                    file_body = await resp.read()
        except Exception as e:
            log.error(f"[transport] download error: {e}"); return

        # Парсим: [4B длина заголовка][JSON заголовок][бинарные данные]
        if len(file_body) < 4:
            log.warning("[transport] файл слишком короткий"); return
        hdr_len = int.from_bytes(file_body[:4], "big")
        if len(file_body) < 4 + hdr_len:
            log.warning("[transport] повреждённый заголовок файла"); return
        try:
            obj = json.loads(file_body[4:4 + hdr_len])
        except Exception as e:
            log.warning(f"[transport] не удалось распарсить заголовок: {e}"); return

        raw_data = file_body[4 + hdr_len:]
        if raw_data:
            obj["d"] = base64.b64encode(raw_data).decode()

        if obj.get("src") == self.role:
            return  # наш собственный фрейм, игнорируем
        log.debug(f"[transport] recv_file ok  action={obj.get('a')}  id={obj.get('id')}  size={len(raw_data)}")
        if self.on_frame:
            asyncio.create_task(self.on_frame(obj))

    async def connect(self):
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

    async def _keepalive(self):
        """Отправляем no-op фрейм каждые 30с чтобы не получить таймаут от MAX."""
        while True:
            await asyncio.sleep(30)
            try:
                frame = {"ver": 11, "cmd": 2, "seq": self._next_seq(), "opcode": 0, "payload": {}}
                await self.ws.send(json.dumps(frame, separators=(",", ":")))
                log.debug(f"[transport:{self.role}] keepalive sent")
            except Exception as e:
                log.debug(f"[transport:{self.role}] keepalive error: {e}")
                break

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
        self.queues:    dict[str, asyncio.Queue] = {}
        self.status:    dict[str, str]           = {}
        self._stats:    dict[str, dict]          = {}
        self._next_seq: dict[str, int]           = {}
        self._buf:      dict[str, dict]          = {}
        self._send_seq: dict[str, int]           = {}
        transport.on_frame = self._on_frame

    def _stat(self, cid):
        if cid not in self._stats:
            self._stats[cid] = {"rx": 0, "tx": 0, "frames_rx": 0, "frames_tx": 0,
                                "t0": time.time(), "host": "", "port": 0}
        return self._stats[cid]

    async def _on_frame(self, obj):
        a, cid = obj.get("a"), obj.get("id", "")
        if a == "ok":
            log.debug(f"[{cid}] <- ok"); self.status[cid] = "ok"
        elif a == "err":
            log.info(f"[{cid}] <- ошибка сервера: {obj.get('msg')}")
            self.status[cid] = "err"; await self._push(cid, None)
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
        self.queues[cid] = asyncio.Queue()
        self.status[cid] = "pending"
        self._next_seq[cid] = self._send_seq[cid] = 0
        self._buf[cid] = {}
        st = self._stat(cid); st["host"] = host; st["port"] = port

        await self.t.send({"a": "connect", "id": cid, "host": host, "port": port})
        for i in range(150):
            await asyncio.sleep(0.1)
            s = self.status.get(cid)
            if s == "ok":
                log.info(f"tunnel {host}:{port} [{cid}]  открыт за ~{(i+1)*100} мс")
                return cid
            if s in ("err", "closed"):
                self._cleanup(cid); return None
        log.info(f"tunnel {host}:{port} [{cid}]  TIMEOUT")
        self._cleanup(cid); return None

    def _cleanup(self, cid):
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
            try:
                while True:
                    try:
                        chunk = await asyncio.wait_for(reader.read(2900), timeout=60)
                    except asyncio.TimeoutError:
                        log.debug(f"[{cid}] local read timeout"); break
                    if not chunk:
                        log.debug(f"[{cid}] local EOF"); break
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
                    seq = self._send_seq.get(cid, 0); self._send_seq[cid] = seq + 1
                    frame = {"a": "data", "id": cid, "seq": seq, "d": base64.b64encode(data).decode()}
                    log.debug(f"[{cid}] -> #{st['frames_tx']}  {len(data)}B  seq={seq}")
                    await self.t.send(frame)
                    await asyncio.sleep(0.5 if st["frames_tx"] % 20 == 0 else 0.03)
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