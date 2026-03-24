#!/usr/bin/env python3
"""
server.py — серверная сторона HTTP-батч прокси через MAX файловый канал.

Архитектура:
  Получает файл с батчем HTTP запросов от client.py.
  Выполняет все запросы параллельно через aiohttp.
  Собирает ответы в один файл и отправляет обратно.

Один файл туда = один файл обратно = вся загрузка страницы.

Конфиг (server.conf):
    TOKEN     = <токен>
    VIEWER_ID = <viewerId>
    DEVICE_ID = <deviceId>
    # Опционально:
    TOKEN_2   = ...  VIEWER_ID_2 = ...  DEVICE_ID_2 = ...  # мультиаккаунт

Зависимости:
    pip install websockets aiohttp
"""

import asyncio
import base64
import json
import logging
import logging.handlers
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

ACCOUNTS  = _load_accounts(_cfg)
TOKEN     = ACCOUNTS[0]["token"]
VIEWER_ID = ACCOUNTS[0]["viewer_id"]
DEVICE_ID = ACCOUNTS[0]["device_id"]

STATUS_URL    = "https://telegram.mooner.pro/api/max/status"
SESSIONS_FILE = Path("sessions.json")
POLL_INTERVAL = 30

# Параллельность fetch на один батч
FETCH_CONCURRENCY = int(_cfg.get("FETCH_CONCURRENCY", "16"))
# Таймаут одного HTTP запроса (секунд)
FETCH_TIMEOUT = float(_cfg.get("FETCH_TIMEOUT", "20"))
# Максимальный размер тела ответа (байт) — крупные файлы обрезаем
FETCH_MAX_BODY = int(_cfg.get("FETCH_MAX_BODY", str(10 * 1024 * 1024)))  # 10 МБ

_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE  = _LOGS_DIR / f"server_{time.strftime('%Y-%m-%d_%H-%M-%S')}.log"

# ══════════════════════════════════════════════════════════════════════════════
# ЛОГИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════════════

class _SpeedFilter(logging.Filter):
    def filter(self, record):
        return "BATCH" in record.getMessage()

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

def _pack_file(data: bytes) -> bytes:
    c = zlib.compress(data, level=1)
    if len(c) < len(data):
        return b"\x01" + c
    return b"\x00" + data

def _unpack_file(payload: bytes) -> bytes:
    if not payload: return b""
    if payload[0] == 1: return zlib.decompress(payload[1:])
    return payload[1:]

def _fmt_speed(total_bytes: float, elapsed: float) -> str:
    if elapsed <= 0: return "—"
    bps = total_bytes / elapsed
    if bps >= 1_048_576: return f"{bps/1_048_576:.1f} МБ/с"
    return f"{bps/1024:.1f} КБ/с"

def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        try: return json.loads(SESSIONS_FILE.read_text())
        except Exception: pass
    return {}

def _save_sessions(sessions: dict):
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2, ensure_ascii=False))

# ══════════════════════════════════════════════════════════════════════════════
# ТРАНСПОРТ
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
                 device_id: str, chat_id: int, label: str = "acc1"):
        self.label      = label
        self.role       = role
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
        # Колбэк: вызывается когда пришёл файл с батчем запросов (bytes)
        self.on_batch_request: callable = None

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

        fut136 = loop.create_future()
        self._once[f"op136_{file_id}"] = fut136
        await self._send_raw(65, {"chatId": self.chat_id, "type": "FILE"})

        form = aiohttp.FormData()
        form.add_field("file", file_body,
                       filename="batch_resp.bin",
                       content_type="application/octet-stream")
        async with http.post(up_url, data=form) as resp:
            if resp.status != 200:
                body = await resp.text()
                self._once.pop(f"op136_{file_id}", None)
                log.error(f"[transport:{self.label}] upload failed {resp.status}: {body}"); return

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
        log.debug(f"[transport:{self.label}] published response fileId={file_id} size={len(file_body)}")

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

            if (op == 128 and cmd == 0) or (op == 64 and cmd == 1 and isinstance(pl, dict) and "message" in pl):
                msg      = pl.get("message", {})
                attaches = msg.get("attaches", [])
                text     = msg.get("text", "")
                sender   = msg.get("sender")
                chat_id  = pl.get("chatId")

                if not attaches:
                    # Текстовый сигнал "."
                    if text.strip() == ".":
                        log.info(f"[server] получили '.' от {sender}, отвечаем '.'")
                        try:
                            await self._send_raw(64, {
                                "chatId": chat_id,
                                "message": {"text": ".", "cid": -int(time.time() * 1000),
                                            "elements": [], "attaches": []},
                                "notify": True,
                            })
                        except Exception as e:
                            log.error(f"[server] не удалось отправить '.': {e}")
                    continue

                attach  = attaches[0]
                if attach.get("_type") != "FILE": continue
                file_id = attach.get("fileId") or attach.get("id")
                msg_id  = msg.get("msgId") or msg.get("id") or ""
                if not file_id: continue
                file_id = int(file_id)
                if file_id in self._recent_outgoing_file_ids:
                    self._recent_outgoing_file_ids.discard(file_id)
                    continue
                if file_id in self._seen_file_ids: continue
                self._mark_seen_file(file_id)
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
            _WS_URL, additional_headers=_WS_HEADERS,
            ping_interval=20, ping_timeout=30, close_timeout=5,
        ) as ws:
            self.ws = ws
            connector = aiohttp.TCPConnector(
                limit=FETCH_CONCURRENCY * 2,
                limit_per_host=8,
                keepalive_timeout=30,
            )
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
            raise RuntimeError("recv_loop завершился")


# ══════════════════════════════════════════════════════════════════════════════
# HTTP FETCHER — выполняет батч запросов параллельно
# ══════════════════════════════════════════════════════════════════════════════

class BatchFetcher:
    """Принимает батч запросов, выполняет параллельно, возвращает батч ответов."""

    def __init__(self, transport: MaxTransport):
        self.t = transport
        self.t.on_batch_request = self._on_batch_request
        self._sem = asyncio.Semaphore(FETCH_CONCURRENCY)
        # Отдельная HTTP сессия для fetch запросов (не для MAX API)
        connector = aiohttp.TCPConnector(
            limit=FETCH_CONCURRENCY * 2,
            limit_per_host=6,
            ttl_dns_cache=300,
            keepalive_timeout=30,
        )
        self._http = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            headers={"User-Agent": "Mozilla/5.0 (compatible; MaxProxy/2.0)"},
        )
        # TCP туннельные сессии: session_id → (reader, writer)
        self._tunnels: dict[str, tuple] = {}

    async def _on_batch_request(self, data: bytes):
        """Вызывается при получении файла с батчем запросов."""
        try:
            batch = json.loads(data)
        except Exception as e:
            log.error(f"[fetcher] ошибка парсинга батча: {e}"); return

        batch_id = batch.get("batch_id", "?")
        requests = batch.get("requests", [])
        n = len(requests)
        t0 = time.time()
        log.info(f"BATCH recv  id={batch_id}  reqs={n}")

        # Выполняем все запросы параллельно
        tasks = [asyncio.create_task(self._fetch_one(req)) for req in requests]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        results = []
        total_bytes = 0
        for req, resp in zip(requests, responses):
            if isinstance(resp, Exception):
                log.warning(f"[fetcher] {req.get('url', '?')} → error: {resp}")
                results.append({
                    "id": req["id"],
                    "status": 502,
                    "headers": {"content-type": "text/plain"},
                    "body_b64": base64.b64encode(str(resp).encode()).decode(),
                })
            else:
                results.append(resp)
                total_bytes += len(base64.b64decode(resp.get("body_b64", "")))

        resp_obj = {"batch_id": batch_id, "responses": results}
        resp_json = json.dumps(resp_obj, ensure_ascii=False).encode()
        file_body = _pack_file(resp_json)

        elapsed = time.time() - t0
        speed   = _fmt_speed(total_bytes, elapsed)
        log.info(
            f"BATCH done  id={batch_id}  reqs={n}  "
            f"payload={total_bytes//1024}КБ  "
            f"file={len(file_body)//1024}КБ  "
            f"{elapsed:.1f}s  {speed}"
        )
        _console(
            f"BATCH  {n} req  {total_bytes//1024}КБ данных  "
            f"→ {len(file_body)//1024}КБ файл  {elapsed:.1f}s  {speed}"
        )

        await self.t.send_file(file_body)

    async def _fetch_one(self, req: dict) -> dict:
        """Выполнить один HTTP запрос."""
        async with self._sem:
            req_id  = req["id"]
            method  = req.get("method", "GET").upper()
            url     = req.get("url", "")
            headers = req.get("headers", {})
            body_b64 = req.get("body_b64", "")
            body    = base64.b64decode(body_b64) if body_b64 else None

            # ── TCP TUNNEL (для HTTPS CONNECT без MITM) ──────────────────────
            if method in ("TUNNEL", "TUNNEL_CLOSE"):
                session_id = headers.get("x-tunnel-session", "")
                # Парсим tunnel://host:port
                host_port = url.replace("tunnel://", "")
                host, _, port_s = host_port.rpartition(":")
                port = int(port_s or 443)

                if method == "TUNNEL_CLOSE":
                    tup = self._tunnels.pop(session_id, None)
                    if tup:
                        try: tup[1].close()
                        except Exception: pass
                    return {"id": req_id, "status": 200,
                            "headers": {"content-type": "text/plain"},
                            "body_b64": ""}

                # Открываем или переиспользуем TCP соединение к хосту
                if session_id not in self._tunnels:
                    try:
                        r, w = await asyncio.wait_for(
                            asyncio.open_connection(host, port, ssl=False),
                            timeout=10.0,
                        )
                        self._tunnels[session_id] = (r, w)
                        log.debug(f"[tunnel] открыт {host}:{port} session={session_id}")
                    except Exception as e:
                        log.warning(f"[tunnel] не удалось подключиться к {host}:{port}: {e}")
                        return {"id": req_id, "status": 502,
                                "headers": {"content-type": "text/plain"},
                                "body_b64": base64.b64encode(str(e).encode()).decode()}

                tun_reader, tun_writer = self._tunnels[session_id]

                # Отправляем данные от клиента на сервер
                if body:
                    try:
                        tun_writer.write(body)
                        await tun_writer.drain()
                    except Exception as e:
                        self._tunnels.pop(session_id, None)
                        return {"id": req_id, "status": 502,
                                "headers": {"content-type": "text/plain"},
                                "body_b64": base64.b64encode(str(e).encode()).decode()}

                # Читаем ответ от сервера (с небольшим таймаутом)
                resp_data = b""
                try:
                    resp_data = await asyncio.wait_for(
                        tun_reader.read(131072),  # 128KB
                        timeout=15.0,
                    )
                except asyncio.TimeoutError:
                    pass  # Нет данных — нормально, вернём пустой ответ
                except Exception as e:
                    self._tunnels.pop(session_id, None)
                    log.debug(f"[tunnel] read error {host}: {e}")

                return {
                    "id": req_id,
                    "status": 200,
                    "headers": {"content-type": "application/octet-stream"},
                    "body_b64": base64.b64encode(resp_data).decode(),
                }
            # ─────────────────────────────────────────────────────────────────

            # Убираем заголовки которые могут мешать
            clean_headers = {
                k: v for k, v in headers.items()
                if k.lower() not in ("host", "content-length", "transfer-encoding",
                                      "connection", "keep-alive")
            }

            try:
                async with self._http.request(
                    method, url,
                    headers=clean_headers,
                    data=body,
                    allow_redirects=True,
                    ssl=False,  # не верифицируем cert на сервере (всё равно через MITM)
                ) as resp:
                    # Читаем тело с ограничением
                    body_data = b""
                    async for chunk in resp.content.iter_chunked(65536):
                        body_data += chunk
                        if len(body_data) >= FETCH_MAX_BODY:
                            log.warning(f"[fetcher] {url} тело обрезано до {FETCH_MAX_BODY}B")
                            break

                    resp_headers = dict(resp.headers)
                    # Убираем hop-by-hop заголовки
                    for h in ("transfer-encoding", "connection", "keep-alive",
                               "proxy-authenticate", "proxy-authorization",
                               "te", "trailers", "upgrade"):
                        resp_headers.pop(h, None)
                        resp_headers.pop(h.title(), None)

                    log.debug(f"[fetcher] {method} {url} → {resp.status} {len(body_data)}B")
                    return {
                        "id":       req_id,
                        "status":   resp.status,
                        "headers":  resp_headers,
                        "body_b64": base64.b64encode(body_data).decode(),
                    }
            except asyncio.TimeoutError:
                return {
                    "id": req_id, "status": 504,
                    "headers": {"content-type": "text/plain"},
                    "body_b64": base64.b64encode(b"Fetch timeout").decode(),
                }
            except Exception as e:
                return {
                    "id": req_id, "status": 502,
                    "headers": {"content-type": "text/plain"},
                    "body_b64": base64.b64encode(f"Fetch error: {e}".encode()).decode(),
                }

    async def close(self):
        await self._http.close()


# ══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGER (упрощён — логика сессий та же что в оригинале)
# ══════════════════════════════════════════════════════════════════════════════

class SessionManager:
    def __init__(self):
        self.sessions: dict[str, dict]         = _load_sessions()
        self._tasks:   dict[str, asyncio.Task] = {}

    async def start(self):
        migrated = False
        for url, info in list(self.sessions.items()):
            if info.get("chat_id") != 0 or info.get("name") != "self-chat":
                self.sessions[url] = {"chat_id": 0, "user_id": VIEWER_ID, "name": "self-chat"}
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
                log.info(f"[sync] перезапуск: {info.get('name', url)}")
                self._tasks[url] = asyncio.create_task(
                    self._run_proxy(url, info["chat_id"], info.get("name", url)))

    async def _run_proxy(self, url: str, chat_id: int, name: str):
        """Запускает по одному WS-соединению на каждый аккаунт параллельно."""
        async def _run_one(acc: dict):
            delay = 5
            while True:
                transport = MaxTransport(
                    "server", acc["token"], acc["viewer_id"], acc["device_id"],
                    chat_id, label=acc["label"],
                )
                fetcher = BatchFetcher(transport)
                try:
                    log.info(f"[proxy:{name}] WS подключение ({acc['label']}, chat_id={chat_id})")
                    await transport.connect()
                    delay = 5
                except asyncio.CancelledError:
                    log.info(f"[proxy:{name}] {acc['label']} остановлен")
                    await fetcher.close()
                    return
                except Exception as e:
                    log.error(f"[proxy:{name}] {acc['label']} разрыв: {e!r}. Reconnect in {delay}s...")
                    await fetcher.close()
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 60)

        await asyncio.gather(*[_run_one(acc) for acc in ACCOUNTS])


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    _console("=" * 55)
    _console(f"MAX Proxy SERVER (batch HTTP mode)  viewer_id={VIEWER_ID}")
    _console(f"CONFIG: {(Path(__file__).parent / 'server.conf')}")
    _console(f"API: {STATUS_URL}  poll={POLL_INTERVAL}s")
    _console(f"Fetch: concurrency={FETCH_CONCURRENCY}  timeout={FETCH_TIMEOUT}s  max_body={FETCH_MAX_BODY//1024}КБ")
    _console(f"Лог: {LOG_FILE}")
    _console("=" * 55)

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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass