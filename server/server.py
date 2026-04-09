#!/usr/bin/env python3.12
"""
SSH TUN сервер — OpenVPN-стиль.

Один постоянный strans-tun0. Клиент подключается, получает IP (PUSH_REPLY),
затем открывает SSH канал для форвардинга пакетов.
"""

import asyncio
import time
import asyncssh
import fcntl
import ipaddress
import json
import logging
import os
import struct
import subprocess
import sys
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path

# ─── Конфигурация ─────────────────────────────────────────────────────────────

TUN_DEV    = "strans-tun0"
SERVER_IP  = "198.19.0.1"
SUBNET     = "198.19.0.0/24"
POOL_START = 2
POOL_END   = 254

IFF_TUN    = 0x0001
IFF_NO_PI  = 0x1000
TUNSETIFF  = 0x400454ca

# ─── Сессия сервера ───────────────────────────────────────────────────────────

SESSION_UUID = str(_uuid.uuid4())
SESSION_START = datetime.now()
SESSION_START_ISO = SESSION_START.astimezone(timezone.utc).isoformat()
SESSION_DIR = SESSION_START.strftime("%Y%m%d_%H%M%S")

# ─── Логирование ──────────────────────────────────────────────────────────────

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_ch)

_log_dir = Path("logs")
_log_dir.mkdir(parents=True, exist_ok=True)
_log_file = str(_log_dir / f"{SESSION_DIR}_{SESSION_UUID}.log")
_fh = logging.FileHandler(_log_file, mode="w", encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_fh)

log.info("=== Запуск сервера ===")
log.info("Session UUID: %s", SESSION_UUID)
log.info("Лог файл: %s", _log_file)


# ─── Статистика ──────────────────────────────────────────────────────────────

STATISTICS_FILE = "statistics.json"


class Statistics:
    """Собирает статистику текущей сессии и сохраняет в statistics.json."""

    def __init__(self):
        self._connected_devices: list[dict] = []
        self._bandwidth_download = 0.0  # МБ
        self._bandwidth_upload = 0.0    # МБ
        self._lock = asyncio.Lock()

    def record_device(self, user_id: str, real_ip: str, local_ip: str,
                      bw_upload: float, bw_download: float,
                      connected_devices: int, speed_rate: dict | None) -> None:
        """Вызывается при каждой выдаче IP клиенту."""
        self._connected_devices.append({
            "id": user_id,
            "ip": real_ip,
            "ip_local": local_ip,
            "bandwidth_upload": round(bw_upload, 3),
            "bandwidth_download": round(bw_download, 3),
            "connected_devices": connected_devices,
            "speed_rate": speed_rate,
        })

    def add_traffic(self, download_bytes: int, upload_bytes: int) -> None:
        """Добавляет трафик. download = TUN->SSH (к клиенту), upload = SSH->TUN (от клиента)."""
        self._bandwidth_download += download_bytes / (1024 * 1024)
        self._bandwidth_upload += upload_bytes / (1024 * 1024)

    def _build_entry(self) -> dict:
        return {
            "started_at": SESSION_START_ISO,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "bandwidth_download": round(self._bandwidth_download, 3),
                "bandwidth_upload": round(self._bandwidth_upload, 3),
                "connected_devices": self._connected_devices,
            }
        }

    async def save(self) -> None:
        """Сохраняет статистику в файл."""
        async with self._lock:
            try:
                p = Path(STATISTICS_FILE)
                if p.exists():
                    data = json.loads(p.read_text())
                else:
                    data = {}
                data[SESSION_UUID] = self._build_entry()
                p.write_text(json.dumps(data, indent=2))
            except Exception as e:
                log.error("Ошибка сохранения статистики: %s", e)

    async def save_loop(self) -> None:
        """Сохраняет статистику каждые 60 секунд. Первый save — сразу при старте."""
        await self.save()
        while True:
            await asyncio.sleep(60)
            await self.save()


import struct




# Алгоритмы OpenSSH 8.9p1 Ubuntu — для имитации стандартного сервера
OPENSSH_KEX_ALGS = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
]
OPENSSH_ENCRYPTION_ALGS = [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
]
OPENSSH_MAC_ALGS = [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
]
OPENSSH_COMPRESSION_ALGS = ["none", "zlib@openssh.com"]
OPENSSH_SERVER_VERSION = "OpenSSH_8.2p1 Ubuntu-4ubuntu0.13"

# ─── IP пул ───────────────────────────────────────────────────────────────────

class IPPool:
    """IP пул — постоянные адреса хранятся в users.json в поле ip_pool.
    - Поле отсутствует или невалидно — выдаётся новый IP и сохраняется в users.json
    - Поле валидно — используется сохранённый IP
    """

    def __init__(self, user_store: 'UserStore'):
        self._user_store = user_store
        self._used: dict[str, str] = {}  # ip -> username

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except Exception:
            return False

    def _save_ip(self, username: str, ip: str) -> None:
        """Сохраняет IP адрес в поле ip_pool в users.json."""
        try:
            p = Path(USERS_FILE)
            data = json.loads(p.read_text())
            for entry in data:
                creds = entry.get("ssh_creds", "")
                if ":" in creds:
                    u = creds.split(":", 1)[0].strip()
                    if u == username:
                        entry["ip_pool"] = ip
                        break
            p.write_text(json.dumps(data, indent=2))
            # Обновляем кэш
            self._user_store._users[username]["ip_pool"] = ip
            log.info("Пул: сохранён IP %s для %s в users.json", ip, username)
        except Exception as e:
            log.error("Ошибка сохранения IP в users.json: %s", e)

    def allocate(self, username: str) -> str | None:
        users = self._user_store._users
        static_ip = users.get(username, {}).get("ip_pool", "")

        # Проверяем валидность сохранённого IP
        if static_ip and self._is_valid_ip(static_ip):
            if static_ip not in self._used:
                self._used[static_ip] = username
                log.info("Пул: %s <- сохранённый %s", username, static_ip)
                return static_ip
            else:
                log.info("Пул: сохранённый %s для %s уже занят, выдаю новый", static_ip, username)
        elif static_ip:
            # Поле есть но невалидное — очищаем
            log.warning("Пул: невалидный ip_pool '%s' для %s, выдаю новый", static_ip, username)

        # Выдаём новый IP из диапазона (не перезаписываем ip_pool — это доп. устройство)
        net = ipaddress.IPv4Network(SUBNET)
        for host in list(net.hosts())[POOL_START - 1: POOL_END]:
            ip = str(host)
            if ip == SERVER_IP or ip in self._used:
                continue
            self._used[ip] = username
            # Сохраняем ip_pool только если у пользователя ещё нет сохранённого
            if not (static_ip and self._is_valid_ip(static_ip)):
                self._save_ip(username, ip)
            log.info("Пул: %s <- новый %s", username, ip)
            return ip

        log.error("Пул исчерпан")
        return None

    def release(self, ip: str):
        if ip in self._used:
            log.info("Пул: освобождён %s (был у %s)", ip, self._used.pop(ip))


# ─── Открытие TUN fd ──────────────────────────────────────────────────────────

def open_tun_fd(name: str) -> int:
    """Открывает существующий TUN интерфейс и возвращает fd."""
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


class TunRouter:
    """Единственный reader TUN fd.  Раздаёт входящие пакеты зарегистрированным
    TunnelSession по dst IP.  Все сессии пишут в TUN напрямую через общий fd."""

    def __init__(self):
        self._fd: int | None = None
        self._sessions: dict[str, 'TunnelSession'] = {}  # client_ip -> session
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        """Открывает TUN fd и запускает read-loop.  Вызывается один раз."""
        if self._fd is not None:
            return
        self._fd = open_tun_fd(TUN_DEV)
        self._task = asyncio.create_task(self._read_loop())
        log.info("TunRouter: запущен, fd=%d", self._fd)

    @property
    def fd(self) -> int | None:
        return self._fd

    def register(self, client_ip: str, session: 'TunnelSession') -> None:
        self._sessions[client_ip] = session
        log.info("TunRouter: зарегистрирован %s (всего %d)", client_ip, len(self._sessions))

    def unregister(self, client_ip: str) -> None:
        self._sessions.pop(client_ip, None)
        log.info("TunRouter: снят %s (осталось %d)", client_ip, len(self._sessions))

    async def _read_loop(self) -> None:
        import select
        loop = asyncio.get_event_loop()

        def _read_batch():
            """Читает все доступные пакеты за один вызов."""
            packets = []
            # Первый read с ожиданием
            r, _, _ = select.select([self._fd], [], [], 0.5)
            if not r:
                return packets
            packets.append(os.read(self._fd, 65536))
            # Дренируем остальные без ожидания
            for _ in range(256):
                r, _, _ = select.select([self._fd], [], [], 0)
                if not r:
                    break
                packets.append(os.read(self._fd, 65536))
            return packets

        while True:
            try:
                packets = await loop.run_in_executor(None, _read_batch)
                if self._fd is None:
                    break
                for data in packets:
                    if len(data) < 20:
                        continue
                    # Быстрый парсинг dst IP без строковых операций
                    dst = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
                    session = self._sessions.get(dst)
                    if session is not None:
                        await session.deliver_from_tun(data)
            except asyncio.CancelledError:
                break
            except OSError:
                break
            except Exception as e:
                log.debug("TunRouter read_loop error: %s", e)

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None



# ─── SSH сессия ───────────────────────────────────────────────────────────────

class VPNSession(asyncssh.SSHServerSession):
    """Обрабатывает exec 'get_ip' — выдаёт IP клиенту."""

    def __init__(self, pool: IPPool, server: 'VPNServer'):
        self._pool = pool
        self._server = server
        self._chan = None
        self._client_ip = None

    def connection_made(self, chan):
        self._chan = chan

    def exec_requested(self, command: str) -> bool:
        return command.strip() == "get_ip"

    def shell_requested(self) -> bool:
        return False

    def session_started(self) -> None:
        try:
            self._do_session_started()
        except Exception as e:
            log.error("VPNSession.session_started EXCEPTION: %s", e, exc_info=True)
            try:
                self._chan.write((json.dumps({"error": f"INTERNAL_ERROR: {e}"}) + "\n").encode())
                self._chan.exit(1)
            except Exception:
                pass

    def _do_session_started(self) -> None:
        log.debug("VPNSession.session_started")
        username = self._chan.get_extra_info("username")

        # Проверяем лимит устройств
        user_store = self._server._config["user_store"]
        user = user_store._users.get(username, {})
        max_devices = int(user.get("max_connected_devices", -1))
        settings_max = int(self._server._config.get("max_connected_devices", -1))
        # Берём per-user лимит, а если нет — глобальный из settings
        effective_max = max_devices if max_devices != -1 else settings_max
        if effective_max != -1:
            current_count = self._server._config["device_tracker"].count(username)
            if current_count >= effective_max:
                log.warning("MAX_CONNECTED_DEVICES_REACHED для %s (%d/%d)",
                            username, current_count, effective_max)
                self._chan.write((json.dumps({"error": "MAX_CONNECTED_DEVICES_REACHED"}) + "\n").encode())
                self._chan.exit(0)
                return

        ip = self._pool.allocate(username)
        if ip is None:
            self._chan.write((json.dumps({"error": "pool_exhausted"}) + "\n").encode())
            self._chan.exit(1)
            return

        # Проверяем лимит трафика
        bw_limit = user.get("bandwidth_reserved", -1)
        bw_spent = user.get("bandwidth_download_spent", 0) + user.get("bandwidth_upload_spent", 0)
        if bw_limit != -1 and bw_spent >= bw_limit:
            log.warning("NO_BANDWIDTH_LEFT для %s (%s/%s МБ)", username, bw_spent, bw_limit)
            self._chan.write((json.dumps({"error": "NO_BANDWIDTH_LEFT"}) + "\n").encode())
            self._chan.exit(0)
            return

        self._client_ip = ip
        self._server.add_client_ip(username, ip)  # трекинг per-username
        # Статистика: новое подключение
        stats = self._server._config.get("statistics")
        if stats:
            device_tracker = self._server._config.get("device_tracker")
            dev_count = device_tracker.count(username) if device_tracker else 0
            speed_mgr = self._server._config.get("speed_manager")
            speed_rate = speed_mgr._get_speed_rate(username) if speed_mgr else None
            # Реальный IP клиента
            peer = self._server._conn.get_extra_info("peername")
            real_ip = peer[0] if peer else ""
            stats.record_device(
                user_id=user.get("id", ""),
                real_ip=real_ip,
                local_ip=ip,
                bw_upload=float(user.get("bandwidth_upload_spent", 0)),
                bw_download=float(user.get("bandwidth_download_spent", 0)),
                connected_devices=dev_count,
                speed_rate=speed_rate,
            )
        subprocess.run(["ip", "route", "replace", f"{ip}/32", "dev", TUN_DEV],
                       check=False, capture_output=True)

        stealth_level = int(self._server._config.get("stealth", 0))
        stealth_level = max(0, min(9, stealth_level))
        mtu, chunk_min, chunk_max, delay_min, delay_max = STEALTH_LEVELS[stealth_level]
        payload = json.dumps({
            "client_ip":   ip,
            "server_ip":   SERVER_IP,
            "subnet":      SUBNET,
            "mtu":         mtu,
            "stealth":     stealth_level,
            "chunk_min":   chunk_min,
            "chunk_max":   chunk_max,
            "delay_min":   delay_min,
            "delay_max":   delay_max,
        })
        log.info("PUSH_REPLY -> %s (%s)", username, ip)
        self._chan.write((payload + "\n").encode())
        self._chan.exit(0)

    def connection_lost(self, exc) -> None:
        pass  # IP освобождается в VPNServer.connection_lost


class TunnelSession(asyncssh.SSHServerSession):
    """
    Обрабатывает exec 'tunnel <client_ip>' — форвардит пакеты через strans-tun0.
    SSH->TUN: через data_received -> пишет в общий TunRouter.fd
    TUN->SSH: TunRouter вызывает deliver_from_tun() для нужной сессии
    """

    def __init__(self, pool: IPPool, user_store, username: str,
                 tun_router: TunRouter, speed_manager=None, statistics=None):
        self._pool = pool
        self._user_store = user_store
        self._username = username
        self._tun_router = tun_router
        self._speed_manager = speed_manager
        self._statistics = statistics
        self._chan = None
        self._bw_task = None
        self._client_ip = None
        self._buf = b""  # буфер для сборки IP пакетов из stealth чанков
        self._bytes_in = 0   # SSH->TUN (от клиента)
        self._bytes_out = 0  # TUN->SSH (к клиенту)
        self._last_bw_check = 0
        self._alive = False
        # Token bucket для ограничения скорости
        self._upload_tokens = 0.0
        self._download_tokens = 0.0
        self._last_upload_refill = time.time()
        self._last_download_refill = time.time()
        # Очередь для последовательной обработки upload (чтобы throttle работал)
        self._upload_queue: asyncio.Queue = asyncio.Queue()
        self._upload_worker_task = None
        # Очередь для download (TUN->SSH) — аналогично upload
        self._download_queue: asyncio.Queue = asyncio.Queue()
        self._download_worker_task = None

    def connection_made(self, chan):
        self._chan = chan

    def exec_requested(self, command: str) -> bool:
        parts = command.strip().split()
        if len(parts) == 2 and parts[0] == "tunnel":
            self._client_ip = parts[1]
            return True
        return False

    def shell_requested(self) -> bool:
        return False

    def session_started(self) -> None:
        try:
            self._alive = True
            self._tun_router.register(self._client_ip, self)
            log.info("Tunnel сессия запущена для %s (%s)", self._username, self._client_ip)

            # Кешируем лимиты скорости в байтах/сек
            self._ul_limit: int | None = None  # SSH->TUN (upload от клиента)
            self._dl_limit: int | None = None  # TUN->SSH (download к клиенту)
            self._update_speed_limits()

            # Регистрируем callback для обновления лимитов после reload users.json
            self._user_store.register_reload_callback(self._on_users_reloaded)

            self._bw_task = asyncio.create_task(self._bandwidth_monitor())
            self._upload_worker_task = asyncio.create_task(self._upload_worker())
            self._download_worker_task = asyncio.create_task(self._download_worker())
        except Exception as e:
            log.error("TunnelSession.session_started EXCEPTION: %s", e, exc_info=True)
            try:
                self._chan.exit(1)
            except Exception:
                pass

    def _update_speed_limits(self) -> None:
        """Обновляет кешированные лимиты скорости из SpeedManager."""
        if self._speed_manager:
            dl_mbit, ul_mbit, mode = self._speed_manager.get_limits(self._username)
            self._dl_limit = int(dl_mbit * 1_000_000 / 8) if dl_mbit else None
            self._ul_limit = int(ul_mbit * 1_000_000 / 8) if ul_mbit else None
            log.info("Лимиты скорости для %s: mode=%d download=%s Mbit/s (%s Б/с) upload=%s Mbit/s (%s Б/с)",
                     self._username, mode, dl_mbit, self._dl_limit, ul_mbit, self._ul_limit)

    def _on_users_reloaded(self) -> None:
        """Вызывается после reload users.json — обновляем лимиты и проверяем bandwidth."""
        self._update_speed_limits()
        user = self._user_store._users.get(self._username, {})
        bw_limit = user.get("bandwidth_reserved", -1)
        bw_spent = user.get("bandwidth_download_spent", 0) + user.get("bandwidth_upload_spent", 0)
        if bw_limit != -1 and bw_spent >= bw_limit:
            log.warning("После reload: %s превысил лимит трафика, отключаю", self._username)
            try:
                self._chan.abort()
            except Exception:
                pass

    BUCKET_SECS = 0.5  # размер bucket — больше = меньше sleep вызовов, точнее скорость

    async def _throttle(self, n_bytes: int, direction: str) -> None:
        """Token bucket throttle. direction: 'upload' или 'download'."""
        limit = self._ul_limit if direction == 'upload' else self._dl_limit
        if not limit or limit <= 0:
            return

        bucket_max = limit * self.BUCKET_SECS

        now = time.time()
        if direction == 'upload':
            elapsed = now - self._last_upload_refill
            self._last_upload_refill = now
            self._upload_tokens = min(self._upload_tokens + elapsed * limit, bucket_max)
            if self._upload_tokens < n_bytes:
                deficit = n_bytes - self._upload_tokens
                wait = deficit / limit
                await asyncio.sleep(wait)
                self._upload_tokens = max(0.0, self._upload_tokens + wait * limit - deficit)
                self._last_upload_refill = time.time()
            else:
                self._upload_tokens -= n_bytes
        else:
            elapsed = now - self._last_download_refill
            self._last_download_refill = now
            self._download_tokens = min(self._download_tokens + elapsed * limit, bucket_max)
            if self._download_tokens < n_bytes:
                deficit = n_bytes - self._download_tokens
                wait = deficit / limit
                await asyncio.sleep(wait)
                self._download_tokens = max(0.0, self._download_tokens + wait * limit - deficit)
                self._last_download_refill = time.time()
            else:
                self._download_tokens -= n_bytes

    async def deliver_from_tun(self, data: bytes) -> None:
        """Вызывается TunRouter — пакет из TUN для этого клиента. Кладём в очередь."""
        if not self._alive:
            return
        self._download_queue.put_nowait(data)

    async def _download_worker(self):
        """Обрабатывает download с throttle. Дренирует очередь batch'ами."""
        while True:
            try:
                # Ждём первый пакет
                data = await self._download_queue.get()
                if not self._alive:
                    break
                # Собираем batch — дренируем всё что есть
                batch = [data]
                while not self._download_queue.empty():
                    try:
                        batch.append(self._download_queue.get_nowait())
                    except Exception:
                        break
                total = sum(len(d) for d in batch)
                await self._throttle(total, 'download')
                for pkt in batch:
                    self._chan.write(pkt)
                self._bytes_out += total
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("download_worker ошибка: %s", e)

    def data_received(self, data, datatype):
        """SSH->TUN: данные от клиента кладём в очередь."""
        if not self._alive:
            return
        self._upload_queue.put_nowait(data)

    async def _upload_worker(self):
        """Последовательно обрабатывает upload с throttle."""
        fd = self._tun_router.fd
        while True:
            try:
                data = await self._upload_queue.get()
                self._buf += data
                while len(self._buf) >= 20:
                    pkt_len = (self._buf[2] << 8) | self._buf[3]
                    if pkt_len < 20 or pkt_len > 65535:
                        log.debug("Невалидная длина IP пакета %d, сбрасываю буфер", pkt_len)
                        self._buf = b""
                        break
                    if len(self._buf) < pkt_len:
                        break
                    pkt = self._buf[:pkt_len]
                    self._buf = self._buf[pkt_len:]
                    try:
                        await self._throttle(pkt_len, 'upload')
                        os.write(fd, pkt)
                        self._bytes_in += pkt_len
                        log.debug("SSH->TUN: %d байт", pkt_len)
                    except OSError as e:
                        log.debug("Ошибка записи в TUN: %s", e)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("upload_worker ошибка: %s", e)

    async def _bandwidth_monitor(self):
        """Каждую минуту сохраняет трафик и отключает при превышении лимита."""
        while True:
            await asyncio.sleep(60)
            bytes_in = self._bytes_in
            bytes_out = self._bytes_out
            total = bytes_in + bytes_out
            if total == 0:
                continue
            self._bytes_in = 0
            self._bytes_out = 0
            # Статистика: upload = от клиента (bytes_in), download = к клиенту (bytes_out)
            if self._statistics:
                self._statistics.add_traffic(download_bytes=bytes_out, upload_bytes=bytes_in)
            exceeded = self._user_store.add_bandwidth(self._username,
                                                       download_bytes=bytes_out,
                                                       upload_bytes=bytes_in)
            self._user_store.save_bandwidth(self._username)
            if exceeded:
                log.warning("Пользователь %s превысил лимит трафика, отключаю", self._username)
                try:
                    self._chan.abort()
                except Exception:
                    pass
                break

    def _cleanup(self):
        self._alive = False
        self._tun_router.unregister(self._client_ip)
        # Снимаем регистрацию callback
        self._user_store.unregister_reload_callback(self._on_users_reloaded)
        # Сохраняем накопленный трафик при отключении
        bytes_in = self._bytes_in
        bytes_out = self._bytes_out
        remaining = bytes_in + bytes_out
        if remaining > 0:
            if self._statistics:
                self._statistics.add_traffic(download_bytes=bytes_out, upload_bytes=bytes_in)
            self._user_store.add_bandwidth(self._username,
                                            download_bytes=bytes_out,
                                            upload_bytes=bytes_in)
            self._user_store.save_bandwidth(self._username)
        log.info("Tunnel сессия завершена для %s", self._client_ip)

    def connection_lost(self, exc) -> None:
        self._cleanup()
        if self._bw_task:
            self._bw_task.cancel()
        if self._upload_worker_task:
            self._upload_worker_task.cancel()
        if self._download_worker_task:
            self._download_worker_task.cancel()


# ─── SSH сервер ───────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Бан на BAN_SECONDS если:
    - более MAX_CONN подключений за WINDOW секунд, ИЛИ
    - более MAX_AUTH_FAIL неверных паролей
    """
    MAX_CONN      = 3
    MAX_AUTH_FAIL = 3
    WINDOW        = 10   # сек для подсчёта подключений
    BAN_SECONDS   = 60   # сек

    def __init__(self):
        self._conns:      dict[str, list[float]] = {}  # ip -> [timestamps]
        self._auth_fails: dict[str, int]         = {}  # ip -> count
        self._banned:     dict[str, float]        = {}  # ip -> ban_until

    def _ban(self, ip: str, reason: str) -> None:
        self._banned[ip] = time.time() + self.BAN_SECONDS
        log.warning("RateLimit: %s забанен на %d сек (%s)", ip, self.BAN_SECONDS, reason)

    def is_banned(self, ip: str) -> bool:
        now = time.time()
        if ip in self._banned:
            if now < self._banned[ip]:
                return True
            else:
                del self._banned[ip]
                self._auth_fails.pop(ip, None)
                self._conns.pop(ip, None)
        return False

    def record_connection(self, ip: str) -> bool:
        """Записывает подключение. Возвращает True если забанен."""
        now = time.time()
        times = self._conns.get(ip, [])
        times = [t for t in times if now - t < self.WINDOW]
        times.append(now)
        self._conns[ip] = times
        if len(times) > self.MAX_CONN:
            self._ban(ip, f"{len(times)} подключений за {self.WINDOW}с")
            return True
        return False

    def record_auth_fail(self, ip: str) -> bool:
        """Записывает неверный пароль. Возвращает True если забанен."""
        count = self._auth_fails.get(ip, 0) + 1
        self._auth_fails[ip] = count
        if count > self.MAX_AUTH_FAIL:
            self._ban(ip, f"{count} неверных паролей")
            return True
        return False

    def record_auth_ok(self, ip: str) -> None:
        """Сбрасывает счётчик неверных паролей при успехе."""
        self._auth_fails.pop(ip, None)


class SpeedManager:
    """Управляет ограничением скорости для пользователей.
    speed_mode:
      -1 - без ограничений
      -2 - скорость сервера делится на общее количество подключённых устройств
      -3 - фиксированные значения из max_download_speed / max_upload_speed
    """

    def __init__(self, config: dict, user_store):
        self._config = config
        self._user_store = user_store

    def _get_speed_rate(self, username: str) -> dict:
        """Возвращает speed_rate для пользователя: сначала из users.json, потом из settings."""
        user = self._user_store._users.get(username, {})
        user_rate = user.get("speed_rate")
        if user_rate and isinstance(user_rate, dict):
            return user_rate
        return self._config.get("speed_rate", {})

    def get_limits(self, username: str) -> tuple:
        """Возвращает (max_download_mbit, max_upload_mbit, mode) или (None, None, -1)."""
        rate = self._get_speed_rate(username)
        if not rate:
            return None, None, -1
        mode = int(rate.get("speed_mode", -1))
        if mode == -1:
            return None, None, -1
        elif mode == -2:
            # Делим скорость сервера на общее количество подключённых устройств
            speed = self._config.get("server_speed", {})
            srv_dl = speed.get("download")
            srv_ul = speed.get("upload")
            tracker = self._config.get("device_tracker")
            n = max(tracker.total() if tracker else 1, 1)
            dl = round(srv_dl / n, 2) if srv_dl else None
            ul = round(srv_ul / n, 2) if srv_ul else None
            return dl, ul, mode
        elif mode == -3:
            dl = rate.get("max_download_speed")
            ul = rate.get("max_upload_speed")
            return dl, ul, mode
        return None, None, -1


class DeviceTracker:
    """Отслеживает количество подключённых устройств per username."""

    def __init__(self):
        self._devices: dict[str, set[str]] = {}  # username -> set of client_ips

    def add(self, username: str, client_ip: str) -> None:
        self._devices.setdefault(username, set()).add(client_ip)

    def remove(self, username: str, client_ip: str) -> None:
        if username in self._devices:
            self._devices[username].discard(client_ip)
            if not self._devices[username]:
                del self._devices[username]

    def count(self, username: str) -> int:
        return len(self._devices.get(username, set()))

    def total(self) -> int:
        """Общее количество подключённых устройств во всей сети."""
        return sum(len(ips) for ips in self._devices.values())


class VPNServer(asyncssh.SSHServer):

    def __init__(self, config: dict, pool: IPPool, rate_limiter: RateLimiter):
        self._config = config
        self._pool = pool
        self._rate_limiter = rate_limiter
        self._speed_manager: SpeedManager = config["speed_manager"]
        self._client_ips: set[str] = set()  # все IP этого SSH-соединения
        self._username: str | None = None

    def add_client_ip(self, username: str, ip: str) -> None:
        """Регистрирует выданный IP для этого соединения."""
        self._client_ips.add(ip)
        self._config["device_tracker"].add(username, ip)

    def connection_made(self, conn):
        self._conn = conn
        peer = conn.get_extra_info("peername")
        ip = peer[0]
        if self._rate_limiter.is_banned(ip):
            log.warning("RateLimit: отклонено подключение от %s (бан)", ip)
            conn.abort()
            return
        if self._rate_limiter.record_connection(ip):
            conn.abort()
            return
        log.info("Подключение от %s:%s", *peer)

    def connection_lost(self, exc):
        if self._username:
            tracker = self._config["device_tracker"]
            for ip in self._client_ips:
                subprocess.run(["ip", "route", "del", f"{ip}/32", "dev", TUN_DEV],
                               check=False, capture_output=True)
                self._pool.release(ip)
                tracker.remove(self._username, ip)
                log.info("Клиент отключён, IP %s освобождён", ip)
        self._client_ips.clear()

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        ok = self._config["user_store"].validate(username, password)
        log.info("Аутентификация %s: %s", username, "OK" if ok else "FAIL")
        peer = self._conn.get_extra_info("peername") if hasattr(self, "_conn") else None
        if peer:
            ip = peer[0]
            if ok:
                self._rate_limiter.record_auth_ok(ip)
                self._username = username
            else:
                if self._rate_limiter.record_auth_fail(ip):
                    self._conn.abort()
        return ok

    def public_key_auth_supported(self) -> bool:
        return False

    def session_requested(self):
        return _SessionDispatcher(self._pool, self)


class _SessionDispatcher(asyncssh.SSHServerSession):
    """Диспетчер: выбирает VPNSession или TunnelSession по команде."""

    def __init__(self, pool: IPPool, server: 'VPNServer'):
        self._pool = pool
        self._server = server
        self._delegate = None
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan
        log.debug("_SessionDispatcher.connection_made")

    def exec_requested(self, command: str) -> bool:
        cmd = command.strip()
        log.info("exec_requested: %r", cmd)
        if cmd == "get_ip":
            self._delegate = VPNSession(self._pool, self._server)
        elif cmd.startswith("tunnel "):
            username = self._chan.get_extra_info("username") if self._chan else ""
            self._delegate = TunnelSession(
                self._pool,
                self._server._config["user_store"],
                username,
                self._server._config["tun_router"],
                self._server._config.get("speed_manager"),
                self._server._config.get("statistics"),
            )
        else:
            log.warning("Неизвестная команда: %r", cmd)
            return False
        self._delegate.connection_made(self._chan)
        result = self._delegate.exec_requested(command)
        log.debug("exec_requested delegate result: %s", result)
        return result

    def shell_requested(self) -> bool:
        return False

    def session_started(self) -> None:
        log.debug("_SessionDispatcher.session_started, delegate=%s", self._delegate)
        if self._delegate:
            self._delegate.session_started()

    def data_received(self, data, datatype):
        if self._delegate:
            self._delegate.data_received(data, datatype)

    def connection_lost(self, exc) -> None:
        log.debug("_SessionDispatcher.connection_lost exc=%s", exc)
        if self._delegate:
            self._delegate.connection_lost(exc)


# ─── Системная настройка ──────────────────────────────────────────────────────

def find_external_interface() -> str:
    try:
        r = subprocess.run(["ip", "route", "show", "0.0.0.0/0"], capture_output=True, text=True, check=True)
        for line in r.stdout.splitlines():
            if "default via" in line:
                parts = line.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
    except Exception as e:
        log.warning("Не удалось найти внешний интерфейс: %s", e)
    return "ens6"


def setup_server_tun(external_if: str) -> None:
    r = subprocess.run(["ip", "link", "show", TUN_DEV], capture_output=True, check=False)
    if r.returncode == 0:
        log.info("TUN %s уже существует", TUN_DEV)
    else:
        subprocess.run(["ip", "tuntap", "add", "dev", TUN_DEV, "mode", "tun"], check=True, capture_output=True)
        subprocess.run(["ip", "addr", "add", f"{SERVER_IP}/24", "dev", TUN_DEV], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", "dev", TUN_DEV, "mtu", "1280", "up"], check=True, capture_output=True)
        log.info("TUN %s создан: %s/24", TUN_DEV, SERVER_IP)

    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False, capture_output=True)

    r = subprocess.run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", SUBNET, "-o", external_if, "-j", "MASQUERADE"],
        capture_output=True, check=False
    )
    if r.returncode != 0:
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", SUBNET, "-o", external_if, "-j", "MASQUERADE"],
            check=False, capture_output=True
        )
        log.info("NAT: %s -> %s", SUBNET, external_if)

    subprocess.run(["iptables", "-I", "FORWARD", "-i", TUN_DEV, "-j", "ACCEPT"], check=False, capture_output=True)
    subprocess.run(
        ["iptables", "-I", "FORWARD", "-o", TUN_DEV, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        check=False, capture_output=True
    )


# ─── Вспомогательные функции ──────────────────────────────────────────────────

USERS_FILE = "users.json"

try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False
    log.warning("bcrypt не установлен: pip install bcrypt")


def _parse_users(data: list) -> dict:
    """Парсит список пользователей из JSON.
    Формат: {"id": "uuid", "ssh_creds": "login:$2b$hash", "ip_pool": "198.19.0.2",
             "bandwidth_reserved": 10240, "bandwidth_download_spent": 0, "bandwidth_upload_spent": 0}
    """
    users = {}
    for entry in data:
        creds = entry.get("ssh_creds", "")
        if ":" not in creds:
            continue
        username, bcrypt_hash = creds.split(":", 1)
        username = username.strip()
        if username:
            bw = entry.get("bandwidth_reserved", -1)
            users[username] = {
                "id":                     entry.get("id", ""),
                "bcrypt":                 bcrypt_hash,
                "ip_pool":                entry.get("ip_pool", ""),
                "bandwidth_reserved":     int(bw),  # -1 = безлимит
                "bandwidth_download_spent": float(entry.get("bandwidth_download_spent", 0)),
                "bandwidth_upload_spent":   float(entry.get("bandwidth_upload_spent", 0)),
                "speed_rate":             entry.get("speed_rate"),  # None = использовать global
                "max_connected_devices":  int(entry.get("max_connected_devices", -1)),
            }
    return users


class UserStore:
    """Хранилище пользователей с автообновлением каждые 30 секунд.
    Формат users.json: [{"ssh_creds": "login:$2b$12$hash..."}]
    """

    def __init__(self):
        self._users: dict[str, dict] = {}  # username -> {bcrypt}
        self._lock = asyncio.Lock()
        self._reload_callbacks: list = []  # список функций вызываемых после reload
        self.load()

    def load(self) -> None:
        """Синхронная загрузка — при старте."""
        p = Path(USERS_FILE)
        if not p.exists():
            log.warning("Файл пользователей не найден: %s", USERS_FILE)
            return
        try:
            data = json.loads(p.read_text())
            self._users = _parse_users(data)
            log.info("Загружено %d пользователей из %s", len(self._users), USERS_FILE)
        except Exception as e:
            log.error("Ошибка загрузки пользователей: %s", e)

    def register_reload_callback(self, cb) -> None:
        """Регистрирует callback который вызывается после каждого reload."""
        self._reload_callbacks.append(cb)

    def unregister_reload_callback(self, cb) -> None:
        """Удаляет callback."""
        try:
            self._reload_callbacks.remove(cb)
        except ValueError:
            pass

    async def reload_loop(self) -> None:
        """Перезагружает пользователей каждые 30 секунд."""
        while True:
            await asyncio.sleep(30)
            try:
                p = Path(USERS_FILE)
                if not p.exists():
                    continue
                data = json.loads(p.read_text())
                users = _parse_users(data)
                async with self._lock:
                    self._users = users
                log.debug("Пользователи перезагружены: %d записей", len(users))
                # Уведомляем активные сессии об обновлении
                for cb in list(self._reload_callbacks):
                    try:
                        cb()
                    except Exception as e:
                        log.debug("Ошибка reload callback: %s", e)
            except Exception as e:
                log.error("Ошибка перезагрузки пользователей: %s", e)

    def validate(self, username: str, password: str) -> bool:
        users = self._users
        if username not in users:
            return False
        user = users[username]
        # Лимит трафика проверяется в get_ip, не здесь
        bcrypt_hash = user["bcrypt"]
        if not bcrypt_hash:
            return False
        if not _BCRYPT_AVAILABLE:
            log.error("bcrypt не установлен, аутентификация невозможна")
            return False
        try:
            return _bcrypt.checkpw(password.encode(), bcrypt_hash.encode())
        except Exception as e:
            log.error("Ошибка bcrypt: %s", e)
            return False

    def add_bandwidth(self, username: str, download_bytes: int, upload_bytes: int) -> bool:
        """Добавляет трафик пользователю. Возвращает True если лимит превышен."""
        users = self._users
        if username not in users:
            return False
        user = users[username]
        dl_mb = download_bytes / (1024 * 1024)
        ul_mb = upload_bytes / (1024 * 1024)
        user["bandwidth_download_spent"] = user.get("bandwidth_download_spent", 0) + dl_mb
        user["bandwidth_upload_spent"] = user.get("bandwidth_upload_spent", 0) + ul_mb
        bw_limit = user.get("bandwidth_reserved", -1)
        if bw_limit == -1:
            return False  # безлимит — не отключаем
        total_spent = user["bandwidth_download_spent"] + user["bandwidth_upload_spent"]
        return total_spent >= bw_limit

    def save_bandwidth(self, username: str) -> None:
        """Сохраняет bandwidth_download_spent и bandwidth_upload_spent в users.json."""
        try:
            p = Path(USERS_FILE)
            data = json.loads(p.read_text())
            user = self._users.get(username, {})
            dl_spent = user.get("bandwidth_download_spent", 0)
            ul_spent = user.get("bandwidth_upload_spent", 0)
            for entry in data:
                creds = entry.get("ssh_creds", "")
                if ":" in creds and creds.split(":", 1)[0].strip() == username:
                    entry["bandwidth_download_spent"] = round(dl_spent, 3)
                    entry["bandwidth_upload_spent"] = round(ul_spent, 3)
                    break
            p.write_text(json.dumps(data, indent=2))
        except Exception as e:
            log.error("Ошибка сохранения bandwidth: %s", e)




# ─── Main ─────────────────────────────────────────────────────────────────────

def load_or_generate_host_key(path: str, key_type: str = "ssh-ed25519", key_size: int = None) -> asyncssh.SSHKey:
    p = Path(path)
    if p.exists():
        return asyncssh.read_private_key(str(p))
    kwargs = {}
    if key_size:
        kwargs['key_size'] = key_size
    key = asyncssh.generate_private_key(key_type, **kwargs)
    key.write_private_key(str(p))
    os.chmod(p, 0o600)
    log.info("Сгенерирован host key (%s): %s", key_type, path)
    return key


SPEEDTEST_BIN = "/usr/local/bin/speedtest-cli"


async def run_speedtest() -> None:
    """Запускает speedtest-cli и сохраняет результат в settings.json."""
    log.info("Запуск speedtest...")
    try:
        proc = await asyncio.create_subprocess_exec(
            SPEEDTEST_BIN, "--simple",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()
        download = upload = None
        ping = download = upload = None
        for line in output.splitlines():
            if line.startswith("Ping:"):
                ping = float(line.split()[1])
            elif line.startswith("Download:"):
                download = float(line.split()[1])
            elif line.startswith("Upload:"):
                upload = float(line.split()[1])
        if download is not None and upload is not None:
            p = Path(SETTINGS_FILE)
            try:
                data = json.loads(p.read_text()) if p.exists() else {}
            except Exception:
                data = {}
            data["server_speed"] = {
                "ping":       ping,
                "download":   download,
                "upload":     upload,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            p.write_text(json.dumps(data, indent=2))
            log.info("Speedtest: ping=%.2f ms download=%.2f Mbit/s upload=%.2f Mbit/s",
                     ping or 0, download, upload)
        else:
            log.warning("Speedtest: не удалось разобрать вывод: %s", output)
    except asyncio.TimeoutError:
        log.error("Speedtest: таймаут")
    except Exception as e:
        log.error("Speedtest: ошибка: %s", e)


async def speedtest_loop() -> None:
    """Запускает speedtest раз в сутки."""
    while True:
        await asyncio.sleep(86400)
        await run_speedtest()


def should_run_speedtest() -> bool:
    """Проверяет нужно ли запустить speedtest при старте."""
    try:
        p = Path(SETTINGS_FILE)
        if not p.exists():
            return True
        data = json.loads(p.read_text())
        speed = data.get("server_speed", {})
        updated_at = speed.get("updated_at")
        if not updated_at:
            return True
        dt = datetime.fromisoformat(updated_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() > 86400
    except Exception:
        return True


async def settings_reload_loop(config: dict) -> None:
    """Перечитывает settings.json каждые 60 сек, обновляет config in-place (кроме host/port)."""
    RELOAD_KEYS = ("stealth", "max_connected_devices", "speed_rate", "server_speed", "debug")
    while True:
        await asyncio.sleep(60)
        try:
            p = Path(SETTINGS_FILE)
            if not p.exists():
                continue
            data = json.loads(p.read_text())
            changed = []
            for key in RELOAD_KEYS:
                if key not in data:
                    continue
                new_val = data[key]
                old_val = config.get(key)
                if new_val != old_val:
                    config[key] = new_val
                    changed.append(key)
            if changed:
                # debug toggle
                if "debug" in changed:
                    if config.get("debug"):
                        logging.getLogger().setLevel(logging.DEBUG)
                        log.info("Debug режим включён (hot-reload)")
                    else:
                        logging.getLogger().setLevel(logging.INFO)
                        log.info("Debug режим выключен (hot-reload)")
                log.info("Settings hot-reload: обновлены %s", ", ".join(changed))
        except json.JSONDecodeError as e:
            log.error("Settings reload: ошибка JSON: %s", e)
        except Exception as e:
            log.error("Settings reload: ошибка: %s", e)


async def run_server(config: dict) -> None:
    ext_if = find_external_interface()
    log.info("Внешний интерфейс: %s", ext_if)
    setup_server_tun(ext_if)

    user_store = UserStore()
    pool = IPPool(user_store)
    rate_limiter = RateLimiter()
    speed_manager = SpeedManager(config, user_store)
    device_tracker = DeviceTracker()
    tun_router = TunRouter()
    tun_router.start()

    config["user_store"] = user_store
    config["speed_manager"] = speed_manager
    config["device_tracker"] = device_tracker
    config["tun_router"] = tun_router
    statistics = Statistics()
    config["statistics"] = statistics
    asyncio.create_task(user_store.reload_loop())
    asyncio.create_task(settings_reload_loop(config))
    asyncio.create_task(statistics.save_loop())

    # Speedtest при старте если данные устарели
    if should_run_speedtest():
        asyncio.create_task(run_speedtest())
    asyncio.create_task(speedtest_loop())

    def server_factory():
        return VPNServer(config, pool, rate_limiter)

    Path("keys").mkdir(exist_ok=True)
    host_key_ed25519 = load_or_generate_host_key("keys/host_key",         "ssh-ed25519")
    host_key_rsa     = load_or_generate_host_key("keys/host_key_rsa",     "ssh-rsa",              key_size=3072)
    host_key_ecdsa   = load_or_generate_host_key("keys/host_key_ecdsa",   "ecdsa-sha2-nistp256")

    server = await asyncssh.create_server(
        server_factory,
        host=config.get("host", "0.0.0.0"),
        port=config.get("port", 2222),
        server_host_keys=[host_key_rsa, host_key_ecdsa, host_key_ed25519],
        encoding=None,
        reuse_address=True,
        server_version=OPENSSH_SERVER_VERSION,
        kex_algs=OPENSSH_KEX_ALGS,
        encryption_algs=OPENSSH_ENCRYPTION_ALGS,
        mac_algs=OPENSSH_MAC_ALGS,
        compression_algs=OPENSSH_COMPRESSION_ALGS,
    )
    log.info("SSH VPN сервер запущен на %s:%d", config.get("host", "0.0.0.0"), config.get("port", 2222))

    async with server:
        await asyncio.Future()


SETTINGS_FILE = "settings.json"

DEFAULT_SETTINGS = {
    "host":         "0.0.0.0",
    "port":         2222,
    "stealth":      0,
    "debug":        False,
    "max_connected_devices": -1,   # -1 = безлимит, N = максимум устройств на аккаунт
    "speed_rate":   {"speed_mode": -1, "max_download_speed": None, "max_upload_speed": None},
    "server_speed": {},
}

# Таблица параметров stealth по уровням
# (mtu, chunk_min, chunk_max, delay_min, delay_max)
STEALTH_LEVELS = {
    0: (1280, None,  None,  0,     0    ),
    1: (1280, 512,   1024,  0,     0.001),
    2: (1024, 256,   512,   0.001, 0.003),
    3: (900,  128,   256,   0.002, 0.005),
    4: (800,  100,   200,   0.003, 0.008),
    5: (700,  80,    150,   0.005, 0.010),
    6: (600,  64,    100,   0.005, 0.015),
    7: (576,  52,    80,    0.008, 0.015),
    8: (576,  40,    60,    0.010, 0.018),
    9: (576,  36,    52,    0.010, 0.020),
}


def load_settings() -> dict:
    """Загружает settings.json, создаёт с дефолтами если не существует."""
    p = Path(SETTINGS_FILE)
    if not p.exists():
        p.write_text(json.dumps(DEFAULT_SETTINGS, indent=2))
        log.info("Создан %s с настройками по умолчанию", SETTINGS_FILE)
        return dict(DEFAULT_SETTINGS)

    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        log.error("Ошибка чтения %s: %s", SETTINGS_FILE, e)
        sys.exit(1)

    # Заполняем отсутствующие ключи дефолтами
    settings = dict(DEFAULT_SETTINGS)
    settings.update(data)

    log.info("Настройки загружены из %s", SETTINGS_FILE)
    log.debug("Настройки: %s", {k: v for k, v in settings.items()})
    return settings


def main():
    settings = load_settings()

    if settings["debug"]:
        logging.getLogger().setLevel(logging.DEBUG)

    config = {
        "host":         settings["host"],
        "port":         settings["port"],
        "stealth":      settings["stealth"],
        "max_connected_devices": settings.get("max_connected_devices", -1),
        "speed_rate":   settings.get("speed_rate", {}),
        "server_speed": settings.get("server_speed", {}),
    }
    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        log.info("Сервер остановлен")


if __name__ == "__main__":
    main()