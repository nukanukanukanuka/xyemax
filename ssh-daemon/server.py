#!/usr/bin/env python3.12
"""
SSH TUN сервер.

Принимает TUN соединения от клиентов, создаёт TUN интерфейс и форвардит пакеты.
"""

import asyncio
import asyncssh
import logging
import sys
import os
import argparse
import struct
import fcntl
import socket
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

# TUN константы
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

# Настройка логгера с записью в файл
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Консольный вывод
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
console_handler.setFormatter(console_formatter)
log.addHandler(console_handler)

# Файловый вывод (с timestamp в имени)
log_file = f"server_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(file_formatter)
log.addHandler(file_handler)

log.info("=== Запуск сервера ===")
log.info("Лог файл: %s", log_file)


class TUNDevice:
    """TUN интерфейс на стороне сервера."""

    def __init__(self, name: str):
        self.name = name
        self.fd = None
        self.loop = None

    def open(self) -> None:
        """Открывает TUN устройство."""
        try:
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
        except OSError as e:
            raise RuntimeError(f"Не удалось открыть /dev/net/tun: {e}")

        ifr = struct.pack("16sH", f"{self.name}\x00".encode(), IFF_TUN | IFF_NO_PI)
        try:
            fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        except OSError as e:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError(f"Не удалось создать TUN {self.name}: {e}")

        # Настраиваем point-to-point интерфейс
        try:
            # Удаляем старый адрес если есть
            subprocess.run(
                ["ip", "addr", "flush", "dev", self.name],
                check=False, capture_output=True
            )
            # Добавляем point-to-point адрес
            subprocess.run(
                ["ip", "addr", "add", "198.18.0.2/32", "peer", "198.18.0.1/32", "dev", self.name],
                check=True, capture_output=True
            )
            # Поднимаем интерфейс
            subprocess.run(
                ["ip", "link", "set", "dev", self.name, "up"],
                check=True, capture_output=True
            )
            # Добавляем маршрут к клиенту через TUN (для обратных пакетов)
            subprocess.run(
                ["ip", "route", "add", "198.18.0.1/32", "dev", self.name],
                check=True, capture_output=True
            )
            log.info("TUN %s настроен: 198.18.0.2 peer 198.18.0.1, маршрут добавлен", self.name)
        except subprocess.CalledProcessError as e:
            log.warning("Не удалось настроить интерфейс %s: %s", self.name, e)

        self.loop = asyncio.get_event_loop()

    def close(self) -> None:
        """Закрывает и удаляет TUN."""
        # Удаляем маршрут к клиенту
        subprocess.run(
            ["ip", "route", "del", "198.18.0.1/32", "dev", self.name],
            check=False, capture_output=True
        )
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        subprocess.run(["ip", "link", "delete", self.name], check=False, capture_output=True)
        log.debug("TUN %s закрыт", self.name)


class TunnelServer(asyncssh.SSHServer):
    """SSH сервер с поддержкой TUN туннелирования."""

    def __init__(self, config: dict):
        self._config = config
        self._conn = None
        self._tun_sessions = {}  # conn -> (tun, session)
        self._nat_rule_added = False
        log.debug("TunnelServer инициализирован с конфигом: %s", config)
        self._setup_nat()

    def _find_external_interface(self) -> str | None:
        """Находит внешний интерфейс с публичным IP."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "0.0.0.0/0"],
                capture_output=True, text=True, check=True
            )
            # Разбираем строку с дефолтным маршрутом
            for line in result.stdout.strip().splitlines():
                if "default via" in line:
                    # Формат: default via X.X.X.X.X dev YYY
                    parts = line.split()
                    if "dev" in parts:
                        idx = parts.index("dev")
                        if idx + 1 < len(parts):
                            dev = parts[idx + 1]
                            log.info("Найден внешний интерфейс: %s", dev)
                            return dev
        except Exception as e:
            log.warning("Не удалось найти внешний интерфейс: %s", e)
        return None

    def _setup_nat(self) -> None:
        """Настраивает NAT для трафика из туннеля."""
        ext_if = self._find_external_interface()
        if not ext_if:
            log.warning("Не удалось найти внешний интерфейс, NAT не настроен")
            return

        try:
            # Проверяем существует ли правило
            result = subprocess.run(
                ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "198.18.0.0/15", "-o", ext_if, "-j", "MASQUERADE"],
                capture_output=True, text=True, check=False
            )

            if result.returncode == 0:
                log.info("NAT правило уже существует для %s", ext_if)
                self._nat_rule_added = True
            else:
                # Добавляем правило
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "198.18.0.0/15", "-o", ext_if, "-j", "MASQUERADE"],
                    check=True, capture_output=True
                )
                log.info("NAT правило добавлено для %s: 198.18.0.0/15 -> %s", ext_if, ext_if)
                self._nat_rule_added = True
        except Exception as e:
            log.error("Ошибка настройки NAT: %s", e)

    def _cleanup_nat(self) -> None:
        """Удаляет NAT правило."""
        if not self._nat_rule_added:
            return

        ext_if = self._find_external_interface()
        if not ext_if:
            return

        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "198.18.0.0/15", "-o", ext_if, "-j", "MASQUERADE"],
                check=False, capture_output=True
            )
            log.info("NAT правило удалено для %s", ext_if)
        except Exception as e:
            log.warning("Ошибка удаления NAT правила: %s", e)

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        log.info("Подключение от %s:%s", *peer)
        log.debug("Соединение ID: %s", conn.get_extra_info("connection_id"))

    def connection_lost(self, exc: Exception | None) -> None:
        if self._conn:
            peer = self._conn.get_extra_info("peername")
            if peer:
                if exc:
                    log.warning("Соединение с %s:%s разорвано: %s", *peer, exc)
                else:
                    log.info("Соединение с %s:%s закрыто", *peer)
            else:
                if exc:
                    log.warning("Соединение разорвано: %s", exc)
                else:
                    log.info("Соединение закрыто")

            # Закрываем TUN сессию если есть
            if self._conn in self._tun_sessions:
                tun, _ = self._tun_sessions[self._conn]
                tun.close()
                del self._tun_sessions[self._conn]
        log.debug("connection_lost вызван")

    def begin_auth(self, username: str) -> bool:
        log.debug("begin_auth для пользователя: %s", username)
        return True

    def password_auth_supported(self) -> bool:
        log.debug("password_auth_supported: True")
        return True

    def validate_password(self, username: str, password: str) -> bool:
        users = self._config.get("users", {})
        expected = users.get(username)
        log.debug("Попытка аутентификации: user=%s, password_len=%d", username, len(password))
        if expected is None:
            log.warning("Неизвестный пользователь: %s", username)
            return False
        ok = password == expected
        if ok:
            log.info("Пользователь '%s' аутентифицирован", username)
        else:
            log.warning("Неверный пароль для '%s'", username)
        return ok

    def public_key_auth_supported(self) -> bool:
        log.debug("public_key_auth_supported: False")
        return False

    def tun_requested(self, unit: int | None):
        """
        Вызывается когда клиент запрашивает TUN туннель.
        Создаём TUN интерфейс и возвращаем callable для форвардинга.
        """
        tun_name = f"tun{unit}" if unit else "tun0"
        log.info("TUN запрос от клиента: unit=%s, device=%s", unit, tun_name)

        # Создаём TUN устройство
        tun = TUNDevice(tun_name)
        try:
            tun.open()
        except RuntimeError as e:
            log.error("Не удалось создать TUN %s: %s", tun_name, e)
            return False

        # Возвращаем callable для форвардинга пакетов
        # Этот callable будет вызван asyncssh с (reader, writer)
        async def session_handler(reader, writer):
            log.info("Создана SSH сессия для TUN %s", tun_name)

            # Создаём простой session объект с send/recv методами
            class SimpleSession:
                async def send(self, data):
                    writer.write(data)
                    await writer.drain()

                async def recv(self):
                    return await reader.read(65536)

            session = SimpleSession()
            self._tun_sessions[self._conn] = (tun, session)
            await forward_tun(tun, session)
            log.info("SSH сессия для TUN %s закрыта", tun_name)
            if self._conn in self._tun_sessions:
                del self._tun_sessions[self._conn]

        return session_handler


async def forward_tun(tun: TUNDevice, session) -> None:
    """
    Форвардит пакеты между TUN и SSH сессией.
    Пакеты из TUN → SSH, из SSH → TUN.
    """
    log.info("Запускаю форвардинг TUN пакетов: %s", tun.name)

    async def read_tun_to_ssh():
        """Читает из TUN и пишет в SSH."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                # Читаем из TUN через run_in_executor (TUN не сокет!)
                data = await loop.run_in_executor(None, os.read, tun.fd, 65536)
                if data:
                    log.debug("TUN -> SSH: %d байт", len(data))
                    await session.send(data)
            except (OSError, ConnectionResetError, asyncio.CancelledError) as e:
                log.debug("Чтение из TUN завершено: %s", e)
                break

    async def read_ssh_to_tun():
        """Читает из SSH и пишет в TUN."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                data = await session.recv()
                if not data:
                    break
                log.debug("SSH -> TUN: %d байт", len(data))
                # Пишем в TUN через run_in_executor
                await loop.run_in_executor(None, os.write, tun.fd, data)
            except (OSError, ConnectionResetError, asyncio.CancelledError) as e:
                log.debug("Чтение из SSH завершено: %s", e)
                break

    try:
        await asyncio.gather(read_tun_to_ssh(), read_ssh_to_tun())
    except Exception as e:
        log.debug("Форвардинг TUN завершён: %s", e)
    finally:
        tun.close()
        log.info("Форвардинг TUN завершён, интерфейс закрыт")


def load_users_file(path: str) -> dict[str, str]:
    log.debug("Загружаю пользователей из: %s", path)
    users: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        log.error("Файл пользователей не найден: %s", path)
        sys.exit(1)
    for lineno, raw in enumerate(p.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            log.error("%s:%d — неверный формат", path, lineno)
            sys.exit(1)
        u, pw = line.split(":", 1)
        u = u.strip()
        if not u:
            log.error("%s:%d — пустое имя пользователя", path, lineno)
            sys.exit(1)
        users[u] = pw
        log.debug("Загружен пользователь: %s (пароль: *** )", u)
    log.info("Загружено %d пользователей из %s", len(users), path)
    return users


def load_or_generate_host_key(path: str) -> asyncssh.SSHKey:
    p = Path(path)
    if p.exists():
        log.info("Загружаю host key: %s", path)
        return asyncssh.read_private_key(str(p))
    log.info("Генерирую новый host key: %s", path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(p))
    os.chmod(p, 0o600)
    return key


async def run_server(config: dict) -> None:
    log.debug("Запуск сервера с конфигом: %s", config)

    host_key = load_or_generate_host_key(config["host_key"])

    listen_host = config.get("host", "0.0.0.0")
    listen_port = config.get("port", 2222)

    log.info("Запуск SSH сервера на %s:%d", listen_host, listen_port)

    # Создаём и сохраняем экземпляр сервера для последующей очистки
    tunnel_server = TunnelServer(config)

    def server_factory():
        return tunnel_server

    try:
        server = await asyncssh.create_server(
            server_factory,
            host=listen_host,
            port=listen_port,
            server_host_keys=[host_key],
        )
        log.info("SSH TUN сервер запущен на %s:%d", listen_host, listen_port)
        log.info("Подключение: sudo python3.12 client.py --host <ip> --user <user> --password <pass>")
    except Exception as e:
        log.error("Не удалось запустить SSH сервер: %s", e)
        log.exception("Детали ошибки:")
        sys.exit(1)

    try:
        async with server:
            log.debug("Сервер ожидает подключений...")
            await asyncio.Future()
    finally:
        # Очистка NAT при остановке
        tunnel_server._cleanup_nat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSH TUN сервер",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  %(prog)s
  %(prog)s --port 2222
""",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Адрес (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=2222, help="Порт (default: 2222)")
    parser.add_argument("--host-key", default="host_key", help="Host key файл")
    parser.add_argument("--users-file", metavar="FILE", default="users.txt",
                        help="Файл пользователей (default: users.txt)")
    parser.add_argument("--debug", action="store_true", help="Debug логирование")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    users = load_users_file(args.users_file)

    config = {
        "host": args.host,
        "port": args.port,
        "host_key": args.host_key,
        "users": users,
    }

    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        log.info("Сервер остановлен")


if __name__ == "__main__":
    main()
