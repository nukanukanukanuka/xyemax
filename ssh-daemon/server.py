#!/usr/bin/env python3.12
"""
SSH TUN сервер.

Принимает TUN соединения от клиентов и форвардит пакеты в сеть.
"""

import asyncio
import asyncssh
import logging
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

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


class TunnelServer(asyncssh.SSHServer):
    """SSH сервер с поддержкой TUN туннелирования."""

    def __init__(self, config: dict):
        self._config = config
        self._conn = None
        log.debug("TunnelServer инициализирован с конфигом: %s", config)

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

    def tun_requested(self, unit: int | None) -> bool:
        """Принимаем TUN запросы - asyncssh сам форвардит пакеты."""
        log.info("TUN запрос от клиента (unit=%s)", unit)
        log.debug("tun_requested: возвращаем True для приёма туннеля")
        return True


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

    def server_factory():
        return TunnelServer(config)

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

    async with server:
        log.debug("Сервер ожидает подключений...")
        await asyncio.Future()


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
