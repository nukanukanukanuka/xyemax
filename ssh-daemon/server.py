#!/usr/bin/env python3.12
"""
SSH tunnel server — кастомный SSH сервер для проксирования трафика.

Совместим со стандартным ssh клиентом:
    ssh -D 127.0.0.1:1080 -N -p 2222 user@server

Поверх которого работает tun2socks:
    tun2socks -device tun10 -proxy socks5://127.0.0.1:1080
"""

import asyncio
import asyncssh
import logging
import sys
import os
import argparse
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


class TunnelServer(asyncssh.SSHServer):
    """
    SSH сервер, принимающий подключения и разрешающий TCP форвардинг (direct-tcpip).

    Именно direct-tcpip каналы открывает ssh клиент при использовании флага -D.
    Для каждого SOCKS5 запроса клиент открывает direct-tcpip канал, а asyncssh
    автоматически проксирует соединение когда connection_requested возвращает True.
    """

    def __init__(self, config: dict):
        self._config = config
        self._conn = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        log.info("Подключение от %s:%s", *peer)

    def connection_lost(self, exc: Exception | None) -> None:
        if self._conn:
            peer = self._conn.get_extra_info("peername")
            if exc:
                log.warning("Соединение с %s:%s разорвано: %s", *peer, exc)
            else:
                log.info("Соединение с %s:%s закрыто", *peer)

    # ── Аутентификация ──────────────────────────────────────────────────────

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        users = self._config.get("users", {})
        expected = users.get(username)
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
        return False

    # ── Форвардинг ─────────────────────────────────────────────────────────

    def connection_requested(
        self,
        dest_host: str,
        dest_port: int,
        orig_host: str,
        orig_port: int,
    ) -> bool:
        """
        Вызывается когда ssh клиент открывает direct-tcpip канал.
        Возврат True — asyncssh сам установит TCP соединение и будет
        проксировать данные в обе стороны.
        """
        log.info("Форвард: %s:%d -> %s:%d", orig_host, orig_port, dest_host, dest_port)
        return True

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        """Remote port forwarding — отключено."""
        return False

    def session_requested(self) -> bool:
        """Shell/exec сессии — отключены, это только tunnel сервер."""
        return False


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
    host_key = load_or_generate_host_key(config["host_key"])

    listen_host = config.get("host", "0.0.0.0")
    listen_port = config.get("port", 2222)

    def server_factory():
        return TunnelServer(config)

    server = await asyncssh.create_server(
        server_factory,
        host=listen_host,
        port=listen_port,
        server_host_keys=[host_key],
    )

    log.info("SSH tunnel сервер запущен на %s:%d", listen_host, listen_port)
    log.info("Подключение: ssh -D 127.0.0.1:1080 -N -p %d user@<ip>", listen_port)

    async with server:
        await asyncio.Future()  # бесконечный цикл


def load_users_file(path: str) -> dict[str, str]:
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
            log.error("%s:%d — неверный формат, ожидается user:password", path, lineno)
            sys.exit(1)
        u, pw = line.split(":", 1)
        u = u.strip()
        if not u:
            log.error("%s:%d — пустое имя пользователя", path, lineno)
            sys.exit(1)
        users[u] = pw
    log.info("Загружено %d пользователей из %s", len(users), path)
    return users


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSH tunnel server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Формат файла пользователей (--users-file):
  # комментарий
  alice:secret123
  bob:pass456
  joe:qwerty

Примеры:
  %(prog)s --users-file /etc/ssh-tunnel/users.txt
  %(prog)s --users-file users.txt --port 2222

  # Подключение клиентом:
  ssh -D 127.0.0.1:1080 -N -p 2222 alice@server-ip

  # tun2socks поверх:
  tun2socks -device tun10 -proxy socks5://127.0.0.1:1080
""",
    )
    parser.add_argument("--host", default="0.0.0.0",
                        help="Адрес для прослушивания (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=2222,
                        help="Порт (default: 2222)")
    parser.add_argument("--host-key", default="host_key",
                        help="Путь к host key файлу (создаётся если нет)")
    parser.add_argument("--users-file", metavar="FILE", default="users.txt",
                        help="Файл с пользователями (default: users.txt)")
    parser.add_argument("--debug", action="store_true",
                        help="Включить debug логирование")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("asyncssh").setLevel(logging.DEBUG)

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
