#!/usr/bin/env python3.12
"""
SSH TUN клиент.

Создаёт TUN интерфейс и проксирует IP пакеты через SSH.
"""

import asyncio
import asyncssh
import argparse
import logging
import os
import signal
import sys
import re
import subprocess
from dataclasses import dataclass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

TUN_ADDR = "198.18.0.1"


@dataclass
class Route:
    dst: str
    via: str
    dev: str


def get_default_routes() -> list[Route]:
    out = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True, check=True
    ).stdout.strip()
    routes = []
    for line in out.splitlines():
        via = re.search(r"via (\S+)", line)
        dev = re.search(r"dev (\S+)", line)
        if via and dev:
            routes.append(Route(dst="default", via=via.group(1), dev=dev.group(1)))
    return routes


def host_route_exists(host: str) -> bool:
    out = subprocess.run(
        ["ip", "route", "show", f"{host}/32"],
        capture_output=True, text=True
    ).stdout.strip()
    return bool(out)


class RouteManager:
    def __init__(self):
        self.added = []

    def add(self, *args):
        cmd = ["ip", "route", "add"] + list(args)
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            self.added.append(list(args))
        except subprocess.CalledProcessError as e:
            log.warning("Маршрут не добавлен %s: %s", " ".join(args), e)

    def rollback(self):
        for args in reversed(self.added):
            subprocess.run(["ip", "route", "del"] + list(args), check=False, capture_output=True)
        self.added.clear()


def setup_full_tunnel(server_host: str, orig_routes: list[Route],
                     rm: RouteManager, tun_dev: str) -> None:
    """Переключает весь трафик в туннель."""
    for r in orig_routes:
        if not host_route_exists(server_host):
            log.info("Маршрут к серверу %s via %s dev %s", server_host, r.via, r.dev)
            rm.add(f"{server_host}/32", "via", r.via, "dev", r.dev)

    log.info("Переключаю трафик в туннель (%s)", tun_dev)
    rm.add("0.0.0.0/1", "dev", tun_dev)
    rm.add("128.0.0.0/1", "dev", tun_dev)


async def run_client(cfg: argparse.Namespace) -> None:
    unit = int(cfg.tun_dev.replace("tun", ""))

    log.info("Подключаюсь к %s:%d как '%s'", cfg.host, cfg.port, cfg.user)

    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                cfg.host, port=cfg.port, username=cfg.user, password=cfg.password,
                known_hosts=None, preferred_auth="password",
            ),
            timeout=10,
        )
    except (asyncio.TimeoutError, OSError, asyncssh.Error) as e:
        log.error("Ошибка подключения: %s", e)
        sys.exit(1)
    except asyncssh.PermissionDenied:
        log.error("Неверный логин или пароль")
        sys.exit(1)

    log.info("SSH соединение установлено")

    # TUN туннель поверх SSH (asyncssh сам создаёт TUN устройство)
    try:
        ssh_tun = await conn.forward_tun(
            local_unit=unit,
            remote_unit=unit,
        )
    except Exception as e:
        log.error("Не удалось создать TUN туннель через SSH: %s", e)
        conn.close()
        sys.exit(1)

    log.info("TUN туннель создан: %s (unit=%d)", cfg.tun_dev, unit)

    # Настраиваем IP на созданном устройстве
    subprocess.run(
        ["ip", "addr", "add", f"{TUN_ADDR}/15", "dev", cfg.tun_dev],
        check=True, capture_output=True
    )
    log.info("IP настроен: %s/15 на %s", TUN_ADDR, cfg.tun_dev)

    # Маршруты
    rm = RouteManager()
    if cfg.mode == "full":
        orig_routes = get_default_routes()
        if not orig_routes:
            log.error("Не найден дефолтный маршрут с шлюзом")
            ssh_tun.close()
            conn.close()
            sys.exit(1)
        setup_full_tunnel(cfg.host, orig_routes, rm, cfg.tun_dev)
        log.info("Режим: весь трафик через туннель")
    else:
        log.info("Режим: только TUN интерфейс")

    log.info("Туннель активен. Ctrl+C для остановки.")

    # Обработка сигналов
    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    def _on_signal():
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    # Ждём сигнала или обрыва соединения
    try:
        await stop
    except KeyboardInterrupt:
        pass

    # Cleanup
    log.info("Останавливаю туннель...")

    if cfg.mode == "full":
        rm.rollback()

    ssh_tun.close()
    conn.close()
    log.info("Остановлено")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSH TUN клиент",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  %(prog)s --host 1.2.3.4 --user alice --password secret
  %(prog)s --host 1.2.3.4 --user alice --password secret --mode full
  %(prog)s --host 1.2.3.4 --user alice --password secret --tun-dev tun97
""",
    )
    parser.add_argument("--host", required=True, help="Адрес сервера")
    parser.add_argument("--port", type=int, default=2222, help="Порт сервера")
    parser.add_argument("--user", required=True, help="Имя пользователя")
    parser.add_argument("--password", required=True, help="Пароль")
    parser.add_argument("--mode", choices=["tun-only", "full"], default="tun-only",
                        help="tun-only | full")
    parser.add_argument("--tun-dev", default="tun10", help="Имя TUN устройства")
    parser.add_argument("--debug", action="store_true", help="Debug логирование")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0 and args.mode == "full":
        log.error("Режим full требует root")
        sys.exit(1)

    try:
        asyncio.run(run_client(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
