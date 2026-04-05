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
log_file = f"client_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(file_formatter)
log.addHandler(file_handler)

log.info("=== Запуск клиента ===")
log.info("Лог файл: %s", log_file)

TUN_ADDR = "198.18.0.1"


@dataclass
class Route:
    dst: str
    via: str
    dev: str


def get_default_routes() -> list[Route]:
    log.debug("Получаю дефолтные маршруты")
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
            log.debug("Найден маршрут: default via %s dev %s", via.group(1), dev.group(1))
    log.info("Найдено %d дефолтных маршрутов", len(routes))
    return routes


def host_route_exists(host: str) -> bool:
    log.debug("Проверяю маршрут к хосту %s", host)
    out = subprocess.run(
        ["ip", "route", "show", f"{host}/32"],
        capture_output=True, text=True
    ).stdout.strip()
    exists = bool(out)
    log.debug("Маршрут к %s %s", host, "существует" if exists else "не существует")
    return exists


class RouteManager:
    def __init__(self):
        self.added = []
        log.debug("RouteManager инициализирован")

    def add(self, *args):
        cmd = ["ip", "route", "add"] + list(args)
        log.debug("Добавляю маршрут: %s", " ".join(cmd))
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            self.added.append(list(args))
            log.info("Маршрут добавлен: %s", " ".join(args))
        except subprocess.CalledProcessError as e:
            log.warning("Маршрут не добавлен %s: %s", " ".join(args), e)

    def rollback(self):
        log.debug("Откат маршрутов, всего: %d", len(self.added))
        for args in reversed(self.added):
            cmd = ["ip", "route", "del"] + list(args)
            log.debug("Удаляю маршрут: %s", " ".join(cmd))
            subprocess.run(cmd, check=False, capture_output=True)
        self.added.clear()
        log.info("Маршруты откачены")


def setup_full_tunnel(server_host: str, orig_routes: list[Route],
                     rm: RouteManager, tun_dev: str) -> None:
    """Переключает весь трафик в туннель."""
    log.info("Настройка full tunnel режима")
    log.debug("Исходные дефолтные маршруты: %s", orig_routes)

    for r in orig_routes:
        if not host_route_exists(server_host):
            log.info("Добавляю маршрут к серверу %s via %s dev %s", server_host, r.via, r.dev)
            rm.add(f"{server_host}/32", "via", r.via, "dev", r.dev)

    log.info("Переключаю трафик в туннель (%s)", tun_dev)
    rm.add("0.0.0.0/1", "dev", tun_dev)
    rm.add("128.0.0.0/1", "dev", tun_dev)

    # Проверяем добавленные маршруты
    result = subprocess.run(
        ["ip", "route", "show"],
        capture_output=True, text=True
    )
    log.debug("Таблица маршрутизации после настройки:\n%s", result.stdout)


async def run_client(cfg: argparse.Namespace) -> None:
    log.debug("Запуск клиента с конфигом: host=%s, port=%d, user=%s, tun_dev=%s, mode=%s",
              cfg.host, cfg.port, cfg.user, cfg.tun_dev, cfg.mode)

    unit = int(cfg.tun_dev.replace("tun", ""))
    log.debug("Вычислен unit: %d из устройства: %s", unit, cfg.tun_dev)

    log.info("Подключаюсь к %s:%d как '%s'", cfg.host, cfg.port, cfg.user)

    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                cfg.host, port=cfg.port, username=cfg.user, password=cfg.password,
                known_hosts=None, preferred_auth="password",
            ),
            timeout=10,
        )
        log.info("SSH соединение установлено успешно")
    except (asyncio.TimeoutError, OSError, asyncssh.Error) as e:
        log.error("Ошибка подключения: %s", e)
        log.exception("Детали ошибки:")
        sys.exit(1)
    except asyncssh.PermissionDenied:
        log.error("Неверный логин или пароль")
        sys.exit(1)

    log.info("SSH соединение установлено")
    log.debug("Соединение ID: %s", conn.get_extra_info("connection_id"))

    # TUN туннель поверх SSH (asyncssh сам создаёт TUN устройство)
    log.info("Создаю TUN туннель через SSH (local_unit=%d, remote_unit=%d)", unit, unit)
    try:
        ssh_tun = await conn.forward_tun(
            local_unit=unit,
            remote_unit=unit,
        )
        log.info("TUN туннель создан: %s (unit=%d)", cfg.tun_dev, unit)
    except Exception as e:
        log.error("Не удалось создать TUN туннель через SSH: %s", e)
        log.exception("Детали ошибки:")
        conn.close()
        sys.exit(1)

    # Настраиваем IP на созданном устройстве
    log.info("Настраиваю IP адрес на интерфейсе %s", cfg.tun_dev)
    try:
        subprocess.run(
            ["ip", "addr", "add", f"{TUN_ADDR}/15", "dev", cfg.tun_dev],
            check=True, capture_output=True
        )
        log.debug("IP адрес добавлен: %s/15 на %s", TUN_ADDR, cfg.tun_dev)

        subprocess.run(
            ["ip", "link", "set", "dev", cfg.tun_dev, "up"],
            check=True, capture_output=True
        )
        log.debug("Интерфейс %s поднят", cfg.tun_dev)

        # Проверяем состояние интерфейса
        result = subprocess.run(
            ["ip", "addr", "show", cfg.tun_dev],
            capture_output=True, text=True
        )
        log.info("Состояние интерфейса %s:\n%s", cfg.tun_dev, result.stdout)
    except subprocess.CalledProcessError as e:
        log.error("Ошибка настройки IP/поднимания интерфейса: %s", e)
        log.exception("Детали ошибки:")
        ssh_tun.close()
        conn.close()
        sys.exit(1)

    log.info("IP настроен: %s/15 на %s", TUN_ADDR, cfg.tun_dev)

    # Маршруты
    rm = RouteManager()
    if cfg.mode == "full":
        log.info("Режим: full (весь трафик через туннель)")
        orig_routes = get_default_routes()
        if not orig_routes:
            log.error("Не найден дефолтный маршрут с шлюзом")
            ssh_tun.close()
            conn.close()
            sys.exit(1)
        setup_full_tunnel(cfg.host, orig_routes, rm, cfg.tun_dev)
    else:
        log.info("Режим: tun-only (только TUN интерфейс)")

    log.info("Туннель активен. Ctrl+C для остановки.")
    log.info("Интерфейс: %s, IP: %s/15", cfg.tun_dev, TUN_ADDR)

    # Обработка сигналов
    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    def _on_signal():
        log.debug("Получен сигнал остановки")
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    log.debug("Ожидание сигналов остановки...")

    # Ждём сигнала или обрыва соединения
    try:
        await stop
    except KeyboardInterrupt:
        log.debug("Получен KeyboardInterrupt")
        pass

    # Cleanup
    log.info("Останавливаю туннель...")

    if cfg.mode == "full":
        rm.rollback()

    log.debug("Закрываю SSH туннель...")
    ssh_tun.close()

    log.debug("Закрываю SSH соединение...")
    conn.close()

    # Удаляем интерфейс
    log.debug("Удаляю интерфейс %s", cfg.tun_dev)
    subprocess.run(
        ["ip", "link", "delete", cfg.tun_dev],
        check=False, capture_output=True
    )

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
