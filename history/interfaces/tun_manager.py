#!/usr/bin/env python3
"""
tun_manager.py — управление tun2socks интерфейсами через systemd.

Читает interfaces.conf из папки скрипта, генерирует systemd сервисы
для каждого интерфейса и перезапускает их.

Формат interfaces.conf:
    # Комментарий
    tun10 = socks5://user:pass@host:port
    tun11 = socks5://user2:pass2@host2:port2
"""

import os
import sys
import subprocess
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════════════
# КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR   = Path(__file__).parent
CONF_FILE    = SCRIPT_DIR / "interfaces.conf"
SYSTEMD_DIR  = Path("/etc/systemd/system")
TUN2SOCKS    = "/usr/local/bin/tun2socks"

# ══════════════════════════════════════════════════════════════════════════════
# ПАРСИНГ КОНФИГА
# ══════════════════════════════════════════════════════════════════════════════

def load_interfaces(conf_path: Path) -> dict[str, str]:
    """Читает interfaces.conf и возвращает {iface: proxy_url}."""
    if not conf_path.exists():
        print(f"[!] Конфиг не найден: {conf_path}")
        print(f"    Создай файл с содержимым:")
        print(f"    tun10 = socks5://user:pass@host:port")
        sys.exit(1)

    interfaces = {}
    for line in conf_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            print(f"[!] Неверная строка в конфиге: {line!r}")
            continue
        iface, _, proxy = line.partition("=")
        iface = iface.strip()
        proxy = proxy.strip()
        if not iface or not proxy:
            continue
        interfaces[iface] = proxy

    return interfaces

# ══════════════════════════════════════════════════════════════════════════════
# ГЕНЕРАЦИЯ SYSTEMD СЕРВИСОВ
# ══════════════════════════════════════════════════════════════════════════════

def tun2socks_subnet(iface: str) -> tuple[str, str]:
    """Генерирует уникальный IP и подсеть для интерфейса на основе его номера."""
    # tun10 → 10, tun11 → 11 и т.д.
    num = int("".join(filter(str.isdigit, iface)) or "0")
    # Используем 198.18.x.1/15 диапазон
    # tun10 → 198.18.0.1, tun11 → 198.20.0.1 и т.д.
    base = 18 + (num - 10) * 2
    ip = f"198.{base}.0.1"
    mask = "15"
    return ip, mask


def make_service(iface: str, proxy: str) -> str:
    """Генерирует содержимое systemd unit файла для одного интерфейса."""
    ip, mask = tun2socks_subnet(iface)
    service_name = f"tun2socks-{iface}"

    return f"""[Unit]
Description=tun2socks tunnel on {iface} via {proxy}
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/sh -c '\\
    ip link delete {iface} 2>/dev/null || true; \\
    ip tuntap add mode tun dev {iface} 2>/dev/null || true; \\
    ip addr add {ip}/{mask} dev {iface} 2>/dev/null || true; \\
    ip link set dev {iface} up'
ExecStart={TUN2SOCKS} -device {iface} -proxy {proxy}
ExecStartPost=/bin/sh -c '\\
    ip rule add from 10.0.1.0/30 table 100 2>/dev/null || true; \\
    ip route add default via {ip} dev {iface} table 100 2>/dev/null || true'
ExecStopPost=/bin/sh -c '\\
    ip link set dev {iface} down 2>/dev/null || true'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


# ══════════════════════════════════════════════════════════════════════════════
# УПРАВЛЕНИЕ СЕРВИСАМИ
# ══════════════════════════════════════════════════════════════════════════════

def run(cmd: list[str], check=True) -> int:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[!] Ошибка: {' '.join(cmd)}")
        print(f"    {result.stderr.strip()}")
    return result.returncode


def get_existing_services() -> list[str]:
    """Находит все существующие tun2socks-*.service файлы."""
    return [
        f.stem for f in SYSTEMD_DIR.glob("tun2socks-tun*.service")
    ]


def apply(interfaces: dict[str, str]):
    """Создаёт/обновляет сервисы и удаляет старые."""
    existing = set(get_existing_services())
    wanted   = {f"tun2socks-{iface}" for iface in interfaces}

    # Удалить сервисы которых больше нет в конфиге
    for service in existing - wanted:
        print(f"[-] Удаляю {service}")
        run(["systemctl", "stop",    service], check=False)
        run(["systemctl", "disable", service], check=False)
        service_file = SYSTEMD_DIR / f"{service}.service"
        service_file.unlink(missing_ok=True)

    # Создать/обновить сервисы из конфига
    for iface, proxy in interfaces.items():
        service_name = f"tun2socks-{iface}"
        service_file = SYSTEMD_DIR / f"{service_name}.service"
        content      = make_service(iface, proxy)

        # Проверить изменился ли конфиг
        old_content = service_file.read_text() if service_file.exists() else ""
        changed     = old_content != content

        service_file.write_text(content)
        print(f"[+] Записал {service_file}")

        run(["systemctl", "enable", service_name])

        if changed or service_name not in existing:
            print(f"[~] Перезапускаю {service_name}")
            run(["systemctl", "restart", service_name])
        else:
            print(f"[=] {service_name} не изменился, пропускаю")

    run(["systemctl", "daemon-reload"])

    # Статус
    print()
    for iface in interfaces:
        service_name = f"tun2socks-{iface}"
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True, text=True
        )
        status = result.stdout.strip()
        icon   = "✓" if status == "active" else "✗"
        print(f"  {icon} {service_name}: {status}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if os.geteuid() != 0:
        print("Ошибка: нужен root (sudo python3 tun_manager.py)")
        sys.exit(1)

    interfaces = load_interfaces(CONF_FILE)

    if not interfaces:
        print("[!] Нет интерфейсов в конфиге")
        sys.exit(1)

    print(f"Найдено интерфейсов: {len(interfaces)}")
    for iface, proxy in interfaces.items():
        print(f"  {iface} → {proxy}")
    print()

    apply(interfaces)


if __name__ == "__main__":
    main()