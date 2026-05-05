#!/usr/bin/env python3.12
"""
SSH TUN клиент — OpenVPN-стиль.

1. get_ip -> получает IP (PUSH_REPLY)
2. Создаёт strans-tun0 через ip tuntap add
3. Открывает SSH канал 'tunnel <client_ip>' для форвардинга пакетов
"""

import asyncio
import asyncssh
import argparse
import fcntl
import json
import logging
import os
import random
import re
import signal
import socket
import struct
import subprocess
import sys
import zlib
from datetime import datetime
from pathlib import Path

# ─── Логирование ──────────────────────────────────────────────────────────────

_DEBUG_PACKETS = os.environ.get("YOVPN_DEBUG", "").lower() in {"1", "true", "yes"}

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG if _DEBUG_PACKETS else logging.INFO)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_ch)

Path("logs").mkdir(exist_ok=True)
_log_file = f"logs/client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
_fh = logging.FileHandler(_log_file, mode="w", encoding="utf-8")
_fh.setLevel(logging.DEBUG if _DEBUG_PACKETS else logging.INFO)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_fh)

log.info("=== Запуск клиента ===")
log.info("Лог файл: %s", _log_file)

IFACE_PREFIX = "strans-tun"
IFACE_MAX    = 100


def pick_iface() -> str | None:
    """Выбирает первый свободный интерфейс из strans-tun0..strans-tun100."""
    for i in range(IFACE_MAX + 1):
        name = f"{IFACE_PREFIX}{i}"
        r = subprocess.run(["ip", "link", "show", name],
                           capture_output=True, check=False)
        if r.returncode != 0:  # интерфейс не существует — свободен
            return name
    return None  # все заняты


IFACE = f"{IFACE_PREFIX}0"  # будет переопределён в run_client
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca
TUN_READ_BATCH_PACKETS = 256
TUN_READ_BATCH_BYTES = 256 * 1024


# ─── TUN устройство ───────────────────────────────────────────────────────────

def create_tun(name: str, client_ip: str, server_ip: str, mtu: int) -> int:
    """Создаёт TUN интерфейс и возвращает fd."""
    subprocess.run(["ip", "tuntap", "add", "dev", name, "mode", "tun"], check=True, capture_output=True)

    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)

    subprocess.run(["ip", "addr", "add", f"{client_ip}/32", "peer", f"{server_ip}/32", "dev", name],
                   check=True, capture_output=True)
    subprocess.run(["ip", "link", "set", "dev", name, "mtu", str(mtu),
                    "txqueuelen", "2000", "up"],
                   check=True, capture_output=True)

    r = subprocess.run(["ip", "addr", "show", name], capture_output=True, text=True)
    log.info("Интерфейс %s:\n%s", name, r.stdout.strip())
    return fd


def destroy_tun(name: str, fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass
    subprocess.run(["ip", "link", "delete", name], check=False, capture_output=True)
    log.info("Интерфейс %s удалён", name)


# ─── Маршруты (policy-based routing) ─────────────────────────────────────────
#
# Вместо удаления дефолтных маршрутов WiFi из main table используем:
#   1. ip rule add to server_ip lookup main  — трафик к серверу идёт по main (WiFi)
#   2. ip rule add to <local>  lookup main   — локальные подсети обходят VPN
#   3. ip rule add lookup VPN_TABLE           — весь остальной трафик -> TUN
#   4. ip route add default dev tun0 table VPN — дефолт через TUN в отдельной таблице
#
# NetworkManager не трогается, WiFi маршруты остаются на месте.

VPN_TABLE  = 100
VPN_PRIO   = 100   # приоритет правила VPN (ниже = важнее)
SRV_PRIO   = 50    # приоритет правила для серверного IP (выше VPN)
LOCAL_PRIO = 80    # приоритет правил для локальных подсетей (между SRV и VPN)
OIF_BYPASS_PRIO = int(os.environ.get("YOVPN_FULL_BYPASS_OIF_PRIO", "60"))
OIF_BYPASS_TABLE_BASE = int(os.environ.get("YOVPN_FULL_BYPASS_TABLE_BASE", "11000"))
OIF_BYPASS_SYNC_INTERVAL = float(os.environ.get("YOVPN_FULL_BYPASS_SYNC_INTERVAL", "2"))
OIF_BYPASS_PREFIXES = tuple(
    p.strip()
    for p in os.environ.get("YOVPN_FULL_BYPASS_OIF_PREFIXES", "strans-m2a").split(",")
    if p.strip()
)
_oif_bypass_tables: dict[str, int] = {}

LOCAL_SUBNETS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
]


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True, **kw)


def _oif_bypass_table(iface: str) -> int:
    m = re.search(r"(\d+)$", iface)
    if m:
        return OIF_BYPASS_TABLE_BASE + int(m.group(1))
    return OIF_BYPASS_TABLE_BASE + 1000 + (zlib.crc32(iface.encode()) % 4000)


def _iter_oif_bypass_ifaces(exclude_iface: str | None = None) -> set[str]:
    if not OIF_BYPASS_PREFIXES:
        return set()
    r = _run(["ip", "-br", "link", "show"])
    found: set[str] = set()
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0].split("@", 1)[0]
        state = parts[1]
        if name == exclude_iface or state == "DOWN":
            continue
        if any(name.startswith(prefix) for prefix in OIF_BYPASS_PREFIXES):
            found.add(name)
    return found


def _add_oif_bypass(iface: str) -> None:
    table = _oif_bypass_table(iface)
    _run(["ip", "route", "replace", "default", "dev", iface, "table", str(table)])
    rules = _run(["ip", "rule", "show"]).stdout or ""
    expected_a = f"oif {iface} lookup {table}"
    expected_b = f"oif {iface} lookup {str(table)}"
    if expected_a not in rules and expected_b not in rules:
        r = _run(["ip", "rule", "add", "oif", iface, "lookup", str(table),
                  "prio", str(OIF_BYPASS_PRIO)])
        if r.returncode != 0 and "File exists" not in (r.stderr or ""):
            log.warning("OIF bypass rule failed for %s table %d: %s",
                        iface, table, (r.stderr or "").strip())
            return
    if _oif_bypass_tables.get(iface) != table:
        log.info("OIF bypass: %s -> table %d (prio %d)", iface, table, OIF_BYPASS_PRIO)
    _oif_bypass_tables[iface] = table


def _del_oif_bypass(iface: str, table: int | None = None) -> None:
    table = table or _oif_bypass_tables.get(iface) or _oif_bypass_table(iface)
    for _ in range(20):
        r = _run(["ip", "rule", "del", "oif", iface, "lookup", str(table),
                  "prio", str(OIF_BYPASS_PRIO)])
        if r.returncode != 0:
            break
    _run(["ip", "route", "flush", "table", str(table)])
    _oif_bypass_tables.pop(iface, None)


def cleanup_oif_bypass_rules() -> None:
    """Remove stale test-interface bypass rules from previous crashed clients."""
    rules = _run(["ip", "rule", "show"]).stdout or ""
    for line in rules.splitlines():
        m = re.search(r"\boif\s+(\S+)\s+lookup\s+(\S+)", line)
        if not m:
            continue
        iface, table_name = m.group(1), m.group(2)
        if not any(iface.startswith(prefix) for prefix in OIF_BYPASS_PREFIXES):
            continue
        if not table_name.isdigit():
            continue
        _del_oif_bypass(iface, int(table_name))


def sync_oif_bypass_rules(exclude_iface: str | None = None) -> None:
    desired = _iter_oif_bypass_ifaces(exclude_iface)
    for iface in sorted(desired):
        _add_oif_bypass(iface)
    for iface, table in list(_oif_bypass_tables.items()):
        if iface not in desired:
            _del_oif_bypass(iface, table)


def _server_rule_target(server_host: str) -> str:
    try:
        socket.inet_aton(server_host)
        return f"{server_host}/32"
    except OSError:
        return f"{socket.gethostbyname(server_host)}/32"


def ensure_server_bypass(server_host: str) -> None:
    """Keep the SSH control TCP outside any already-active full tunnel."""
    try:
        target = _server_rule_target(server_host)
    except OSError as e:
        log.warning("Не удалось resolve server host %s для bypass: %s", server_host, e)
        return
    rules = _run(["ip", "rule", "show"]).stdout
    if f"to {target[:-3]} lookup main" in rules or f"to {target} lookup main" in rules:
        return
    r = _run(["ip", "rule", "add", "to", target, "lookup", "main", "prio", str(SRV_PRIO)])
    if r.returncode == 0:
        log.info("Pre-connect rule: трафик к %s -> main", target)
    elif "File exists" not in (r.stderr or ""):
        log.warning("Pre-connect rule failed for %s: %s", target, (r.stderr or "").strip())


def _set_fd_nonblocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def _is_ipv4_packet(pkt: bytes) -> bool:
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return False
    pkt_len = (pkt[2] << 8) | pkt[3]
    return pkt_len == len(pkt)


def get_default_gateway() -> dict | None:
    """Возвращает первый дефолтный маршрут из main table."""
    r = _run(["ip", "route", "show", "default"])
    for line in r.stdout.splitlines():
        via = re.search(r"via (\S+)", line)
        dev = re.search(r"dev (\S+)", line)
        if via and dev:
            return {"via": via.group(1), "dev": dev.group(1)}
    return None


def _save_resolv_conf() -> str | None:
    """Сохраняет текущий /etc/resolv.conf и возвращает содержимое."""
    try:
        return Path("/etc/resolv.conf").read_text()
    except OSError:
        return None


def _set_dns(servers: list[str]) -> None:
    """Перезаписывает /etc/resolv.conf на указанные DNS серверы."""
    content = "# set by strans-client (VPN)\n"
    for s in servers:
        content += f"nameserver {s}\n"
    try:
        Path("/etc/resolv.conf").write_text(content)
        log.info("DNS установлен: %s", ", ".join(servers))
    except OSError as e:
        log.warning("Не удалось обновить /etc/resolv.conf: %s", e)


def _restore_resolv_conf(original: str | None) -> None:
    """Восстанавливает оригинальный /etc/resolv.conf."""
    if original is None:
        return
    try:
        Path("/etc/resolv.conf").write_text(original)
        log.info("DNS восстановлен")
    except OSError as e:
        log.warning("Не удалось восстановить /etc/resolv.conf: %s", e)


def _disable_ipv6() -> None:
    """Отключает IPv6 на всех интерфейсах через sysctl."""
    _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
    _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])
    log.info("IPv6 отключён")


def _enable_ipv6() -> None:
    """Включает IPv6 обратно."""
    _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
    _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"])
    log.info("IPv6 включён")


# DNS серверы для VPN (публичные, без логов)
VPN_DNS = ["1.1.1.1", "8.8.8.8"]

# Оригинальный resolv.conf — сохраняется при setup, восстанавливается при teardown
_original_resolv: str | None = None


def setup_full_tunnel(server_host: str, tun_iface: str) -> bool:
    """Настраивает policy routing: весь трафик через TUN, серверный — через WiFi."""
    global _original_resolv

    gw = get_default_gateway()
    if not gw:
        log.error("Нет дефолтного маршрута — не могу настроить full tunnel")
        return False

    # 0. Отключаем IPv6 — предотвращает утечку реального IP через IPv6
    _disable_ipv6()

    # Полная очистка стale правил от предыдущих сессий (удаляем все до упора)
    for prio in ([SRV_PRIO, VPN_PRIO]
                 + [LOCAL_PRIO + i for i in range(len(LOCAL_SUBNETS))]):
        for _ in range(20):
            if _run(["ip", "rule", "del", "prio", str(prio)]).returncode != 0:
                break
    cleanup_oif_bypass_rules()

    # 1. Маршрут к серверу через реальный шлюз (приоритет выше чем VPN)
    _run(["ip", "rule", "add", "to", f"{server_host}/32",
          "lookup", "main", "prio", str(SRV_PRIO)])
    log.info("Rule: трафик к %s -> main table (через %s dev %s)", server_host, gw["via"], gw["dev"])

    # 2. Дефолтный маршрут через TUN в отдельной таблице
    _run(["ip", "route", "flush", "table", str(VPN_TABLE)])
    _run(["ip", "route", "add", "default", "dev", tun_iface, "table", str(VPN_TABLE)])
    log.info("Route: default dev %s (table %d)", tun_iface, VPN_TABLE)

    # 3. Локальные подсети — обходят VPN, идут через main table
    for i, subnet in enumerate(LOCAL_SUBNETS):
        _run(["ip", "rule", "add", "to", subnet, "lookup", "main", "prio", str(LOCAL_PRIO + i)])
    log.info("Rule: локальные подсети (%d шт.) -> main table (prio %d+)",
             len(LOCAL_SUBNETS), LOCAL_PRIO)

    # 4. Правило: весь остальной трафик -> таблица VPN
    _run(["ip", "rule", "add", "lookup", str(VPN_TABLE), "prio", str(VPN_PRIO)])
    log.info("Rule: весь трафик -> table %d (prio %d)", VPN_TABLE, VPN_PRIO)
    sync_oif_bypass_rules(exclude_iface=tun_iface)

    # 4. DNS — переключаем на публичные серверы (через туннель)
    _original_resolv = _save_resolv_conf()
    _set_dns(VPN_DNS)

    return True


def full_tunnel_routes_present(server_host: str, tun_iface: str) -> bool:
    """Проверяет, что full-mode policy routing всё ещё установлен."""
    try:
        rules = _run(["ip", "rule", "show"]).stdout or ""
        routes = _run(["ip", "route", "show", "table", str(VPN_TABLE)]).stdout or ""
        target = _server_rule_target(server_host)[:-3]
        has_server_rule = f"to {target} lookup main" in rules
        has_vpn_rule = f"lookup {VPN_TABLE}" in rules
        has_default = f"default dev {tun_iface}" in routes
        return has_server_rule and has_vpn_rule and has_default
    except Exception as e:
        log.debug("full_tunnel_routes_present failed: %s", e)
        return False


def teardown_full_tunnel(server_host: str) -> None:
    """Убирает policy routing правила и VPN таблицу."""
    global _original_resolv

    for prio in ([SRV_PRIO, VPN_PRIO]
                 + [LOCAL_PRIO + i for i in range(len(LOCAL_SUBNETS))]):
        for _ in range(20):
            if _run(["ip", "rule", "del", "prio", str(prio)]).returncode != 0:
                break
    _run(["ip", "route", "flush", "table", str(VPN_TABLE)])
    cleanup_oif_bypass_rules()

    # Восстанавливаем DNS
    _restore_resolv_conf(_original_resolv)
    _original_resolv = None

    # Включаем IPv6 обратно
    _enable_ipv6()

    log.info("Policy routing очищен")


# ─── OpenSSH 8.9p1 алгоритмы — для имитации стандартного клиента ─────────────

OPENSSH_KEX_ALGS = [
    # "sntrup761x25519-sha512@openssh.com",  # не поддерживается asyncssh
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
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
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
OPENSSH_COMPRESSION_ALGS = ["none"]

# ─── Stealth режим ────────────────────────────────────────────────────────────

# Детектор считает подозрительным:
# 1. Пакеты >1024 байт (>15% = +0.25 score)
# 2. Bulk-серии: 5+ крупных пакетов подряд (+0.20)
# 3. IAT CV > 1.5 — нерегулярные интервалы (+0.08)
# 4. Средний пакет >600 байт при долгой сессии (+0.12)
#
# Stealth стратегия:
# - Фрагментируем все пакеты до MAX_STEALTH_CHUNK байт → убираем крупные пакеты
# - Добавляем случайную задержку между чанками → регуляризуем IAT
# - Размер чанка рандомизируем в диапазоне 36-52 байт (SSH keystroke размер) → avg_size низкий

STEALTH_CHUNK_MIN  = 36    # минимум — имитация SSH keystroke
STEALTH_CHUNK_MAX  = 52    # максимум — не превышаем DIRECT_KEYSTROKE_MAX=52
STEALTH_DELAY_MIN  = 0.005 # сек между чанками (5ms)
STEALTH_DELAY_MAX  = 0.020 # сек между чанками (20ms)




async def stealth_write(stdin, data: bytes, cfg) -> None:
    """
    Отправляет IP пакет мелкими случайными чанками с паузами.
    Параметры берутся из cfg (переданы сервером в PUSH_REPLY).
    """
    import random
    chunk_min = getattr(cfg, "chunk_min", None) or STEALTH_CHUNK_MIN
    chunk_max = getattr(cfg, "chunk_max", None) or STEALTH_CHUNK_MAX
    delay_min = getattr(cfg, "delay_min", STEALTH_DELAY_MIN)
    delay_max = getattr(cfg, "delay_max", STEALTH_DELAY_MAX)
    offset = 0
    while offset < len(data):
        chunk_size = random.randint(chunk_min, chunk_max)
        chunk = data[offset:offset + chunk_size]
        offset += chunk_size
        stdin.write(chunk)
        if delay_max > 0:
            await asyncio.sleep(random.uniform(delay_min, delay_max))


# ─── Форвардинг ───────────────────────────────────────────────────────────────

async def forward_packets(fd: int, stdin, stdout, cfg, conn=None) -> None:
    """Форвардит пакеты между локальным TUN fd и SSH каналом."""
    loop = asyncio.get_event_loop()
    stealth = getattr(cfg, "stealth", 0)

    if stealth <= 0:
        await forward_packets_fast(fd, stdin, stdout)
        return

    # Получаем raw TCP socket для диагностики: send_q / unacked / retrans
    tcp_sock = None
    try:
        if conn is not None:
            tcp_sock = conn._transport.get_extra_info('socket')
    except Exception:
        pass

    def _tcp_diag() -> str:
        if tcp_sock is None:
            return "no-sock"
        try:
            import struct as _s
            TCP_INFO = 11
            info = tcp_sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 248)
            n = len(info)
            def u32(off): return _s.unpack_from('I', info, off)[0] if n >= off+4 else 0
            def u64(off): return _s.unpack_from('Q', info, off)[0] if n >= off+8 else 0
            state    = info[0]
            retrans  = info[2]     # tcpi_retransmits (u8)
            unacked  = u32(24)     # tcpi_unacked
            total_retrans = u32(100)   # tcpi_total_retrans
            bytes_acked   = u64(120)   # tcpi_bytes_acked
            notsent       = u32(144)   # tcpi_notsent_bytes — ключевой
            bytes_sent    = u64(200)   # tcpi_bytes_sent
            bytes_retrans = u64(208)   # tcpi_bytes_retrans
            snd_wnd = u32(228)
            rcv_wnd = u32(232)
            import fcntl as _f
            SIOCOUTQ = 0x5411
            buf = _s.pack('I', 0)
            send_q = _s.unpack('I', _f.ioctl(tcp_sock.fileno(), SIOCOUTQ, buf))[0]
            return (f"state={state} retx={retrans}/{total_retrans} unacked={unacked} "
                    f"sent={bytes_sent} retxB={bytes_retrans} ack={bytes_acked} "
                    f"notsent={notsent} sendq={send_q} sndwnd={snd_wnd} rcvwnd={rcv_wnd}")
        except Exception as e:
            return f"err:{e}"

    async def tun_to_ssh():
        """TUN -> SSH: читаем из TUN fd, пишем в stdin SSH канала."""
        pkt_count = 0
        bytes_total = 0
        last_diag_time = 0
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, fd, 65536)
                if not data:
                    log.debug("TUN->SSH: EOF")
                    break
                # Валидируем IPv4: version=4, minimum 20 bytes
                if len(data) < 20 or (data[0] >> 4) != 4:
                    log.debug("TUN->SSH: drop non-IPv4, %d байт first=0x%02x", len(data), data[0] if data else 0)
                    continue
                pkt_len_from_hdr = (data[2] << 8) | data[3]
                if pkt_len_from_hdr != len(data):
                    log.warning("TUN->SSH: длина в заголовке=%d но читано %d байт — DROP", pkt_len_from_hdr, len(data))
                    continue
                if stealth > 0:
                    await stealth_write(stdin, data, cfg)
                else:
                    stdin.write(data)
                    await stdin.drain()
                pkt_count += 1
                bytes_total += len(data)
                src = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
                dst = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
                # Каждые 3 секунды: раскладка TCP сокета + первые 3 пакета
                now = loop.time()
                if pkt_count <= 3 or now - last_diag_time > 3:
                    last_diag_time = now
                    log.info("TUN->SSH: %d байт src=%s dst=%s [#%d total=%d] | TCP: %s",
                             len(data), src, dst, pkt_count, bytes_total, _tcp_diag())
                else:
                    log.debug("TUN->SSH: %d байт src=%s dst=%s [#%d total=%d]", len(data), src, dst, pkt_count, bytes_total)
            except asyncio.CancelledError:
                log.debug("TUN->SSH: отменён (pkt=%d total=%d) | TCP: %s", pkt_count, bytes_total, _tcp_diag())
                break
            except OSError as e:
                log.debug("TUN->SSH OSError: %s", e)
                break
            except Exception as e:
                log.error("TUN->SSH EXCEPTION: %s", e, exc_info=True)
                break

    async def ssh_to_tun():
        """SSH -> TUN: читаем из stdout SSH, сервер шлёт целые IP пакеты."""
        buf = b""
        while True:
            try:
                chunk = await asyncio.wait_for(stdout.read(65536), timeout=0.5)
                if not chunk:
                    log.debug("SSH->TUN: EOF")
                    break
                buf += chunk
                # Восстанавливаем границы IP пакетов по заголовку
                while len(buf) >= 20:
                    pkt_len = (buf[2] << 8) | buf[3]
                    if pkt_len < 20 or pkt_len > 65535:
                        buf = b""
                        break
                    if len(buf) < pkt_len:
                        break
                    pkt = buf[:pkt_len]
                    buf = buf[pkt_len:]
                    await loop.run_in_executor(None, os.write, fd, pkt)
                    src2 = f"{pkt[12]}.{pkt[13]}.{pkt[14]}.{pkt[15]}" if len(pkt) >= 16 else "?"
                    dst2 = f"{pkt[16]}.{pkt[17]}.{pkt[18]}.{pkt[19]}" if len(pkt) >= 20 else "?"
                    log.debug("SSH->TUN: %d байт src=%s dst=%s", len(pkt), src2, dst2)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                log.debug("SSH->TUN: отменён")
                break
            except OSError as e:
                log.debug("SSH->TUN OSError: %s", e)
                break

    log.info("Форвардинг запущен [stealth=%d]", stealth)
    await asyncio.gather(tun_to_ssh(), ssh_to_tun(), return_exceptions=True)
    log.info("Форвардинг завершён")


async def forward_packets_fast(fd: int, stdin, stdout) -> None:
    """Fast path for normal mode: non-blocking TUN + batched SSH writes."""
    loop = asyncio.get_running_loop()
    done = asyncio.Event()

    try:
        _set_fd_nonblocking(fd)
    except OSError as e:
        log.warning("TUN nonblock failed: %s", e)

    async def tun_to_ssh():
        state = {"reader_on": False, "resume_task": None}
        pkt_count = 0
        bytes_total = 0
        last_diag_time = loop.time()

        def _do_remove():
            if not state["reader_on"]:
                return
            try:
                loop.remove_reader(fd)
            except Exception:
                pass
            state["reader_on"] = False

        def _do_add():
            if state["reader_on"] or done.is_set():
                return
            try:
                loop.add_reader(fd, _on_readable)
                state["reader_on"] = True
            except Exception as e:
                log.debug("TUN add_reader: %s", e)
                done.set()

        async def _resume_after_drain():
            try:
                await stdin.drain()
            except Exception as e:
                log.debug("TUN->SSH drain: %s", e)
                done.set()
                return
            _do_add()

        def _on_readable():
            nonlocal pkt_count, bytes_total, last_diag_time
            if done.is_set():
                _do_remove()
                return

            out = bytearray()
            first_pkt = None
            for _ in range(TUN_READ_BATCH_PACKETS):
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    break
                except (OSError, BrokenPipeError, ConnectionResetError) as e:
                    log.debug("TUN->SSH: %s", e)
                    done.set()
                    return
                if not data:
                    break
                if not _is_ipv4_packet(data):
                    continue
                if first_pkt is None:
                    first_pkt = data
                out.extend(data)
                pkt_count += 1
                bytes_total += len(data)
                if len(out) >= TUN_READ_BATCH_BYTES:
                    break
            if not out:
                return
            try:
                stdin.write(out)
            except Exception as e:
                log.debug("TUN->SSH write: %s", e)
                done.set()
                return

            now = loop.time()
            if first_pkt and (pkt_count <= 3 or now - last_diag_time > 10):
                last_diag_time = now
                src = f"{first_pkt[12]}.{first_pkt[13]}.{first_pkt[14]}.{first_pkt[15]}"
                dst = f"{first_pkt[16]}.{first_pkt[17]}.{first_pkt[18]}.{first_pkt[19]}"
                log.info("TUN->SSH batch: %dB first=%s->%s packets=%d total=%d",
                         len(out), src, dst, pkt_count, bytes_total)

            _do_remove()
            rt = state.get("resume_task")
            if rt is None or rt.done():
                state["resume_task"] = asyncio.create_task(_resume_after_drain())

        _do_add()
        try:
            await done.wait()
            return "done"
        except asyncio.CancelledError:
            return "cancelled"
        finally:
            _do_remove()
            rt = state.get("resume_task")
            if rt is not None and not rt.done():
                rt.cancel()

    async def _write_tun(pkt: bytes) -> bool:
        for _ in range(8):
            try:
                os.write(fd, pkt)
                return True
            except BlockingIOError:
                await asyncio.sleep(0)
            except OSError as e:
                log.debug("SSH->TUN write: %s", e)
                return False
        return False

    async def ssh_to_tun():
        buf = bytearray()
        while not done.is_set():
            try:
                chunk = await asyncio.wait_for(stdout.read(65536), timeout=0.5)
                if not chunk:
                    log.info("SSH->TUN: EOF от сервера")
                    return "ssh-eof"
                buf.extend(chunk)
                while len(buf) >= 20:
                    pkt_len = (buf[2] << 8) | buf[3]
                    if pkt_len < 20 or pkt_len > 65535:
                        buf.clear()
                        break
                    if len(buf) < pkt_len:
                        break
                    pkt = bytes(buf[:pkt_len])
                    del buf[:pkt_len]
                    if not await _write_tun(pkt):
                        return "tun-write-failed"
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return "cancelled"
            except (OSError, BrokenPipeError, ConnectionResetError) as e:
                log.info("SSH->TUN: %s", e)
                return f"ssh-error:{e}"
        return "done"

    log.info("Форвардинг запущен [fast]")
    tasks = [
        asyncio.create_task(tun_to_ssh(), name="tun_to_ssh"),
        asyncio.create_task(ssh_to_tun(), name="ssh_to_tun"),
    ]
    try:
        done_tasks, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done_tasks:
            try:
                reason = task.result()
            except Exception as e:
                reason = f"exception:{e}"
            log.info("Форвардинг task завершён: %s reason=%s", task.get_name(), reason)
    finally:
        done.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    log.info("Форвардинг завершён")


# ─── DPI mimicry ──────────────────────────────────────────────────────────────

# Короткие "человечные" команды. В неудачных попытках 41B out / 564B in за 13с
# DPI успевал классифицировать и резать TCP. В единственной удачной — 28B out /
# 1048B in. Вывод: меньше исходящей активности = меньше пищи для классификатора.
_MIMIC_COMMANDS = ["ls", "pwd", "w", "id", "date", "uptime"]

# Бюджет: 1-2 команды максимум, чтобы преамбула была "тихой".
_MIMIC_MAX_SECONDS  = 8.0
_MIMIC_MIN_SECONDS  = 4.0


async def _run_mimic_preamble(conn) -> None:
    """Имитация интерактивной shell-сессии для маскировки от DPI.

    Тактика: открываем pty+shell, 2-3с читаем MOTD (юзер смотрит welcome),
    набираем 1-2 короткие команды с паузой 1-3с между ними (как будто человек
    думает), после последнего вывода закрываем канал. Цель — отдать DPI
    паттерн "открыл ssh, глянул что на сервере, ушёл" — без массива быстрых
    команд, которые могут выглядеть как скрипт-автомат.
    """
    loop = asyncio.get_event_loop()
    t_start = loop.time()
    try:
        proc = await conn.create_process(
            term_type="xterm-256color",
            term_size=(120, 40),
            encoding=None,
        )
    except Exception as e:
        log.warning("mimic: shell не открылся: %s", e)
        return

    bytes_in = 0
    bytes_out = 0

    async def drain(timeout: float) -> None:
        nonlocal bytes_in
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=timeout)
            if chunk:
                bytes_in += len(chunk)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return
        except Exception:
            return

    # Юзер только что залогинился, читает MOTD/last-login — 2-3 секунды тихо.
    initial_read = random.uniform(2.0, 3.2)
    deadline = t_start + initial_read
    while loop.time() < deadline:
        await drain(timeout=0.5)

    # Набираем максимум 2 команды.
    cmds = random.sample(_MIMIC_COMMANDS, k=2)
    for i, cmd in enumerate(cmds):
        if loop.time() - t_start >= _MIMIC_MAX_SECONDS - 1.0:
            break
        # Пауза "думаю что бы набрать" — чем дальше, тем длиннее.
        await asyncio.sleep(random.uniform(0.8, 2.0) if i == 0 else random.uniform(1.5, 3.0))
        for ch in cmd:
            try:
                proc.stdin.write(ch.encode())
                bytes_out += 1
            except Exception:
                return
            await asyncio.sleep(random.uniform(0.09, 0.22))
            await drain(timeout=0.005)
        try:
            proc.stdin.write(b"\r")
            bytes_out += 1
        except Exception:
            return
        wait_until = loop.time() + random.uniform(0.9, 1.8)
        while loop.time() < wait_until:
            await drain(timeout=0.25)

    # Минимальное окно: даже если команд не набрали, сидим как юзер который
    # открыл терминал и отвлёкся — это нормальный паттерн для DPI.
    while loop.time() - t_start < _MIMIC_MIN_SECONDS:
        await drain(timeout=0.4)

    # Выход без "exit" — пользователь просто закрыл терминал (SSH_MSG_DISCONNECT).
    try:
        proc.close()
    except Exception:
        pass
    log.info("mimic preamble: %dB in / %dB out за %.1fs",
             bytes_in, bytes_out, loop.time() - t_start)


# ─── Основная логика ──────────────────────────────────────────────────────────

RECONNECT_DELAY_MIN = 10  # сек
RECONNECT_DELAY_MAX = 60  # сек


async def connect_once(cfg, stop: asyncio.Future,
                       tun_state: dict) -> bool:
    """
    Одна попытка подключения и работы туннеля.
    tun_state: {'fd': int|None, 'client_ip': str|None} — сохраняется между реконнектами.
    Возвращает True если нужен реконнект, False если остановка по сигналу.
    """
    log.info("Подключаюсь к %s:%d как '%s'", cfg.host, cfg.port, cfg.user)
    ensure_server_bypass(cfg.host)

    known_hosts_file = Path("known_hosts")
    if not known_hosts_file.exists():
        known_hosts_file.write_text("")

    entry = cfg.host if cfg.port == 22 else f"[{cfg.host}]:{cfg.port}"
    existing = known_hosts_file.read_text()
    is_new_server = not any(l.startswith(entry) for l in existing.splitlines())

    # TOFU: первое подключение — принять любой ключ, сохранить после коннекта.
    # Не используем ssh-keyscan, чтобы не триггерить fail2ban лишним соединением.
    known_hosts_arg = None if is_new_server else (
        str(known_hosts_file) if known_hosts_file.stat().st_size > 0 else None
    )

    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                cfg.host, port=cfg.port,
                username=cfg.user, password=cfg.password,
                known_hosts=known_hosts_arg,
                preferred_auth="password",
                keepalive_interval=10, keepalive_count_max=6,
                client_version="OpenSSH_8.2p1 Ubuntu-4ubuntu0.13",
                kex_algs=OPENSSH_KEX_ALGS,
                encryption_algs=OPENSSH_ENCRYPTION_ALGS,
                mac_algs=OPENSSH_MAC_ALGS,
                compression_algs=OPENSSH_COMPRESSION_ALGS,
            ),
            timeout=10,
        )
    except asyncssh.HostKeyNotVerifiable:
        log.error("БЛОКИРОВКА: Ключ сервера %s изменился! Возможная MITM атака.", entry)
        return False, False
    except (asyncio.TimeoutError, OSError, asyncssh.Error) as e:
        log.error("Ошибка подключения: %s", e)
        return False, True

    # Поднимаем SO_SNDBUF/SO_RCVBUF на SSH-сокете — kernel auto-tuning
    # запускается только когда app явно просит > дефолта (~200KB).
    # В stealth-режиме пропускаем: setsockopt меняет TCP wscale в SYN,
    # DPI может отличать такой fingerprint от стокового OpenSSH.
    if not getattr(cfg, "mimic_real_connection", False):
        try:
            import socket as _socket
            _sock = conn.get_extra_info("socket")
            if _sock:
                _sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, 16 * 1024 * 1024)
                _sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, 16 * 1024 * 1024)
        except Exception as _e:
            log.debug("SO_SNDBUF bump: %s", _e)

    log.info("SSH соединение установлено%s", " (mimic-real-connection)" if getattr(cfg, "mimic_real_connection", False) else "")

    # Mimic-preamble: до первого exec "get_ip" имитируем интерактивный
    # shell-логин, чтобы DPI видел паттерн размеров/таймингов обычного ssh.
    if getattr(cfg, "mimic_real_connection", False):
        try:
            await _run_mimic_preamble(conn)
        except Exception as _e:
            log.warning("mimic preamble: %s", _e)

    # TOFU: сохраняем ключ сервера после первого успешного подключения
    if is_new_server:
        try:
            server_key = conn.get_extra_info("server_host_key")
            if server_key is not None:
                key_line = server_key.export_public_key("openssh").decode().strip()
                with open(known_hosts_file, "a") as _kh:
                    _kh.write(f"{entry} {key_line}\n")
                log.info("Ключ сервера %s сохранён в known_hosts", entry)
        except Exception as _e:
            log.warning("Не удалось сохранить ключ сервера: %s", _e)

    # ── Шаг 1: PULL — получаем IP (с поддержкой select_gateway) ──────────────
    # Интерактивный exec: первая JSON-строка от сервера — либо PUSH_REPLY,
    # либо {"action":"select_gateway","gateways":[{"id","name"}]}. Во втором
    # случае клиент отвечает {"gateway_id":"<uuid>"}\n и читает PUSH_REPLY.
    gateway_mode = (getattr(cfg, "gateway_mode", None) or "").strip()
    get_ip_cmd = f"get_ip {gateway_mode}" if gateway_mode else "get_ip"
    try:
        proc = await conn.create_process(get_ip_cmd, encoding=None)
    except Exception as e:
        log.error("Ошибка get_ip: %s", e)
        conn.close()
        return False, True

    async def _read_json_line():
        raw = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
        if not raw:
            return None
        return json.loads(raw.decode().strip())

    try:
        msg = await _read_json_line()
        if msg is None:
            log.error("Сервер вернул пустой ответ на get_ip")
            proc.close()
            conn.close()
            return False, True

        if msg.get("action") == "select_country":
            countries = msg.get("countries") or []
            if not countries:
                log.error("Сервер прислал select_country с пустым списком")
                proc.close()
                conn.close()
                return False, False

            pref_cc = (getattr(cfg, "gateway_country", None) or "").strip().upper()
            if pref_cc:
                if pref_cc not in [c.upper() for c in countries]:
                    log.error("--gateway-country %s не найдена среди предложенных: %s",
                              pref_cc, countries)
                    proc.close()
                    conn.close()
                    return False, False
                chosen_cc = pref_cc
                log.info("--gateway-country=%s, автовыбор", chosen_cc)
            else:
                print("\n── Выбор страны gateway ──", flush=True)
                for i, cc in enumerate(countries, 1):
                    print(f"  {i}. {cc}", flush=True)
                print("(введите код страны или номер)", flush=True)

                loop = asyncio.get_running_loop()
                try:
                    raw = await asyncio.wait_for(
                        loop.run_in_executor(None, input, "country> "),
                        timeout=120,
                    )
                except (EOFError, asyncio.TimeoutError):
                    log.error("Таймаут/EOF при выборе страны")
                    proc.close()
                    conn.close()
                    return False, False

                raw = (raw or "").strip().upper()
                if raw.isdigit():
                    idx = int(raw) - 1
                    chosen_cc = countries[idx] if 0 <= idx < len(countries) else None
                else:
                    chosen_cc = raw if raw in [c.upper() for c in countries] else None

                if not chosen_cc:
                    log.error("Неверный выбор страны: %r", raw)
                    proc.close()
                    conn.close()
                    return False, False
                log.info("Выбрана страна: %s", chosen_cc)

            reply = (json.dumps({"country_code": chosen_cc}) + "\n").encode()
            proc.stdin.write(reply)
            try:
                await proc.stdin.drain()
            except Exception:
                pass

            msg = await _read_json_line()
            if msg is None:
                log.error("Сервер не ответил после выбора страны")
                proc.close()
                conn.close()
                return False, True

        if msg.get("action") == "select_gateway":
            gateways = msg.get("gateways") or []
            if not gateways:
                log.error("Сервер прислал select_gateway с пустым списком")
                proc.close()
                conn.close()
                return False, False

            pref = (getattr(cfg, "gateway", None) or "").strip()
            chosen = None
            sticky = False

            if pref:
                # --gateway: автоматический выбор по id + sticky
                for g in gateways:
                    if g.get("id") == pref:
                        chosen = g
                        break
                if chosen is None:
                    log.error("--gateway %s не найден среди предложенных сервером", pref)
                    proc.close()
                    conn.close()
                    return False, False
                sticky = True
                log.info("--gateway=%s -> %s [%s], sticky=true", pref,
                         chosen.get("real_ip") or "?", chosen.get("country_code") or "")
            else:
                # Интерактивный выбор через терминал
                print("\n── Сервер предлагает выбор gateway ──", flush=True)
                for i, g in enumerate(gateways, 1):
                    real_ip = g.get("real_ip") or "?"
                    cc      = g.get("country_code") or ""
                    print(f"  {i}. {real_ip} [{cc}]  {g.get('id')}", flush=True)
                print("(введите UUID или номер; чтобы запомнить выбор, "
                      "перезапустите клиент с --gateway <id>)", flush=True)

                loop = asyncio.get_running_loop()
                try:
                    raw = await asyncio.wait_for(
                        loop.run_in_executor(None, input, "gateway> "),
                        timeout=120,
                    )
                except (EOFError, asyncio.TimeoutError):
                    log.error("Таймаут/EOF при выборе gateway")
                    proc.close()
                    conn.close()
                    return False, False

                raw = (raw or "").strip()
                if raw.isdigit():
                    idx = int(raw) - 1
                    if 0 <= idx < len(gateways):
                        chosen = gateways[idx]
                else:
                    # Match by UUID or by country code (case-insensitive)
                    raw_upper = raw.upper()
                    cc_matches = [g for g in gateways if (g.get("country_code") or "").upper() == raw_upper]
                    if len(cc_matches) == 1:
                        chosen = cc_matches[0]
                    elif len(cc_matches) > 1:
                        # Multiple gateways for that country — pick first
                        chosen = cc_matches[0]
                        log.info("Несколько gateway для %s, выбран первый: %s", raw_upper, chosen.get("id"))
                    else:
                        for g in gateways:
                            if g.get("id") == raw:
                                chosen = g
                                break

                if chosen is None:
                    log.error("Неверный выбор gateway: %r", raw)
                    proc.close()
                    conn.close()
                    return False, False
                log.info("Выбран gateway: %s [%s] (%s), sticky=false",
                         chosen.get("real_ip") or "?", chosen.get("country_code") or "", chosen["id"])

            reply = (json.dumps({"gateway_id": chosen["id"], "sticky": sticky}) + "\n").encode()
            proc.stdin.write(reply)
            try:
                await proc.stdin.drain()
            except Exception:
                pass

            msg = await _read_json_line()
            if msg is None:
                log.error("Сервер не ответил после выбора gateway")
                proc.close()
                conn.close()
                return False, True

        push = msg
    except Exception as e:
        log.error("Ошибка get_ip: %s", e)
        try:
            proc.close()
        except Exception:
            pass
        conn.close()
        return False, True

    try:
        proc.close()
    except Exception:
        pass

    if "error" in push:
        err = push["error"]
        if err == "MAX_CONNECTED_DEVICES_REACHED":
            log.error("Превышен лимит устройств на аккаунт. Клиент останавливается.")
        elif err == "NO_BANDWIDTH_LEFT":
            log.error("Лимит трафика исчерпан. Клиент останавливается.")
        else:
            log.error("Сервер: %s", err)
        conn.close()
        return False, False  # не реконнектимся при любом сообщении от сервера

    client_ip   = push["client_ip"]
    server_ip   = push["server_ip"]
    mtu         = push.get("mtu", 1400)
    stealth     = int(push.get("stealth", 0))
    chunk_min   = push.get("chunk_min")
    chunk_max   = push.get("chunk_max")
    delay_min   = push.get("delay_min", 0)
    delay_max   = push.get("delay_max", 0)
    cfg.stealth     = stealth
    cfg.chunk_min   = chunk_min
    cfg.chunk_max   = chunk_max
    cfg.delay_min   = delay_min
    cfg.delay_max   = delay_max
    gw_info = push.get("gateway")
    if gw_info:
        log.info("PUSH_REPLY: client_ip=%s server_ip=%s mtu=%d stealth=%d gateway=%s (tun=%s)",
                 client_ip, server_ip, mtu, stealth,
                 gw_info.get("real_ip") or f"[{gw_info.get('country_code') or '?'}]", gw_info.get("tun"))
    else:
        log.info("PUSH_REPLY: client_ip=%s server_ip=%s mtu=%d stealth=%d", client_ip, server_ip, mtu, stealth)

    # ── Шаг 2: TUN — создаём только если нет или IP изменился ────────────────
    # MTU приходит от сервера в зависимости от уровня stealth
    if tun_state["fd"] is None or tun_state["client_ip"] != client_ip:
        if tun_state["fd"] is not None:
            destroy_tun(IFACE, tun_state["fd"])
            tun_state["fd"] = None
        try:
            fd = create_tun(IFACE, client_ip, server_ip, mtu)
            tun_state["fd"] = fd
            tun_state["client_ip"] = client_ip
        except Exception as e:
            log.error("Не удалось создать TUN: %s", e)
            conn.close()
            return False, True
    else:
        fd = tun_state["fd"]
        log.info("Переиспользую существующий TUN %s (%s)", IFACE, client_ip)

    # ── Шаг 3: SSH канал для форвардинга ──────────────────────────────────────
    try:
        process = await conn.create_process(
            f"tunnel {client_ip}", encoding=None,
            window=8 * 1024 * 1024, max_pktsize=65536,
        )
        stdin = process.stdin
        stdout = process.stdout
        log.info("SSH tunnel канал открыт")
    except Exception as e:
        log.error("Не удалось открыть tunnel канал: %s", e)
        conn.close()
        return False, True

    # ── Шаг 4: маршруты. На реконнекте проверяем фактическое состояние:
    # другой процесс/ручная очистка могли удалить policy routing, а локальный
    # флаг routes_set остался True.
    if cfg.mode == "full" and (
        not tun_state.get("routes_set") or
        not full_tunnel_routes_present(cfg.host, IFACE)
    ):
        if tun_state.get("routes_set"):
            log.warning("Full tunnel routes lost, applying policy routing again")
        if setup_full_tunnel(cfg.host, IFACE):
            tun_state["routes_set"] = True

    # Диагностика: состояние SSH сокета ПОСЛЕ setup_full_tunnel
    try:
        sock = conn._transport.get_extra_info('socket')
        if sock is not None:
            log.info("DIAG SSH socket: local=%s peer=%s fd=%d",
                     sock.getsockname(), sock.getpeername(), sock.fileno())
        # Текущее состояние rules/route для cfg.host
        r = _run(["ip", "rule", "show"])
        log.info("DIAG ip rule:\n%s", r.stdout.strip())
        r = _run(["ip", "route", "get", cfg.host])
        log.info("DIAG route to %s: %s", cfg.host, r.stdout.strip())
        r = _run(["ip", "route", "get", client_ip, "from", cfg.host])
        log.info("DIAG reverse route to %s: %s", client_ip, r.stdout.strip())
    except Exception as e:
        log.warning("DIAG failed: %s", e)

    log.info("Туннель активен.")

    # ── Форвардинг — ждём либо stop либо обрыва ───────────────────────────────
    fwd_started = asyncio.get_running_loop().time()
    fwd_task = asyncio.create_task(forward_packets(fd, stdin, stdout, cfg, conn=conn))

    done, _ = await asyncio.wait(
        [fwd_task, asyncio.ensure_future(stop)],
        return_when=asyncio.FIRST_COMPLETED,
    )

    user_stop = stop.done()
    fwd_elapsed = asyncio.get_running_loop().time() - fwd_started
    fwd_task.cancel()

    try:
        process.close()
    except Exception:
        pass
    conn.close()

    if user_stop:
        return True, False
    else:
        if fwd_elapsed < 3.0:
            log.warning("Форвардинг завершился сразу (%.2fs), пересоздам TUN и routes на следующем реконнекте", fwd_elapsed)
            if cfg.mode == "full" and tun_state.get("routes_set"):
                teardown_full_tunnel(cfg.host)
                tun_state["routes_set"] = False
            if tun_state.get("fd") is not None:
                try:
                    destroy_tun(IFACE, tun_state["fd"])
                finally:
                    tun_state["fd"] = None
                    tun_state["client_ip"] = None
            return False, True
        log.warning("Туннель оборвался, будет реконнект")
        return True, True


async def run_client(cfg) -> None:
    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    oif_bypass_task: asyncio.Task | None = None

    def _on_signal():
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    # Очистка зомби strans-tun* от прошлых крашей: DOWN-интерфейсы без
    # владельцев. Они накапливают local routes с дублирующими 198.19.0.X,
    # что ломает выбор src-IP и маршрутизацию для новых туннелей.
    try:
        r = _run(["ip", "-br", "link", "show"])
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if not parts: continue
            name = parts[0].split("@")[0]
            if not name.startswith(IFACE_PREFIX): continue
            state = parts[1] if len(parts) > 1 else ""
            if state == "DOWN":
                _run(["ip", "link", "delete", name])
                log.info("Удалён зомби-интерфейс: %s", name)
    except Exception as e:
        log.warning("Не удалось почистить зомби: %s", e)

    global IFACE
    iface = pick_iface()
    if iface is None:
        log.error("Нет свободных TUN интерфейсов (strans-tun0..strans-tun%d заняты)", IFACE_MAX)
        return
    IFACE = iface
    log.info("Используется интерфейс: %s", IFACE)

    tun_state = {"fd": None, "client_ip": None}
    delay = RECONNECT_DELAY_MIN
    attempt = 0

    async def _oif_bypass_loop() -> None:
        while not stop.done():
            try:
                sync_oif_bypass_rules(exclude_iface=IFACE)
            except Exception as e:
                log.debug("OIF bypass sync failed: %s", e)
            try:
                await asyncio.wait_for(asyncio.shield(stop), timeout=OIF_BYPASS_SYNC_INTERVAL)
            except asyncio.TimeoutError:
                pass

    if cfg.mode == "full" and OIF_BYPASS_PREFIXES:
        oif_bypass_task = asyncio.create_task(_oif_bypass_loop())
        log.info("OIF bypass sync enabled for prefixes: %s", ", ".join(OIF_BYPASS_PREFIXES))

    try:
        while not stop.done():
            if attempt > 0:
                log.info("Реконнект через %d сек (попытка %d)...", delay, attempt)
                try:
                    await asyncio.wait_for(asyncio.shield(stop), timeout=delay)
                    break
                except asyncio.TimeoutError:
                    pass

            attempt += 1
            connected_ok, should_reconnect = await connect_once(cfg, stop, tun_state)

            if not should_reconnect:
                break

            # Если соединение было успешным (туннель работал) — сбрасываем backoff
            if connected_ok:
                delay = RECONNECT_DELAY_MIN
                attempt = 1
                log.info("Соединение было успешным, сбрасываю задержку реконнекта")
            else:
                delay = min(delay * 2, RECONNECT_DELAY_MAX)

    finally:
        log.info("Останавливаю туннель...")
        if oif_bypass_task is not None:
            oif_bypass_task.cancel()
            try:
                await oif_bypass_task
            except asyncio.CancelledError:
                pass
        if cfg.mode == "full":
            teardown_full_tunnel(cfg.host)
        if tun_state["fd"] is not None:
            destroy_tun(IFACE, tun_state["fd"])
        else:
            subprocess.run(["ip", "link", "delete", IFACE], check=False, capture_output=True)
        log.info("Остановлено")


# ─── Аргументы ────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="SSH TUN VPN клиент")
    p.add_argument("--host",     required=True)
    p.add_argument("--port",     type=int, default=2222)
    p.add_argument("--user",     required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--mode",     choices=["tun-only", "full"], default="tun-only")
    p.add_argument("--gateway",  default=None,
                   metavar="UUID",
                   help="UUID outbound gateway. При указании клиент шлёт sticky=true, "
                        "и сервер сохраняет выбор в users.json — следующие коннекты "
                        "не будут запрашивать выбор.")
    p.add_argument("--gateway-mode", default=None, choices=["id", "country"],
                   dest="gateway_mode",
                   help="Режим выбора gateway: id — по UUID (по умолчанию), "
                        "country — выбор по коду страны, сервер рандомно назначает gateway.")
    p.add_argument("--gateway-country", default=None,
                   dest="gateway_country",
                   metavar="CC",
                   help="Код страны для --gateway-mode country (например DE, CA). "
                        "Если не указан — предлагается интерактивный выбор.")
    p.add_argument("--debug",    action="store_true")
    p.add_argument("--mimic-real-connection", action="store_true",
                   dest="mimic_real_connection",
                   help="Не трогать SO_SNDBUF/SO_RCVBUF на SSH-сокете. "
                        "setsockopt меняет TCP wscale в SYN — DPI (ТСПУ) может "
                        "использовать это как fingerprint. Ценой ~200KB default "
                        "буферов получаем TCP-сигнатуру стокового OpenSSH.")
    return p.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if os.geteuid() != 0:
        log.error("Требуется root")
        sys.exit(1)
    try:
        import uvloop  # type: ignore
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        log.debug("uvloop не установлен — fallback на asyncio")
    try:
        asyncio.run(run_client(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
