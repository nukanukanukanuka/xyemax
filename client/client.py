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
import re
import signal
import struct
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ─── Логирование ──────────────────────────────────────────────────────────────

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_ch)

Path("logs").mkdir(exist_ok=True)
_log_file = f"logs/client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
_fh = logging.FileHandler(_log_file, mode="w", encoding="utf-8")
_fh.setLevel(logging.DEBUG)
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


# ─── TUN устройство ───────────────────────────────────────────────────────────

def create_tun(name: str, client_ip: str, server_ip: str, mtu: int) -> int:
    """Создаёт TUN интерфейс и возвращает fd."""
    subprocess.run(["ip", "tuntap", "add", "dev", name, "mode", "tun"], check=True, capture_output=True)

    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)

    subprocess.run(["ip", "addr", "add", f"{client_ip}/32", "peer", f"{server_ip}/32", "dev", name],
                   check=True, capture_output=True)
    subprocess.run(["ip", "link", "set", "dev", name, "mtu", str(mtu), "up"],
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

LOCAL_SUBNETS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
]


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True, **kw)


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

    # 1. Маршрут к серверу через реальный шлюз (приоритет выше чем VPN)
    _run(["ip", "rule", "del", "prio", str(SRV_PRIO)])  # очистка предыдущего
    _run(["ip", "rule", "add", "to", f"{server_host}/32",
          "lookup", "main", "prio", str(SRV_PRIO)])
    log.info("Rule: трафик к %s -> main table (через %s dev %s)", server_host, gw["via"], gw["dev"])

    # 2. Дефолтный маршрут через TUN в отдельной таблице
    _run(["ip", "route", "flush", "table", str(VPN_TABLE)])
    _run(["ip", "route", "add", "default", "dev", tun_iface, "table", str(VPN_TABLE)])
    log.info("Route: default dev %s (table %d)", tun_iface, VPN_TABLE)

    # 3. Локальные подсети — обходят VPN, идут через main table
    for i, subnet in enumerate(LOCAL_SUBNETS):
        prio = LOCAL_PRIO + i
        _run(["ip", "rule", "del", "prio", str(prio)])
        _run(["ip", "rule", "add", "to", subnet, "lookup", "main", "prio", str(prio)])
    log.info("Rule: локальные подсети (%d шт.) -> main table (prio %d+)",
             len(LOCAL_SUBNETS), LOCAL_PRIO)

    # 4. Правило: весь остальной трафик -> таблица VPN
    _run(["ip", "rule", "del", "prio", str(VPN_PRIO)])  # очистка предыдущего
    _run(["ip", "rule", "add", "lookup", str(VPN_TABLE), "prio", str(VPN_PRIO)])
    log.info("Rule: весь трафик -> table %d (prio %d)", VPN_TABLE, VPN_PRIO)

    # 4. DNS — переключаем на публичные серверы (через туннель)
    _original_resolv = _save_resolv_conf()
    _set_dns(VPN_DNS)

    return True


def teardown_full_tunnel(server_host: str) -> None:
    """Убирает policy routing правила и VPN таблицу."""
    global _original_resolv

    _run(["ip", "rule", "del", "prio", str(VPN_PRIO)])
    _run(["ip", "rule", "del", "prio", str(SRV_PRIO)])
    for i in range(len(LOCAL_SUBNETS)):
        _run(["ip", "rule", "del", "prio", str(LOCAL_PRIO + i)])
    _run(["ip", "route", "flush", "table", str(VPN_TABLE)])
    _run(["ip", "route", "del", f"{server_host}/32"])

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

async def forward_packets(fd: int, stdin, stdout, cfg) -> None:
    """Форвардит пакеты между локальным TUN fd и SSH каналом."""
    loop = asyncio.get_event_loop()
    stealth = getattr(cfg, "stealth", 0)

    async def tun_to_ssh():
        """TUN -> SSH: читаем из TUN fd, пишем в stdin SSH канала."""
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, fd, 65536)
                if not data:
                    log.debug("TUN->SSH: EOF")
                    break
                if stealth > 0:
                    await stealth_write(stdin, data, cfg)
                else:
                    stdin.write(data)
                log.debug("TUN->SSH: %d байт", len(data))
            except asyncio.CancelledError:
                log.debug("TUN->SSH: отменён")
                break
            except OSError as e:
                log.debug("TUN->SSH OSError: %s", e)
                break

    async def ssh_to_tun():
        """SSH -> TUN: читаем из stdout SSH, сервер шлёт целые IP пакеты."""
        buf = b""
        while True:
            try:
                chunk = await stdout.read(65536)
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
                    log.debug("SSH->TUN: %d байт", len(pkt))
            except asyncio.CancelledError:
                log.debug("SSH->TUN: отменён")
                break
            except OSError as e:
                log.debug("SSH->TUN OSError: %s", e)
                break

    log.info("Форвардинг запущен [stealth=%d]", stealth)
    await asyncio.gather(tun_to_ssh(), ssh_to_tun(), return_exceptions=True)
    log.info("Форвардинг завершён")


# ─── Основная логика ──────────────────────────────────────────────────────────

RECONNECT_DELAY_MIN = 3   # сек
RECONNECT_DELAY_MAX = 60  # сек


async def connect_once(cfg, stop: asyncio.Future,
                       tun_state: dict) -> bool:
    """
    Одна попытка подключения и работы туннеля.
    tun_state: {'fd': int|None, 'client_ip': str|None} — сохраняется между реконнектами.
    Возвращает True если нужен реконнект, False если остановка по сигналу.
    """
    log.info("Подключаюсь к %s:%d как '%s'", cfg.host, cfg.port, cfg.user)

    known_hosts_file = Path("known_hosts")
    if not known_hosts_file.exists():
        known_hosts_file.write_text("")

    host_entry = f"[{cfg.host}]:{cfg.port}"
    existing = known_hosts_file.read_text()
    saved_lines = [l for l in existing.splitlines() if l.startswith(host_entry)]

    entry = cfg.host if cfg.port == 22 else f"[{cfg.host}]:{cfg.port}"
    existing = known_hosts_file.read_text()
    saved = [l for l in existing.splitlines() if l.startswith(entry)]
    is_new_server = not saved

    if is_new_server:
        log.info("Новый сервер %s — получаю host key...", entry)
        try:
            scan = subprocess.run(
                ["ssh-keyscan", "-p", str(cfg.port), cfg.host],
                capture_output=True, text=True, timeout=10
            )
            if scan.stdout.strip():
                # ssh-keyscan возвращает "host alg key" — нам нужно "[host]:port alg key"
                lines = []
                for line in scan.stdout.splitlines():
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.split(" ", 1)
                    if len(parts) == 2:
                        lines.append(f"{entry} {parts[1]}\n")
                if lines:
                    with open(known_hosts_file, "a") as f:
                        f.writelines(lines)
                    log.info("Ключ сервера %s сохранён в known_hosts", entry)
            else:
                log.warning("ssh-keyscan не вернул ключ, подключаюсь без проверки")
        except Exception as e:
            log.warning("ssh-keyscan failed: %s", e)

    known_hosts_arg = str(known_hosts_file) if known_hosts_file.stat().st_size > 0 else None

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

    log.info("SSH соединение установлено")

    # ── Шаг 1: PULL — получаем IP (с поддержкой select_gateway) ──────────────
    # Интерактивный exec: первая JSON-строка от сервера — либо PUSH_REPLY,
    # либо {"action":"select_gateway","gateways":[{"id","name"}]}. Во втором
    # случае клиент отвечает {"gateway_id":"<uuid>"}\n и читает PUSH_REPLY.
    try:
        proc = await conn.create_process("get_ip", encoding=None)
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
                log.info("--gateway=%s -> %s, sticky=true", pref, chosen.get("name"))
            else:
                # Интерактивный выбор через терминал
                print("\n── Сервер предлагает выбор gateway ──", flush=True)
                for i, g in enumerate(gateways, 1):
                    print(f"  {i}. {g.get('name')}  {g.get('id')}", flush=True)
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
                    for g in gateways:
                        if g.get("id") == raw:
                            chosen = g
                            break

                if chosen is None:
                    log.error("Неверный выбор gateway: %r", raw)
                    proc.close()
                    conn.close()
                    return False, False
                log.info("Выбран gateway: %s (%s), sticky=false",
                         chosen.get("name"), chosen["id"])

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
    mtu         = push.get("mtu", 1280)
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
                 client_ip, server_ip, mtu, stealth, gw_info.get("name"), gw_info.get("tun"))
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
        process = await conn.create_process(f"tunnel {client_ip}", encoding=None)
        stdin = process.stdin
        stdout = process.stdout
        log.info("SSH tunnel канал открыт")
    except Exception as e:
        log.error("Не удалось открыть tunnel канал: %s", e)
        conn.close()
        return False, True

    # ── Шаг 4: маршруты (только при первом подключении) ───────────────────────
    if cfg.mode == "full" and not tun_state.get("routes_set"):
        if setup_full_tunnel(cfg.host, IFACE):
            tun_state["routes_set"] = True

    log.info("Туннель активен.")

    # ── Форвардинг — ждём либо stop либо обрыва ───────────────────────────────
    fwd_task = asyncio.create_task(forward_packets(fd, stdin, stdout, cfg))

    done, _ = await asyncio.wait(
        [fwd_task, asyncio.ensure_future(stop)],
        return_when=asyncio.FIRST_COMPLETED,
    )

    user_stop = stop.done()
    fwd_task.cancel()

    try:
        process.close()
    except Exception:
        pass
    conn.close()

    if user_stop:
        return True, False
    else:
        log.warning("Туннель оборвался, будет реконнект")
        return True, True


async def run_client(cfg) -> None:
    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    def _on_signal():
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

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
    p.add_argument("--debug",    action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if os.geteuid() != 0:
        log.error("Требуется root")
        sys.exit(1)
    try:
        asyncio.run(run_client(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()