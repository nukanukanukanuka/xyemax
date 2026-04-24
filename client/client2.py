#!/usr/bin/env python3.12
"""
SSH TUN клиент — через субпроцесс /usr/bin/ssh (ControlMaster multiplexing).

Отличие от client.py: вместо asyncssh используем настоящий OpenSSH.
Все фингерпринт-признаки (TCP wscale в SYN, HASSH, client_version,
тайминги handshake, размеры первых пакетов) идентичны обычному `ssh`
в том же окружении — ТСПУ не должна отличать нас от ручного ssh.

Поток:
  1. `sshpass -p ... ssh -N -M -S <sock>` — мастер-сессия (один handshake).
  2. `ssh -S <sock> user@host "get_ip <mode>"` — PUSH_REPLY через slave exec.
  3. `ssh -S <sock> user@host "tunnel <ip>"` — slave с пайпами для пакетов.
  4. Остальное (TUN, routing) — как в client.py.

Зависимости: /usr/bin/ssh (OpenSSH), sshpass.
"""

import asyncio
import argparse
import fcntl
import json
import logging
import os
import random
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
from collections import deque
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
_log_file = f"logs/client2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
_fh = logging.FileHandler(_log_file, mode="w", encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_fh)

log.info("=== Запуск клиента2 (OpenSSH subprocess) ===")
log.info("Лог файл: %s", _log_file)

IFACE_PREFIX = "strans-tun"
IFACE_MAX    = 100
IFACE = f"{IFACE_PREFIX}0"
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca


# ─── TUN устройство ───────────────────────────────────────────────────────────

def pick_iface() -> str | None:
    for i in range(IFACE_MAX + 1):
        name = f"{IFACE_PREFIX}{i}"
        r = subprocess.run(["ip", "link", "show", name], capture_output=True, check=False)
        if r.returncode != 0:
            return name
    return None


def create_tun(name: str, client_ip: str, server_ip: str, mtu: int) -> int:
    subprocess.run(["ip", "tuntap", "add", "dev", name, "mode", "tun"],
                   check=True, capture_output=True)
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    subprocess.run(["ip", "addr", "add", f"{client_ip}/32", "peer", f"{server_ip}/32", "dev", name],
                   check=True, capture_output=True)
    subprocess.run(["ip", "link", "set", "dev", name, "mtu", str(mtu),
                    "txqueuelen", "2000", "up"], check=True, capture_output=True)
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


# ─── Policy routing (идентично client.py) ────────────────────────────────────

VPN_TABLE  = 100
VPN_PRIO   = 100
SRV_PRIO   = 50
LOCAL_PRIO = 80
LOCAL_SUBNETS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "127.0.0.0/8",
]
VPN_DNS = ["1.1.1.1", "8.8.8.8"]
_original_resolv: str | None = None


def _run(cmd, **kw):
    return subprocess.run(cmd, check=False, capture_output=True, text=True, **kw)


def get_default_gateway() -> dict | None:
    r = _run(["ip", "route", "show", "default"])
    for line in r.stdout.splitlines():
        via = re.search(r"via (\S+)", line)
        dev = re.search(r"dev (\S+)", line)
        if via and dev:
            return {"via": via.group(1), "dev": dev.group(1)}
    return None


def _save_resolv_conf():
    try:
        return Path("/etc/resolv.conf").read_text()
    except OSError:
        return None


def _set_dns(servers):
    content = "# set by strans-client (VPN)\n"
    for s in servers:
        content += f"nameserver {s}\n"
    try:
        Path("/etc/resolv.conf").write_text(content)
        log.info("DNS установлен: %s", ", ".join(servers))
    except OSError as e:
        log.warning("Не удалось обновить /etc/resolv.conf: %s", e)


def _restore_resolv_conf(original):
    if original is None:
        return
    try:
        Path("/etc/resolv.conf").write_text(original)
        log.info("DNS восстановлен")
    except OSError as e:
        log.warning("Не удалось восстановить /etc/resolv.conf: %s", e)


def _disable_ipv6():
    _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
    _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])
    log.info("IPv6 отключён")


def _enable_ipv6():
    _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
    _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"])
    log.info("IPv6 включён")


def setup_full_tunnel(server_host: str, tun_iface: str) -> bool:
    global _original_resolv
    gw = get_default_gateway()
    if not gw:
        log.error("Нет дефолтного маршрута — не могу настроить full tunnel")
        return False
    _disable_ipv6()
    for prio in ([SRV_PRIO, VPN_PRIO] + [LOCAL_PRIO + i for i in range(len(LOCAL_SUBNETS))]):
        for _ in range(20):
            if _run(["ip", "rule", "del", "prio", str(prio)]).returncode != 0:
                break
    _run(["ip", "rule", "add", "to", f"{server_host}/32",
          "lookup", "main", "prio", str(SRV_PRIO)])
    log.info("Rule: трафик к %s -> main (%s dev %s)", server_host, gw["via"], gw["dev"])
    _run(["ip", "route", "flush", "table", str(VPN_TABLE)])
    _run(["ip", "route", "add", "default", "dev", tun_iface, "table", str(VPN_TABLE)])
    log.info("Route: default dev %s (table %d)", tun_iface, VPN_TABLE)
    for i, subnet in enumerate(LOCAL_SUBNETS):
        _run(["ip", "rule", "add", "to", subnet, "lookup", "main", "prio", str(LOCAL_PRIO + i)])
    log.info("Rule: локальные (%d шт.) -> main", len(LOCAL_SUBNETS))
    _run(["ip", "rule", "add", "lookup", str(VPN_TABLE), "prio", str(VPN_PRIO)])
    log.info("Rule: весь трафик -> table %d (prio %d)", VPN_TABLE, VPN_PRIO)
    _original_resolv = _save_resolv_conf()
    _set_dns(VPN_DNS)
    return True


def teardown_full_tunnel(server_host: str) -> None:
    global _original_resolv
    for prio in ([SRV_PRIO, VPN_PRIO] + [LOCAL_PRIO + i for i in range(len(LOCAL_SUBNETS))]):
        for _ in range(20):
            if _run(["ip", "rule", "del", "prio", str(prio)]).returncode != 0:
                break
    _run(["ip", "route", "flush", "table", str(VPN_TABLE)])
    _restore_resolv_conf(_original_resolv)
    _original_resolv = None
    _enable_ipv6()
    log.info("Policy routing очищен")


# ─── OpenSSH subprocess wrapper ──────────────────────────────────────────────

class SSHMaster:
    """ControlMaster — персистентное аутентифицированное SSH-соединение.

    После start() запускается фоновый `ssh -N -M` процесс, который держит
    один TCP/SSH сеанс. Все последующие `exec()` открывают slave-ssh,
    который обнаруживает ControlPath сокет и мультиплексирует новый
    канал внутри уже установленного сеанса — без нового handshake'а
    и без нового TCP соединения. Снаружи (для ТСПУ) виден один обычный
    OpenSSH-сеанс, как будто человек его держит.
    """

    def __init__(self, host: str, port: int, user: str, password: str,
                 socket_path: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.sock = socket_path
        self.proc: asyncio.subprocess.Process | None = None
        self._askpass_dir: str | None = None
        self._askpass_sh: str | None = None
        self._askpass_pw: str | None = None
        self._stderr_tail: deque[str] = deque(maxlen=32)

    def _entry(self) -> str:
        return self.host if self.port == 22 else f"[{self.host}]:{self.port}"

    def _stderr_text(self) -> str:
        return "\n".join(self._stderr_tail)

    def _is_hostkey_mismatch(self, text: str) -> bool:
        hay = text.upper()
        return (
            "REMOTE HOST IDENTIFICATION HAS CHANGED" in hay
            or "HOST KEY VERIFICATION FAILED" in hay
            or "OFFENDING " in hay
        )

    def _is_wrong_password(self, text: str) -> bool:
        hay = text or ""
        low = hay.lower()
        return (
            "Permission denied, please try again." in hay
            or "Permission denied (password" in hay
            or "password authentication failed" in low
            or "authentication failed" in low
        )

    def _log_probable_mitm(self, text: str) -> None:
        entry = self._entry()
        log.error("БЛОКИРОВКА: Ключ сервера %s изменился! Возможная MITM атака.", entry)
        if text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    log.error("OpenSSH: %s", line)

    def _setup_askpass(self):
        """Создаёт askpass-скрипт и файл с паролем (chmod 600).

        Используется вместо sshpass. OpenSSH >= 8.4 с SSH_ASKPASS_REQUIRE=force
        принудительно вызывает askpass даже при наличии tty/stdin — значит
        пароль передаётся без видимости в ps и без /dev/tty.
        """
        self._askpass_dir = tempfile.mkdtemp(prefix="yovpn-askpass-")
        os.chmod(self._askpass_dir, 0o700)
        self._askpass_pw = os.path.join(self._askpass_dir, "pw")
        self._askpass_sh = os.path.join(self._askpass_dir, "askpass.sh")
        with open(self._askpass_pw, "w") as f:
            f.write(self.password)
        os.chmod(self._askpass_pw, stat.S_IRUSR | stat.S_IWUSR)
        with open(self._askpass_sh, "w") as f:
            f.write("#!/bin/sh\nexec cat " + json.dumps(self._askpass_pw) + "\n")
        os.chmod(self._askpass_sh,
                 stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def _cleanup_askpass(self):
        if self._askpass_dir and os.path.isdir(self._askpass_dir):
            try:
                shutil.rmtree(self._askpass_dir, ignore_errors=True)
            except Exception:
                pass

    def _env(self) -> dict:
        env = os.environ.copy()
        if self._askpass_sh:
            env["SSH_ASKPASS"] = self._askpass_sh
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = env.get("DISPLAY", ":0")
        return env

    def _common_opts(self, pty: bool = False) -> list[str]:
        opts = [
            "-o", f"ControlPath={self.sock}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=known_hosts",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=6",
            "-o", "TCPKeepAlive=yes",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "Compression=no",
        ]
        # -tt принудительно аллоцирует pty на стороне сервера даже когда
        # у нас stdin = pipe. Нужно для mimic-preamble: сервер при pty+shell
        # запускает FakeShellSession (MOTD + responses).
        opts.append("-tt" if pty else "-T")
        opts.extend(["-p", str(self.port)])
        return opts

    async def start(self) -> bool:
        known_hosts_file = Path("known_hosts")
        if not known_hosts_file.exists():
            known_hosts_file.write_text("")
        if os.path.exists(self.sock):
            try:
                os.unlink(self.sock)
            except OSError:
                pass
        self._setup_askpass()
        cmd = ["ssh"]
        cmd += self._common_opts()
        cmd += [
            "-o", "ControlMaster=yes",
            "-o", "ControlPersist=yes",
            "-N",
            f"{self.user}@{self.host}",
        ]
        log.info("Запуск ControlMaster: ssh -N (socket=%s)", self.sock)
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env(),
            start_new_session=True,
        )
        # Дренаж stderr в фоне, чтобы ssh не завис при заполнении буфера
        asyncio.create_task(self._drain_master_stderr())

        loop = asyncio.get_event_loop()
        deadline = loop.time() + 20
        while loop.time() < deadline:
            if os.path.exists(self.sock):
                return True
            if self.proc.returncode is not None:
                stderr_text = self._stderr_text()
                if self._is_hostkey_mismatch(stderr_text):
                    self._log_probable_mitm(stderr_text)
                    return False
                if self._is_wrong_password(stderr_text):
                    log.error("Сервер: WRONG_PASSWORD")
                    return False
                log.error("ControlMaster умер до готовности сокета (rc=%d)",
                          self.proc.returncode)
                return False
            await asyncio.sleep(0.1)
        log.error("ControlMaster: таймаут ожидания сокета %s", self.sock)
        return False

    async def _drain_master_stderr(self):
        if self.proc is None or self.proc.stderr is None:
            return
        try:
            while True:
                line = await self.proc.stderr.readline()
                if not line:
                    return
                txt = line.decode(errors="replace").rstrip()
                if txt:
                    self._stderr_tail.append(txt)
                    log.debug("master stderr: %s", txt)
        except Exception:
            return

    async def exec(self, command: str) -> asyncio.subprocess.Process:
        """Открывает slave-ssh и exec'ит команду через ControlPath сокет."""
        cmd = ["ssh"]
        cmd += self._common_opts(pty=False)
        cmd += [
            "-o", "ControlMaster=no",  # slave: не создавать мастер
            f"{self.user}@{self.host}",
            command,
        ]
        log.debug("SSH exec: %s", command)
        return await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env(),
            start_new_session=True,
        )

    async def open_shell(self) -> asyncio.subprocess.Process:
        """Открывает slave-ssh с pty и без команды — запустится shell.

        Сервер при pty+shell стартует FakeShellSession: MOTD + ответы на
        ls/ps/cat/... Используется для mimic-preamble перед tunnel exec.
        """
        cmd = ["ssh"]
        cmd += self._common_opts(pty=True)
        cmd += [
            "-o", "ControlMaster=no",
            f"{self.user}@{self.host}",
        ]
        log.debug("SSH open shell (pty)")
        return await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env(),
            start_new_session=True,
        )

    async def stop(self):
        if self.proc is None:
            return
        # Посылаем мастеру команду "exit" через control-сокет
        try:
            stop_cmd = ["ssh", "-O", "exit",
                        "-o", f"ControlPath={self.sock}",
                        "-p", str(self.port),
                        f"{self.user}@{self.host}"]
            p = await asyncio.create_subprocess_exec(
                *stop_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                await asyncio.wait_for(p.wait(), timeout=3)
            except asyncio.TimeoutError:
                p.kill()
        except Exception as e:
            log.debug("master -O exit: %s", e)
        try:
            if self.proc.returncode is None:
                self.proc.terminate()
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=3)
                except asyncio.TimeoutError:
                    self.proc.kill()
        except Exception:
            pass
        try:
            if os.path.exists(self.sock):
                os.unlink(self.sock)
        except Exception:
            pass
        self._cleanup_askpass()


# ─── DPI mimicry preamble ────────────────────────────────────────────────────

_MIMIC_LIGHT = [
    "pwd", "whoami", "id", "date", "uptime", "echo $SHELL", "echo $HOME",
    "hostname", "tty", "groups",
]
_MIMIC_HEAVY = [
    "ls -la", "ls -la /etc", "df -h", "free -m", "cat /etc/os-release",
    "ps auxf", "ss -tln", "ip a", "env", "cat /proc/cpuinfo",
    "cat /proc/meminfo", "dpkg -l", "mount", "lsblk",
]
_MIMIC_TARGET_BYTES = 22 * 1024
_MIMIC_MAX_SECONDS  = 18.0
_MIMIC_MIN_SECONDS  = 6.0


async def _run_mimic_preamble(master: "SSHMaster") -> None:
    """Имитация интерактивной shell-сессии перед tunnel exec.

    Гипотеза: ТСПУ при новом соединении классифицирует по первым
    N байтам/секундам. Если сразу после handshake идёт bulk bidi
    (tunnel traffic) — это не похоже на интерактивный ssh, fail.
    Если же сперва MOTD + typed commands + paged output + exit —
    поток классифицируется как обычная shell-сессия.
    """
    loop = asyncio.get_event_loop()
    t_start = loop.time()
    try:
        proc = await master.open_shell()
    except Exception as e:
        log.warning("mimic: shell не открылся: %s", e)
        return

    bytes_in = 0
    bytes_out = 0

    async def drain(timeout: float) -> None:
        nonlocal bytes_in
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(16384), timeout=timeout)
            if chunk:
                bytes_in += len(chunk)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return
        except Exception:
            return

    async def type_cmd(cmd: str) -> bool:
        nonlocal bytes_out
        t_cmd = loop.time()
        before_in = bytes_in
        for ch in cmd:
            try:
                proc.stdin.write(ch.encode())
                bytes_out += 1
                try:
                    await asyncio.wait_for(proc.stdin.drain(), timeout=1.0)
                except (asyncio.TimeoutError, Exception):
                    pass
            except Exception:
                return False
            await asyncio.sleep(random.uniform(0.06, 0.20))
            await drain(timeout=0.005)
        try:
            proc.stdin.write(b"\r")
            bytes_out += 1
            try:
                await asyncio.wait_for(proc.stdin.drain(), timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                pass
        except Exception:
            return False
        idle_streak = 0
        read_deadline = loop.time() + random.uniform(1.8, 3.2)
        while loop.time() < read_deadline:
            prev = bytes_in
            await drain(timeout=0.25)
            if bytes_in == prev:
                idle_streak += 1
                if idle_streak >= 3:
                    break
            else:
                idle_streak = 0
        delta_in = bytes_in - before_in
        elapsed = loop.time() - t_start
        pct = 100 * (bytes_in + bytes_out) / _MIMIC_TARGET_BYTES
        log.info("mimic: %-20s -> %5dB in %.2fs | total=%dB/%dKB (%.0f%%) elapsed=%.1fs",
                 repr(cmd), delta_in, loop.time() - t_cmd,
                 bytes_in + bytes_out, _MIMIC_TARGET_BYTES // 1024,
                 pct, elapsed)
        return True

    # 1. MOTD/last-login
    initial_read = random.uniform(2.0, 3.2)
    deadline = t_start + initial_read
    while loop.time() < deadline:
        await drain(timeout=0.5)

    # 2. Warm-up
    await asyncio.sleep(random.uniform(0.6, 1.6))
    if not await type_cmd(random.choice(_MIMIC_LIGHT)):
        try:
            proc.terminate()
        except Exception:
            pass
        return

    # 3. Основной блок heavy-команд
    heavy_pool = _MIMIC_HEAVY.copy()
    random.shuffle(heavy_pool)
    light_pool = _MIMIC_LIGHT.copy()
    random.shuffle(light_pool)
    heavy_i = 0
    light_i = 0
    while True:
        elapsed = loop.time() - t_start
        if bytes_in + bytes_out >= _MIMIC_TARGET_BYTES:
            break
        if elapsed >= _MIMIC_MAX_SECONDS - 2.0:
            break
        await asyncio.sleep(random.uniform(0.8, 2.4))
        if random.random() < 0.7 and heavy_i < len(heavy_pool):
            cmd = heavy_pool[heavy_i]; heavy_i += 1
        elif light_i < len(light_pool):
            cmd = light_pool[light_i]; light_i += 1
        elif heavy_i < len(heavy_pool):
            cmd = heavy_pool[heavy_i]; heavy_i += 1
        else:
            break
        if not await type_cmd(cmd):
            try:
                proc.terminate()
            except Exception:
                pass
            return

    while loop.time() - t_start < _MIMIC_MIN_SECONDS:
        await drain(timeout=0.4)

    # 4. Выход
    try:
        await asyncio.sleep(random.uniform(0.4, 1.0))
        proc.stdin.write(b"exit\r")
        bytes_out += 5
        try:
            await asyncio.wait_for(proc.stdin.drain(), timeout=1.0)
        except (asyncio.TimeoutError, Exception):
            pass
    except Exception:
        pass
    end_deadline = loop.time() + 1.2
    while loop.time() < end_deadline:
        await drain(timeout=0.3)
    try:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                proc.kill()
    except Exception:
        pass

    log.info("mimic preamble: %dB in / %dB out за %.1fs (target=%dKB)",
             bytes_in, bytes_out, loop.time() - t_start, _MIMIC_TARGET_BYTES // 1024)


# ─── Форвардинг ───────────────────────────────────────────────────────────────

async def forward_packets(fd: int, stdin, stdout) -> None:
    """TUN ↔ subprocess pipes: целые IP-пакеты в обе стороны."""
    loop = asyncio.get_event_loop()

    async def tun_to_ssh():
        pkt_count = 0
        bytes_total = 0
        last_diag_time = 0
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, fd, 65536)
                if not data:
                    log.debug("TUN->SSH: EOF")
                    break
                if len(data) < 20 or (data[0] >> 4) != 4:
                    continue
                pkt_len_from_hdr = (data[2] << 8) | data[3]
                if pkt_len_from_hdr != len(data):
                    log.warning("TUN->SSH: header len=%d != read %d — DROP",
                                pkt_len_from_hdr, len(data))
                    continue
                stdin.write(data)
                await stdin.drain()
                pkt_count += 1
                bytes_total += len(data)
                now = loop.time()
                if pkt_count <= 3 or now - last_diag_time > 3:
                    last_diag_time = now
                    src = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
                    dst = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
                    log.info("TUN->SSH: %d байт src=%s dst=%s [#%d total=%d]",
                             len(data), src, dst, pkt_count, bytes_total)
            except asyncio.CancelledError:
                break
            except (OSError, BrokenPipeError, ConnectionResetError) as e:
                log.debug("TUN->SSH: %s", e)
                break
            except Exception as e:
                log.error("TUN->SSH: %s", e, exc_info=True)
                break

    async def ssh_to_tun():
        buf = b""
        while True:
            try:
                chunk = await asyncio.wait_for(stdout.read(65536), timeout=0.5)
                if not chunk:
                    log.debug("SSH->TUN: EOF")
                    break
                buf += chunk
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
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except (OSError, BrokenPipeError, ConnectionResetError) as e:
                log.debug("SSH->TUN: %s", e)
                break

    log.info("Форвардинг запущен")
    await asyncio.gather(tun_to_ssh(), ssh_to_tun(), return_exceptions=True)
    log.info("Форвардинг завершён")


# ─── Основная логика ──────────────────────────────────────────────────────────

RECONNECT_DELAY_MIN = 10
RECONNECT_DELAY_MAX = 60


async def _read_json_line(stream, timeout=30):
    raw = await asyncio.wait_for(stream.readline(), timeout=timeout)
    if not raw:
        return None
    return json.loads(raw.decode().strip())


async def _terminate_proc(proc, tag="proc"):
    try:
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()
    except Exception:
        pass
    try:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                proc.kill()
    except Exception as e:
        log.debug("terminate %s: %s", tag, e)


async def _exchange_get_ip(master: SSHMaster, cfg) -> dict | None:
    """get_ip exec → (optional select_country) → (optional select_gateway) → PUSH_REPLY."""
    split_cc = (getattr(cfg, "split_tunneling", None) or "").strip().upper()
    gateway_mode = (getattr(cfg, "gateway_mode", None) or "").strip()
    get_ip_cmd = f"get_ip {gateway_mode}" if gateway_mode else "get_ip"
    if split_cc:
        get_ip_cmd += f" split:{split_cc}"
    proc = await master.exec(get_ip_cmd)
    try:
        msg = await _read_json_line(proc.stdout)
        if msg is None:
            log.error("get_ip: пустой ответ")
            return None

        if msg.get("action") == "select_country":
            countries = msg.get("countries") or []
            if not countries:
                log.error("select_country: пустой список")
                return None
            pref_cc = (getattr(cfg, "gateway_country", None) or "").strip().upper()
            if pref_cc:
                if pref_cc not in [c.upper() for c in countries]:
                    log.error("--gateway-country %s не в списке: %s", pref_cc, countries)
                    return None
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
                    return None
                raw = (raw or "").strip().upper()
                if raw.isdigit():
                    idx = int(raw) - 1
                    chosen_cc = countries[idx] if 0 <= idx < len(countries) else None
                else:
                    chosen_cc = raw if raw in [c.upper() for c in countries] else None
                if not chosen_cc:
                    log.error("Неверный выбор страны: %r", raw)
                    return None
                log.info("Выбрана страна: %s", chosen_cc)

            proc.stdin.write((json.dumps({"country_code": chosen_cc}) + "\n").encode())
            await proc.stdin.drain()
            msg = await _read_json_line(proc.stdout)
            if msg is None:
                log.error("Нет ответа после выбора страны")
                return None

        if msg.get("action") == "select_gateway":
            gateways = msg.get("gateways") or []
            if not gateways:
                log.error("select_gateway: пустой список")
                return None
            pref = (getattr(cfg, "gateway", None) or "").strip()
            chosen = None
            sticky = False
            if pref:
                for g in gateways:
                    if g.get("id") == pref:
                        chosen = g
                        break
                if chosen is None:
                    log.error("--gateway %s не найден среди предложенных сервером", pref)
                    return None
                sticky = True
                log.info("--gateway=%s -> %s [%s], sticky=true", pref,
                         chosen.get("real_ip") or "?", chosen.get("country_code") or "")
            else:
                print("\n── Сервер предлагает выбор gateway ──", flush=True)
                for i, g in enumerate(gateways, 1):
                    real_ip = g.get("real_ip") or "?"
                    cc = g.get("country_code") or ""
                    print(f"  {i}. {real_ip} [{cc}]  {g.get('id')}", flush=True)
                print("(введите UUID, код страны или номер; "
                      "для sticky — перезапусти с --gateway <id>)", flush=True)
                loop = asyncio.get_running_loop()
                try:
                    raw = await asyncio.wait_for(
                        loop.run_in_executor(None, input, "gateway> "),
                        timeout=120,
                    )
                except (EOFError, asyncio.TimeoutError):
                    log.error("Таймаут/EOF при выборе gateway")
                    return None
                raw = (raw or "").strip()
                if raw.isdigit():
                    idx = int(raw) - 1
                    if 0 <= idx < len(gateways):
                        chosen = gateways[idx]
                else:
                    raw_upper = raw.upper()
                    cc_matches = [g for g in gateways
                                  if (g.get("country_code") or "").upper() == raw_upper]
                    if cc_matches:
                        chosen = cc_matches[0]
                        if len(cc_matches) > 1:
                            log.info("Несколько gateway для %s, выбран первый: %s",
                                     raw_upper, chosen.get("id"))
                    else:
                        for g in gateways:
                            if g.get("id") == raw:
                                chosen = g
                                break
                if chosen is None:
                    log.error("Неверный выбор gateway: %r", raw)
                    return None
                log.info("Выбран gateway: %s [%s] (%s), sticky=false",
                         chosen.get("real_ip") or "?",
                         chosen.get("country_code") or "", chosen["id"])

            proc.stdin.write((json.dumps({"gateway_id": chosen["id"], "sticky": sticky}) + "\n").encode())
            await proc.stdin.drain()
            msg = await _read_json_line(proc.stdout)
            if msg is None:
                log.error("Нет ответа после выбора gateway")
                return None

        return msg
    finally:
        await _terminate_proc(proc, "get_ip")


async def connect_once(cfg, stop: asyncio.Future, tun_state: dict):
    """Возвращает (connected_ok, should_reconnect)."""
    log.info("Подключаюсь к %s:%d как '%s'", cfg.host, cfg.port, cfg.user)

    if not shutil.which("ssh"):
        log.error("/usr/bin/ssh (OpenSSH) не найден")
        return False, False

    sock_path = f"/tmp/yovpn-ssh-{os.getpid()}.sock"
    master = SSHMaster(cfg.host, cfg.port, cfg.user, cfg.password, sock_path)

    if not await master.start():
        return False, True

    log.info("SSH ControlMaster установлен (socket=%s)", sock_path)

    try:
        # ── Шаг 0: mimic preamble ─────────────────────────────────────────────
        # До любых наших команд прогоняем shell-сессию с MOTD + typed cmds,
        # чтобы ТСПУ видела первые 10-20KB как обычный интерактивный ssh.
        if getattr(cfg, "mimic_real_connection", False):
            try:
                await _run_mimic_preamble(master)
            except Exception as e:
                log.warning("mimic preamble: %s", e)

        # ── Шаг 1: PULL — PUSH_REPLY ──────────────────────────────────────────
        push = await _exchange_get_ip(master, cfg)
        if push is None:
            return False, True

        if "error" in push:
            err = push["error"]
            if err == "MAX_CONNECTED_DEVICES_REACHED":
                log.error("Превышен лимит устройств на аккаунт. Клиент останавливается.")
            elif err == "NO_BANDWIDTH_LEFT":
                log.error("Лимит трафика исчерпан. Клиент останавливается.")
            else:
                log.error("Сервер: %s", err)
            return False, False

        client_ip = push["client_ip"]
        server_ip = push["server_ip"]
        mtu = push.get("mtu", 1400)
        gw_info = push.get("gateway")
        split_info = push.get("split_gateway")
        if gw_info:
            log.info("PUSH_REPLY: client_ip=%s server_ip=%s mtu=%d gateway=%s (tun=%s)",
                     client_ip, server_ip, mtu,
                     gw_info.get("real_ip") or f"[{gw_info.get('country_code') or '?'}]",
                     gw_info.get("tun"))
        else:
            log.info("PUSH_REPLY: client_ip=%s server_ip=%s mtu=%d",
                     client_ip, server_ip, mtu)
        if split_info:
            log.info("Split gateway: %s (tun=%s) cc=%s",
                     split_info.get("real_ip") or f"[{split_info.get('country_code') or '?'}]",
                     split_info.get("tun"), split_info.get("split_cc"))

        # ── Шаг 2: TUN ────────────────────────────────────────────────────────
        if tun_state["fd"] is None or tun_state["client_ip"] != client_ip:
            if tun_state["fd"] is not None:
                destroy_tun(IFACE, tun_state["fd"])
                tun_state["fd"] = None
            try:
                fd = create_tun(IFACE, client_ip, server_ip, mtu)
                tun_state["fd"] = fd
                tun_state["client_ip"] = client_ip
            except Exception as e:
                log.error("create_tun: %s", e)
                return False, True
        else:
            fd = tun_state["fd"]
            log.info("Переиспользую существующий TUN %s (%s)", IFACE, client_ip)

        # ── Шаг 3: tunnel slave-канал ────────────────────────────────────────
        tunnel_proc = await master.exec(f"tunnel {client_ip}")
        log.info("SSH tunnel канал открыт")

        # ── Шаг 4: маршруты ──────────────────────────────────────────────────
        if cfg.mode == "full" and not tun_state.get("routes_set"):
            if setup_full_tunnel(cfg.host, IFACE):
                tun_state["routes_set"] = True

        # Диагностика текущих rules/routes
        try:
            r = _run(["ip", "rule", "show"])
            log.info("DIAG ip rule:\n%s", r.stdout.strip())
            r = _run(["ip", "route", "get", cfg.host])
            log.info("DIAG route to %s: %s", cfg.host, r.stdout.strip())
        except Exception as e:
            log.warning("DIAG failed: %s", e)

        log.info("Туннель активен.")

        async def _drain_stderr(proc, tag):
            if proc.stderr is None:
                return
            while True:
                try:
                    line = await proc.stderr.readline()
                    if not line:
                        return
                    txt = line.decode(errors="replace").rstrip()
                    if txt:
                        log.debug("%s stderr: %s", tag, txt)
                except Exception:
                    return

        stderr_task = asyncio.create_task(_drain_stderr(tunnel_proc, "tunnel"))
        fwd_task = asyncio.create_task(
            forward_packets(fd, tunnel_proc.stdin, tunnel_proc.stdout))
        wait_task = asyncio.create_task(tunnel_proc.wait())

        done, _pending = await asyncio.wait(
            [fwd_task, wait_task, asyncio.ensure_future(stop)],
            return_when=asyncio.FIRST_COMPLETED,
        )

        user_stop = stop.done()
        fwd_task.cancel()
        stderr_task.cancel()
        await _terminate_proc(tunnel_proc, "tunnel")

        if user_stop:
            return True, False
        log.warning("Туннель оборвался, будет реконнект")
        return True, True
    finally:
        await master.stop()


async def run_client(cfg):
    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    def _on_signal():
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    # Зомби-интерфейсы от прошлых крашей
    try:
        r = _run(["ip", "-br", "link", "show"])
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[0].split("@")[0]
            if not name.startswith(IFACE_PREFIX):
                continue
            state = parts[1] if len(parts) > 1 else ""
            if state == "DOWN":
                _run(["ip", "link", "delete", name])
                log.info("Удалён зомби-интерфейс: %s", name)
    except Exception as e:
        log.warning("Не удалось почистить зомби: %s", e)

    global IFACE
    iface = pick_iface()
    if iface is None:
        log.error("Нет свободных TUN интерфейсов")
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
    p = argparse.ArgumentParser(
        description="SSH TUN VPN клиент (OpenSSH subprocess, ControlMaster)")
    p.add_argument("--host",     required=True)
    p.add_argument("--port",     type=int, default=2478)
    p.add_argument("--user",     required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--mode",     choices=["tun-only", "full"], default="tun-only")
    p.add_argument("--gateway",  default=None, metavar="UUID",
                   help="UUID outbound gateway (sticky).")
    p.add_argument("--gateway-mode", default=None, choices=["id", "country"],
                   dest="gateway_mode",
                   help="Режим выбора gateway: id (по UUID) или country (по коду).")
    p.add_argument("--gateway-country", default=None, dest="gateway_country",
                   metavar="CC",
                   help="Код страны для --gateway-mode country.")
    p.add_argument("--split-tunneling", default=None, dest="split_tunneling",
                   metavar="CC",
                   help="Split tunneling: трафик для указанной страны идёт "
                        "через ближайший gateway с этой страной, остальной — напрямую.")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--mimic-real-connection", action="store_true",
                   dest="mimic_real_connection",
                   help="Перед tunnel exec прогнать интерактивную shell-сессию "
                        "(MOTD + typed heavy commands + exit) — чтобы ТСПУ "
                        "классифицировала первые KB как обычный ssh, а не "
                        "bulk-трафик с первой секунды.")
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
