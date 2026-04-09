#!/usr/bin/env python3
"""
SSH Tunnel Detection via Entropy & Behavioral Analysis
Анализирует PCAP файл на признаки SSH-туннеля внутри SSH-соединения.

Требования:
    pip install scapy numpy scipy

Использование:
    python3 ssh_tunnel_detect.py capture.pcap
    python3 ssh_tunnel_detect.py capture.pcap --json          # JSON-вывод
    python3 ssh_tunnel_detect.py capture.pcap --threshold 0.6 # порог вероятности
"""

import sys
import math
import argparse
import json
import struct
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.layers.inet import TCP as ScapyTCP
except ImportError:
    print("[ERROR] scapy не установлен: pip install scapy")
    sys.exit(1)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# ─── Константы ────────────────────────────────────────────────────────────────

# Пороги энтропии
# ВАЖНО: обычный SSH после key exchange тоже даёт ~7.9-8.0 бит/байт (шифрование
# делает трафик равномерным). Энтропия — слабый признак для SSH-в-SSH.
# Используем её только как дополнительный индикатор, не как основной.
ENTROPY_NORMAL_SSH   = (7.0, 8.0)   # реальный диапазон для любого SSH (после хендшейка ≈8)
ENTROPY_TUNNEL_MIN   = 7.95         # SSH-в-SSH почти не отличается по энтропии
ENTROPY_RANDOM_MIN   = 7.99         # практически невозможно отличить от обычного SSH

# Поведенческие пороги — ГЛАВНЫЕ признаки туннеля (по исследованию Trisul/RFC4253)
# SSH keystroke без туннеля: 36-48 байт на пакет
# SSH keystroke через туннель: 76-98 байт (SSH header + [inner SSH pkt] + HMAC)
LARGE_PKT_RATIO_THRESHOLD  = 0.15   # >15% пакетов > 1024 байт → подозрительно
SUSTAINED_BULK_THRESHOLD   = 5      # серий крупных пакетов подряд
INTER_ARRIVAL_CV_THRESHOLD = 1.5    # коэффициент вариации IAT

# Паттерн SSH-в-SSH keystroke (размеры пакетов туннельного нажатия клавиши)
# Источник: John B. Althouse III / Trisul research
TUNNEL_KEYSTROKE_SIZES = list(range(68, 104, 4))  # 68,72,76,80,84,88,92,96,100 байт
TUNNEL_KEYSTROKE_MIN_STREAK = 6   # минимум 6 таких пакетов подряд = паттерн туннеля
DIRECT_KEYSTROKE_MAX = 52         # прямой SSH keystroke не превышает ~52 байт

SSH_BANNER_SIGNATURES = [b"SSH-", b"OpenSSH", b"libssh", b"dropbear"]

# ─── Структуры данных ─────────────────────────────────────────────────────────

@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port)

    def reverse(self):
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port)

@dataclass
class FlowStats:
    packets: list = field(default_factory=list)          # (timestamp, size, payload_bytes)
    payloads: list = field(default_factory=list)          # bytes
    timestamps: list = field(default_factory=list)
    sizes: list = field(default_factory=list)
    ssh_banner_seen: bool = False
    ssh_client: str = ""
    ssh_server: str = ""

@dataclass
class AnalysisResult:
    flow_id: str
    src: str
    dst: str
    duration_sec: float
    total_packets: int
    total_bytes: int
    avg_pkt_size: float

    # Энтропия
    entropy_mean: float
    entropy_std: float
    entropy_max: float
    entropy_above_threshold: float   # доля окон с высокой энтропией

    # Поведение
    large_pkt_ratio: float
    bulk_burst_count: int
    iat_cv: float                    # coefficient of variation межпакетного времени
    upload_download_ratio: float
    keystroke_patterns: int          # кол-во SSH-в-SSH keystroke паттернов (метод Althouse)
    max_keystroke_streak: int        # максимальная серия туннельных пакетов

    # SSH специфика
    ssh_banner_detected: bool
    ssh_client_fingerprint: str
    match_by_port_only: bool

    # Итог
    tunnel_score: float              # 0.0 – 1.0
    tunnel_probability: str          # LOW / MEDIUM / HIGH / VERY HIGH
    indicators: list = field(default_factory=list)

# ─── Функции анализа ──────────────────────────────────────────────────────────

def byte_entropy(data: bytes) -> float:
    """Шеннонова энтропия в битах на байт (0–8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def windowed_entropy(payload: bytes, window: int = 256) -> list:
    """Энтропия по скользящим окнам."""
    if len(payload) < window:
        return [byte_entropy(payload)] if payload else []
    return [byte_entropy(payload[i:i+window]) for i in range(0, len(payload) - window, window // 2)]


def detect_ssh_banner(payload: bytes) -> tuple[bool, str]:
    """Обнаружение SSH-баннера и версии клиента/сервера."""
    for sig in SSH_BANNER_SIGNATURES:
        if sig in payload:
            try:
                idx = payload.index(sig)
                end = payload.index(b"\n", idx) if b"\n" in payload[idx:] else idx + 64
                banner = payload[idx:end].decode("ascii", errors="replace").strip()
                return True, banner
            except Exception:
                return True, ""
    return False, ""


def compute_iat_cv(timestamps: list) -> float:
    """Коэффициент вариации межпакетных интервалов."""
    if len(timestamps) < 3:
        return 0.0
    iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1) if timestamps[i+1] > timestamps[i]]
    if not iats:
        return 0.0
    mean = sum(iats) / len(iats)
    if mean == 0:
        return 0.0
    variance = sum((x - mean)**2 for x in iats) / len(iats)
    return math.sqrt(variance) / mean


def detect_tunnel_keystroke_pattern(sizes: list) -> tuple[int, int]:
    """
    Детектирует паттерн SSH-в-SSH keystroke по размерам пакетов.

    Источник: John B. Althouse III / Trisul research:
    - Прямой SSH keystroke: 36-52 байт (header + 1 байт + padding + HMAC)
    - Туннельный keystroke: 68-104 байт (header + [inner SSH pkt] + HMAC)

    Возвращает: (количество найденных паттернов, длина максимальной серии)
    """
    pattern_count = 0
    max_streak = 0
    current_streak = 0

    for s in sizes:
        tcp_payload = s - 40  # вычитаем IP+TCP заголовки
        if tcp_payload in TUNNEL_KEYSTROKE_SIZES:
            current_streak += 1
            if current_streak >= TUNNEL_KEYSTROKE_MIN_STREAK:
                pattern_count += 1
                current_streak = 0  # сбрасываем чтобы не считать перекрытия
        else:
            max_streak = max(max_streak, current_streak)
            current_streak = 0

    max_streak = max(max_streak, current_streak)
    return pattern_count, max_streak


def score_flow(stats: FlowStats, flow_id: str, src: str, dst: str) -> AnalysisResult:
    """Вычисляет вероятность туннеля для потока."""
    payloads = stats.payloads
    timestamps = stats.timestamps
    sizes = stats.sizes

    total_bytes = sum(sizes)
    total_pkts = len(sizes)
    avg_size = total_bytes / total_pkts if total_pkts else 0
    duration = (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0

    # Энтропия
    all_payload = b"".join(payloads)
    windows = windowed_entropy(all_payload, window=512)
    if windows:
        e_mean = sum(windows) / len(windows)
        e_max = max(windows)
        if HAS_NUMPY and len(windows) > 1:
            e_std = float(np.std(windows))
        else:
            mean = e_mean
            e_std = math.sqrt(sum((x - mean)**2 for x in windows) / len(windows)) if len(windows) > 1 else 0.0
        e_above = sum(1 for e in windows if e > ENTROPY_TUNNEL_MIN) / len(windows)
    else:
        e_mean = e_max = e_std = e_above = 0.0

    # Поведение
    large_pkts = sum(1 for s in sizes if s > 1024)
    large_ratio = large_pkts / total_pkts if total_pkts else 0

    # Серии крупных пакетов (burst)
    burst_count = 0
    current_burst = 0
    for s in sizes:
        if s > 512:
            current_burst += 1
            if current_burst >= SUSTAINED_BULK_THRESHOLD:
                burst_count += 1
                current_burst = 0
        else:
            current_burst = 0

    iat_cv = compute_iat_cv(timestamps)

    # Keystroke pattern (SSH-в-SSH fingerprint по размерам пакетов)
    keystroke_patterns, max_keystroke_streak = detect_tunnel_keystroke_pattern(sizes)

    # Upload/download ratio (по направлению потока — упрощённо по размеру окон)
    # Реальный анализ требует отслеживания направления пакетов
    upload_download_ratio = 1.0  # нейтральное значение без двунаправленного анализа

    # ─── Скоринг ──────────────────────────────────────────────────────────────
    # Веса основаны на исследованиях:
    # - Trisul/Althouse: главный признак — размеры пакетов (keystroke fingerprint)
    # - MDPI 2024: энтропия SSH ≈ 8 бит/байт в любом случае → слабый признак
    # - RFC4253: OpenSSH не реализует random padding → паттерны видны на wire
    score = 0.0
    indicators = []

    # 1. ГЛАВНЫЙ ПРИЗНАК: паттерн SSH-в-SSH keystroke по размерам пакетов
    #    Метод Althouse: пакеты 68-104 байт сериями = туннель с интерактивным TTY
    if keystroke_patterns >= 5:
        score += 0.40
        indicators.append(f"⚡ SSH-в-SSH keystroke паттерн: {keystroke_patterns} серий по {TUNNEL_KEYSTROKE_MIN_STREAK}+ пакетов (68-104 байт) — высокая уверенность в туннеле")
    elif keystroke_patterns >= 2:
        score += 0.25
        indicators.append(f"SSH-в-SSH keystroke паттерн: {keystroke_patterns} серии (пакеты 68-104 байт)")
    elif max_keystroke_streak >= 3:
        score += 0.10
        indicators.append(f"Частичный keystroke паттерн: серия {max_keystroke_streak} пакетов туннельного размера")

    # 2. ГЛАВНЫЙ ПРИЗНАК: доля крупных пакетов (bulk transfer через туннель)
    if large_ratio > 0.30:
        score += 0.25
        indicators.append(f"Высокая доля крупных пакетов (>1024 байт): {large_ratio*100:.1f}% — характерно для bulk transfer через туннель")
    elif large_ratio > LARGE_PKT_RATIO_THRESHOLD:
        score += 0.15
        indicators.append(f"Повышенная доля крупных пакетов: {large_ratio*100:.1f}% (норма <15%)")

    # 3. Пачки крупных пакетов (bulk transfer)
    if burst_count > 10:
        score += 0.20
        indicators.append(f"Bulk-серий ({SUSTAINED_BULK_THRESHOLD}+ крупных подряд): {burst_count} — массовая передача данных через туннель")
    elif burst_count > 3:
        score += 0.12
        indicators.append(f"Bulk-серий: {burst_count}")

    # 4. СЛАБЫЙ ПРИЗНАК: энтропия
    #    После хендшейка любой SSH имеет энтропию ≈7.9-8.0 бит/байт.
    #    SSH-в-SSH практически неотличим по этому признаку.
    #    Небольшой бонус только если энтропия аномально низкая (сигнал о проблемах).
    if e_mean < 7.0 and e_mean > 0:
        score += 0.05
        indicators.append(f"Низкая энтропия для SSH: {e_mean:.2f} бит/байт (возможно частично незашифрованный контент)")
    # Информационно показываем, но не влияет на score при высоких значениях
    if e_mean > 7.5:
        indicators.append(f"ℹ Энтропия: {e_mean:.2f} бит/байт (норма для любого SSH после хендшейка ≈7.9-8.0, не является признаком туннеля)")

    # 5. IAT — вспомогательный признак
    #    Для -D туннеля (SOCKS proxy) IAT нерегулярен из-за разных HTTP-запросов
    if iat_cv > 2.0:
        score += 0.08
        indicators.append(f"Высокая нерегулярность межпакетных интервалов: CV={iat_cv:.2f} — нетипично для интерактивного SSH")
    elif iat_cv > INTER_ARRIVAL_CV_THRESHOLD:
        score += 0.04
        indicators.append(f"Умеренная нерегулярность IAT: CV={iat_cv:.2f}")

    # 6. Длинная сессия с большим средним пакетом
    if avg_size > 600 and duration > 60:
        score += 0.12
        indicators.append(f"Долгая сессия ({duration:.0f}с) с большим средним пакетом ({avg_size:.0f} байт) — нетипично для интерактивного SSH")
    elif avg_size > 400 and duration > 30:
        score += 0.06
        indicators.append(f"Повышенный средний пакет ({avg_size:.0f} байт) при сессии {duration:.0f}с")
    # 7. SSH-баннер не обнаружен (match by port only)
    match_by_port = not stats.ssh_banner_seen
    if match_by_port:
        score += 0.10
        indicators.append("SSH-баннер не обнаружен в захваченном трафике (определён только по порту)")

    # 8. Длительность + объём
    if total_bytes > 1_000_000 and duration > 120:
        score += 0.05
        indicators.append(f"Большой объём данных ({total_bytes/1024:.0f} КБ за {duration:.0f}с) — нетипично для интерактивной сессии")

    # Нормировка
    score = min(score, 1.0)

    if score >= 0.75:
        probability = "VERY HIGH"
    elif score >= 0.50:
        probability = "HIGH"
    elif score >= 0.30:
        probability = "MEDIUM"
    else:
        probability = "LOW"

    return AnalysisResult(
        flow_id=flow_id,
        src=src,
        dst=dst,
        duration_sec=round(duration, 2),
        total_packets=total_pkts,
        total_bytes=total_bytes,
        avg_pkt_size=round(avg_size, 1),
        entropy_mean=round(e_mean, 4),
        entropy_std=round(e_std, 4),
        entropy_max=round(e_max, 4),
        entropy_above_threshold=round(e_above, 4),
        large_pkt_ratio=round(large_ratio, 4),
        bulk_burst_count=burst_count,
        iat_cv=round(iat_cv, 4),
        upload_download_ratio=round(upload_download_ratio, 4),
        keystroke_patterns=keystroke_patterns,
        max_keystroke_streak=max_keystroke_streak,
        ssh_banner_detected=stats.ssh_banner_seen,
        ssh_client_fingerprint=stats.ssh_client or stats.ssh_server,
        match_by_port_only=match_by_port,
        tunnel_score=round(score, 4),
        tunnel_probability=probability,
        indicators=indicators,
    )

# ─── Парсинг PCAP ─────────────────────────────────────────────────────────────

def parse_pcap(path: str) -> dict:
    """Читает PCAP и группирует пакеты по потокам."""
    print(f"[*] Читаем PCAP: {path}")
    try:
        packets = rdpcap(path)
    except Exception as e:
        print(f"[ERROR] Не удалось прочитать файл: {e}")
        sys.exit(1)

    flows = defaultdict(FlowStats)
    total = len(packets)

    for i, pkt in enumerate(packets, 1):
        if i % 1000 == 0:
            print(f"    ... обработано {i}/{total} пакетов", end="\r")

        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]

        fk = FlowKey(ip.src, ip.dst, tcp.sport, tcp.dport)
        rfk = fk.reverse()

        # Нормализуем в одном направлении
        canonical = fk if (fk.src_ip, fk.src_port) < (rfk.src_ip, rfk.src_port) else rfk

        fs = flows[canonical]
        fs.timestamps.append(float(pkt.time))
        fs.sizes.append(len(pkt))

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            fs.payloads.append(payload)

            # Проверяем SSH-баннер
            if not fs.ssh_banner_seen:
                found, banner = detect_ssh_banner(payload)
                if found:
                    fs.ssh_banner_seen = True
                    if b"SSH-" in payload:
                        if canonical.dst_port == 22 or canonical.dst_port == 2222:
                            fs.ssh_server = banner
                        else:
                            fs.ssh_client = banner

    print(f"\n[*] Найдено потоков: {len(flows)}")
    return flows


# ─── Вывод ────────────────────────────────────────────────────────────────────

COLORS = {
    "VERY HIGH": "\033[91m",  # red
    "HIGH":      "\033[93m",  # yellow
    "MEDIUM":    "\033[94m",  # blue
    "LOW":       "\033[92m",  # green
    "RESET":     "\033[0m",
    "BOLD":      "\033[1m",
    "DIM":       "\033[2m",
}

PROB_EMOJI = {
    "VERY HIGH": "🔴",
    "HIGH":      "🟠",
    "MEDIUM":    "🟡",
    "LOW":       "🟢",
}


def print_result(r: AnalysisResult, use_color: bool = True):
    C = COLORS if use_color else defaultdict(str)
    emoji = PROB_EMOJI.get(r.tunnel_probability, "⚪")

    print(f"\n{'─'*65}")
    print(f"{C['BOLD']}Поток: {r.flow_id}{C['RESET']}")
    print(f"  {r.src}  →  {r.dst}")
    print(f"  Длительность: {r.duration_sec}с  |  Пакетов: {r.total_packets}  |  Байт: {r.total_bytes:,}")
    print(f"  Средний пакет: {r.avg_pkt_size} байт")
    print()
    print(f"  {C['BOLD']}Энтропия:{C['RESET']}")
    print(f"    Среднее: {r.entropy_mean:.3f} бит/байт  |  Макс: {r.entropy_max:.3f}  |  Std: {r.entropy_std:.3f}")
    print(f"    Окон с высокой энтропией (>{ENTROPY_TUNNEL_MIN}): {r.entropy_above_threshold*100:.1f}%")
    print()
    print(f"  {C['BOLD']}Поведение:{C['RESET']}")
    print(f"    Крупных пакетов (>1024): {r.large_pkt_ratio*100:.1f}%")
    print(f"    Bulk-серий:              {r.bulk_burst_count}")
    print(f"    IAT коэф. вариации:      {r.iat_cv:.3f}")
    print(f"    SSH-в-SSH keystroke:     паттернов={r.keystroke_patterns}  макс.серия={r.max_keystroke_streak} пакетов")
    print(f"    SSH баннер обнаружен:    {'да' if r.ssh_banner_detected else 'нет'}")
    if r.ssh_client_fingerprint:
        print(f"    Фингерпринт:             {r.ssh_client_fingerprint}")
    print()

    col = C.get(r.tunnel_probability, "")
    print(f"  {C['BOLD']}Вероятность туннеля:{C['RESET']} {col}{emoji} {r.tunnel_probability} (score={r.tunnel_score:.2f}){C['RESET']}")

    if r.indicators:
        print(f"\n  {C['BOLD']}Индикаторы:{C['RESET']}")
        for ind in r.indicators:
            print(f"    {C['DIM']}•{C['RESET']} {ind}")


def print_summary(results: list, threshold: float):
    print(f"\n{'═'*65}")
    print(f"  ИТОГО: проанализировано потоков: {len(results)}")
    suspicious = [r for r in results if r.tunnel_score >= threshold]
    print(f"  Подозрительных (score ≥ {threshold}): {len(suspicious)}")
    for r in suspicious:
        emoji = PROB_EMOJI.get(r.tunnel_probability, "⚪")
        print(f"    {emoji} {r.flow_id}  score={r.tunnel_score:.2f}  [{r.tunnel_probability}]")
    print(f"{'═'*65}\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SSH Tunnel Detection via Entropy & Behavioral Analysis"
    )
    parser.add_argument("pcap", help="Путь к PCAP файлу")
    parser.add_argument("--json", action="store_true", help="Вывод в JSON формате")
    parser.add_argument("--threshold", type=float, default=0.40,
                        help="Порог вероятности для выделения подозрительных потоков (0.0–1.0, по умолчанию 0.40)")
    parser.add_argument("--no-color", action="store_true", help="Отключить цветной вывод")
    args = parser.parse_args()

    flows = parse_pcap(args.pcap)

    if not flows:
        print("[!] Не найдено TCP-потоков в файле.")
        sys.exit(0)

    results = []
    for fk, fs in flows.items():
        if len(fs.timestamps) < 5:
            continue  # слишком мало пакетов для анализа
        flow_id = f"{fk.src_ip}:{fk.src_port} → {fk.dst_ip}:{fk.dst_port}"
        src = f"{fk.src_ip}:{fk.src_port}"
        dst = f"{fk.dst_ip}:{fk.dst_port}"
        result = score_flow(fs, flow_id, src, dst)
        results.append(result)

    # Сортировка по убыванию score
    results.sort(key=lambda r: r.tunnel_score, reverse=True)

    if args.json:
        print(json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2))
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        print(f"\n{'═'*65}")
        print("  SSH TUNNEL DETECTION — ENTROPY & BEHAVIORAL ANALYSIS")
        print(f"{'═'*65}")
        for r in results:
            print_result(r, use_color=use_color)
        print_summary(results, args.threshold)


if __name__ == "__main__":
    main()