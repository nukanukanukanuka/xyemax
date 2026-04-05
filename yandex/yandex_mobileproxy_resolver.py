#!/usr/bin/env python3
"""
DNS Resolution для Yandex Passport Mobileproxy
==========================================

Скрипт ресолвит IP адреса для mobileproxy серверов Яндекса.

Использование:
    python3 yandex_mobileproxy_resolver.py [--region DEFAULT|FI|KZ|RC]

Примеры:
    python3 yandex_mobileproxy_resolver.py
    python3 yandex_mobileproxy_resolver.py --region FI
    python3 yandex_mobileproxy_resolver.py --region KZ
"""

import socket
import sys
from typing import List, Dict, Tuple


class YandexMobileProxyResolver:
    """Класс для DNS resolution mobileproxy серверов Яндекса"""
    
    def __init__(self, timeout: float = 5.0):
        """
        Инициализация
        
        Args:
            timeout (float): Тайм-аут соединения в секундах
        """
        self.timeout = timeout
        self.regions = {
            "DEFAULT": "mobileproxy.passport.yandex.net",
            "FI": "mobileproxy.fi.passport.yandex.net",
            "KZ": "mobileproxy.kz.passport.yandex.net",
            "RC": "mobileproxy-rc.passport.yandex.net",
            "TEAM_TESTING": "mobileproxy-yateam-test.passport.yandex.net",
            "TESTING": "mobileproxy-test.passport.yandex.net",
        }
        
        print("=" * 70)
        print("🌐 DNS RESOLUTION - YANDEX PASSPORT MOBILEPROXY")
        print("=" * 70)
        print()
    
    def resolve_domain(self, domain: str) -> List[str]:
        """
        Ресолвит IP адреса для домена
        
        Args:
            domain (str): Домен для ресолвинга
        
        Returns:
            List[str]: Список IP адресов
        """
        print(f"🔍 Ресолвинг: {domain}")
        print(f"⏱ Тайм-аут: {self.timeout} секунд")
        print()
        
        ip_addresses = []
        
        try:
            # Получаем информацию о домене
            info = socket.getaddrinfo(domain, None)
            
            # Экстрактим IP адреса из результатов
            for addr_info in info:
                # addr_info[4] = (address, port, flow, scopeaddr)
                address = addr_info[4][0]
                ip_addresses.append(address)
                
            # Удаляем дубликаты, сохраняя порядок
            ip_addresses = list(dict.fromkeys(ip_addresses).keys())
            
            # Ограничиваем до 10 IP адресов
            ip_addresses = ip_addresses[:10]
            
            if ip_addresses:
                print("✅ Успешно получены IP адреса:")
                for i, ip in enumerate(ip_addresses, 1):
                    print(f"   {i}. {ip}")
                print()
                return ip_addresses
            else:
                print("❌ Не удалось получить IP адреса!")
                print()
                return []
                
        except socket.gaierror as e:
            print(f"❌ Ошибка DNS: {e}")
            print(f"   Тип ошибки: DNS resolution failed")
            print()
            return []
        except socket.timeout as e:
            print(f"❌ Тайм-аут соединения: {e}")
            print()
            return []
        except Exception as e:
            print(f"❌ Неизвестная ошибка: {e}")
            print()
            return []
    
    def resolve_all_regions(self) -> Dict[str, List[str]]:
        """
        Ресолвит IP адреса для всех регионов
        
        Returns:
            Dict[str, List[str]]: Словарь {регион: [IP адреса]}
        """
        print("=" * 70)
        print("🌍 РЕСОЛВИНИЕ ВСЕХ РЕГИОНОВ")
        print("=" * 70)
        print()
        
        results = {}
        
        for region, domain in self.regions.items():
            print(f"📍 Регион: {region}")
            ips = self.resolve_domain(domain)
            
            if ips:
                results[region] = ips
            else:
                print(f"⚠️  Пропускаем регион {region} — не удалось ресолвить")
                print()
        
        return results
    
    def resolve_region(self, region: str = "DEFAULT") -> Tuple[str, List[str]]:
        """
        Ресолвит IP адреса для указанного региона
        
        Args:
            region (str): Окружение (DEFAULT, FI, KZ, RC, TEAM_TESTING, TESTING)
        
        Returns:
            Tuple[str, List[str]]: (домен, IP адреса)
        """
        print("=" * 70)
        print(f"📍 РЕГИОН: {region}")
        print("=" * 70)
        print()
        
        domain = self.regions.get(region.upper())
        
        if not domain:
            print(f"❌ Неверный регион: {region}")
            print()
            print(f"✅ Доступные регионы:")
            for r in self.regions.keys():
                print(f"   • {r}")
            print()
            return ("", [])
        
        print(f"🌐 Домен: {domain}")
        print()
        
        ips = self.resolve_domain(domain)
        
        return (domain, ips)
    
    def show_final_result(self, results: Dict[str, List[str]]) -> None:
        """
        Покажет финальный результат
        
        Args:
            results (Dict[str, List[str]]): Результаты ресолвинга
        """
        print("=" * 70)
        print("📋 ФИНАЛЬНЫЙ РЕЗУЛЬТАТ")
        print("=" * 70)
        print()
        
        if not results:
            print("❌ Не удалось ресолвить ни один IP адрес!")
            print()
            return
        
        for region, ips in results.items():
            print(f"📍 {region}:")
            print(f"   🌐 Домен: {self.regions[region]}")
            print(f"   📍 IP адреса:")
            for ip in ips:
                print(f"      • {ip}")
            print()
        
        print("=" * 70)
        print(f"📊 Всего регионов: {len(results)}")
        print(f"📊 Всего IP адресов: {sum(len(ips) for ips in results.values())}")
        print()
    
    def test_tcp_connection(self, ip: str, port: int = 443) -> bool:
        """
        Тестирует TCP соединение к IP адресу
        
        Args:
            ip (str): IP адрес
            port (int): Порт (по умолчанию: 443)
        
        Returns:
            bool: True если соединение успешно, False если нет
        """
        print(f"🔌 Тест TCP соединения: {ip}:{port}")
        print()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                print("✅ TCP соединение успешно!")
                print()
                return True
            else:
                print(f"❌ TCP соединение не удалось! Код ошибки: {result}")
                print()
                return False
                
        except socket.timeout:
            print("❌ Тайм-аут соединения!")
            print()
            return False
        except Exception as e:
            print(f"❌ Ошибка соединения: {e}")
            print()
            return False


def main():
    """Главная функция"""
    
    # Парсинг аргументов командной строки
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Использование:")
        print("  python3 yandex_mobileproxy_resolver.py [--region <регион>] [--all]")
        print()
        print("Опции:")
        print("  --region <регион>  Регион для ресолвинга")
        print("                       DEFAULT (Россия)")
        print("                       FI (Финляндия)")
        print("                       KZ (Казахстан)")
        print("                       RC (Release Candidate)")
        print("                       TESTING (Test environment)")
        print("  --all                Ресолвить все регионы")
        print()
        print("Примеры:")
        print("  # Ресолвить DEFAULT регион")
        print("  python3 yandex_mobileproxy_resolver.py")
        print()
        print("  # Ресолвить FI регион")
        print("  python3 yandex_mobileproxy_resolver.py --region FI")
        print()
        print("  # Ресолвить все регионы")
        print("  python3 yandex_mobileproxy_resolver.py --all")
        print()
        print("Доступные регионы:")
        print("  DEFAULT   - Россия")
        print("  FI        - Финляндия")
        print("  KZ        - Казахстан")
        print("  RC        - Release Candidate")
        print("  TESTING   - Test environment")
        print()
        return
    
    # Проверяем флаг --all
    resolve_all = "--all" in sys.argv
    
    # Парсинг региона если указан
    region = None
    if "--region" in sys.argv:
        try:
            region_index = sys.argv.index("--region") + 1
            region = sys.argv[region_index]
        except (ValueError, IndexError):
            print("❌ Ошибка: Неверный формат параметра --region")
            print()
            print("Используйте:")
            print("  python3 yandex_mobileproxy_resolver.py --region <регион>")
            print()
            return
    
    # Создаем резолвер
    try:
        resolver = YandexMobileProxyResolver(timeout=5.0)
    except Exception as e:
        print(f"❌ Ошибка инициализации резолвера: {e}")
        return
    
    # Ресолвинг
    if resolve_all:
        # Ресолвим все регионы
        results = resolver.resolve_all_regions()
        
        # Покажем финальный результат
        resolver.show_final_result(results)
    elif region:
        # Ресолвим указанный регион
        domain, ips = resolver.resolve_region(region)
        
        if domain and ips:
            print("=" * 70)
            print("📋 РЕЗУЛЬТАТ РЕСОЛВИНГА")
            print("=" * 70)
            print()
            print(f"📍 Регион: {region.upper()}")
            print(f"🌐 Домен: {domain}")
            print(f"📍 IP адреса:")
            for ip in ips:
                print(f"   • {ip}")
            print()
            
            # Тест TCP соединения
            if ips:
                print("=" * 70)
                print(f"🔌 ТЕСТ TCP СОЕДИНЕНИЯ С ПЕРВЫМ IP: {ips[0]}:443")
                print("=" * 70)
                resolver.test_tcp_connection(ips[0], 443)
        else:
            print("❌ Не удалось ресолвить IP адреса для региона!")
    else:
        # По умолчанию - ресолвим DEFAULT регион
        domain, ips = resolver.resolve_region("DEFAULT")
        
        if domain and ips:
            print("=" * 70)
            print("📋 РЕЗУЛЬТАТ РЕСОЛВИНГА")
            print("=" * 70)
            print()
            print(f"📍 Регион: DEFAULT (Россия)")
            print(f"🌐 Домен: {domain}")
            print(f"📍 IP адреса:")
            for ip in ips:
                print(f"   • {ip}")
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("=" * 70)
        print("❌ ОТМЕНЕНО Пользователем")
        print("=" * 70)
        print()
    except Exception as e:
        print()
        print("=" * 70)
        print(f"❌ КРИТИЧЕСКАЯ ОШИБКА: {e}")
        print("=" * 70)
        print()
