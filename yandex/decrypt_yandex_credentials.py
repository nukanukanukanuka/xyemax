#!/usr/bin/env python3
"""
Дешифровка client_id и client_secret из Yandex Messenger (ИСПРАВЛЕННАЯ ВЕРСИЯ)
================================================================================

Скрипт дешифрует зашифрованные credentials из кода приложения.

Версия 2.0 - исправлены проблемы с PyCryptodome CFB режимом

Использование:
    python3 decrypt_yandex_credentials.py <encrypted_id> <encrypted_secret>

Пример:
    python3 decrypt_yandex_credentials.py \\
        "ixnjS4SWsp6DD8fshySJ/ClWdh38gE/8EyyCvNaD+qEPmlANxFG2IvCpi9PDzl/E" \\
        "iU22SNiVvsrSCJG7hy2Or80ApPky0d92/7+fYSB60nZjmc18fduySNaiLpXlwdwk"


        python3 decrypt_yandex_credentials.py "ixnjS4SWsp6DD8fshySJ/ClWdh38gE/8EyyCvNaD+qEPmlANxFG2IvCpi9PDzl/E" "iU22SNiVvsrSCJG7hy2Or80ApPky0d92/7+fYSB60nZjmc18fduySNaiLpXlwdwk"
"""

import base64
import hashlib
import sys
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    HAS_PYCRYPTO = True
except ImportError:
    HAS_PYCRYPTO = False


def generate_encryption_key():
    """
    Генерация ключа шифрования из фразы "yandex account manager"
    
    Процесс:
    1. Хешируем каждую часть фразы через SHA-256
    2. Конвертируем в hex
    3. Кодируем в UTF-8 байты
    4. XOR всех частей
    5. Base64-кодируем результат
    
    Returns:
        str: Base64-закодированный ключ (~44 символа)
    """
    phrase = "yandex account manager"
    parts = phrase.split(" ")
    
    key_bytes = bytearray(32)
    
    for part in parts:
        # SHA-256 хеширование
        hash_obj = hashlib.sha256(part.encode('utf-8'))
        hash_bytes = hash_obj.digest()
        
        # Конвертация в hex
        hex_str = ''.join(f'{b:02x}' for b in hash_bytes)
        
        # Кодирование hex строки в UTF-8
        hex_bytes = hex_str.encode('utf-8')
        
        # XOR с предыдущими данными
        for i in range(32):
            if i < len(hex_bytes):
                key_bytes[i] ^= hex_bytes[i]
    
    # Base64-кодирование ключа
    key_b64 = base64.b64encode(key_bytes).decode('utf-8')
    
    return key_b64


def decrypt_credential_aes_cfb(encrypted_str, key_b64):
    """
    Дешифровка зашифрованной строки через AES/CFB/NoPadding
    
    Args:
        encrypted_str (str): Зашифрованная строка (64 символа Base64)
        key_b64 (str): Base64-закодированный ключ
    
    Returns:
        str: Дешифрованные первые 32 символа (client_id или client_secret)
    """
    if not HAS_PYCRYPTO:
        raise RuntimeError("PyCryptodome не установлен! Установи: pip3 install pycryptodome")
    
    if len(encrypted_str) != 64:
        raise ValueError(f"Credential string must be 64 bytes long, got {len(encrypted_str)}")
    
    try:
        # Декодирование ключа из Base64
        key_bytes = base64.b64decode(key_b64)
        
        # Проверка длины ключа (AES-256 требует 32 байта)
        if len(key_bytes) != 32:
            raise ValueError(f"Key must be 32 bytes long, got {len(key_bytes)}")
        
        # Создание AES шифра (CFB mode с размером сегмента 128 бит = 16 байт)
        cipher = AES.new(
            key_bytes,
            AES.MODE_CFB,
            iv=b'\x00' * 16,  # IV: 16 байт нулей
            segment_size=128  # Размер сегмента для CFB (важно!)
        )
        
        # Дешифрование входных данных
        encrypted_bytes = base64.b64decode(encrypted_str)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        
        # Декодирование из UTF-8
        decrypted_str = decrypted_bytes.decode('utf-8')
        
        # Разделение по "^"
        parts = decrypted_str.split('^')
        
        if len(parts) < 1:
            raise ValueError("No separator '^' found in decrypted string")
        
        # Берем первые 32 символа
        result = parts[0][:32]
        
        if len(result) != 32:
            raise ValueError(f"Decrypted string must be 32 bytes long, got {len(result)}")
        
        return result
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def main():
    """
    Главная функция
    """
    if len(sys.argv) != 3:
        print("Использование:")
        print("  python3 decrypt_yandex_credentials.py <encrypted_id> <encrypted_secret>")
        print()
        print("Пример:")
        print('  python3 decrypt_yandex_credentials.py \\')
        print('    "ixnjS4SWsp6DD8fshySJ/ClWdh38gE/8EyyCvNaD+qEPmlANxFG2IvCpi9PDzl/E" \\')
        print('    "iU22SNiVvsrSCJG7hy2Or80ApPky0d92/7+fYSB60nZjmc18fduySNaiLpXlwdwk"')
        print()
        print("Для Production окружения (passport.yandex.net)")
        print()
        if not HAS_PYCRYPTO:
            print("⚠️  PyCryptodome не установлен!")
            print("   Установи: pip3 install pycryptodome")
            print()
        sys.exit(1)
    
    if not HAS_PYCRYPTO:
        print("ОШИБКА: PyCryptodome не установлен!")
        print()
        print("Установи:")
        print("  pip3 install pycryptodome")
        print()
        sys.exit(1)
    
    encrypted_id = sys.argv[1]
    encrypted_secret = sys.argv[2]
    
    print("=" * 70)
    print("Дешифровка Yandex Messenger credentials (v2.0)")
    print("=" * 70)
    print()
    
    # Генерация ключа шифрования
    print("1. Генерация ключа шифрования...")
    print(f"   Фраза: 'yandex account manager'")
    key_b64 = generate_encryption_key()
    print(f"   Ключ (Base64): {key_b64}")
    print()
    
    # Дешифровка client_id
    print("2. Дешифровка client_id...")
    try:
        client_id = decrypt_credential_aes_cfb(encrypted_id, key_b64)
        print(f"   ✓ client_id: {client_id}")
    except Exception as e:
        print(f"   ✗ ОШИБКА: {e}")
        client_id = None
    print()
    
    # Дешифровка client_secret
    print("3. Дешифровка client_secret...")
    try:
        client_secret = decrypt_credential_aes_cfb(encrypted_secret, key_b64)
        print(f"   ✓ client_secret: {client_secret}")
    except Exception as e:
        print(f"   ✗ ОШИБКА: {e}")
        client_secret = None
    print()
    
    # Результат
    print("=" * 70)
    print("РЕЗУЛЬТАТ:")
    print("=" * 70)
    print()
    
    if client_id and client_secret:
        print("✓ Дешифровка успешна!")
        print()
        print(f"client_id:      {client_id}")
        print(f"client_secret:  {client_secret}")
        print()
        print("=" * 70)
        print("HTTP запрос к Passport API:")
        print("=" * 70)
        print()
        print(f'curl -X POST https://passport.yandex.net/1/external_auth_by_password \\')
        print(f'  -H "Content-Type: application/x-www-form-urlencoded" \\')
        print(f'  -d "client_id={client_id}" \\')
        print(f'  -d "client_secret={client_secret}" \\')
        print(f'  -d "email=your@email.com" \\')
        print(f'  -d "password=your_password"')
        print()
    else:
        print("✗ Дешифровка не удалась!")
        print("Проверьте правильность зашифрованных строк.")
        print()
        print("Возможные причины:")
        print("  1. Неверная зашифрованная строка (должна быть 64 символа)")
        print("  2. PyCryptodome не установлен")
        print("  3. Несовпадение алгоритмов шифрования")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
