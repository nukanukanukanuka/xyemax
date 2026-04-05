#!/bin/bash
# Установка SSH tunnel клиента

set -e

CLIENT_PATH="/var/www/html2/xyemax.test/ssh-daemon/client.py"
PYTHON="/usr/bin/python3.12"
USER=$(whoami)

echo "Настройка беспарольного sudo для SSH tunnel клиента..."
echo "Скрипт попросит пароль sudo один раз."

# Создаём файл в sudoers.d с правильными правами
echo "$USER ALL=(ALL) NOPASSWD: $PYTHON $CLIENT_PATH *" | sudo tee /etc/sudoers.d/ssh-tunnel-client > /dev/null
sudo chmod 0440 /etc/sudoers.d/ssh-tunnel-client

# Проверяем конфигурацию
sudo visudo -c > /dev/null 2>&1 || {
    echo "Ошибка в конфигурации sudoers. Удаляю файл..."
    sudo rm /etc/sudoers.d/ssh-tunnel-client
    exit 1
}

echo "✓ Готово. Теперь можно запускать:"
echo "  sudo python3.12 /var/www/html2/xyemax.test/ssh-daemon/client.py --host ..."
echo "  (без ввода пароля)"
