import cv2
from pyzbar.pyzbar import decode
import subprocess

def scan_qr_from_screenshot():
    # Скриншот экрана
    # subprocess.run(["scrot", "/tmp/screen.png"])

    # Декодируем QR
    img  = cv2.imread("/var/www/html2/xyemax.test/max/img.png")
    qrs  = decode(img)

    for qr in qrs:
        data = qr.data.decode("utf-8")
        print(f"QR: {data}")
        if "/:auth/" in data:
            return data
    return None

url = scan_qr_from_screenshot()