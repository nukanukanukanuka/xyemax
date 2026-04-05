import requests
import uuid

PHONE    = input("Телефон (+7...): ").strip()
PASSWORD = input("Пароль: ").strip()
DEVICE_ID = str(uuid.uuid4())

HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "User-Agent": "VKAndroidApp/8.52-7543 (Android 14; SDK 34; arm64-v8a; Samsung SM-A515F; ru; 2400x1080)",
    "X-VK-Android-Client": "new",
    "X-Screen": "login",
}

print(f"\ndevice_id: {DEVICE_ID}")
print("current IP:", requests.get("https://api.ipify.org").text)

# Step 0 — anonymous token
print("\n--- Step 0: getAnonymToken ---")
r = requests.post(
    "https://api.vk.com/method/auth.getAnonymToken",
    headers=HEADERS,
    data={
        "v": "5.131", "https": "1", "lang": "ru",
        "client_id": "2274003",
        "client_secret": "hHbZxrka2uZ6jB1inYsH",
        "device_id": DEVICE_ID,
        "client_type": "SDK_ANDROID",
        "client_version": "android_8",
    }
)
print(f"HTTP {r.status_code}: {r.text}")
anon_token = r.json()["response"]["token"]

# Step 4 — прямой логин с паролем (без OTP)
print("\n--- Step 4: /oauth/token (grant_type=password) ---")
r = requests.post(
    "https://api.vk.com/oauth/token",
    headers=HEADERS,
    data={
        "grant_type":     "password",
        "username":       PHONE,
        "password":       PASSWORD,
        "client_id":      "2274003",
        "client_secret":  "hHbZxrka2uZ6jB1inYsH",
        "device_id":      DEVICE_ID,
        "2fa_supported":  "1",
        "supported_ways": "push,email,sms_inbox,call_in",
        "anonymous_token": anon_token,
        "v":              "5.131",
    }
)
print(f"HTTP {r.status_code}: {r.text}")
