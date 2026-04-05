import requests
import uuid

PHONE = input("Телефон (+7...): ").strip()
DEVICE_ID = str(uuid.uuid4())
HEADERS_BASE = {
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "User-Agent": "VKAndroidApp/8.52-7543 (Android 14; SDK 34; arm64-v8a; Samsung SM-A515F; ru; 2400x1080)",
    "X-VK-Android-Client": "new",
    "X-Screen": "login",
}

print(f"\ndevice_id: {DEVICE_ID}")
print(f"current IP: ", end="", flush=True)
print(requests.get("https://api.ipify.org").text)

# Step 0
print("\n--- Step 0: getAnonymToken ---")
r = requests.post(
    "https://api.vk.com/method/auth.getAnonymToken",
    headers=HEADERS_BASE,
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

# Step 2 — validatePhone без подписи
print("\n--- Step 2: auth.validatePhone (unsigned token) ---")
r = requests.post(
    "https://api.vk.com/method/auth.validatePhone",
    headers={**HEADERS_BASE, "Authorization": f"Bearer {anon_token}"},
    data={
        "v": "5.131", "https": "1", "lang": "ru",
        "phone": PHONE,
        "supported_ways": "push,email,sms_inbox,call_in",
        "allow_callreset": "1",
        "client_id": "2274003",
        "device_id": DEVICE_ID,
    }
)
print(f"HTTP {r.status_code}: {r.text}")
