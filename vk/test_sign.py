import requests
import uuid
import hmac
import hashlib
import base64

DEVICE_ID = str(uuid.uuid4())
HEADERS_BASE = {
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "User-Agent": "VKAndroidApp/8.52-7543 (Android 14; SDK 34; arm64-v8a; Samsung SM-A515F; ru; 2400x1080)",
    "X-VK-Android-Client": "new",
    "X-Screen": "login",
}

print(f"device_id: {DEVICE_ID}\n")

# Step 0
print("--- Step 0: getAnonymToken ---")
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
print(f"HTTP {r.status_code}: {r.text}\n")
anon_token = r.json()["response"]["token"]

# Step 1
print("--- Step 1: get_hashes ---")
r = requests.post(
    "https://api.vk.com/oauth/get_hashes",
    headers=HEADERS_BASE,
    data={"anonymous_token": anon_token, "device_id": DEVICE_ID}
)
print(f"HTTP {r.status_code}: {r.text}\n")
nonce = r.json()["nonce"]

# Вычисляем подпись — вариант A: msg = полный токен с "anonym."
jwt_full = anon_token
sig_a = base64.b64encode(hmac.new(nonce.encode(), jwt_full.encode(), hashlib.sha256).digest()).decode()

# Вариант B: msg = JWT без "anonym."
jwt_no_prefix = anon_token.removeprefix("anonym.")
sig_b = base64.b64encode(hmac.new(nonce.encode(), jwt_no_prefix.encode(), hashlib.sha256).digest()).decode()

# Вариант C: МУСОР — проверяем, валидирует ли сервер подпись вообще
sig_garbage = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

for label, sig in [("A: full token", sig_a), ("B: jwt no prefix", sig_b), ("C: garbage", sig_garbage)]:
    print(f"--- Step 1b [{label}] ---")
    print(f"signature_base64: {sig}")
    r = requests.post(
        "https://api.vk.com/oauth/sign_anonymous_token",
        headers={**HEADERS_BASE, "Authorization": f"Bearer {anon_token}"},
        data={"signature_base64": sig, "device_id": DEVICE_ID, "lang": "ru", "https": "1"}
    )
    print(f"HTTP {r.status_code}: {r.text}\n")
