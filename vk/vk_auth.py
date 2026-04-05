#!/usr/bin/env python3
"""
VK Auth — Phone + SMS (+ без пароля / новый аккаунт)
Основан на актуальной документации VK Android APK.

Использование:
    python vk_auth.py +79001234567
    python vk_auth.py +79001234567 --proxy socks5://user:pass@host:port

Флоу:
    Step 0  POST /method/auth.getAnonymToken     → anonymous_token  (ключ: "token")
    Step 1  POST /oauth/get_hashes              → nonce
    Step 2  POST /method/auth.validatePhone      → sid, validation_type
            (Bearer: anonymous_token)
    Step 3  POST /method/auth.validatePhoneConfirm → sid, next_step
            (Bearer: anonymous_token)
    Step 4  POST /oauth/token
            grant_type=phone_confirmation_sid    → access_token
         или grant_type=without_password         → access_token (без пароля)
"""

import sys
import uuid
import json
import re
import hmac
import hashlib
import base64
import getpass
try:
    from curl_cffi import requests
    # TLS fingerprint impersonation — VK fingerprints TLS ClientHello on auth endpoints
    # (validatePhone returns error 9 with standard Python TLS, works with Chrome JA3)
    _SESSION_KWARGS = {"impersonate": "chrome124"}
except ImportError:
    import requests
    _SESSION_KWARGS = {}

# ─── Константы ────────────────────────────────────────────────────────────────

API_BASE      = "https://api.vk.com/method/"
OAUTH_TOKEN   = "https://oauth.vk.com/token"
GET_HASHES    = "https://oauth.vk.com/get_hashes"
SIGN_ANON     = "https://api.vk.com/oauth/sign_anonymous_token"
CLIENT_ID     = "2274003"
CLIENT_SECRET = "hHbZxrka2uZ6jB1inYsH"
API_V         = "5.131"
SAK_VERSION   = "1.143"   # из AndroidManifest meta-data sak_version (w590.java:122)

COMMON_BODY = {"v": API_V, "https": "1", "lang": "ru"}

# User-Agent — точный формат из vhb.java:84 (отсутствие вызывает error 9)
USER_AGENT = (
    "VKAndroidApp/8.52-7543 "
    "(Android 14; SDK 34; arm64-v8a; Samsung SM-A515F; ru; 2400x1080)"
)

# Прокси — устанавливается из аргумента --proxy
PROXIES: dict | None = None
# Residential proxy ТОЛЬКО для sign_anonymous_token (--sign-proxy)
SIGN_PROXIES: dict | None = None

# Глобальная curl_cffi сессия с TLS-fingerprint impersonation (Chrome124)
# VK fingerprints TLS ClientHello: стандартный Python TLS → error 9 на validatePhone
_HTTP_SESSION: requests.Session | None = None

def _get_session() -> requests.Session:
    global _HTTP_SESSION
    if _HTTP_SESSION is None:
        _HTTP_SESSION = requests.Session(**_SESSION_KWARGS)
    return _HTTP_SESSION

SENSITIVE = {
    "token", "anonymous_token", "access_token", "exchange_token",
    "client_secret", "password", "sid", "auth_hash", "silent_token",
    "webview_access_token", "webview_refresh_token", "nonce", "hash",
}


class CaptchaRequired(Exception):
    """Сервер запросил капчу (error=need_captcha)."""
    def __init__(self, data: dict):
        self.captcha_sid     = data.get("captcha_sid", "")
        self.captcha_img     = data.get("captcha_img", "")
        self.captcha_ts      = data.get("captcha_ts", 0)
        self.captcha_attempt = int(data.get("captcha_attempt", 1))
        super().__init__(f"need_captcha sid={self.captcha_sid}")

# ─── Логирование ──────────────────────────────────────────────────────────────

def _mask(key: str, val: str) -> str:
    if key in SENSITIVE and isinstance(val, str) and len(val) > 10:
        return val[:6] + "···" + val[-4:]
    return str(val)

def _mask_json(raw: str) -> str:
    for key in SENSITIVE:
        raw = re.sub(
            rf'("{re.escape(key)}":\s*")([^"]+)(")',
            lambda m: m.group(1) + _mask(
                m.group(1).strip().strip('"').rstrip('"').split('"')[0], m.group(2)
            ) + m.group(3),
            raw,
        )
    return raw

QUIET = False   # -q / --quiet: минимальный вывод
SEP = "─" * 68

# ─── 2captcha ─────────────────────────────────────────────────────────────────

TWO_CAPTCHA_KEY: str = ""   # устанавливается через --2cap

def solve_captcha(captcha_img: str, captcha_sid: str) -> str:
    """Решает капчу: автоматически через 2captcha.com или вручную из stdin."""
    import time as _time
    import base64 as _b64
    if TWO_CAPTCHA_KEY:
        print(f"  [2cap] Отправляем капчу: {captcha_img}", flush=True)
        img_data = _b64.b64encode(
            _get_session().get(captcha_img, timeout=15).content
        ).decode()
        submit = _get_session().post("https://2captcha.com/in.php", data={
            "key": TWO_CAPTCHA_KEY, "method": "base64",
            "body": img_data, "json": 1,
        }, timeout=20).json()
        if submit.get("status") != 1:
            raise RuntimeError(f"2captcha submit failed: {submit}")
        task_id = submit["request"]
        print(f"  [2cap] task_id={task_id}, ждём решения...", flush=True)
        for _ in range(24):
            _time.sleep(5)
            res = _get_session().get("https://2captcha.com/res.php", params={
                "key": TWO_CAPTCHA_KEY, "action": "get",
                "id": task_id, "json": 1,
            }, timeout=15).json()
            if res.get("status") == 1:
                answer = res["request"]
                print(f"  [2cap] решение: {answer!r}", flush=True)
                return answer
            if res.get("request") != "CAPCHA_NOT_READY":
                raise RuntimeError(f"2captcha error: {res}")
        raise RuntimeError("2captcha: тайм-аут решения капчи")
    print(f"\n  🔒 CAPTCHA!")
    print(f"     Откройте в браузере: {captcha_img}")
    return input("  Введите текст с картинки: ").strip()

def log_req(method: str, url: str, headers: dict, body: dict) -> None:
    if QUIET:
        endpoint = url.split("/")[-1].split("?")[0]
        keys = list(body.keys())
        print(f"  → {endpoint}  [{', '.join(keys[:6])}{'…' if len(keys)>6 else ''}]", flush=True)
        return
    print(f"\n{SEP}")
    print(f"  ▶  {method}  {url}")
    print(SEP)
    if headers:
        print("  HEADERS:")
        for k, v in headers.items():
            v_show = (v[:12] + "···" + v[-6:]) if k == "Authorization" and len(v) > 22 else v
            print(f"    {k}: {v_show}")
    print("  BODY:")
    for k, v in body.items():
        print(f"    {k} = {_mask(k, str(v))}")

def log_resp(status: int, data: dict, raw_text: str = "") -> None:
    if QUIET:
        err = data.get("error")
        resp = data.get("response", data)
        if err:
            print(f"  ← HTTP {status}  error={err!r}  code={data.get('error_code') or (err.get('error_code') if isinstance(err,dict) else '')}", flush=True)
        else:
            keys = list(resp.keys()) if isinstance(resp, dict) else []
            print(f"  ← HTTP {status}  OK  [{', '.join(keys[:8])}]", flush=True)
        return
    print(f"  HTTP STATUS: {status}")
    if raw_text:
        print(f"  RAW BODY ({len(raw_text)} bytes):")
        for line in raw_text[:4000].splitlines():
            print("    " + line)
        if len(raw_text) > 4000:
            print(f"    ... (обрезано, полная длина {len(raw_text)})")
    print("  RESPONSE (parsed + masked):")
    masked = _mask_json(json.dumps(data, ensure_ascii=False, indent=4))
    for line in masked.splitlines():
        print("    " + line)
    print(SEP)
    sys.stdout.flush()

# ─── HTTP-обёртки ─────────────────────────────────────────────────────────────

def _do_request(resp: requests.Response) -> dict:
    """Парсим ответ, логируем сырой текст + JSON, бросаем при ошибке."""
    raw  = resp.text
    try:
        data = resp.json()
    except Exception:
        print(f"  HTTP STATUS: {resp.status_code}")
        print(f"  RAW BODY ({len(raw)} bytes):")
        for line in raw[:4000].splitlines():
            print("    " + line)
        print(SEP)
        sys.stdout.flush()
        raise RuntimeError(f"Не удалось разобрать JSON: {raw[:400]}")

    log_resp(resp.status_code, data, raw)

    # Сначала проверяем смысловые ошибки — ДО raise_for_status,
    # т.к. /oauth/token отвечает 401 с полезным JSON при need_captcha
    if "error" in data:
        e = data["error"]
        if e == "need_captcha":
            raise CaptchaRequired(data)
        if isinstance(e, dict):
            raise RuntimeError(f"[VK {e.get('error_code')}] {e.get('error_msg')}")
        raise RuntimeError(f"[VK error] {e}")

    resp.raise_for_status()
    return data

def post_method(endpoint: str, body: dict, anon_token: str | None = None) -> dict:
    """POST на /method/<endpoint> с опциональным Bearer-заголовком."""
    url     = API_BASE + endpoint
    payload = {**COMMON_BODY, **body}
    headers = {
        "Content-Type":        "application/x-www-form-urlencoded; charset=utf-8",
        "User-Agent":          USER_AGENT,
        "X-VK-Android-Client": "new",
        "X-Screen":            "login",
    }
    if anon_token:
        headers["Authorization"] = f"Bearer {anon_token}"

    log_req("POST", url, headers, payload)
    resp = _get_session().post(url, data=payload, headers=headers, timeout=30, proxies=PROXIES)
    data = _do_request(resp)
    return data.get("response", data)

def post_raw(url: str, body: dict, headers: dict | None = None,
             proxies_override: dict | None = None) -> dict:
    """POST на произвольный URL (get_hashes, oauth/token)."""
    h = {
        "Content-Type":        "application/x-www-form-urlencoded; charset=utf-8",
        "User-Agent":          USER_AGENT,
        "X-VK-Android-Client": "new",
    }
    if headers:
        h.update(headers)

    px = proxies_override if proxies_override is not None else PROXIES
    log_req("POST", url, h, body)
    resp = _get_session().post(url, data=body, headers=h, timeout=30, proxies=px)
    return _do_request(resp)

# ─── Шаги ─────────────────────────────────────────────────────────────────────

def step0_anon_token(device_id: str) -> str:
    print("\n\033[1;34m[STEP 0] auth.getAnonymToken\033[0m")
    r = post_method("auth.getAnonymToken", {
        "client_id":      CLIENT_ID,
        "client_secret":  CLIENT_SECRET,
        "device_id":      device_id,
        "client_type":    "SDK_ANDROID",
        "client_version": "android_8",
    })
    # Новый формат: ключ "token" внутри response
    token = r.get("token") or r.get("anonymous_token")
    if not token:
        raise RuntimeError(
            "Токен не найден в ответе.\n"
            f"Полный response: {json.dumps(r, ensure_ascii=False, indent=2)}"
        )
    expired_at = r.get("expired_at", "?")
    print(f"\n  \033[92m✔ anonymous_token получен\033[0m  expired_at={expired_at}")
    return token


def step1_get_hashes(anon_token: str, device_id: str) -> str:
    print("\n\033[1;34m[STEP 1] /oauth/get_hashes — получаем nonce\033[0m")
    # kq4.java:41: aaa0.a() добавляет v и https к телу запроса
    r = post_raw(GET_HASHES, {
        "anonymous_token": anon_token,
        "device_id":       device_id,
        "v":               API_V,
        "https":           "1",
    })
    nonce = r.get("nonce")
    if not nonce:
        # Fallback: без anonymous_token
        print("  ⚠ nonce не получен через anonymous_token, пробуем client credentials...")
        r = post_raw(GET_HASHES, {
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "device_id":     device_id,
        })
        nonce = r.get("nonce")
    if not nonce:
        print("  ⚠ nonce недоступен, продолжаем без него")
        return ""
    print(f"\n  \033[92m✔ nonce получен\033[0m")
    return nonce


def step1b_sign_anon_token(anon_token: str, nonce: str, device_id: str) -> str:
    """
    Step 1b — /oauth/sign_anonymous_token
    Переводит анонимный токен из is_verified=false -> is_verified=true.
    Без этого auth.validatePhone возвращает flood control (error 9).

    Алгоритм (wz.java:68-72):
        mac.init(new SecretKeySpec(nonce.getBytes(), "HmacSHA256"))
        signature = Base64(mac.doFinal(token.getToken().getBytes()))
    Где token.getToken() — ПОЛНЫЙ токен включая "anonym." префикс.

    Запрос (lse0.java:28-40):
        POST /oauth/sign_anonymous_token
        Authorization: Bearer <anon_token>
        Body: signature_base64, lang, https, device_id, v   ← v добавляется aaa0.a()
    Ответ (kse0.java:23): {"signed_token": "..."}  ← корневой уровень, не {"response":...}
    """
    print("\n\033[1;34m[STEP 1b] /oauth/sign_anonymous_token — подпись токена\033[0m")

    # wz.java:71: token.getToken() — полный токен с "anonym." префиксом
    sig = hmac.new(
        key       = nonce.encode("utf-8"),
        msg       = anon_token.encode("utf-8"),
        digestmod = hashlib.sha256,
    ).digest()
    # wz.java:71: Base64.encodeToString(bytes, 0) — flag 0 = DEFAULT, adds trailing \n
    # Python base64.b64encode does NOT add \n → must add manually to match Android
    signature_base64 = base64.b64encode(sig).decode("utf-8") + "\n"

    # lse0.java:40: aaa0.a(aaa0.a, this.b, vKApiConfig.g, null, vKApiConfig.b, null, null, 244)
    # bitmask 244: bit2(=4)→str2=null, bit4(=16)→map3=empty, bit6(=64)→collection=empty
    # bit3(=8) NOT set → i (vKApiConfig.b = CLIENT_ID) is kept → api_id=CLIENT_ID added by aaa0.b()
    if SIGN_PROXIES:
        print(f"  ℹ  Используем residential proxy для подписи токена")
    r = post_raw(SIGN_ANON, {
        "signature_base64": signature_base64,
        "device_id":        device_id,
        "lang":             "ru",
        "https":            "1",
        "v":                API_V,
        "api_id":           CLIENT_ID,   # aaa0.a() bitmask 244 → api_id added (i=vKApiConfig.b)
    }, headers={"Authorization": f"Bearer {anon_token}"},
       proxies_override=SIGN_PROXIES)

    # kse0.java:23: ответ на корневом уровне {"signed_token": "..."}, не {"response":{}}
    signed_token = r.get("signed_token")
    if not signed_token:
        raise RuntimeError(
            f"sign_anonymous_token не вернул signed_token.\n"
            f"Ответ: {json.dumps(r, ensure_ascii=False, indent=2)}"
        )
    print(f"\n  \033[92m✔ signed_token получен\033[0m")
    return signed_token


def step2_validate_phone(phone: str, device_id: str, anon_token: str,
                         external_device_id: str) -> dict:
    print("\n\033[1;34m[STEP 2] auth.validatePhone — отправка OTP\033[0m")
    # КЛЮЧЕВОЕ: НЕ включаем max_messenger в supported_ways.
    # Если max_messenger присутствует → VK возвращает type=general (экран выбора
    # Telegram vs SMS) без validation_type, и SMS так и не отправляется.
    # Без max_messenger → VK сразу возвращает validation_type=sms.
    # Проверено на Georgia, India, Uzbekistan: первый же запрос даёт validation_type=sms.
    base_body = {
        "phone":                    phone,
        "supported_ways":           "sms_inbox",
        "supported_ways_settings":  "callreset_preview_enabled",
        "allow_callreset":          "1",
        "libverify_support":        "1",
        "device_id":                device_id,
        "sak_version":              SAK_VERSION,
        "external_device_id":       external_device_id,
    }

    # Капча-ретрай: до 5 попыток с разными supported_ways при каждом retry
    ways_sequence = ["sms_inbox", "sms_inbox", "sms_inbox"]
    r = None
    for attempt, ways in enumerate(ways_sequence):
        body = {**base_body, "supported_ways": ways}
        if attempt > 0:
            print(f"  ↳ retry {attempt} supported_ways={ways!r}", flush=True)
        try:
            r = post_method("auth.validatePhone", body, anon_token=anon_token)
            break
        except CaptchaRequired as cap:
            captcha_key = solve_captcha(cap.captcha_img, cap.captcha_sid)
            retry_body = {**body,
                          "captcha_sid": cap.captcha_sid,
                          "captcha_key": captcha_key}
            r = post_method("auth.validatePhone", retry_body, anon_token=anon_token)
            break
        except RuntimeError as e:
            if attempt == len(ways_sequence) - 1:
                raise
            print(f"  ✘ attempt {attempt}: {e}", flush=True)
            continue

    vtype  = r.get("type", r.get("validation_type", "?"))
    vtype2 = r.get("validation_type", "")
    delay  = r.get("delay", "?")
    clen   = r.get("code_length", "?")
    print(f"\n  \033[92m✔ OTP отправлен\033[0m  type={vtype}  validation_type={vtype2!r}  "
          f"code_length={clen}  delay={delay}s")
    return r


def step3_confirm_otp(sid: str, phone: str, device_id: str, anon_token: str,
                      external_id: str = "") -> dict:
    code = input(f"\n\033[1;33m[INPUT]\033[0m OTP-код для {phone}: ").strip()
    if not code:
        raise RuntimeError("Код не введён.")
    print("\n\033[1;34m[STEP 3] auth.validatePhoneConfirm\033[0m")
    # wvj.java:82-110: validatePhoneConfirm — standard API, Bearer added
    body: dict = {
        "sid":                  sid,
        "phone":                phone,
        "code":                 code,
        "client_id":            CLIENT_ID,
        "device_id":            device_id,
        "sak_version":          SAK_VERSION,
        "can_skip_password":    "1",
        "is_code_autocomplete": "0",
    }
    if external_id:
        body["external_id"] = external_id
    r = post_method("auth.validatePhoneConfirm", body, anon_token=anon_token)
    # VK returns success=1 (int) or True, not False/"" on success
    if not r.get("success"):
        reason = r.get("reason") or r.get("error") or "неверный код или истёк sid"
        raise RuntimeError(f"OTP не принят: {reason}")
    next_step  = r.get("next_step") or ""
    auth_hash  = r.get("auth_hash") or ""
    profile    = r.get("profile") or {}
    name       = f"{profile.get('first_name','')} {profile.get('last_name','')}".strip()
    print(f"\n  \033[92m✔ OTP подтверждён\033[0m  next_step={next_step!r}  "
          f"auth_hash={'есть' if auth_hash else 'нет'}  profile={name!r}")
    return r


def step4_oauth_token(phone: str, sid: str, device_id: str,
                      anon_token: str, nonce: str, next_step: str,
                      auth_hash: str = "") -> dict:
    """
    Получаем access_token через /oauth/token.

    next_step из validatePhoneConfirm (NextStepDto в DTO):
      "show_with_password"          → grant_type=phone_confirmation_sid (нужен пароль)
      "show_without_password"       → grant_type=without_password
      "auth"                        → grant_type=without_password (can_skip_password=true)
      "registration"                → grant_type=without_password (новый аккаунт)
      "silent_registration"         → grant_type=without_password
      "show_with_account_recovery"  → grant_type=without_password
      "on_success_validation"       → auth уже завершён (сюда не должны попасть)
    """
    need_password = (next_step == "show_with_password")

    is_registration = next_step in ("registration", "silent_registration")

    if need_password:
        password = getpass.getpass(f"\n\033[1;33m[INPUT]\033[0m Пароль для аккаунта: ").strip()
        grant    = "phone_confirmation_sid"
        print("\n\033[1;34m[STEP 4] /oauth/token — grant_type=phone_confirmation_sid\033[0m")
    else:
        password = ""
        grant    = "without_password"
        label    = "регистрация" if is_registration else next_step or "без пароля"
        print(f"\n\033[1;34m[STEP 4] /oauth/token — grant_type=without_password ({label})\033[0m")

    # ms4.java: URL = oauth.vk.com/token
    # in5.java:e(): sends anonymous_token instead of client_id+client_secret when available
    # in5.java:h(): aaa0.a() with bitmask 144 → api_id=2274003 added
    # VkAuthState.c(): jb("supported_ways","push") + jb("supported_ways","email") → "push,email"
    body: dict = {
        "grant_type":        grant,
        "username":          phone,
        "sid":               sid,
        "password":          password,     # "" for without_password (VkAuthState.a.c sets it)
        "anonymous_token":   anon_token,   # replaces client_id+client_secret (in5.java)
        "api_id":            CLIENT_ID,    # aaa0.a() bitmask 144 adds api_id (not client_id)
        "device_id":         device_id,
        "2fa_supported":     "1",
        "supported_ways":    "push,email", # VkAuthState.jb() appends: "push" + "email"
        "libverify_support": "1",          # ms4.java:18
        "v":                 API_V,
    }
    # Для регистрации нового аккаунта — согласие с условиями (tse0.java logic)
    if is_registration:
        body["additional_sign_up_agreement_showed"] = "1"
    # nonce из /get_hashes — передаётся здесь (ms4.java), NOT в validatePhone
    if nonce:
        body["nonce"] = nonce
    # auth_hash из Step 3 — дополнительная верификация сессии
    if auth_hash:
        body["auth_hash"] = auth_hash

    # Капча-ретрай (q8z.java:35-56)
    for _attempt in range(5):
        try:
            r = post_raw(OAUTH_TOKEN, body)
            break
        except CaptchaRequired as cap:
            captcha_key = solve_captcha(cap.captcha_img, cap.captcha_sid)
            body["captcha_sid"]     = cap.captcha_sid
            body["captcha_key"]     = captcha_key
            body["captcha_attempt"] = str(cap.captcha_attempt)
            body["captcha_ts"]      = str(cap.captcha_ts)
            # device_id в нижнем регистре при ретрае (q8z.java:68)
            body["device_id"] = device_id.lower()
    else:
        raise RuntimeError("Капча не решена за 5 попыток")

    access_token = r.get("access_token")
    if not access_token:
        raise RuntimeError(
            f"access_token не получен.\nОтвет: {json.dumps(r, ensure_ascii=False, indent=2)}"
        )
    print(f"\n  \033[92m✔ access_token получен\033[0m  user_id={r.get('user_id')}")
    return r


def step_success(sid: str, access_token: str) -> None:
    print("\n\033[1;34m[STEP 5] auth.onSuccessValidation\033[0m")
    try:
        post_method("auth.onSuccessValidation", {
            "sid":          sid,
            "access_token": access_token,
        })
        print("\n  \033[92m✔ Сервер уведомлён\033[0m")
    except Exception as e:
        # Не критично — авторизация уже прошла
        print(f"\n  ⚠ onSuccessValidation вернул ошибку (не критично): {e}")

# ─── Прямой логин через пароль (обход validatePhone) ─────────────────────────

def direct_password_flow(phone: str, password: str) -> dict:
    """
    Альтернативный флоу: grant_type=password → /oauth/token напрямую,
    без validatePhone / OTP.  Требует пароль аккаунта.

    Плюсы: не зависит от sign_anonymous_token (flood control на validatePhone
    не затрагивает этот путь).  Возвращает need_captcha вместо flood control.
    """
    device_id  = str(uuid.uuid4())
    print(f"\n  device_id : {device_id}")

    print("\n\033[1;34m[STEP 0] auth.getAnonymToken\033[0m")
    anon_token = step0_anon_token(device_id)

    print("\n\033[1;34m[STEP 1] /oauth/get_hashes — nonce\033[0m")
    nonce = step1_get_hashes(anon_token, device_id)

    print("\n\033[1;34m[STEP P] /oauth/token — grant_type=password\033[0m")
    body: dict = {
        "grant_type":        "password",
        "username":          phone,
        "password":          password,
        "anonymous_token":   anon_token,   # in5.java: replaces client_id+client_secret
        "api_id":            CLIENT_ID,    # aaa0.a() bitmask 144
        "device_id":         device_id,
        "2fa_supported":     "1",
        "supported_ways":    "push,email", # VkAuthState.jb()
        "libverify_support": "1",
        "v":                 API_V,
    }
    if nonce:
        body["nonce"] = nonce

    for _attempt in range(5):
        try:
            r = post_raw(OAUTH_TOKEN, body)
            break
        except CaptchaRequired as cap:
            captcha_key = solve_captcha(cap.captcha_img, cap.captcha_sid)
            body["captcha_sid"]     = cap.captcha_sid
            body["captcha_key"]     = captcha_key
            body["captcha_attempt"] = str(cap.captcha_attempt)
            body["captcha_ts"]      = str(cap.captcha_ts)
            body["device_id"]       = device_id.lower()
    else:
        raise RuntimeError("Капча не решена за 5 попыток")

    # Сервер может вернуть redirect_uri (not_robot_captcha) вместо access_token
    if r.get("redirect_uri") and not r.get("access_token"):
        raise RuntimeError(
            f"Требуется подтверждение через браузер.\n"
            f"redirect_uri: {r.get('redirect_uri')}"
        )

    access_token = r.get("access_token")
    if not access_token:
        raise RuntimeError(
            f"access_token не получен.\nОтвет: {json.dumps(r, ensure_ascii=False, indent=2)}"
        )
    print(f"\n  \033[92m✔ access_token получен\033[0m  user_id={r.get('user_id')}")
    return r


# ─── Основной флоу ────────────────────────────────────────────────────────────

def auth_flow(phone: str) -> dict:
    # device_id — session UUID (каждый раз новый)
    device_id          = str(uuid.uuid4())
    # external_device_id — симулируем GAID (стабильный per-device идентификатор)
    external_device_id = str(uuid.uuid4())
    print(f"\n  device_id          : {device_id}")
    print(f"  external_device_id : {external_device_id}")

    # 0 — anonymous token (is_verified=false)
    anon_token = step0_anon_token(device_id)

    # 1 — nonce для /oauth/token (get_hashes)
    nonce = step1_get_hashes(anon_token, device_id)

    # 1b — sign_anonymous_token (попытка; сервер возвращает null без FCM-nonce)
    try:
        signed_token = step1b_sign_anon_token(anon_token, nonce, device_id)
    except RuntimeError:
        print("  ⚠  sign_anonymous_token недоступен, продолжаем с unsigned token")
        signed_token = anon_token

    # 2 — отправить OTP
    s2          = step2_validate_phone(phone, device_id, signed_token, external_device_id)
    sid         = s2["sid"]
    external_id = s2.get("external_id", "")  # передаём в step3

    # validation_type всегда приходит как "sms" — ждём ввода кода.

    # 3 — подтвердить OTP (ждём ввода кода от пользователя)
    s3        = step3_confirm_otp(sid, phone, device_id, signed_token, external_id)
    sid       = s3.get("sid", sid)
    next_step = s3.get("next_step") or ""
    auth_hash = s3.get("auth_hash") or ""

    # on_success_validation → auth уже завершён на сервере, step4 не нужен
    if next_step == "on_success_validation":
        print("\n  ℹ  next_step=on_success_validation — step4 пропускается")
        access_token = s3.get("access_token") or ""
        if not access_token:
            # попробуем всё равно — иногда access_token есть прямо в s3
            raise RuntimeError(
                f"on_success_validation: access_token не получен.\n"
                f"Ответ step3: {json.dumps(s3, ensure_ascii=False, indent=2)}"
            )
        step_success(sid, access_token)
        return {
            "access_token":          access_token,
            "user_id":               s3.get("user_id"),
            "webview_access_token":  s3.get("webview_access_token"),
            "webview_refresh_token": s3.get("webview_refresh_token"),
            "silent_token":          s3.get("silent_token"),
            "exchange_token":        s3.get("exchange_token"),
        }

    # 4 — свежий nonce для /oauth/token
    nonce2 = step1_get_hashes(anon_token, device_id)

    s4           = step4_oauth_token(phone, sid, device_id, anon_token, nonce2, next_step, auth_hash)
    access_token = s4["access_token"]

    # 5 — success callback
    step_success(sid, access_token)

    return {
        "access_token":          access_token,
        "user_id":               s4.get("user_id"),
        "webview_access_token":  s4.get("webview_access_token"),
        "webview_refresh_token": s4.get("webview_refresh_token"),
        "silent_token":          s4.get("silent_token"),
        "exchange_token":        s4.get("exchange_token"),
    }

# ─── Точка входа ──────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    global PROXIES

    parser = argparse.ArgumentParser(description="VK Auth via phone + SMS")
    parser.add_argument("phone", help="Номер телефона, например +79001234567")
    parser.add_argument("--proxy", metavar="URL",
                        help="Прокси URL, например socks5://user:pass@host:port")
    parser.add_argument("--password", action="store_true",
                        help="Использовать grant_type=password (обход validatePhone)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Минимальный вывод (только ключевые события)")
    parser.add_argument("--sign-proxy", metavar="URL",
                        help="Residential/mobile proxy ТОЛЬКО для sign_anonymous_token "
                             "(datacenter IP → signed_token=null). "
                             "Например: socks5://user:pass@host:port")
    parser.add_argument("--2cap", dest="twocap", default="",
                        metavar="KEY",
                        help="API ключ 2captcha.com для автоматического решения капчи")
    args = parser.parse_args()
    global QUIET, SIGN_PROXIES, TWO_CAPTCHA_KEY
    QUIET = args.quiet
    if args.twocap:
        TWO_CAPTCHA_KEY = args.twocap
    if args.sign_proxy:
        SIGN_PROXIES = {"http": args.sign_proxy, "https": args.sign_proxy}
        print(f"  sign-proxy: {args.sign_proxy}")

    phone = args.phone.strip()
    if not phone.startswith("+"):
        phone = "+" + phone

    if args.proxy:
        PROXIES = {"http": args.proxy, "https": args.proxy}
        print(f"  proxy: {args.proxy}")

    mode = "password" if args.password else "OTP"
    print("=" * 68)
    print(f"  VK Auth  |  телефон: {phone}  |  режим: {mode}")
    print("=" * 68)

    _ip_services = [
        ("https://api.ipify.org?format=json", lambda r: r.json()["ip"]),
        ("https://ifconfig.me/ip",            lambda r: r.text.strip()),
        ("https://api4.my-ip.io/ip.json",     lambda r: r.json()["ip"]),
    ]
    current_ip = "не удалось определить"
    for _url, _parse in _ip_services:
        try:
            _r = _get_session().get(_url, proxies=PROXIES, timeout=5)
            current_ip = _parse(_r)
            break
        except Exception:
            continue
    print(f"  current IP: {current_ip}")

    try:
        if args.password:
            pwd = getpass.getpass(f"\n\033[1;33m[INPUT]\033[0m Пароль для {phone}: ").strip()
            result = direct_password_flow(phone, pwd)
        else:
            result = auth_flow(phone)
    except RuntimeError as e:
        print(f"\n\033[91m❌  Ошибка: {e}\033[0m")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(0)

    tok = result["access_token"]
    print("\n" + "=" * 68)
    print("\033[92m✅  Авторизация успешна!\033[0m")
    print(f"   user_id:      {result.get('user_id')}")
    print(f"   access_token: {tok[:12]}···{tok[-8:]}")
    if result.get("exchange_token"):
        et = result["exchange_token"]
        print(f"   exchange_tok: {et[:8]}···{et[-4:]}")
    print("=" * 68)

    # Сохраняем токены в файл рядом со скриптом
    import os
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vk_session.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n  Данные сохранены → {out_path}")


if __name__ == "__main__":
    main()