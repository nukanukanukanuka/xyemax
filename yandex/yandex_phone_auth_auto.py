#!/usr/bin/env python3
"""
Авторизация / регистрация по номеру телефона в Yandex Passport
==============================================================
Использование:
    python3 yandex_auth.py +79991234567

Флоу автоматически определяется по ответу /2/bundle/mobile/start/:
  • status=ok              → существующий аккаунт → challenge-флоу (SMS/push)
  • account.not_found
    + can_register=true    → новый номер → регистрационный флоу
"""

import sys
import uuid
import time
import socket

from curl_cffi import requests as cf_requests

# Доступные профили: "chrome110", "chrome120", "safari17_2_ios"
IMPERSONATE = "chrome110"


BASE_URL    = "https://mobileproxy.passport.yandex.net"
MOBILEPROXY = "mobileproxy.passport.yandex.net"

# ─────────────────────────────────────────────
#  Профиль устройства (имитация Android SDK)
# ─────────────────────────────────────────────

DEVICE = {
    "manufacturer":     "Samsung",
    "model":            "Galaxy S21",
    "android_version":  "11",
    "am_version_name":  "7.48.2(748024408)",
    "app_id":           "com.yandex.yamb",
    "app_version_name": "7.48.2",
}

# Генерируются один раз на сессию
DEVICE_UUID = str(uuid.uuid4()).replace("-", "")
DEVICE_ID   = str(uuid.uuid4()).replace("-", "")

# ─────────────────────────────────────────────
#  Credentials приложения com.yandex.yamb
#  (расшифровываются из credentials/f.java AES/CFB)
# ─────────────────────────────────────────────

CLIENT_ID             = "c0ebe342af7d48fbbbfcf2d2eedb8f9e"   # f.j первый e(), поле .c
CLIENT_SECRET         = "ad0a908f0aa341a182a37ecd75bc319e"   # f.j первый e(), поле .d
X_TOKEN_CLIENT_ID     = "21e27582fcb04aa4b11356934b7f28f1"   # f.j второй e(), поле .c
X_TOKEN_CLIENT_SECRET = "afff6b0ce658454b9bb7e3ef1afe6711"   # f.j второй e(), поле .d


def _make_user_agent() -> str:
    return (
        f"com.yandex.mobile.auth.sdk/7.48.2.748024408 "
        f"({DEVICE['manufacturer']} {DEVICE['model']}; Android {DEVICE['android_version']})"
    )


def _make_query_params() -> dict:
    """Query-параметры, которые добавляются к запросам согласно документации."""
    return {
        "manufacturer":     DEVICE["manufacturer"],
        "model":            DEVICE["model"],
        "app_platform":     "android",
        "am_version_name":  DEVICE["am_version_name"],
        "app_id":           DEVICE["app_id"],
        "app_version_name": DEVICE["app_version_name"],
        # device_id нужен дважды — оба ключа (l.java:224–231)
        "deviceid":         DEVICE_ID,
        "device_id":        DEVICE_ID,
        "uuid":             DEVICE_UUID,
        "request_id":       f"{DEVICE_UUID}{int(time.time() * 1000)}",
        # am_app = app_id + " " + app_version_name (l.java метод d())
        "am_app":           f"{DEVICE['app_id']} {DEVICE['app_version_name']}",
    }



# ─────────────────────────────────────────────
#  Резолвинг через mobileproxy
# ─────────────────────────────────────────────

def resolve_via_mobileproxy(proxy_domain: str = MOBILEPROXY, timeout: float = 5.0) -> str | None:
    _section("0 / Резолвинг через mobileproxy")
    _log("DNS", f"Резолвинг {proxy_domain!r} ...")
    try:
        socket.setdefaulttimeout(timeout)
        info = socket.getaddrinfo(proxy_domain, None, socket.AF_INET)
        ips  = list(dict.fromkeys(a[4][0] for a in info))[:5]
        if not ips:
            _err("DNS", "getaddrinfo вернул пустой список")
            return None
        for ip in ips:
            print(f"       → {proxy_domain}  A  {ip}")
        _ok("DNS", f"Используем {ips[0]}")
        return ips[0]
    except socket.gaierror as e:
        _err("DNS", f"gaierror: {e}")
    except socket.timeout:
        _err("DNS", "таймаут")
    except Exception as e:
        _err("DNS", str(e))
    return None


# ─────────────────────────────────────────────
#  Вывод / дамп
# ─────────────────────────────────────────────

def _log(tag, msg):  print(f"  [{tag}] {msg}")
def _ok(tag, msg):   print(f"  [✓ {tag}] {msg}")
def _err(tag, msg):  print(f"  [✗ {tag}] {msg}")

def _section(title):
    print()
    print(f"  ── {title} {'─' * max(0, 52 - len(title))}")


def _dump(resp) -> None:
    """Полный дамп запроса и ответа в терминал."""
    req = resp.request

    print()
    print("  ┌─ REQUEST ──────────────────────────────────────────")
    print(f"  │  {req.method} {req.url}")
    print("  │  Headers:")
    for k, v in req.headers.items():
        print(f"  │    {k}: {v}")
    if req.body:
        body_str = req.body if isinstance(req.body, str) else req.body.decode(errors="replace")
        print("  │  Body:")
        for pair in body_str.split("&"):
            print(f"  │    {pair}")
    print("  ├─ RESPONSE ─────────────────────────────────────────")
    print(f"  │  HTTP {resp.status_code} {resp.reason}")
    print("  │  Headers:")
    for k, v in resp.headers.items():
        print(f"  │    {k}: {v}")
    print("  │  Body:")
    print(f"  │    {resp.text}")
    print("  └────────────────────────────────────────────────────")


# ─────────────────────────────────────────────
#  API-шаги
# ─────────────────────────────────────────────

def step_warm_cookies(session) -> None:
    """
    GET /1/am/config.json — получаем _yasc с domain=.yandex.net.
    Идентично:
      curl -H "User-Agent: ..." \
        "https://mobileproxy.passport.yandex.net/1/am/config.json?app_id=com.yandex.yamb&app_platform=android"
    Session сохраняет Set-Cookie автоматически и передаёт в POST-запросы.
    """
    _section("0.1 / Получение _yasc (config.json)")
    url = "https://mobileproxy.passport.yandex.net/1/am/config.json"
    try:
        r = session.get(url, params={"app_id": DEVICE["app_id"], "app_platform": "android"}, timeout=15)
        _dump(r)
        yasc = session.cookies.get("_yasc")
        if yasc:
            _ok("OK", f"_yasc установлен · domain=.yandex.net · expires 2036")
        else:
            _err("WARN", "_yasc не установлен")
    except Exception as e:
        _err("EXC", f"config.json: {e}")


def step_start(session, phone: str) -> tuple[str | None, bool, str]:
    """
    /2/bundle/mobile/start/ — инициализация сессии (sq4.java:64).

    Возвращает (track_id, need_register, account_type):
      need_register=False  → аккаунт найден, идём в challenge-флоу
      need_register=True   → account.not_found + can_register=true → регистрация
      account_type         → "neophonish" | "portal" | ...
    """
    _section("0.5 / Инициализация сессии (start)")
    url    = f"{BASE_URL}/2/bundle/mobile/start/"
    params = _make_query_params()
    data   = {
        "login":                 phone,
        "force_register":        "false",
        "is_phone_number":       "true",
        "display_language":      "ru",
        "client_id":             CLIENT_ID,
        "client_secret":         CLIENT_SECRET,
        "x_token_client_id":     X_TOKEN_CLIENT_ID,
        "x_token_client_secret": X_TOKEN_CLIENT_SECRET,
    }
    try:
        r = session.post(url, params=params, data=data, timeout=30)
        _dump(r)

        if r.status_code == 403 and r.headers.get("X-Yandex-Captcha"):
            _err("CAPTCHA", "Сервер вернул капчу — запрос идёт не через mobileproxy.")
            return None, False, ""

        body     = r.json()
        track_id = body.get("track_id")
        errors   = body.get("errors", [])

        # Предпочитаем neophonish если доступен (упрощённый флоу без логина)
        allowed  = body.get("allowed_account_types", [])
        acct_type = "neophonish" if "neophonish" in allowed else body.get("account_type", "portal")

        if body.get("status") == "ok":
            _ok("OK", f"Аккаунт найден · track_id={track_id}")
            return track_id, False, acct_type

        if "account.not_found" in errors and body.get("can_register"):
            _ok("REG", f"Аккаунт не найден · can_register=true · track_id={track_id}")
            _log("REG", f"account_type выбран={acct_type} · allowed={allowed} · country={body.get('country')}")
            return track_id, True, acct_type

        _err("ERR", f"errors={errors}")
    except Exception as e:
        _err("EXC", str(e))
    return None, False, ""


def step_validate(session, track_id, phone) -> bool:
    _section("R-1 / Валидация номера (validate/phone_number)")
    url    = f"{BASE_URL}/1/bundle/mobile/validate/phone_number/"
    params = _make_query_params()
    data   = {
        "track_id":          track_id,
        "phone_number":      phone,
        "validate_for_call": "true",
    }
    try:
        r = session.post(url, params=params, data=data, timeout=30)
        _dump(r)
        body = r.json()
        if body.get("status") == "ok":
            _ok("OK", (
                f"Номер валиден · "
                f"valid_for_call={body.get('valid_for_call')} · "
                f"valid_for_flash_call={body.get('valid_for_flash_call')}"
            ))
            return True
        _err("ERR", body.get("errors", body.get("error", "unknown")))
    except Exception as e:
        _err("EXC", str(e))
    return False


def step_phone_confirm_submit(session, track_id, phone: str) -> bool:
    """
    R-2: Триггер отправки SMS.
    Endpoint: /1/bundle/phone/confirm/submit/
    Ответ содержит deny_resend_until, code_length и т.д.
    """
    _section("R-2 / Запрос SMS-кода (phone/confirm/submit)")
    url  = f"{BASE_URL}/1/bundle/phone/confirm/submit/"
    data = {
        "track_id":        track_id,
        "number":          phone,          # поле "number", не "phone_number"
        "display_language": "ru",
        "country":         "ru",
        "gps_package_name": "com.google.android.gms",
        "confirm_method":  "by_sms",       # by_sms / by_call / by_flash_call
    }
    try:
        r = session.post(url, data=data, timeout=30)
        _dump(r)
        body = r.json()
        if body.get("status") == "ok":
            _ok("OK", (
                f"SMS отправлен · "
                f"code_length={body.get('code_length')} · "
                f"deny_resend_until={body.get('deny_resend_until')}"
            ))
            return True
        _err("ERR", body.get("errors", body.get("error", "unknown")))
    except Exception as e:
        _err("EXC", str(e))
    return False


def step_input_code() -> str | None:
    _section("R-3 / Ввод SMS-кода")
    while True:
        try:
            code = input("       Код из SMS (6 цифр, q — отмена): ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return None
        if code.lower() == "q":
            return None
        if len(code) == 6 and code.isdigit():
            return code
        print("       Неверный формат. Нужно ровно 6 цифр.")


def step_phone_confirm_commit(session, track_id, sms_code: str) -> bool:
    """
    R-4: Подтверждение кода из SMS.
    Endpoint: /1/bundle/phone/confirm/commit/
    """
    _section("R-4 / Подтверждение SMS-кода (phone/confirm/commit)")
    url  = f"{BASE_URL}/1/bundle/phone/confirm/commit/"
    data = {
        "track_id": track_id,
        "code":     sms_code,
    }
    try:
        r = session.post(url, data=data, timeout=30)
        _dump(r)
        body = r.json()
        if body.get("status") == "ok":
            _ok("OK", "Код принят · номер подтверждён в сессии")
            return True
        _err("ERR", body.get("errors", body.get("error", "unknown")))
    except Exception as e:
        _err("EXC", str(e))
    return False


def step_register_neophonish(session, track_id) -> str | None:
    """
    R-5: Создание аккаунта neophonish и получение токена.
    Endpoint: /1/bundle/mobile/register/neophonish/
    phone_number уже подтверждён в сессии — не передаём.
    Ответ: { status, x_token, access_token (optional) }
    """
    _section("R-5 / Регистрация аккаунта (register/neophonish)")
    url  = f"{BASE_URL}/1/bundle/mobile/register/neophonish/"
    data = {
        "track_id":              track_id,
        "client_id":             CLIENT_ID,
        "client_secret":         CLIENT_SECRET,
        "x_token_client_id":     X_TOKEN_CLIENT_ID,
        "x_token_client_secret": X_TOKEN_CLIENT_SECRET,
        "display_language":      "ru",
    }
    try:
        r = session.post(url, data=data, timeout=30)
        _dump(r)
        body = r.json()
        if body.get("status") == "ok":
            token = body.get("access_token") or body.get("x_token")
            _ok("OK", f"Аккаунт создан · expires_in={body.get('expires_in')}s")
            if token:
                return token
            _log("INFO", "access_token не в ответе — пробуем /1/token")
            return "__need_token__"
        _err("ERR", body.get("errors", body.get("error", "unknown")))
    except Exception as e:
        _err("EXC", str(e))
    return None


# ─────────────────────────────────────────────
#  Шаги авторизации существующего аккаунта
# ─────────────────────────────────────────────

def step_challenge_sms(session, track_id) -> bool:
    """
    /1/bundle/mobile/challenge/sms/ — запрос SMS-кода для существующего аккаунта.
    """
    _section("A-1 / Challenge: запрос SMS-кода")
    url  = f"{BASE_URL}/1/bundle/mobile/challenge/sms/"
    data = {"track_id": track_id}
    try:
        r = session.post(url, data=data, timeout=30)
        _dump(r)
        body = r.json()
        if body.get("status") == "ok":
            _ok("OK", f"SMS отправлен · телефон={body.get('phone_number')}")
            return True
        _err("ERR", body.get("errors", body.get("error", "unknown")))
    except Exception as e:
        _err("EXC", str(e))
    return False


def step_challenge_commit(session, track_id, sms_code) -> bool:
    """
    /1/bundle/mobile/challenge/commit/ — подтверждение кода существующего аккаунта.
    """
    _section("A-2 / Challenge: подтверждение кода")
    url  = f"{BASE_URL}/1/bundle/mobile/challenge/commit/"
    data = {
        "track_id": track_id,
        "code":     sms_code,
    }
    try:
        r = session.post(url, data=data, timeout=30)
        _dump(r)
        body = r.json()
        if body.get("status") == "ok":
            _ok("OK", "Код принят")
            return True
        _err("ERR", body.get("errors", body.get("error", "unknown")))
    except Exception as e:
        _err("EXC", str(e))
    return False


def step_get_token(session, track_id) -> str | None:
    _section("A-3 / Получение OAuth-токена (/1/token)")
    url  = f"{BASE_URL}/1/token"
    data = {
        "track_id":              track_id,
        "client_id":             CLIENT_ID,
        "client_secret":         CLIENT_SECRET,
    }
    try:
        r = session.post(url, data=data, timeout=30)
        _dump(r)
        body = r.json()
        if body.get("status") == "ok":
            token = body.get("access_token")
            _ok("OK", f"Токен получен · expires_in={body.get('expires_in')}s")
            return token
        _err("ERR", body.get("errors", body.get("error", "unknown")))
    except Exception as e:
        _err("EXC", str(e))
    return None


# ─────────────────────────────────────────────
#  Точка входа
# ─────────────────────────────────────────────

def _print_token_result(token: str) -> None:
    print()
    print("  ══════════════════════════════════════════════════════")
    print("  ЗАВЕРШЕНО")
    print("  ══════════════════════════════════════════════════════")
    print(f"  OAuth токен: {token}")
    print()


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    phone = sys.argv[1].strip()
    if not phone.startswith("+"):
        phone = "+" + phone

    print()
    print("  ══════════════════════════════════════════════════════")
    print("  YANDEX PASSPORT · авторизация / регистрация")
    print("  ══════════════════════════════════════════════════════")
    print(f"  Телефон    : {phone}")
    print(f"  Device UUID: {DEVICE_UUID}")
    print(f"  Device ID  : {DEVICE_ID}")
    print(f"  User-Agent : {_make_user_agent()}")
    print(f"  Сервер     : {BASE_URL}  (mobileproxy)")

    resolved_ip = resolve_via_mobileproxy()

    session = cf_requests.Session(impersonate=IMPERSONATE)
    session.headers.update({
        "User-Agent":   _make_user_agent(),
        "Content-Type": "application/x-www-form-urlencoded",
    })

    if resolved_ip:
        _ok("DNS", f"mobileproxy резолвится → {resolved_ip}  (curl_cffi использует системный DNS)")
    else:
        _err("DNS", "mobileproxy не резолвится — запросы идут с обычного IP.")
        _err("DNS", "Сервер вернёт X-Yandex-Captcha: 403. Продолжаем, но скорее всего упадём.")
        print()

    _ok("TLS", f"Профиль TLS fingerprint: {IMPERSONATE}  (curl_cffi impersonate)")

    step_warm_cookies(session)

    track_id, need_register, account_type = step_start(session, phone)
    if not track_id:
        sys.exit("  Прервано: не удалось получить track_id.")

    print(f"  Track ID   : {track_id}")
    print(f"  Acct type  : {account_type}")

    # ══════════════════════════════════════════
    #  ФЛОУ РЕГИСТРАЦИИ (новый номер)
    # ══════════════════════════════════════════
    if need_register:
        print()
        _log("FLOW", "→ РЕГИСТРАЦИЯ нового аккаунта")

        # R-1: валидация номера
        if not step_validate(session, track_id, phone):
            sys.exit("  Прервано: номер не прошёл валидацию.")

        # R-2: запрос SMS через phone/confirm/submit
        if not step_phone_confirm_submit(session, track_id, phone):
            sys.exit("  Прервано: SMS не отправлен.")

        # R-3: ввод кода
        code = step_input_code()
        if not code:
            sys.exit("  Отменено пользователем.")

        # R-4: подтверждение кода через phone/confirm/commit
        if not step_phone_confirm_commit(session, track_id, code):
            sys.exit("  Прервано: код не принят.")

        # R-5: создание аккаунта neophonish
        result = step_register_neophonish(session, track_id)
        if not result:
            sys.exit("  Прервано: ошибка при создании аккаунта.")

        if result == "__need_token__":
            token = step_get_token(session, track_id)
        else:
            token = result

        if not token:
            sys.exit("  Прервано: токен не получен.")

        _print_token_result(token)

    # ══════════════════════════════════════════
    #  ФЛОУ АВТОРИЗАЦИИ (существующий аккаунт)
    # ══════════════════════════════════════════
    else:
        print()
        _log("FLOW", "→ АВТОРИЗАЦИЯ существующего аккаунта")

        # A-1: запрос SMS-кода через challenge
        if not step_challenge_sms(session, track_id):
            sys.exit("  Прервано: challenge SMS не запрошен.")

        # A-2: ввод кода
        code = step_input_code()
        if not code:
            sys.exit("  Отменено пользователем.")

        # A-3: подтверждение challenge
        if not step_challenge_commit(session, track_id, code):
            sys.exit("  Прервано: challenge код не принят.")

        # A-4: получение токена
        token = step_get_token(session, track_id)
        if not token:
            sys.exit("  Прервано: токен не получен.")

        _print_token_result(token)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("  Прервано пользователем.")
        sys.exit(1)