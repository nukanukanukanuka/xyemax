#!/usr/bin/env python3
"""
VK SMS Debug — берёт виртуальный номер через onlinesim.io или smsfast.cc,
автоматически проходит весь OTP флоу до access_token.

Использование:
    python vk_sms_debug.py                               # по умолчанию: ru proxy, onlinesim sim=7
    python vk_sms_debug.py --country kz --sim 77         # Kazakhstan via onlinesim
    python vk_sms_debug.py --country kz --sim 77 --2cap <KEY>  # KZ + авто-капча
    python vk_sms_debug.py --provider smsfast --sf-country 2   # KZ via smsfast.cc
    python vk_sms_debug.py --provider smsfast --sf-country 40  # UZ via smsfast.cc
"""
import sys
import time
import json
import re
import uuid
import argparse
import os

# onlinesim использует обычный requests (без прокси)
try:
    import requests as _req
except ImportError:
    print("pip install requests")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vk_auth

# ─── Конфиг ───────────────────────────────────────────────────────────────────

ONLINESIM_KEY  = "5UQ4PfWRR197W4v-1F37v4P4-1XXfG5Vd-EQkw1959-C2r19p3D43M6yev"
ONLINESIM_BASE = "https://onlinesim.io/api"

SMSFAST_KEY  = "hTh9ITbTLDimL2VtLaeeUUSyoiI7yE"
SMSFAST_BASE = "https://backend.smsfast.cc/stubs/handler_api.php"  # реальный API эндпоинт

# Country IDs for smsfast.cc (from their docs)
SMSFAST_COUNTRIES = {
    "ru": 7,   # Russia (not listed, but standard)
    "kz": 2,   # Kazakhstan
    "kg": 11,  # Kyrgyzstan
    "uz": 40,  # Uzbekistan
    "ua": 1,   # Ukraine
    "by": 51,  # Belarus
    "de": 43,  # Germany
    "uk": 16,  # United Kingdom
    "pl": 15,  # Poland
    "in": 22,  # India
    "ge": 29,  # Serbia (closest mapping, no Georgia listed)
    "ng": 19,  # Nigeria
    "id": 6,   # Indonesia
    "vn": 10,  # Vietnam
    "ph": 4,   # Philippines
    "cn": 3,   # China
    "sl": 115, # Sierra Leone — единственная страна с VK-номерами на smsfast прямо сейчас
}

PROXY_HOST         = "gw.dataimpulse.com"
PROXY_USER_PREFIX  = "c0b4678c46eefeef8307__cr"
PROXY_PASS         = "de1670adcc5e712f"
PROXY_STICKY_PORT  = 10000
PROXY_ROTATE_PORT  = 824

TWO_CAPTCHA_KEY: str = "93668940b329365cb0bc8c780163f2b4"

def make_proxy(country: str, sticky: bool = True) -> dict:
    port = PROXY_STICKY_PORT if sticky else PROXY_ROTATE_PORT
    url  = f"socks5://{PROXY_USER_PREFIX}.{country}:{PROXY_PASS}@{PROXY_HOST}:{port}"
    return {"http": url, "https": url}

# ─── 2captcha автоматическое решение ─────────────────────────────────────────

def solve_captcha_2cap(captcha_img_url: str, captcha_sid: str) -> str:
    """Отправляет капчу в 2captcha.com и возвращает решение."""
    if not TWO_CAPTCHA_KEY:
        raise RuntimeError("2captcha ключ не задан (--2cap)")
    print(f"  [2cap] Отправляем капчу: {captcha_img_url}")
    submit = _req.post("https://2captcha.com/in.php", data={
        "key":    TWO_CAPTCHA_KEY,
        "method": "base64",
        "body":   __import__("base64").b64encode(
            _req.get(captcha_img_url, timeout=15).content
        ).decode(),
        "json":   1,
    }, timeout=20).json()
    if submit.get("status") != 1:
        raise RuntimeError(f"2captcha submit failed: {submit}")
    task_id = submit["request"]
    print(f"  [2cap] task_id={task_id}, ждём решения...")
    for _ in range(24):          # max ~120 seconds
        time.sleep(5)
        res = _req.get("https://2captcha.com/res.php", params={
            "key":    TWO_CAPTCHA_KEY,
            "action": "get",
            "id":     task_id,
            "json":   1,
        }, timeout=15).json()
        if res.get("status") == 1:
            answer = res["request"]
            print(f"  [2cap] решение: {answer!r}")
            return answer
        if res.get("request") != "CAPCHA_NOT_READY":
            raise RuntimeError(f"2captcha error: {res}")
    raise RuntimeError("2captcha: тайм-аут решения капчи")

def solve_captcha(captcha_img_url: str, captcha_sid: str) -> str:
    """Решает капчу: автоматически через 2captcha или вручную через stdin."""
    if TWO_CAPTCHA_KEY:
        return solve_captcha_2cap(captcha_img_url, captcha_sid)
    print(f"\n  🔒 CAPTCHA!")
    print(f"     Откройте в браузере: {captcha_img_url}")
    return input("  Введите текст капчи: ").strip()

# ─── Onlinesim API ────────────────────────────────────────────────────────────

def sim_call(endpoint: str, **params):
    params["apikey"] = ONLINESIM_KEY
    params["lang"]   = "en"
    r = _req.get(f"{ONLINESIM_BASE}/{endpoint}", params=params, timeout=20)
    r.raise_for_status()
    return r.json()

def sim_get_number(service: str, country: int) -> int:
    data = sim_call("getNum.php", service=service, country=country)
    print(f"  [sim] getNum → {data}")
    if data.get("response") != 1:
        raise RuntimeError(f"onlinesim getNum failed: {data}")
    return int(data["tzid"])

def sim_get_state(tzid: int):
    return sim_call("getState.php", tzid=tzid, message_to_code=0)

def sim_wait_number(tzid: int, max_wait: int = 60) -> str:
    """Ждём пока onlinesim назначит номер, возвращаем номер телефона."""
    print(f"  [sim] Ждём назначения номера (tzid={tzid})...")
    for i in range(max_wait):
        state = sim_get_state(tzid)
        if isinstance(state, list) and state:
            s     = state[0]
            resp  = s.get("response", "")
            phone = s.get("number", "")
            print(f"  [sim] [{i+1}s] {resp!r}  number={phone!r}")
            if resp in ("TZ_NUM_WAIT", "TZ_NUM_ANSWER") and phone:
                return str(phone)
            if resp in ("TZ_OVER_EMPTY", "TZ_OVER_OK"):
                raise RuntimeError(f"onlinesim: операция закрыта до назначения: {resp}")
        time.sleep(1)
    raise RuntimeError("onlinesim: номер не назначен за 60с")

def sim_wait_sms(tzid: int, timeout: int = 180) -> str:
    """Поллим onlinesim пока не придёт SMS."""
    poll_interval = 5   # раз в 5с, чтобы не словить 429
    print(f"\n  [sim] Ждём SMS (max {timeout}s, poll каждые {poll_interval}с)...")
    elapsed = 0
    while elapsed < timeout:
        try:
            state = sim_get_state(tzid)
        except Exception as e:
            print(f"  [sim] poll error: {e} — ждём 10с...")
            time.sleep(10)
            elapsed += 10
            continue
        if isinstance(state, list) and state:
            s    = state[0]
            resp = s.get("response", "")
            msg  = s.get("msg", "")
            print(f"  [sim] [{elapsed}s] {resp!r}  msg={msg!r}")
            if resp == "TZ_NUM_ANSWER" and msg:
                return str(msg)
            if resp in ("TZ_OVER_EMPTY", "TZ_OVER_OK"):
                raise RuntimeError(f"onlinesim: операция закрыта без SMS: {resp}")
        time.sleep(poll_interval)
        elapsed += poll_interval
    raise RuntimeError(f"onlinesim: SMS не получена за {timeout}с")

def sim_ok(tzid: int) -> None:
    data = sim_call("setOperationOk.php", tzid=tzid)
    print(f"  [sim] setOperationOk → {data}")

def sim_cancel(tzid: int) -> None:
    try:
        print(f"  [sim] Отменяем tzid={tzid}...")
        data = sim_call("setOperationOk.php", tzid=tzid, ban=1)
        print(f"  [sim] cancel → {data}")
    except Exception as e:
        print(f"  [sim] cancel error: {e}")

# ─── Smsfast.cc API ───────────────────────────────────────────────────────────

def smsfast_call(action: str, **params) -> str:
    """Выполняет GET-запрос к smsfast API. Возвращает текст ответа."""
    p = {"api_key": SMSFAST_KEY, "action": action}
    p.update(params)
    r = _req.get(SMSFAST_BASE, params=p, timeout=20)
    r.raise_for_status()
    text = r.text.strip()
    if text == "BAD_KEY":
        raise RuntimeError("smsfast: BAD_KEY — неверный API ключ")
    if text in ("ERROR_SQL", "BAD_ACTION", "BAD_SERVICE"):
        raise RuntimeError(f"smsfast: ошибка API: {text}")
    return text

def smsfast_balance() -> str:
    resp = smsfast_call("getBalance")
    # ACCESS_BALANCE:X
    if resp.startswith("ACCESS_BALANCE:"):
        return resp.split(":", 1)[1]
    return resp

def smsfast_get_number(service: str, country_id: int) -> tuple:
    """Заказывает номер. Возвращает (activation_id, phone_number)."""
    resp = smsfast_call("getNumber", service=service, country=country_id)
    # ACCESS_NUMBER:ID:PHONE
    if resp.startswith("ACCESS_NUMBER:"):
        parts = resp.split(":")
        act_id = parts[1]
        phone  = parts[2]
        return act_id, phone
    if resp == "NO_NUMBERS":
        raise RuntimeError(f"smsfast: NO_NUMBERS — нет номеров для service={service!r} country={country_id}")
    if resp == "NO_BALANCE":
        raise RuntimeError("smsfast: NO_BALANCE — недостаточно средств")
    raise RuntimeError(f"smsfast getNumber: неожиданный ответ: {resp!r}")

def smsfast_get_status(act_id: str) -> str:
    """Возвращает сырой статус."""
    return smsfast_call("getStatus", id=act_id)

def smsfast_wait_sms(act_id: str, timeout: int = 600) -> str:
    """Поллим smsfast пока не придёт SMS. Возвращает текст SMS."""
    poll_interval = 5
    elapsed = 0
    print(f"\n  [smsfast] Ждём SMS (id={act_id}, max {timeout}s, poll каждые {poll_interval}с)...")
    while elapsed < timeout:
        try:
            status = smsfast_get_status(act_id)
        except RuntimeError as e:
            print(f"  [smsfast] poll error: {e} — ждём 10с...", flush=True)
            time.sleep(10)
            elapsed += 10
            continue
        print(f"  [smsfast] [{elapsed}s] статус: {status!r}", flush=True)
        if status.startswith("STATUS_OK:"):
            # STATUS_OK:CODE
            code = status.split(":", 1)[1]
            return code
        if status == "STATUS_CANCEL":
            raise RuntimeError("smsfast: активация отменена (STATUS_CANCEL)")
        # STATUS_WAIT_CODE → ждём
        time.sleep(poll_interval)
        elapsed += poll_interval
    raise RuntimeError(f"smsfast: SMS не получена за {timeout}с")

def smsfast_ok(act_id: str) -> None:
    try:
        resp = smsfast_call("setStatus", id=act_id, status=6)
        print(f"  [smsfast] setStatus(6=ok) → {resp}")
    except Exception as e:
        print(f"  [smsfast] setStatus ok error: {e}")

def smsfast_cancel(act_id: str) -> None:
    try:
        print(f"  [smsfast] Отменяем id={act_id}...")
        resp = smsfast_call("setStatus", id=act_id, status=8)
        print(f"  [smsfast] setStatus(8=cancel) → {resp}")
    except Exception as e:
        print(f"  [smsfast] cancel error: {e}")

def smsfast_resend(act_id: str) -> None:
    try:
        resp = smsfast_call("setStatus", id=act_id, status=3)
        print(f"  [smsfast] setStatus(3=resend) → {resp}")
    except Exception as e:
        print(f"  [smsfast] resend error: {e}")

# ─── Флоу ─────────────────────────────────────────────────────────────────────

def run(proxy_country: str, sim_country: int, supported_ways: str,
        provider: str = "onlinesim", sf_country: int = None,
        sf_service: str = "vk") -> dict:
    proxy = make_proxy(proxy_country, sticky=True)
    vk_auth.PROXIES = proxy
    # Сбрасываем глобальную сессию чтобы подхватить новый прокси
    vk_auth._HTTP_SESSION = None

    print(f"  proxy       : {list(proxy.values())[0]}")
    print(f"  provider    : {provider}")

    # ── 1. Получаем номер ──────────────────────────────────────────────────────
    act_id = None   # универсальный идентификатор (tzid для onlinesim, str id для smsfast)

    if provider == "smsfast":
        country_id = sf_country
        if country_id is None:
            country_id = SMSFAST_COUNTRIES.get(proxy_country, 2)  # по умолч. KZ
        print(f"\n[1/6] Заказываем номер у smsfast.cc (service={sf_service!r}, country_id={country_id})...")
        # Проверяем баланс
        try:
            bal = smsfast_balance()
            print(f"  [smsfast] баланс: {bal}")
        except Exception as e:
            print(f"  [smsfast] баланс: ошибка {e}")
        act_id, phone = smsfast_get_number(service=sf_service, country_id=country_id)
        if not phone.startswith("+"):
            phone = "+" + phone
        print(f"\n  ✔ Номер: {phone}  act_id={act_id}")
    else:
        print(f"\n[1/6] Заказываем номер у onlinesim (service=vkcom, sim_country={sim_country})...")
        tzid  = sim_get_number(service="vkcom", country=sim_country)
        phone = sim_wait_number(tzid)
        act_id = tzid
        if not phone.startswith("+"):
            phone = "+" + phone
        print(f"\n  ✔ Номер: {phone}  tzid={tzid}")

    # Единые хелперы для работы с провайдером (onlinesim или smsfast)
    def do_cancel():
        if provider == "smsfast":
            smsfast_cancel(act_id)
        else:
            sim_cancel(act_id)

    def do_wait_sms(timeout=600) -> str:
        if provider == "smsfast":
            # smsfast возвращает только код, а не полный текст SMS
            code = smsfast_wait_sms(act_id, timeout=timeout)
            return code
        else:
            return sim_wait_sms(act_id, timeout=timeout)

    def do_ok():
        if provider == "smsfast":
            smsfast_ok(act_id)
        else:
            sim_ok(act_id)

    # ── 2. VK: anonymous token + hashes ───────────────────────────────────────
    device_id          = str(uuid.uuid4())
    external_device_id = str(uuid.uuid4())
    print(f"\n[2/6] device_id={device_id[:8]}...  ext={external_device_id[:8]}...")

    try:
        anon_token = vk_auth.step0_anon_token(device_id)
    except Exception as e:
        do_cancel()
        raise

    nonce = vk_auth.step1_get_hashes(anon_token, device_id)

    try:
        signed_token = vk_auth.step1b_sign_anon_token(anon_token, nonce, device_id)
    except RuntimeError:
        print("  ⚠  signed_token недоступен, используем unsigned")
        signed_token = anon_token

    # ── 3. validatePhone ───────────────────────────────────────────────────────
    print(f"\n[3/6] auth.validatePhone  supported_ways={supported_ways!r}")
    s2 = None
    for attempt, ways in enumerate([supported_ways, "sms_inbox", "sms_inbox"]):
        if attempt > 0:
            print(f"  ↳ Повтор {attempt} с supported_ways={ways!r}")
        try:
            s2 = vk_auth.post_method("auth.validatePhone", {
                "phone":                    phone,
                "supported_ways":           ways,
                "supported_ways_settings":  "callreset_preview_enabled",
                "allow_callreset":          "1",
                "libverify_support":        "1",
                "device_id":                device_id,
                "sak_version":              vk_auth.SAK_VERSION,
                "external_device_id":       external_device_id,
            }, anon_token=signed_token)
            break
        except vk_auth.CaptchaRequired as cap:
            try:
                captcha_key = solve_captcha(cap.captcha_img, cap.captcha_sid)
                s2 = vk_auth.post_method("auth.validatePhone", {
                    "phone":                    phone,
                    "supported_ways":           ways,
                    "allow_callreset":          "1",
                    "libverify_support":        "1",
                    "device_id":                device_id,
                    "sak_version":              vk_auth.SAK_VERSION,
                    "external_device_id":       external_device_id,
                    "captcha_sid":              cap.captcha_sid,
                    "captcha_key":              captcha_key,
                }, anon_token=signed_token)
                break
            except Exception as e2:
                print(f"  ✘ капча: {e2}")
                continue
        except RuntimeError as e:
            print(f"  ✘ attempt {attempt}: {e}")
            if attempt == 2:
                do_cancel()
                raise
            continue

    if not s2:
        do_cancel()
        raise RuntimeError("validatePhone не удался после всех попыток")

    sid         = s2.get("sid", "")
    vtype       = s2.get("type", s2.get("validation_type", "?"))
    external_id = s2.get("external_id", "")
    delay       = s2.get("delay", "?")
    code_length = s2.get("code_length", "?")

    print(f"\n  ✔ validatePhone response:")
    print(f"     type        = {vtype!r}")
    print(f"     delay       = {delay}s")
    print(f"     code_length = {code_length}")
    print(f"     sid         = {'ДА (' + sid[:10] + '...)' if sid else 'ОТСУТСТВУЕТ!'}")

    if not sid:
        do_cancel()
        raise RuntimeError(f"validatePhone не вернул sid. Полный ответ: {s2}")

    print(f"\n  ℹ  validation_type={s2.get('validation_type')!r} — ждём SMS")

    # ── 4. Ждём SMS ───────────────────────────────────────────────────────────
    print(f"\n[4/6] Ждём SMS на {phone}...")
    try:
        sms_text = do_wait_sms(timeout=600)
    except RuntimeError as e:
        do_cancel()
        raise

    print(f"\n  ✔ SMS/код получен: {sms_text!r}")
    # smsfast может вернуть уже только код; onlinesim — полный текст SMS
    codes = re.findall(r'\b\d{4,8}\b', sms_text)
    if not codes:
        do_cancel()
        raise RuntimeError(f"Код не найден в тексте: {sms_text!r}")
    code = codes[0]
    print(f"  ✔ Код: {code}")

    # ── 5. validatePhoneConfirm ────────────────────────────────────────────────
    print(f"\n[5/6] auth.validatePhoneConfirm  code={code}")
    body = {
        "sid":                  sid,
        "phone":                phone,
        "code":                 code,
        "client_id":            vk_auth.CLIENT_ID,
        "device_id":            device_id,
        "sak_version":          vk_auth.SAK_VERSION,
        "can_skip_password":    "1",
        "is_code_autocomplete": "1",
    }
    if external_id:
        body["external_id"] = external_id

    try:
        s3 = vk_auth.post_method("auth.validatePhoneConfirm", body, anon_token=signed_token)
    except Exception as e:
        do_cancel()
        raise

    if not s3.get("success"):
        do_cancel()
        raise RuntimeError(f"OTP не принят: {s3}")

    next_step = s3.get("next_step") or ""
    auth_hash = s3.get("auth_hash") or ""
    print(f"  ✔ OTP подтверждён: next_step={next_step!r}")

    # ── 6. /oauth/token ────────────────────────────────────────────────────────
    print(f"\n[6/6] /oauth/token  next_step={next_step!r}")
    if next_step == "on_success_validation":
        access_token = s3.get("access_token", "")
        user_id      = s3.get("user_id")
        vk_auth.step_success(sid, access_token)
    else:
        nonce2       = vk_auth.step1_get_hashes(anon_token, device_id)
        s4           = vk_auth.step4_oauth_token(
                           phone, sid, device_id, anon_token,
                           nonce2, next_step, auth_hash)
        access_token = s4["access_token"]
        user_id      = s4.get("user_id")
        vk_auth.step_success(sid, access_token)

    # ── Завершаем активацию у провайдера ──────────────────────────────────────
    try:
        do_ok()
    except Exception as e:
        print(f"  ⚠ finish activation: {e}")

    # ── Сохраняем ─────────────────────────────────────────────────────────────
    result = {
        "access_token": access_token,
        "user_id":      user_id,
        "phone":        phone,
    }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vk_session.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 68)
    print("\033[92m✅  Успех!\033[0m")
    print(f"   phone        : {phone}")
    print(f"   user_id      : {user_id}")
    tok = access_token or ""
    print(f"   access_token : {tok[:12]}···{tok[-8:]}" if tok else "   access_token : ПУСТО!")
    print(f"   Сохранено → {out}")
    print("=" * 68)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="VK SMS Debug — onlinesim.io или smsfast.cc",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python -u vk_sms_debug.py                                    # onlinesim RU
  python -u vk_sms_debug.py --country kz --sim 77             # onlinesim KZ
  python -u vk_sms_debug.py --provider smsfast --sf-country 2  # smsfast KZ
  python -u vk_sms_debug.py --provider smsfast --sf-country 40 # smsfast UZ
  python -u vk_sms_debug.py --provider smsfast --sf-country 11 # smsfast KG

smsfast country IDs: 2=KZ 11=KG 40=UZ 51=BY 43=DE 16=UK 15=PL 22=IN 19=NG
""")
    parser.add_argument("--country", default="ru",
                        help="ISO код страны прокси (ru, kz, uz...). По умолч: ru")
    parser.add_argument("--sim", type=int, default=7,
                        help="Диалинг-код для onlinesim (7=RU, 77=KZ, 998=UZ). По умолч: 7")
    parser.add_argument("--ways", default="sms_inbox",
                        help="supported_ways для validatePhone (по умолч: sms_inbox)")
    parser.add_argument("--2cap", dest="twocap", default="",
                        help="2captcha.com API ключ для авто-капчи")
    parser.add_argument("--provider", default="onlinesim", choices=["onlinesim", "smsfast"],
                        help="SMS провайдер: onlinesim (по умолч) или smsfast")
    parser.add_argument("--sf-country", dest="sf_country", type=int, default=None,
                        help="Числовой ID страны для smsfast (2=KZ, 40=UZ, 11=KG, 43=DE...)")
    parser.add_argument("--sf-service", dest="sf_service", default="vk",
                        help="Код сервиса для smsfast (по умолч: vk). Попробуй 'ok' если 'vk' не работает")
    args = parser.parse_args()

    if args.twocap:
        global TWO_CAPTCHA_KEY
        TWO_CAPTCHA_KEY = args.twocap
        vk_auth.TWO_CAPTCHA_KEY = args.twocap

    print("=" * 68)
    print(f"  VK SMS Debug  |  proxy={args.country}  provider={args.provider}  ways={args.ways}")
    if args.provider == "smsfast":
        print(f"  smsfast: country={args.sf_country}  service={args.sf_service}")
    else:
        print(f"  onlinesim: sim_cc={args.sim}")
    print("=" * 68)

    # Быстрый тест баланса smsfast перед стартом
    if args.provider == "smsfast":
        try:
            bal = smsfast_balance()
            print(f"  [smsfast] баланс аккаунта: {bal}")
        except Exception as e:
            print(f"  [smsfast] ⚠ не удалось получить баланс: {e}")

    try:
        run(proxy_country=args.country,
            sim_country=args.sim,
            supported_ways=args.ways,
            provider=args.provider,
            sf_country=args.sf_country,
            sf_service=args.sf_service)
    except RuntimeError as e:
        print(f"\n\033[91m❌  {e}\033[0m")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(0)


if __name__ == "__main__":
    main()
