import json
import urllib.parse
import urllib.request
from config import Config


def normalize_phone(phone):
    """Return a 10-digit Indian mobile number, or None if invalid."""
    digits = "".join(c for c in (phone or "") if c.isdigit())
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return digits if len(digits) == 10 and digits[0] in "6789" else None


def send_otp_sms(phone, code):
    if not Config.SMS_OTP_ENABLED:
        return False
    number = normalize_phone(phone)
    if not number:
        return False
    params = urllib.parse.urlencode({
        "authorization": Config.FAST2SMS_API_KEY,
        "route": "otp",
        "variables_values": code,
        "numbers": number,
    })
    try:
        with urllib.request.urlopen(
                "https://www.fast2sms.com/dev/bulkV2?" + params, timeout=15) as r:
            return json.loads(r.read().decode()).get("return") is True
    except Exception as e:
        print(f"[SMS ERROR] Failed to send OTP SMS: {e}", flush=True)
        return False