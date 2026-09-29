import json
import urllib.request
from config import Config


def send_otp_email(to_email, code):
    if not Config.BREVO_API_KEY or not to_email:
        return False

    subject = "Your Security Verification Code"
    body = (
        f"Your one-time verification code is: {code}\n\n"
        f"This code expires in {Config.OTP_EXPIRY_SECONDS // 60} minutes.\n"
        f"If you did not attempt to log in, please secure your account immediately.\n\n"
        f"- AI Adaptive Authentication System"
    )

    payload = json.dumps({
        "sender": {"email": Config.SMTP_EMAIL, "name": "AI Adaptive Authentication"},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": body,
    }).encode()

    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=payload,
        method="POST",
        headers={
            "api-key": Config.BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send OTP email: {e}", flush=True)
        return False