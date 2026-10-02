import json
import urllib.request
import urllib.error
from config import Config


def _send_via_brevo(to_email, subject, body):
    print(f"[DEBUG] BREVO_API_KEY loaded: {bool(Config.BREVO_API_KEY)}", flush=True)
    print(f"[DEBUG] SMTP_EMAIL (sender) loaded: {Config.SMTP_EMAIL!r}", flush=True)

    if not Config.BREVO_API_KEY or not to_email:
        print("[DEBUG] Missing API key or recipient — aborting send.", flush=True)
        return False

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
            print(f"[DEBUG] Brevo response status: {resp.status}", flush=True)
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        print(f"[EMAIL ERROR] Brevo HTTPError {e.code}: {e.read().decode(errors='replace')}", flush=True)
        return False
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send email: {e}", flush=True)
        return False


def send_otp_email(to_email, code):
    subject = "Your Security Verification Code"
    body = (
        f"Your one-time verification code is: {code}\n\n"
        f"This code expires in {Config.OTP_EXPIRY_SECONDS // 60} minutes.\n"
        f"If you did not attempt to log in, please secure your account immediately.\n\n"
        f"- AI Adaptive Authentication System"
    )
    return _send_via_brevo(to_email, subject, body)


def send_password_reset_email(to_email, reset_link):
    subject = "Reset Your Password"
    body = (
        f"We received a request to reset your password.\n\n"
        f"Click the link below to choose a new password. This link expires in 30 minutes:\n"
        f"{reset_link}\n\n"
        f"If you did not request this, you can safely ignore this email.\n\n"
        f"- AI Adaptive Authentication System"
    )
    return _send_via_brevo(to_email, subject, body)