import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import Config


def send_otp_email(to_email, code):
    """Sends the OTP code to the user's email via Gmail SMTP.
    Returns True if sent successfully, False otherwise (falls back to console)."""

    if not Config.EMAIL_OTP_ENABLED:
        return False

    subject = "Your Security Verification Code"
    body = (
        f"Your one-time verification code is: {code}\n\n"
        f"This code expires in {Config.OTP_EXPIRY_SECONDS // 60} minutes.\n"
        f"If you did not attempt to log in, please secure your account immediately.\n\n"
        f"- AI Adaptive Authentication System"
    )

    msg = MIMEMultipart()
    msg["From"] = Config.SMTP_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.SMTP_EMAIL, Config.SMTP_APP_PASSWORD)
            server.sendmail(Config.SMTP_EMAIL, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send OTP email: {e}", flush=True)
        return False