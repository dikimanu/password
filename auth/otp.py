import secrets
import string
from datetime import datetime, timedelta

from database.database import get_connection
from config import Config
from notifications.email_service import send_otp_email
from notifications.sms_service import send_otp_sms


def _mask_email(email):
    name, _, domain = email.partition("@")
    return f"{name[:1]}***@{domain}"


def _mask_phone(phone):
    digits = "".join(c for c in phone if c.isdigit())
    return "******" + digits[-4:]


def generate_otp(user_id, email=None, phone=None):
    """Creates an OTP and sends it by email and/or SMS.
    Returns a list of where it was sent, e.g. ['email a***@gmail.com']."""
    code = "".join(secrets.choice(string.digits) for _ in range(Config.OTP_LENGTH))
    expires_at = (datetime.now() + timedelta(seconds=Config.OTP_EXPIRY_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE otp_codes SET used = 1 WHERE user_id = ? AND used = 0", (user_id,))
    cursor.execute(
        "INSERT INTO otp_codes (user_id, code, expires_at) VALUES (?, ?, ?)",
        (user_id, code, expires_at),
    )
    conn.commit()
    conn.close()

    sent_to = []
    if email and send_otp_email(email, code):
        sent_to.append(f"email {_mask_email(email)}")
    if phone and send_otp_sms(phone, code):
        sent_to.append(f"mobile {_mask_phone(phone)}")

    if not sent_to:
        print(f"[DEV OTP] User {user_id} OTP code: {code} "
              f"(expires in {Config.OTP_EXPIRY_SECONDS}s)", flush=True)
    return sent_to


def otp_message(sent_to):
    if sent_to:
        return "OTP sent to " + " and ".join(sent_to) + "."
    return "Email/SMS is not configured, so the OTP was printed in the server console."


def verify_otp(user_id, submitted_code):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM otp_codes
        WHERE user_id = ? AND used = 0
        ORDER BY id DESC LIMIT 1
    """, (user_id,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        return False

    expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.now() > expires_at:
        conn.close()
        return False

    if not secrets.compare_digest(row["code"], (submitted_code or "").strip()):
        conn.close()
        return False

    cursor.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()
    return True