import random
import string
from datetime import datetime, timedelta

from database.database import get_connection
from config import Config


def generate_otp(user_id):
    code = "".join(random.choices(string.digits, k=Config.OTP_LENGTH))
    expires_at = (datetime.now() + timedelta(seconds=Config.OTP_EXPIRY_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO otp_codes (user_id, code, expires_at)
        VALUES (?, ?, ?)
    """, (user_id, code, expires_at))
    conn.commit()
    conn.close()

    print(f"[DEV OTP] User {user_id} OTP code: {code} (expires in {Config.OTP_EXPIRY_SECONDS}s)")
    return code


def verify_otp(user_id, submitted_code):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM otp_codes
        WHERE user_id = ? AND used = 0
        ORDER BY created_at DESC LIMIT 1
    """, (user_id,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        return False

    now = datetime.now()
    expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")

    if now > expires_at:
        conn.close()
        return False

    if row["code"] != submitted_code:
        conn.close()
        return False

    cursor.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()
    return True
