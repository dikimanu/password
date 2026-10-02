import secrets
from datetime import datetime, timedelta

from database.database import get_connection
from auth.password import hash_password
from notifications.email_service import send_password_reset_email

RESET_EXPIRY_MINUTES = 30


def create_reset_token(user_id):
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(minutes=RESET_EXPIRY_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE password_resets SET used = 1 WHERE user_id = %s AND used = 0", (user_id,))
    cursor.execute(
        "INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, %s)",
        (user_id, token, expires_at),
    )
    conn.commit()
    conn.close()
    return token


def get_valid_reset(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM password_resets WHERE token = %s AND used = 0", (token,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None
    expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.now() > expires_at:
        return None
    return row


def consume_reset_token(token, new_password):
    row = get_valid_reset(token)
    if row is None:
        return False

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                   (hash_password(new_password), row["user_id"]))
    cursor.execute("UPDATE password_resets SET used = 1 WHERE id = %s", (row["id"],))
    conn.commit()
    conn.close()
    return True