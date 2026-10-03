from database.database import get_connection
from auth.password import hash_password

def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_attempts WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM security_events WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM otp_codes WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM known_devices WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM password_resets WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    
def create_user(username, email, phone, plain_password, is_admin=0):
    conn = get_connection()
    cursor = conn.cursor()
    password_hash = hash_password(plain_password)

    cursor.execute("""
        INSERT INTO users (username, email, phone, password_hash, is_admin)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
    """, (username, email, phone, password_hash, is_admin))

    user_id = cursor.fetchone()["id"]
    conn.commit()
    conn.close()
    return user_id


def get_user_by_username_or_email(identifier):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (identifier, identifier))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_account_status(user_id, status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET account_status = %s WHERE id = %s", (status, user_id))
    conn.commit()
    conn.close()


def update_risk_level(user_id, risk_level):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET risk_level = %s WHERE id = %s", (risk_level, user_id))
    conn.commit()
    conn.close()


def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    return users


def set_totp_secret(user_id, secret):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET totp_secret = %s WHERE id = %s", (secret, user_id))
    conn.commit()
    conn.close()


def enable_totp(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET totp_enabled = 1 WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()


def disable_totp(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()