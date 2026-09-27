from database.database import get_connection
from auth.password import hash_password


def create_user(username, email, phone, plain_password, is_admin=0):
    conn = get_connection()
    cursor = conn.cursor()
    password_hash = hash_password(plain_password)

    cursor.execute("""
        INSERT INTO users (username, email, phone, password_hash, is_admin)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, phone, password_hash, is_admin))

    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id


def get_user_by_username_or_email(identifier):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_account_status(user_id, status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET account_status = ? WHERE id = ?", (status, user_id))
    conn.commit()
    conn.close()


def update_risk_level(user_id, risk_level):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET risk_level = ? WHERE id = ?", (risk_level, user_id))
    conn.commit()
    conn.close()


def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    return users
