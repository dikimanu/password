import os
import psycopg2
import psycopg2.extras
from config import Config

DATABASE_URL = Config.DATABASE_URL


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set. Add it to your .env (local) or Render environment.")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            account_status TEXT NOT NULL DEFAULT 'ACTIVE',
            risk_level TEXT NOT NULL DEFAULT 'LOW',
            is_admin INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            identifier TEXT NOT NULL,
            success INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            risk_score REAL,
            risk_level TEXT,
            attack_category TEXT,
            timestamp TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            event_type TEXT NOT NULL,
            description TEXT,
            risk_level TEXT,
            timestamp TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            code TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS known_devices (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            ip_address TEXT,
            user_agent TEXT,
            first_seen TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
    print(f"Database initialized (PostgreSQL): {DATABASE_URL.split('@')[-1] if DATABASE_URL else 'N/A'}")


if __name__ == "__main__":
    init_db()