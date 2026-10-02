from dotenv import load_dotenv
load_dotenv()

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    DATABASE_URL = os.environ.get("DATABASE_URL")
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-this-later")
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    DATABASE_PATH = os.path.join(BASE_DIR, "database", "app.db")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    OTP_LENGTH = 6
    OTP_EXPIRY_SECONDS = 300

    # Email (Gmail SMTP) — set these as environment variables, never hardcode
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
    SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD")
    EMAIL_OTP_ENABLED = bool(os.environ.get("SMTP_EMAIL")) and bool(os.environ.get("SMTP_APP_PASSWORD"))

        # SMS (Fast2SMS) - optional
    SMS_PROVIDER = os.environ.get("SMS_PROVIDER", "").lower()
    FAST2SMS_API_KEY = os.environ.get("FAST2SMS_API_KEY")
    SMS_OTP_ENABLED = SMS_PROVIDER == "fast2sms" and bool(FAST2SMS_API_KEY)

    RISK_LOW_MAX = 0.3
    RISK_MEDIUM_MAX = 0.6
    RISK_HIGH_MAX = 0.85

    MODEL_DIR = os.path.join(BASE_DIR, "ml", "trained_models")
    DATASET_PATH = os.path.join(BASE_DIR, "ml", "datasets", "authentication_logs.csv")

    APP_TIMEZONE = "Asia/Kolkata"
    BREVO_API_KEY = os.environ.get("BREVO_API_KEY")