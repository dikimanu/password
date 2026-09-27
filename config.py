import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-this-later")
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    DATABASE_PATH = os.path.join(BASE_DIR, "database", "app.db")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    OTP_LENGTH = 6
    OTP_EXPIRY_SECONDS = 300

    RISK_LOW_MAX = 0.3
    RISK_MEDIUM_MAX = 0.6
    RISK_HIGH_MAX = 0.85

    MODEL_DIR = os.path.join(BASE_DIR, "ml", "trained_models")
    DATASET_PATH = os.path.join(BASE_DIR, "ml", "datasets", "authentication_logs.csv")