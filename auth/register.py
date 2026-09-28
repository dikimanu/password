import re
import sqlite3
from models.user_model import create_user, get_user_by_username_or_email
from notifications.sms_service import normalize_phone

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def register_user(username, email, phone, password, confirm_password):
    username = (username or "").strip()
    email = (email or "").strip()
    phone = (phone or "").strip()

    if not username or not email or not phone or not password:
        return {"success": False, "message": "All fields are required."}

    if not EMAIL_RE.match(email):
        return {"success": False, "message": "Enter a valid email address."}

    clean_phone = normalize_phone(phone)
    if not clean_phone:
        return {"success": False, "message": "Enter a valid 10-digit Indian mobile number."}

    if password != confirm_password:
        return {"success": False, "message": "Passwords do not match."}

    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters."}

    if get_user_by_username_or_email(username) or get_user_by_username_or_email(email):
        return {"success": False, "message": "Username or email already exists."}

    try:
        user_id = create_user(username, email, clean_phone, password)
        return {"success": True, "message": "Registration successful.", "user_id": user_id}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "Username or email already exists."}