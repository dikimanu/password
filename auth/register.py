import sqlite3
from models.user_model import create_user, get_user_by_username_or_email


def register_user(username, email, phone, password, confirm_password):
    if not username or not email or not phone or not password:
        return {"success": False, "message": "All fields are required."}

    if password != confirm_password:
        return {"success": False, "message": "Passwords do not match."}

    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters."}

    if get_user_by_username_or_email(username) or get_user_by_username_or_email(email):
        return {"success": False, "message": "Username or email already exists."}

    try:
        user_id = create_user(username, email, phone, password)
        return {"success": True, "message": "Registration successful.", "user_id": user_id}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "Username or email already exists."}
