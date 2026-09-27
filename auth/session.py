from flask import session


def login_session(user_id, is_admin=False):
    session["user_id"] = user_id
    session["is_admin"] = bool(is_admin)


def logout_session():
    session.clear()


def current_user_id():
    return session.get("user_id")


def is_logged_in():
    return "user_id" in session


def is_admin():
    return session.get("is_admin", False)
