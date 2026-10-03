from flask import Blueprint, request, jsonify, render_template, redirect, url_for

from auth.register import register_user
from auth.login import login_user
from auth.otp import verify_otp
from auth.totp import verify_totp_code, verify_backup_code_hash
from auth.session import login_session, logout_session
from models.user_model import (
    get_user_by_id, get_user_by_username_or_email,
    get_unused_backup_codes, mark_backup_code_used
)
from security.account_protection import unprotect_account
from auth.password_reset import create_reset_token, get_valid_reset, consume_reset_token
from notifications.email_service import send_password_reset_email

auth_bp = Blueprint("auth", __name__)


def get_client_ip():
    """Render (and most hosts) sit behind a proxy, so the real client IP
    arrives in X-Forwarded-For instead of request.remote_addr."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


@auth_bp.route("/register", methods=["GET"])
def register_page():
    return render_template("auth/register.html")


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json() if request.is_json else request.form
    result = register_user(
        username=data.get("username"),
        email=data.get("email"),
        phone=data.get("phone"),
        password=data.get("password"),
        confirm_password=data.get("confirm_password"),
    )
    status_code = 201 if result["success"] else 400
    if request.is_json:
        return jsonify(result), status_code
    return render_template("auth/register.html", result=result)


@auth_bp.route("/login", methods=["GET"])
def login_page():
    return render_template("auth/login.html")


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() if request.is_json else request.form
    result = login_user(
        identifier=data.get("identifier"),
        password=data.get("password"),
        ip_address=get_client_ip(),
        user_agent=request.headers.get("User-Agent"),
    )

    if result.get("action") == "ALLOW" and result["success"]:
        user = get_user_by_id(result["user_id"])
        login_session(user["id"], is_admin=bool(user["is_admin"]))

    ok_actions = ("OTP_REQUIRED", "ADDITIONAL_VERIFICATION", "ACCOUNT_PROTECTED", "TOTP_REQUIRED")
    status_code = 200 if result["success"] or result.get("action") in ok_actions else 401

    if request.is_json:
        return jsonify(result), status_code

    if result.get("action") == "TOTP_REQUIRED":
        return render_template("auth/totp_verify.html", user_id=result.get("user_id"), message=result["message"])
    if result.get("action") in ("OTP_REQUIRED", "ACCOUNT_PROTECTED"):
        return render_template("auth/otp.html", user_id=result.get("user_id"), message=result["message"])
    if result["success"]:
        return redirect(url_for("user.home"))
    return render_template("auth/login.html", result=result)


@auth_bp.route("/verify-otp", methods=["POST"])
def verify_otp_route():
    data = request.get_json() if request.is_json else request.form
    user_id = int(data.get("user_id"))
    code = data.get("code")

    if verify_otp(user_id, code):
        user = get_user_by_id(user_id)
        if user["account_status"] == "PROTECTED":
            unprotect_account(user_id)
        login_session(user_id, is_admin=bool(user["is_admin"]))
        result = {"success": True, "message": "OTP verified. Login successful."}
        if request.is_json:
            return jsonify(result), 200
        return redirect(url_for("user.home"))

    result = {"success": False, "message": "Invalid or expired OTP."}
    if request.is_json:
        return jsonify(result), 400
    return render_template("auth/otp.html", user_id=user_id, message=result["message"])


@auth_bp.route("/verify-totp", methods=["POST"])
def verify_totp_route():
    data = request.get_json() if request.is_json else request.form
    user_id = int(data.get("user_id"))
    code = (data.get("code") or "").strip()

    user = get_user_by_id(user_id)

    if user and user["totp_enabled"]:
        # First try as a normal 6-digit TOTP code
        if verify_totp_code(user["totp_secret"], code):
            if user["account_status"] == "PROTECTED":
                unprotect_account(user_id)
            login_session(user_id, is_admin=bool(user["is_admin"]))
            result = {"success": True, "message": "Code verified. Login successful."}
            if request.is_json:
                return jsonify(result), 200
            return redirect(url_for("user.home"))

        # Not a valid TOTP code — try matching it against unused backup codes
        for backup in get_unused_backup_codes(user_id):
            if verify_backup_code_hash(code, backup["code_hash"]):
                mark_backup_code_used(backup["id"])
                if user["account_status"] == "PROTECTED":
                    unprotect_account(user_id)
                login_session(user_id, is_admin=bool(user["is_admin"]))
                result = {"success": True, "message": "Backup code accepted. Login successful."}
                if request.is_json:
                    return jsonify(result), 200
                return redirect(url_for("user.home"))

    result = {"success": False, "message": "Invalid authenticator code or backup code."}
    if request.is_json:
        return jsonify(result), 400
    return render_template("auth/totp_verify.html", user_id=user_id, message=result["message"])


@auth_bp.route("/logout")
def logout():
    logout_session()
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("auth/forgot_password.html")

    data = request.get_json() if request.is_json else request.form
    email = (data.get("email") or "").strip()
    user = get_user_by_username_or_email(email)

    if user:
        print(f"[DEBUG] Found user, sending reset email to {user['email']}", flush=True)
        token = create_reset_token(user["id"])
        reset_link = url_for("auth.reset_password", token=token, _external=True)
        sent = send_password_reset_email(user["email"], reset_link)
        print(f"[DEBUG] send_password_reset_email returned: {sent}", flush=True)
    else:
        print(f"[DEBUG] No user found for email: {email!r}", flush=True)

    # Same message whether or not the email exists, so the form can't be used to find registered emails
    message = "If that email is registered, a password reset link has been sent."
    if request.is_json:
        return jsonify({"success": True, "message": message}), 200
    return render_template("auth/forgot_password.html", message=message)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset = get_valid_reset(token)

    if reset is None:
        return render_template("auth/reset_password.html", token=token, invalid=True)

    if request.method == "GET":
        return render_template("auth/reset_password.html", token=token, invalid=False)

    data = request.get_json() if request.is_json else request.form
    new_password = data.get("password")
    confirm_password = data.get("confirm_password")

    if not new_password or len(new_password) < 8:
        return render_template("auth/reset_password.html", token=token, invalid=False,
                                error="Password must be at least 8 characters.")
    if new_password != confirm_password:
        return render_template("auth/reset_password.html", token=token, invalid=False,
                                error="Passwords do not match.")

    consume_reset_token(token, new_password)
    return render_template("auth/reset_password.html", token=token, invalid=False, success=True)