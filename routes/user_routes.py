from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash

from auth.session import is_logged_in, current_user_id
from models.user_model import (
    get_user_by_id, set_totp_secret, enable_totp, disable_totp,
    save_backup_codes, get_unused_backup_codes
)
from security.event_logger import get_recent_attempts, get_security_events
from auth.totp import (
    generate_totp_secret, get_provisioning_qr_base64, verify_totp_code,
    generate_backup_codes, hash_backup_code
)


user_bp = Blueprint("user", __name__)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)
    return wrapper


@user_bp.route("/home")
@login_required
def home():
    user_id = current_user_id()
    user = get_user_by_id(user_id)
    return render_template("user/home.html", user=user)


@user_bp.route("/dashboard")
@login_required
def dashboard():
    user_id = current_user_id()
    user = get_user_by_id(user_id)
    attempts = get_recent_attempts(user_id, limit=10)
    events = get_security_events(user_id, limit=10)
    failed_count = sum(1 for a in attempts if a["success"] == 0)

    return render_template(
        "user/dashboard.html",
        user=user,
        attempts=attempts,
        events=events,
        failed_count=failed_count,
    )


@user_bp.route("/security")
@login_required
def security():
    user_id = current_user_id()
    user = get_user_by_id(user_id)
    events = get_security_events(user_id, limit=50)
    return render_template("user/security.html", events=events, user=user)


@user_bp.route("/login-history")
@login_required
def login_history():
    user_id = current_user_id()
    attempts = get_recent_attempts(user_id, limit=50)
    return render_template("user/login_history.html", attempts=attempts)


@user_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    user_id = current_user_id()
    user = get_user_by_id(user_id)

    if user["totp_enabled"]:
        return redirect(url_for("user.security"))

    if request.method == "POST":
        code = request.form.get("code")
        secret = request.form.get("secret")  # hidden field carries the pending secret
        if verify_totp_code(secret, code):
            set_totp_secret(user_id, secret)
            enable_totp(user_id)

            plain_codes = generate_backup_codes()
            hashed = [hash_backup_code(c) for c in plain_codes]
            save_backup_codes(user_id, hashed)

            return render_template("user/totp_backup_codes.html", codes=plain_codes)
        qr_b64 = get_provisioning_qr_base64(user["username"], secret)
        return render_template("user/totp_setup.html", qr_b64=qr_b64, secret=secret,
                                error="Invalid code. Try again.")

    secret = generate_totp_secret()
    qr_b64 = get_provisioning_qr_base64(user["username"], secret)
    return render_template("user/totp_setup.html", qr_b64=qr_b64, secret=secret, error=None)


@user_bp.route("/2fa/disable", methods=["POST"])
@login_required
def totp_disable():
    user_id = current_user_id()
    disable_totp(user_id)
    flash("Two-factor authentication disabled.")
    return redirect(url_for("user.security"))


@user_bp.route("/2fa/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_backup_codes():
    user_id = current_user_id()
    user = get_user_by_id(user_id)
    if not user["totp_enabled"]:
        return redirect(url_for("user.security"))

    plain_codes = generate_backup_codes()
    hashed = [hash_backup_code(c) for c in plain_codes]
    save_backup_codes(user_id, hashed)
    return render_template("user/totp_backup_codes.html", codes=plain_codes)