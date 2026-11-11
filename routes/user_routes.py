import base64
import logging
import os
import time
from contextlib import contextmanager
from functools import wraps

from flask import (
    Blueprint, current_app, flash, jsonify, redirect, render_template,
    request, session, url_for,
)

from auth.session import is_logged_in, current_user_id
from auth.totp import (
    generate_backup_codes, generate_totp_secret, get_provisioning_qr_base64,
    hash_backup_code, verify_totp_code,
)
from database.database import get_connection
from models.user_model import (
    disable_totp, enable_totp, get_user_by_id, save_backup_codes, set_totp_secret,
)
from notifications.ai_advisor import get_ai_security_insights
from security.event_logger import get_recent_attempts, get_security_events

logger = logging.getLogger(__name__)

user_bp = Blueprint("user", __name__)

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

# Sensitive changes (disable 2FA, regenerate backup codes, remove passkey)
# ask for a current TOTP code. Set to False only while you update your forms.
REQUIRE_REAUTH = True

# AI insights are cached per user so refreshing the dashboard can't spam the API.
INSIGHTS_TTL_SECONDS = 300
_insights_cache = {}  # {user_id: (timestamp, text)}  (per-process cache)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)
    return wrapper


@contextmanager
def db_cursor(commit=False):
    """Always closes the cursor and connection, even when an error happens."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        try:
            yield cur
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
    finally:
        conn.close()


def _current_user_or_none():
    user_id = current_user_id()
    user = get_user_by_id(user_id) if user_id else None
    return user_id, user


def _logout_redirect():
    session.clear()
    return redirect(url_for("auth.login_page"))


def _reauth_ok(user, code):
    """Re-checks the user's current TOTP code before a sensitive change."""
    if not REQUIRE_REAUTH or not user or not user["totp_enabled"]:
        return True  # nothing to re-check against
    try:
        secret = user["totp_secret"]  # change if your column has another name
    except (KeyError, TypeError):
        logger.warning("totp_secret not found on user record; re-auth denied")
        return False
    code = (code or "").strip()
    return bool(secret) and bool(code) and verify_totp_code(secret, code)


def _forget_insights(user_id):
    _insights_cache.pop(user_id, None)


# ---------------------------------------------------------------------------
# AI Security Advisor API
# ---------------------------------------------------------------------------

@user_bp.route("/api/security-insights", methods=["GET"])
def security_insights_api():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401

    user_id = current_user_id()

    cached = _insights_cache.get(user_id)
    if cached and time.time() - cached[0] < INSIGHTS_TTL_SECONDS:
        insights = cached[1]
    else:
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401

        events = get_security_events(user_id, limit=5)
        attempts = get_recent_attempts(user_id, limit=10)
        profile = {
            "totp_enabled": bool(user["totp_enabled"]),
            "account_status": user["account_status"],
            "current_risk": user["risk_level"],
            "recent_failed_logins": sum(1 for a in attempts if not a["success"]),
            "recent_logins_checked": len(attempts),
            "recent_logins": attempts[:5],
        }
        insights = get_ai_security_insights(profile, events)

        if len(_insights_cache) > 1000:
            _insights_cache.clear()
        _insights_cache[user_id] = (time.time(), insights)

    response = jsonify({"insights": insights})
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@user_bp.route("/home")
@login_required
def home():
    user_id, user = _current_user_or_none()
    if not user:
        return _logout_redirect()
    return render_template("user/home.html", user=user)


@user_bp.route("/dashboard")
@login_required
def dashboard():
    user_id, user = _current_user_or_none()
    if not user:
        return _logout_redirect()

    attempts = get_recent_attempts(user_id, limit=10)
    events = get_security_events(user_id, limit=10)
    failed_count = sum(1 for a in attempts if not a["success"])

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
    user_id, user = _current_user_or_none()
    if not user:
        return _logout_redirect()

    events = get_security_events(user_id, limit=50)

    with db_cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count FROM user_credentials WHERE user_id = %s",
            (user_id,),
        )
        bio_row = cur.fetchone()
    has_biometric = bool(bio_row and bio_row["count"] > 0)

    return render_template(
        "user/security.html", events=events, user=user, has_biometric=has_biometric
    )


@user_bp.route("/login-history")
@login_required
def login_history():
    user_id = current_user_id()
    attempts = get_recent_attempts(user_id, limit=50)
    return render_template("user/login_history.html", attempts=attempts)


# ---------------------------------------------------------------------------
# Biometric / passkey
# ---------------------------------------------------------------------------

@user_bp.route("/biometric/register-options", methods=["POST"])
@login_required
def biometric_register_options():
    user_id, user = _current_user_or_none()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    challenge = base64.b64encode(os.urandom(32)).decode()
    session["webauthn_challenge"] = challenge  # used once in /biometric/register

    rp_id = current_app.config.get("WEBAUTHN_RP_ID") or request.host.split(":")[0]

    options = {
        "challenge": challenge,
        "rp": {"name": "AI Adaptive Authentication", "id": rp_id},
        "user": {
            "id": list(str(user["id"]).encode()),
            "name": user["username"],
            "displayName": user["username"],
        },
        "pubKeyCredParams": [
            {"alg": -7, "type": "public-key"},
            {"alg": -257, "type": "public-key"},
        ],
        "timeout": 60000,
        "attestation": "none",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "userVerification": "required",
            "residentKey": "preferred",
        },
    }
    return jsonify(options)


@user_bp.route("/biometric/register", methods=["POST"])
@login_required
def biometric_register():
    user_id = current_user_id()

    # The challenge from register-options must exist and can only be used once.
    expected_challenge = session.pop("webauthn_challenge", None)
    if not expected_challenge:
        return jsonify({"success": False, "message": "Registration expired. Please try again."}), 400

    data = request.get_json(silent=True) or {}
    credential_id = data.get("credentialId")
    public_key = data.get("publicKey")

    if (
        not isinstance(credential_id, str) or not isinstance(public_key, str)
        or not credential_id or not public_key
        or len(credential_id) > 1024 or len(public_key) > 4096
    ):
        return jsonify({"success": False, "message": "Invalid credential data."}), 400

    # TODO: verify the attestation against expected_challenge (clientDataJSON
    # challenge, origin and type) with a WebAuthn library such as py_webauthn.
    # Until then this only stores what the browser sends.

    with db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO user_credentials (user_id, credential_id, public_key)
            VALUES (%s, %s, %s) ON CONFLICT (credential_id) DO NOTHING
            """,
            (user_id, credential_id, public_key),
        )
        inserted = cur.rowcount > 0

    if not inserted:
        return jsonify({"success": False, "message": "This credential is already registered."}), 409

    _forget_insights(user_id)
    return jsonify({"success": True, "message": "Biometric credential registered successfully."})


@user_bp.route("/biometric/disable", methods=["POST"])
@login_required
def biometric_disable():
    user_id, user = _current_user_or_none()
    if not user:
        return _logout_redirect()

    if not _reauth_ok(user, request.form.get("code")):
        flash("Invalid verification code. Passkey was not removed.")
        return redirect(url_for("user.security"))

    with db_cursor(commit=True) as cur:
        cur.execute("DELETE FROM user_credentials WHERE user_id = %s", (user_id,))

    _forget_insights(user_id)
    flash("Biometric passkey removed.")
    return redirect(url_for("user.security"))


# ---------------------------------------------------------------------------
# Two-factor authentication (TOTP)
# ---------------------------------------------------------------------------

@user_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    user_id, user = _current_user_or_none()
    if not user:
        return _logout_redirect()

    if user["totp_enabled"]:
        return redirect(url_for("user.security"))

    if request.method == "POST":
        # The secret comes from the server-side session, never from the form.
        secret = session.get("pending_totp_secret")
        code = (request.form.get("code") or "").strip()

        if not secret:
            flash("Setup session expired. Please start again.")
            return redirect(url_for("user.totp_setup"))

        if code and verify_totp_code(secret, code):
            set_totp_secret(user_id, secret)
            enable_totp(user_id)
            session.pop("pending_totp_secret", None)

            plain_codes = generate_backup_codes()
            hashed = [hash_backup_code(c) for c in plain_codes]
            save_backup_codes(user_id, hashed)

            _forget_insights(user_id)
            return render_template("user/totp_backup_codes.html", codes=plain_codes)

        qr_b64 = get_provisioning_qr_base64(user["username"], secret)
        return render_template(
            "user/totp_setup.html", qr_b64=qr_b64, secret=secret,
            error="Invalid code. Try again.",
        )

    secret = generate_totp_secret()
    session["pending_totp_secret"] = secret
    qr_b64 = get_provisioning_qr_base64(user["username"], secret)
    return render_template("user/totp_setup.html", qr_b64=qr_b64, secret=secret, error=None)


@user_bp.route("/2fa/disable", methods=["POST"])
@login_required
def totp_disable():
    user_id, user = _current_user_or_none()
    if not user:
        return _logout_redirect()

    if not _reauth_ok(user, request.form.get("code")):
        flash("Invalid verification code. Two-factor authentication was not disabled.")
        return redirect(url_for("user.security"))

    disable_totp(user_id)
    _forget_insights(user_id)
    flash("Two-factor authentication disabled.")
    return redirect(url_for("user.security"))


@user_bp.route("/2fa/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_backup_codes():
    user_id, user = _current_user_or_none()
    if not user:
        return _logout_redirect()

    if not user["totp_enabled"]:
        return redirect(url_for("user.security"))

    if not _reauth_ok(user, request.form.get("code")):
        flash("Invalid verification code. Backup codes were not regenerated.")
        return redirect(url_for("user.security"))

    plain_codes = generate_backup_codes()
    hashed = [hash_backup_code(c) for c in plain_codes]
    save_backup_codes(user_id, hashed)
    return render_template("user/totp_backup_codes.html", codes=plain_codes)