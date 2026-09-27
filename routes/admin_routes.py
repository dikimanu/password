from functools import wraps
from flask import Blueprint, render_template, redirect, url_for

from auth.session import is_logged_in, is_admin
from models.user_model import get_all_users
from security.event_logger import get_all_login_attempts, get_all_security_events

admin_bp = Blueprint("admin", __name__)


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_logged_in() or not is_admin():
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)
    return wrapper


@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    users = get_all_users()
    attempts = get_all_login_attempts(limit=100)
    events = get_all_security_events(limit=100)

    total_users = len(users)
    failed_attempts = sum(1 for a in attempts if a["success"] == 0)
    suspicious_events = len(events)
    protected_accounts = sum(1 for u in users if u["account_status"] == "PROTECTED")

    attack_categories = {}
    for a in attempts:
        cat = a["attack_category"] or "UNKNOWN"
        attack_categories[cat] = attack_categories.get(cat, 0) + 1

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        total_attempts=len(attempts),
        failed_attempts=failed_attempts,
        suspicious_events=suspicious_events,
        protected_accounts=protected_accounts,
        attack_categories=attack_categories,
    )


@admin_bp.route("/attacks")
@admin_required
def attacks():
    attempts = get_all_login_attempts(limit=200)
    return render_template("admin/attacks.html", attempts=attempts)


@admin_bp.route("/security-events")
@admin_required
def security_events():
    events = get_all_security_events(limit=200)
    return render_template("admin/security_events.html", events=events)
