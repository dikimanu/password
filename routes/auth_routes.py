from flask import Blueprint, request, jsonify, render_template, redirect, url_for

from auth.register import register_user
from auth.login import login_user
from auth.otp import verify_otp
from auth.session import login_session, logout_session
from models.user_model import get_user_by_id
from security.account_protection import unprotect_account

auth_bp = Blueprint("auth", __name__)


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
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )

    if result.get("action") == "ALLOW" and result["success"]:
        user = get_user_by_id(result["user_id"])
        login_session(user["id"], is_admin=bool(user["is_admin"]))

    status_code = 200 if result["success"] or result.get("action") in ("OTP_REQUIRED", "ADDITIONAL_VERIFICATION", "ACCOUNT_PROTECTED") else 401

    if request.is_json:
        return jsonify(result), status_code

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


@auth_bp.route("/logout")
def logout():
    logout_session()
    return redirect(url_for("auth.login_page"))