from models.user_model import get_user_by_username_or_email, update_risk_level
from auth.password import verify_password
from auth.otp import generate_otp, otp_message
from security.event_logger import log_login_attempt
from security.risk_engine import assess_risk
from security.policy_engine import decide_action
from security.device_detection import is_known_device, register_device
from notifications.email_service import send_attacker_keystroke_alert
from geolocation import get_location
from database.database import get_connection


def user_has_biometrics(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM user_credentials WHERE user_id = %s", (user_id,))
    res = cursor.fetchone()
    conn.close()
    return res["count"] > 0 if res else False


def login_user(identifier, password, ip_address=None, user_agent=None):
    user = get_user_by_username_or_email(identifier)

    if user is None:
        log_login_attempt(None, identifier, False, ip_address, user_agent)
        return {"success": False, "message": "Invalid credentials."}

    if user["account_status"] == "PROTECTED":
        location = get_location(ip_address)
        if user["email"]:
            send_attacker_keystroke_alert(user["email"], password, ip_address, location)
        
        has_bio = user_has_biometrics(user["id"])
        if user["totp_enabled"]:
            return {"success": False,
                    "message": "Account is temporarily protected. Enter the code from your authenticator app.",
                    "action": "TOTP_REQUIRED", "user_id": user["id"], "has_biometric": has_bio, "identifier": identifier}
        sent = generate_otp(user["id"], email=user["email"], phone=user["phone"])
        return {"success": False,
                "message": "Account is temporarily protected. " + otp_message(sent),
                "action": "OTP_REQUIRED", "user_id": user["id"], "has_biometric": has_bio, "identifier": identifier}

    if not verify_password(password, user["password_hash"]):
        log_login_attempt(user["id"], identifier, False, ip_address, user_agent)
        location = get_location(ip_address)
        if user["email"]:
            send_attacker_keystroke_alert(user["email"], password, ip_address, location)
        return {"success": False, "message": "Invalid credentials."}

    # Password correct — assess risk before granting access
    risk = assess_risk(user["id"], identifier, ip_address, user_agent)
    policy = decide_action(user["id"], risk, attempted_password=password, ip_address=ip_address)

    log_login_attempt(
        user["id"], identifier, True, ip_address, user_agent,
        risk_score=risk["risk_score"], risk_level=risk["risk_level"],
        attack_category=risk["attack_category"], features=risk["features"],
    )

    update_risk_level(user["id"], risk["risk_level"])

    if not is_known_device(user["id"], ip_address, user_agent):
        register_device(user["id"], ip_address, user_agent)

    has_bio = user_has_biometrics(user["id"])
    result = {
        "success": policy["action"] == "ALLOW",
        "message": policy["message"],
        "action": policy["action"],
        "risk_level": risk["risk_level"],
        "attack_category": risk["attack_category"],
        "user_id": user["id"],
        "has_biometric": has_bio,
        "identifier": identifier,
    }
    return result