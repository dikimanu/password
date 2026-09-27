from models.user_model import get_user_by_username_or_email
from auth.password import verify_password
from security.event_logger import log_login_attempt
from security.risk_engine import assess_risk
from security.policy_engine import decide_action
from security.device_detection import is_known_device, register_device


def login_user(identifier, password, ip_address=None, user_agent=None):
    user = get_user_by_username_or_email(identifier)

    if user is None:
        log_login_attempt(None, identifier, False, ip_address, user_agent)
        return {"success": False, "message": "Invalid credentials."}

    if user["account_status"] == "PROTECTED":
        return {"success": False, "message": "Account is temporarily protected. Verify OTP to continue.",
                "action": "OTP_REQUIRED", "user_id": user["id"]}

    if not verify_password(password, user["password_hash"]):
        log_login_attempt(user["id"], identifier, False, ip_address, user_agent)
        return {"success": False, "message": "Invalid credentials."}

    # Password correct — assess risk before granting access
    risk = assess_risk(user["id"], identifier, ip_address, user_agent)
    policy = decide_action(user["id"], risk)

    log_login_attempt(
        user["id"], identifier, True, ip_address, user_agent,
        risk_score=risk["risk_score"], risk_level=risk["risk_level"],
        attack_category=risk["attack_category"],
    )

    if not is_known_device(user["id"], ip_address, user_agent):
        register_device(user["id"], ip_address, user_agent)

    result = {
        "success": policy["action"] == "ALLOW",
        "message": policy["message"],
        "action": policy["action"],
        "risk_level": risk["risk_level"],
        "attack_category": risk["attack_category"],
        "user_id": user["id"],
    }
    return result
