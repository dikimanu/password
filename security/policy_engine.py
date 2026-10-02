from security.event_logger import log_security_event
from security.account_protection import protect_account
from auth.otp import generate_otp, otp_message
from models.user_model import get_user_by_id


def decide_action(user_id, risk_assessment):
    risk_level = risk_assessment["risk_level"]
    attack_category = risk_assessment["attack_category"]
    user = get_user_by_id(user_id) if user_id else None
    email = user["email"] if user else None
    phone = user["phone"] if user else None
    totp_enabled = bool(user["totp_enabled"]) if user else False

    if risk_level == "LOW":
        return {"action": "ALLOW", "require_otp": False, "message": "Normal login."}

    if risk_level == "MEDIUM":
        log_security_event(user_id, "ADDITIONAL_VERIFICATION",
                           f"Medium risk detected ({attack_category})", risk_level)
        return {"action": "ADDITIONAL_VERIFICATION", "require_otp": False,
                "message": "Additional verification required."}

    if risk_level == "HIGH":
        log_security_event(user_id, "OTP_REQUIRED",
                           f"High risk detected ({attack_category})", risk_level)
        if totp_enabled:
            return {"action": "TOTP_REQUIRED", "require_otp": True,
                    "message": "Enter the code from your authenticator app."}
        sent = generate_otp(user_id, email=email, phone=phone) if user_id else []
        return {"action": "OTP_REQUIRED", "require_otp": True,
                "message": "OTP verification required. " + otp_message(sent)}

    # CRITICAL
    log_security_event(user_id, "CRITICAL_RISK",
                       f"Critical risk detected ({attack_category})", risk_level)
    if user_id:
        protect_account(user_id, reason=f"Critical risk: {attack_category}")
    if totp_enabled:
        return {"action": "TOTP_REQUIRED", "require_otp": True,
                "message": "Account temporarily protected. Enter the code from your authenticator app."}
    sent = generate_otp(user_id, email=email, phone=phone) if user_id else []
    return {"action": "ACCOUNT_PROTECTED", "require_otp": True,
            "message": "Account temporarily protected. " + otp_message(sent)}