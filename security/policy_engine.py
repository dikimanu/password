from security.event_logger import log_security_event
from security.account_protection import protect_account
from auth.otp import generate_otp


def decide_action(user_id, risk_assessment):
    """Deterministic rules that decide the actual security action,
    based on the AI-produced risk level."""

    risk_level = risk_assessment["risk_level"]
    attack_category = risk_assessment["attack_category"]

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
        if user_id:
            generate_otp(user_id)
        return {"action": "OTP_REQUIRED", "require_otp": True,
                "message": "OTP verification required."}

    # CRITICAL
    log_security_event(user_id, "CRITICAL_RISK",
                        f"Critical risk detected ({attack_category})", risk_level)
    if user_id:
        protect_account(user_id, reason=f"Critical risk: {attack_category}")
        generate_otp(user_id)
    return {"action": "ACCOUNT_PROTECTED", "require_otp": True,
            "message": "Account temporarily protected. OTP verification required."}
