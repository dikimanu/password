from models.user_model import update_account_status
from security.event_logger import log_security_event


def protect_account(user_id, reason="CRITICAL risk detected"):
    update_account_status(user_id, "PROTECTED")
    log_security_event(user_id, "ACCOUNT_PROTECTED", reason, risk_level="CRITICAL")


def unprotect_account(user_id):
    update_account_status(user_id, "ACTIVE")
    log_security_event(user_id, "ACCOUNT_UNPROTECTED", "Manually restored", risk_level="LOW")
