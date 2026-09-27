from security.event_logger import get_all_security_events


def get_recent_alerts(limit=20):
    """Local dashboard alerts — pulls recent security events for display."""
    return get_all_security_events(limit=limit)
