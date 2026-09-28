from datetime import datetime, timedelta, timezone
from security.event_logger import get_recent_attempts, get_attempts_by_identifier
from security.device_detection import is_known_device, has_any_known_device


def build_features(user_id, identifier, ip_address, user_agent):
    """Builds a feature vector describing this login attempt's behavior
    relative to recent history. Used as input to the ML risk model."""

    recent = get_recent_attempts(user_id, limit=20) if user_id else []
    id_recent = get_attempts_by_identifier(identifier, limit=20)

    now = datetime.now(timezone.utc).replace(tzinfo=None)  # UTC, matches SQLite timestamps
    window_start = now - timedelta(minutes=10)

    attempts_in_window = 0
    failed_in_window = 0
    for row in id_recent:
        try:
            ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if ts >= window_start:
            attempts_in_window += 1
            if row["success"] == 0:
                failed_in_window += 1

    total_recent = len(recent)
    failed_recent = sum(1 for r in recent if r["success"] == 0)
    failed_ratio = (failed_recent / total_recent) if total_recent else 0.0

    known_device = 1 if (user_id and is_known_device(user_id, ip_address, user_agent)) else 0
    has_history = 1 if (user_id and has_any_known_device(user_id)) else 0
    new_device_flag = 1 if (has_history and not known_device) else 0

    local_hour = datetime.now().hour
    unusual_hour = 1 if (local_hour < 5 or local_hour > 23) else 0

    features = {
        "attempts_in_window": attempts_in_window,
        "failed_in_window": failed_in_window,
        "failed_ratio_recent": round(failed_ratio, 2),
        "new_device_flag": new_device_flag,
        "unusual_hour": unusual_hour,
    }
    return features