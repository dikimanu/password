from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from config import Config


def to_local(value, fmt="%d %b %Y, %I:%M:%S %p"):
    """Convert a UTC timestamp (SQLite string or datetime) to local (IST) time."""
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ZoneInfo(Config.APP_TIMEZONE)).strftime(fmt)