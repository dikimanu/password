FEATURE_ORDER = [
    "attempts_in_window",
    "failed_in_window",
    "failed_ratio_recent",
    "new_device_flag",
    "unusual_hour",
]


def features_to_vector(features: dict):
    """Converts a feature dict into an ordered list matching training column order."""
    return [features[key] for key in FEATURE_ORDER]
