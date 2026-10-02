from user_agents import parse


def describe_device(user_agent_string):
    """Converts a raw User-Agent string into a readable device description,
    e.g. 'Windows 11 · Chrome' or 'Android · Chrome Mobile'."""
    if not user_agent_string:
        return "Unknown device"

    ua = parse(user_agent_string)

    os_name = ua.os.family or "Unknown OS"
    os_version = ua.os.version_string
    if os_version:
        os_name = f"{os_name} {os_version}"

    browser = ua.browser.family or "Unknown browser"

    if ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_pc:
        device_type = "Desktop"
    else:
        device_type = "Device"

    return f"{os_name} · {browser} ({device_type})"