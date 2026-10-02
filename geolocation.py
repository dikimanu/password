import json
import urllib.request

_cache = {}  # simple in-memory cache so the same IP isn't looked up repeatedly


def get_location(ip_address):
    """Returns a short 'City, Region' string for a public IP, or a
    placeholder for private/local addresses. Never raises — always
    returns a string, falling back gracefully if the lookup fails."""
    if not ip_address:
        return "Unknown"

    if ip_address in _cache:
        return _cache[ip_address]

    private_prefixes = ("127.", "10.", "192.168.", "::1")
    if ip_address.startswith(private_prefixes) or ip_address.startswith("172."):
        result = "Local network"
        _cache[ip_address] = result
        return result

    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,city,regionName,country"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            parts = [p for p in (data.get("city"), data.get("regionName")) if p]
            result = ", ".join(parts) if parts else data.get("country", "Unknown")
        else:
            result = "Unknown"
    except Exception as e:
        print(f"[GEO ERROR] Lookup failed for {ip_address}: {e}", flush=True)
        result = "Unknown"

    _cache[ip_address] = result
    return result