import pyotp
import qrcode
import io
import base64


def generate_totp_secret():
    return pyotp.random_base32()


def get_provisioning_qr_base64(username, secret, issuer="AI Adaptive Authentication"):
    """Returns a base64 PNG string of a QR code the user scans into Google Authenticator."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    return base64.b64encode(buf.getvalue()).decode()


def verify_totp_code(secret, code):
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify((code or "").strip(), valid_window=1)