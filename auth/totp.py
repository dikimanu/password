import pyotp
import qrcode
import io
import base64
import secrets
from werkzeug.security import generate_password_hash, check_password_hash


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

def generate_backup_codes(count=8):
    """Returns a list of plaintext codes to show the user once."""
    return [secrets.token_hex(4) for _ in range(count)]  # e.g. 'a1b2c3d4'


def hash_backup_code(code):
    return generate_password_hash(code)


def verify_backup_code_hash(code, code_hash):
    return check_password_hash(code_hash, code)