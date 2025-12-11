import qrcode
import os
import secrets
import time
import json

QR_FOLDER = "qr_codes"
TOKEN_FILE = "qr_tokens.json"

# Ensure folder exists
os.makedirs(QR_FOLDER, exist_ok=True)

# Load token DB
if os.path.exists(TOKEN_FILE):
    try:
        with open(TOKEN_FILE, "r") as f:
            token_db = json.load(f)
    except Exception:
        token_db = {}
else:
    token_db = {}

def persist_tokens():
    """Persist token DB to JSON file."""
    with open(TOKEN_FILE, "w") as f:
        json.dump(token_db, f)

def generate_secure_token(length=16):
    """Generate a cryptographically secure hex token."""
    return secrets.token_hex(length)

def save_token(token, file_name, password, expiry_seconds=None):
    """Save token metadata."""
    expiry_time = int(time.time()) + int(expiry_seconds) if expiry_seconds else None
    token_db[token] = {
        "file_name": file_name,
        "expiry": expiry_time,
        "password": password
    }
    persist_tokens()

def validate_token(token):
    """Return token info if valid and not expired."""
    entry = token_db.get(token)
    if not entry:
        return None
    expiry = entry.get("expiry")
    if expiry is None or expiry > int(time.time()):
        return entry
    # Token expired -> remove it
    token_db.pop(token, None)
    persist_tokens()
    return None

def generate_qr_for_file(token, base_url=None):
    """
    Generate a QR code image pointing to the file access URL.
    Returns (img_path, url)
    """
    if base_url is None:
        raise ValueError("base_url must be provided (use BACKEND_URL + /access-password?token=...)")

    # Make filename unique using token
    qr_filename = f"{token}_qr.png"
    img_path = os.path.join(QR_FOLDER, qr_filename)
    
    secure_url = base_url  # base_url already contains token parameter
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(secure_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(img_path)

    return img_path, secure_url
