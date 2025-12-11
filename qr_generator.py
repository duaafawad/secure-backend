# qr_generator.py
import qrcode
import os
import secrets
import time
import json

QR_FOLDER = "qr_codes"
TOKEN_FILE = "qr_tokens.json"

if not os.path.exists(QR_FOLDER):
    os.makedirs(QR_FOLDER)

# load token DB file
if os.path.exists(TOKEN_FILE):
    try:
        with open(TOKEN_FILE, "r") as f:
            token_db = json.load(f)
    except Exception:
        token_db = {}
else:
    token_db = {}

def persist_tokens():
    with open(TOKEN_FILE, "w") as f:
        json.dump(token_db, f)

def generate_secure_token(length=16):
    return secrets.token_hex(length)

def save_token(token, file_name, password, expiry_seconds=None):
    expiry_time = None
    if expiry_seconds:
        expiry_time = int(time.time()) + int(expiry_seconds)
    token_db[token] = {"file_name": file_name, "expiry": expiry_time, "password": password}
    persist_tokens()

def validate_token(token):
    entry = token_db.get(token)
    if not entry:
        return None
    expiry = entry.get("expiry")
    if expiry is None:
        return entry
    if expiry > int(time.time()):
        return entry
    # expired -> remove
    token_db.pop(token, None)
    persist_tokens()
    return None

def generate_qr_for_file(token, base_url=None):
    """
    Returns (img_path, url) where url is the full access URL that QR encodes.
    base_url should be a full URL like https://yourdomain/access?token=...
    If base_url is None, caller should provide BACKEND_URL-based url.
    """
    if base_url is None:
        raise ValueError("base_url must be provided (use BACKEND_URL + /access?token=...)")

    secure_url = base_url  # we expect base_url already contains ?token=...
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(secure_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    img_path = os.path.join(QR_FOLDER, f"{token}_qr.png")
    img.save(img_path)
    return img_path, secure_url
