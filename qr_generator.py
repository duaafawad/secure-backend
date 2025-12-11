import qrcode
import os
import secrets
import time
import json

# -------------------------------
# IMPORT BACKEND_URL
# -------------------------------
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")


QR_FOLDER = "qr_codes"
TOKEN_FILE = "qr_tokens.json"

if not os.path.exists(QR_FOLDER):
    os.makedirs(QR_FOLDER)

if os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE, "r") as f:
        token_db = json.load(f)
else:
    token_db = {}

def generate_secure_token(length=16):
    return secrets.token_hex(length)

def save_token(token, file_name, password, expiry_seconds=None):
    expiry_time = None
    if expiry_seconds:
        expiry_time = int(time.time()) + expiry_seconds
    token_db[token] = {"file_name": file_name, "expiry": expiry_time, "password": password}
    with open(TOKEN_FILE, "w") as f:
        json.dump(token_db, f)

def validate_token(token):
    if token in token_db:
        expiry = token_db[token]["expiry"]
        if expiry is None or expiry > int(time.time()):
            return token_db[token]
    return None

# ---------------------------------------------------
# UPDATED: QR now uses BACKEND_URL instead of localhost
# ---------------------------------------------------
def generate_qr_for_file(token, base_url=None):
    if base_url is None:
        base_url = f"{BACKEND_URL}/access"   # LIVE URL from Koyeb or localhost automatically

    secure_url = f"{base_url}?token={token}"

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(secure_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    img_path = os.path.join(QR_FOLDER, f"{token}_qr.png")
    img.save(img_path)

    return img_path, secure_url
