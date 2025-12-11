from flask import Flask, request, render_template, redirect, url_for, session, send_file
from qr_generator import generate_secure_token, save_token, validate_token, generate_qr_for_file

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ===========================
# AES ENCRYPTION FUNCTIONS
# ===========================

def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def encrypt_file(infile, outfile, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(infile, "rb") as f:
        plaintext = pad(f.read())
    ciphertext = cipher.encrypt(plaintext)

    with open(outfile, "wb") as f:
        f.write(cipher.iv + ciphertext)

def decrypt_file(infile, key):
    with open(infile, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b"\0")

def file_checksum(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

# ==============================
# ROUTES
# ==============================

@app.route("/", methods=["GET", "POST"])
def index():
    qr_path = None
    file_name = None
    checksum = None

    if request.method == "POST":
        f = request.files["file"]
        password = request.form.get("password")

        file_name = f.filename
        original_path = os.path.join(UPLOAD_FOLDER, file_name)
        encrypted_path = original_path + ".enc"

        f.save(original_path)

        # SHA256 before encryption
        checksum = file_checksum(original_path)

        # AES key = SHA256(password)
        key = hashlib.sha256(password.encode()).digest()

        encrypt_file(original_path, encrypted_path, key)
        os.remove(original_path)

        token = generate_secure_token()
        save_token(token, encrypted_path, password, expiry_seconds=3600)
        qr_img_path, _ = generate_qr_for_file(token)

        qr_path = url_for("serve_qr", filename=os.path.basename(qr_img_path))

    return render_template("index.html", qr_path=qr_path, file_name=file_name, checksum=checksum)

@app.route("/qr_codes/<filename>")
def serve_qr(filename):
    return send_file(os.path.join("qr_codes", filename))

@app.route("/access", methods=["GET", "POST"])
def access_page():
    token = request.args.get("token")
    info = validate_token(token)
    if not info:
        return "Invalid or expired token!"

    encrypted_path = info["file_name"]
    password_required = info["password"]

    # checksum of encrypted file? No → compute checksum of decrypted data
    key = hashlib.sha256(password_required.encode()).digest()
    decrypted_data = decrypt_file(encrypted_path, key)
    checksum = hashlib.sha256(decrypted_data).hexdigest()

    if request.method == "POST":
        password = request.form.get("password")
        user_checksum = request.form.get("userChecksum").strip()

        if password != password_required:
            return "<script>alert('Wrong password!');window.history.back();</script>"

        if user_checksum != checksum:
            return "<script>alert('⚠ Checksum mismatch! Possible tampering.');window.history.back();</script>"

        session["download_token"] = token
        return redirect(url_for("download_file"))

    return render_template("access.html", file_name="Secure File", checksum=checksum)

@app.route("/download")
def download_file():
    token = session.get("download_token")
    if not token:
        return "Unauthorized!"

    info = validate_token(token)
    encrypted_path = info["file_name"]
    password = info["password"]

    key = hashlib.sha256(password.encode()).digest()
    decrypted_data = decrypt_file(encrypted_path, key)

    original_name = os.path.basename(encrypted_path).replace(".enc", "")

    return send_file(
        path_or_file=bytes(decrypted_data),
        download_name=original_name,
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)