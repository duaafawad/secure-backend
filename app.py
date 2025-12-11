# app.py
from flask import Flask, request, jsonify, send_file, send_from_directory, render_template, redirect, url_for
import os
import hashlib
from Crypto.Cipher import AES
from io import BytesIO
from werkzeug.utils import secure_filename
from qr_generator import generate_secure_token, save_token, validate_token, generate_qr_for_file, QR_FOLDER

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

# folders
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

# URL config (KOYEB sets BACKEND_URL in env)
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.environ.get("FRONTEND_URL", BACKEND_URL)  # by default, frontend = backend

# ---------------- AES helpers ----------------
def pad(data: bytes) -> bytes:
    return data + b"\0" * (16 - len(data) % 16)

def encrypt_file(infile: str, outfile: str, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(infile, "rb") as f:
        plaintext = pad(f.read())
    ciphertext = cipher.encrypt(plaintext)
    with open(outfile, "wb") as f:
        f.write(cipher.iv + ciphertext)

def decrypt_file_bytes(infile: str, key: bytes) -> bytes:
    with open(infile, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b"\0")

def file_checksum_bytes(data: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def file_checksum(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

# ---------------- Routes ----------------

@app.route("/", methods=["GET"])
def home():
    # show upload page — template will show qr if present in context
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    # Handles form post from index.html (multipart form)
    try:
        if "file" not in request.files or "password" not in request.form:
            return render_template("index.html", error="Missing file or password")

        f = request.files["file"]
        password = request.form.get("password", "")

        if f.filename == "":
            return render_template("index.html", error="No selected file")

        filename = secure_filename(f.filename)
        original_path = os.path.join(UPLOAD_FOLDER, filename)
        encrypted_path = original_path + ".enc"

        # save original temporarily
        f.save(original_path)

        # checksum before encryption (original file)
        checksum = file_checksum(original_path)

        # AES key from password
        key = hashlib.sha256(password.encode()).digest()

        encrypt_file(original_path, encrypted_path, key)
        os.remove(original_path)

        # generate token and save metadata
        token = generate_secure_token()
        save_token(token, encrypted_path, password, expiry_seconds=3600)

        # access URL points to /access (served by this backend)
        access_url = f"{BACKEND_URL}/access?token={token}"

        # generate qr image pointing to access_url
        qr_img_path, secure_url = generate_qr_for_file(token, base_url=access_url)
        qr_filename = os.path.basename(qr_img_path)
        qr_image_url = f"{BACKEND_URL}/qr_codes/{qr_filename}"

        # Render index with QR and details (forms unchanged)
        return render_template(
            "index.html",
            file_name=filename,
            checksum=checksum,
            qr_path=qr_image_url,
            access_url=secure_url
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return render_template("index.html", error=str(e))

@app.route("/qr_codes/<filename>")
def serve_qr(filename):
    return send_from_directory(QR_FOLDER, filename)

@app.route("/access", methods=["GET", "POST"])
def access_page():
    # GET: show access page with checksum (computed server-side)
    # POST: user submitted password to download file -> verify and stream file
    token = request.args.get("token") or request.form.get("token")
    if not token:
        return render_template("access.html", error="No token provided.", token=None)

    info = validate_token(token)
    if not info:
        return render_template("access.html", error="Invalid or expired token.", token=token)

    encrypted_path = info.get("file_name")
    stored_password = info.get("password")

    # compute checksum of decrypted bytes (server-side using stored password)
    try:
        key = hashlib.sha256(stored_password.encode()).digest()
        decrypted_bytes = decrypt_file_bytes(encrypted_path, key)
        checksum = file_checksum_bytes(decrypted_bytes)
    except Exception as e:
        checksum = None

    if request.method == "GET":
        # show page with expected checksum (so user can compare)
        return render_template("access.html", token=token, checksum=checksum, file_name=os.path.basename(encrypted_path).replace(".enc",""))

    # POST -> user submitted a password (to download)
    password = request.form.get("password", "")
    # verify password matches stored password (you currently store password with token)
    if password != stored_password:
        return render_template("access.html", token=token, checksum=checksum, error="Incorrect password")

    # decrypt and send file
    key = hashlib.sha256(password.encode()).digest()
    try:
        decrypted_bytes = decrypt_file_bytes(encrypted_path, key)
    except Exception as e:
        return render_template("access.html", token=token, checksum=checksum, error="Decryption failed")

    original_name = os.path.basename(encrypted_path).replace(".enc", "")
    return send_file(BytesIO(decrypted_bytes), download_name=original_name, as_attachment=True)

@app.route("/verify-token", methods=["POST"])
def verify_token_api():
    # API endpoint (JSON) to quickly check token existence
    data = request.json or {}
    token = data.get("token")
    if not token:
        return jsonify({"error":"missing token"}), 400
    info = validate_token(token)
    return jsonify({"valid": bool(info)}), (200 if info else 404)

@app.route("/params", methods=["GET"])
def params_api():
    # returns checksum for a token+password (optional use by JS)
    token = request.args.get("token")
    password = request.args.get("password")
    info = validate_token(token)
    if not info:
        return jsonify({"valid": False}), 404
    if password and password != info.get("password"):
        return jsonify({"valid": False}), 403
    # compute checksum
    enc = info.get("file_name")
    key = hashlib.sha256((password or info.get("password")).encode()).digest()
    try:
        decrypted = decrypt_file_bytes(enc, key)
        checksum = file_checksum_bytes(decrypted)
    except Exception:
        return jsonify({"valid": False}), 500
    return jsonify({"valid": True, "checksum": checksum})

if __name__ == "__main__":
    # production: Koyeb will run this with python app.py (buildpack). In prod use gunicorn.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
