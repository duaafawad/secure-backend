from flask import Flask, render_template, request, session, redirect, url_for, send_file, send_from_directory, jsonify
import os, hashlib, time
from io import BytesIO
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from qr_generator import generate_secure_token, save_token, validate_token, generate_qr_for_file, QR_FOLDER

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

# Folders
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

# Base URL for QR (use env in production)
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

# ---------- Crypto helpers ----------
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
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def file_checksum(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            h.update(block)
    return h.hexdigest()

# ---------- Routes ----------

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    # upload file and password, encrypt, save token, generate QR
    if "file" not in request.files or "password" not in request.form:
        return render_template("index.html", error="Missing file or password")
    f = request.files["file"]
    password = request.form.get("password", "")
    if f.filename == "":
        return render_template("index.html", error="No selected file")

    filename = secure_filename(f.filename)
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    encrypted_path = original_path + ".enc"

    # save original, compute checksum, encrypt, remove original
    f.save(original_path)
    checksum = file_checksum(original_path)
    key = hashlib.sha256(password.encode()).digest()
    encrypt_file(original_path, encrypted_path, key)
    os.remove(original_path)

    # token and QR
    token = generate_secure_token()
    save_token(token, encrypted_path, password, expiry_seconds=3600)
    access_url = f"{BACKEND_URL}/access?token={token}"
    qr_img_path, secure_url = generate_qr_for_file(token, base_url=access_url)
    qr_filename = os.path.basename(qr_img_path)
    qr_image_url = url_for("serve_qr", filename=qr_filename, _external=True)

    return render_template("index.html",
                           file_name=filename,
                           checksum=checksum,
                           qr_path=qr_image_url,
                           access_url=secure_url)

@app.route("/qr_codes/<filename>")
def serve_qr(filename):
    return send_from_directory(QR_FOLDER, filename)

#
# Access: password entry
#
@app.route("/access", methods=["GET", "POST"])
def access():
    token = request.args.get("token") or request.form.get("token")
    if not token:
        return render_template("access_password.html", error="No token provided.", token=None)
    info = validate_token(token)
    if not info:
        return render_template("access_password.html", error="Invalid or expired token.", token=token)

    if request.method == "GET":
        return render_template("access_password.html", token=token)

    # POST: password submitted
    password = request.form.get("password", "")
    if password != info.get("password"):
        return render_template("access_password.html", token=token, error="Incorrect password")

    # password correct: ensure verification flag is reset
    session[f"verified_{token}"] = False
    # redirect to verify page (GET)
    return redirect(url_for("access_verify", token=token))

#
# Verify: show expected checksum (GET). Accept checksum (POST) via AJAX and set session flag.
#
@app.route("/access/verify", methods=["GET", "POST"])
def access_verify():
    token = request.args.get("token") or request.form.get("token")
    if not token:
        return "No token provided", 400
    info = validate_token(token)
    if not info:
        return "Invalid or expired token", 404

    encrypted_path = info.get("file_name")
    stored_password = info.get("password")
    # compute expected checksum (server-side) using stored password
    try:
        key = hashlib.sha256(stored_password.encode()).digest()
        decrypted_bytes = decrypt_file_bytes(encrypted_path, key)
        expected_checksum = file_checksum_bytes(decrypted_bytes)
    except Exception:
        expected_checksum = None

    # If AJAX POST verifying checksum
    if request.method == "POST":
        entered = request.form.get("userChecksum", "").strip()
        # normalized comparison
        ok = (entered.lower() == (expected_checksum or "").lower())
        session[f"verified_{token}"] = bool(ok)
        return jsonify({"success": bool(ok)})

    # GET -> render page
    return render_template("access_verify.html",
                           token=token,
                           file_name=os.path.basename(encrypted_path).replace(".enc", ""),
                           checksum=expected_checksum)

#
# Download: only allowed if session verified flag set True for token
#
@app.route("/download/<token>", methods=["GET"])
def download(token):
    if not session.get(f"verified_{token}", False):
        return "Checksum not verified. Download denied.", 403
    info = validate_token(token)
    if not info:
        return "Invalid or expired token", 404
    encrypted_path = info.get("file_name")
    stored_password = info.get("password")
    try:
        key = hashlib.sha256(stored_password.encode()).digest()
        decrypted_bytes = decrypt_file_bytes(encrypted_path, key)
    except Exception:
        return "Decryption failed.", 500

    original_name = os.path.basename(encrypted_path).replace(".enc", "")
    return send_file(BytesIO(decrypted_bytes), download_name=original_name, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
