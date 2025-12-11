from flask import Flask, request, jsonify, send_file, send_from_directory 
from flask import Flask, request, send_from_directory, render_template
from qr_generator import generate_secure_token, save_token, validate_token, generate_qr_for_file

import os
import hashlib
from Crypto.Cipher import AES

app = Flask(__name__)

app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
QR_FOLDER = "qr_codes"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

# AUTO-DETECT KOYEB PUBLIC URL
KOYEB_URL = os.environ.get("KOYEB_URL")

# -------------------------------
# URL CONFIGURATION
# -------------------------------

if KOYEB_URL:
    BACKEND_URL = f"https://{KOYEB_URL}"
else:
    BACKEND_URL = "http://localhost:8000"

FRONTEND_URL = os.environ.get("FRONTEND_URL", BACKEND_URL)  
# default = backend domain unless frontend deployed separately


# ===========================
# AES ENCRYPTION
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


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files or "password" not in request.form:
            return jsonify({"error": "Missing file or password"}), 400

        f = request.files["file"]
        password = request.form.get("password")

        from werkzeug.utils import secure_filename
        file_name = secure_filename(f.filename)

        original_path = os.path.join(UPLOAD_FOLDER, file_name)
        encrypted_path = original_path + ".enc"

        f.save(original_path)

        checksum = file_checksum(original_path)
        key = hashlib.sha256(password.encode()).digest()

        encrypt_file(original_path, encrypted_path, key)
        os.remove(original_path)

        token = generate_secure_token()
        save_token(token, encrypted_path, password, expiry_seconds=3600)

        # Generate correct QR URL pointing to frontend
        access_url = f"{FRONTEND_URL}/access?token={token}"

        qr_img_path = generate_qr_for_file(token, access_url)
        qr_filename = os.path.basename(qr_img_path)

        # Serve QR from backend URL
        qr_image_url = f"{BACKEND_URL}/qr_codes/{qr_filename}"

        return jsonify({
            "message": "File uploaded successfully",
            "file_name": file_name,
            "checksum": checksum,
            "qr_image_url": qr_image_url,
            "access_url": access_url
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/qr_codes/<filename>")
def serve_qr(filename):
    return send_from_directory(QR_FOLDER, filename)

@app.route("/access")
def access_page():
    token = request.args.get("token")

    # If token is missing → show error page or simple message
    if not token:
        return render_template("access.html", error="No token provided.")

    # Pass the token to the frontend page (HTML)
    return render_template("access.html", token=token)



@app.route("/verify-token", methods=["POST"])
def verify_token():
    data = request.json
    token = data.get("token")
    if not token:
        return jsonify({"error": "Token missing"}), 400

    info = validate_token(token)
    if not info:
        return jsonify({"valid": False}), 404

    return jsonify({"valid": True})


@app.route("/download", methods=["POST"])
def download_file():
    data = request.json
    token = data.get("token")
    password = data.get("password")

    info = validate_token(token)
    if not info:
        return jsonify({"error": "Invalid or expired token"}), 401

    if password != info["password"]:
        return jsonify({"error": "Incorrect password"}), 403

    encrypted_path = info["file_name"]
    key = hashlib.sha256(password.encode()).digest()
    decrypted_data = decrypt_file(encrypted_path, key)

    from io import BytesIO
    original_name = os.path.basename(encrypted_path).replace(".enc", "")

    return send_file(
        BytesIO(decrypted_data),
        download_name=original_name,
        as_attachment=True
    )


@app.route("/params", methods=["GET"])
def get_params():
    token = request.args.get("token")
    password = request.args.get("password")

    info = validate_token(token)
    if not info or info["password"] != password:
        return jsonify({"valid": False}), 401

    encrypted_path = info["file_name"]
    key = hashlib.sha256(password.encode()).digest()
    decrypted_data = decrypt_file(encrypted_path, key)
    checksum = hashlib.sha256(decrypted_data).hexdigest()

    return jsonify({"valid": True, "checksum": checksum})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
