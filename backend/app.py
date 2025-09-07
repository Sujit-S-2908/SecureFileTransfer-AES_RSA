# backend/app.py
from flask import Flask, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename
from pathlib import Path
import tempfile
import os
import io
import json

from crypto_utils import (
    generate_aes_key, aes_encrypt, aes_decrypt,
    rsa_wrap_key, rsa_unwrap_key, build_package, parse_package, b64d, b64e
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB limit (tune as needed)

STORAGE = Path(tempfile.gettempdir()) / "hybrid_backend_storage"
STORAGE.mkdir(parents=True, exist_ok=True)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "aes-rsa-hybrid-backend"})

@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    if "file" not in request.files or "recipient_pubkey" not in request.files:
        return jsonify({"error": "file and recipient_pubkey are required"}), 400

    f = request.files["file"]
    rp = request.files["recipient_pubkey"].read()

    aes_mode = request.form.get("aes_mode", "gcm")
    key_bits = int(request.form.get("aes_key_bits", "256"))

    signer_priv = None
    signer_pub = None
    if request.form.get("sign") == "1":
        if "signer_privkey" not in request.files:
            return jsonify({"error": "signer_privkey required when sign=1"}), 400
        signer_priv = request.files["signer_privkey"].read()
        if "signer_pubkey" in request.files:
            signer_pub = request.files["signer_pubkey"].read()

    file_bytes = f.read()
    aes_key = generate_aes_key(key_bits)
    aes_meta = aes_encrypt(file_bytes, aes_key, aes_mode)
    aes_meta["recipient_pub_pem"] = rp

    enc_key = rsa_wrap_key(rp, aes_key)

    package_bytes = build_package(f.filename, aes_mode, key_bits, enc_key, aes_meta, aes_meta["ciphertext"], signer_priv_pem=signer_priv, signer_pub_pem=signer_pub)

    pkg_name = secure_filename(f.filename) + ".hybrid.json"
    pkg_path = STORAGE / pkg_name
    with open(pkg_path, "wb") as fo:
        fo.write(package_bytes)

    return send_file(str(pkg_path), mimetype="application/json", as_attachment=True, download_name=pkg_name)

@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    if "package" not in request.files or "recipient_privkey" not in request.files:
        return jsonify({"error": "package and recipient_privkey required"}), 400

    pkg = request.files["package"].read()
    rp = request.files["recipient_privkey"].read()

    verify_signer = request.form.get("verify_signer") == "1"
    signer_pub = None
    if verify_signer:
        if "signer_pubkey" not in request.files:
            return jsonify({"error": "signer_pubkey required when verify_signer=1"}), 400
        signer_pub = request.files["signer_pubkey"].read()

    doc = parse_package(pkg)
    enc_key = b64d(doc["enc_key"])
    try:
        aes_key = rsa_unwrap_key(rp, enc_key)
    except Exception as e:
        return jsonify({"error": "RSA unwrap failed", "details": str(e)}), 400

    aes_info = doc["aes"]
    mode = aes_info["mode"].lower()
    nonce = b64d(aes_info["nonce"]) if aes_info.get("nonce") else None
    iv = b64d(aes_info["iv"]) if aes_info.get("iv") else None
    tag = b64d(aes_info["tag"]) if aes_info.get("tag") else None

    ciphertext = b64d(doc["ciphertext"])
    try:
        plaintext = aes_decrypt(ciphertext, aes_key, mode, nonce=nonce, iv=iv, tag=tag)
    except Exception as e:
        return jsonify({"error": "decryption failed", "details": str(e)}), 400

    if verify_signer and doc.get("signature"):
        sig = b64d(doc.get("signature"))
        # reconstruct canonical payload for verification (strip signature & signer_pubkey)
        payload = dict(doc)
        payload.pop("signature", None)
        payload.pop("signer_pubkey", None)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        from crypto_utils import rsa_verify
        sig_valid = rsa_verify(signer_pub, canonical, sig)
        if not sig_valid:
            return jsonify({"error": "signature verification failed"}), 400

    filename = doc.get("meta", {}).get("orig_name", "restored.bin")
    return send_file(io.BytesIO(plaintext), mimetype="application/octet-stream", as_attachment=True, download_name=filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
