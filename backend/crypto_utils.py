# backend/crypto_utils.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes
import base64
import json

BLOCK = 16

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK != 0:
        raise ValueError("Invalid padded length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def generate_aes_key(bits: int) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError("AES bits must be 128/192/256")
    return get_random_bytes(bits // 8)

def aes_encrypt(plaintext: bytes, key: bytes, mode: str):
    m = mode.lower()
    if m == "gcm":
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return {"ciphertext": ct, "nonce": nonce, "iv": None, "tag": tag}
    elif m == "ctr":
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ct = cipher.encrypt(plaintext)
        return {"ciphertext": ct, "nonce": nonce, "iv": None, "tag": None}
    elif m == "cbc":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded = pkcs7_pad(plaintext)
        ct = cipher.encrypt(padded)
        return {"ciphertext": ct, "nonce": None, "iv": iv, "tag": None}
    else:
        raise ValueError("Unsupported AES mode")

def aes_decrypt(ciphertext: bytes, key: bytes, mode: str, nonce=None, iv=None, tag=None) -> bytes:
    m = mode.lower()
    if m == "gcm":
        if nonce is None or tag is None:
            raise ValueError("GCM requires nonce and tag")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    elif m == "ctr":
        if nonce is None:
            raise ValueError("CTR requires nonce")
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(ciphertext)
    elif m == "cbc":
        if iv is None:
            raise ValueError("CBC requires IV")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ciphertext)
        return pkcs7_unpad(padded)
    else:
        raise ValueError("Unsupported AES mode")

def rsa_wrap_key(pub_pem_bytes: bytes, aes_key: bytes) -> bytes:
    pub = RSA.import_key(pub_pem_bytes)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return cipher.encrypt(aes_key)

def rsa_unwrap_key(priv_pem_bytes: bytes, enc_key: bytes) -> bytes:
    priv = RSA.import_key(priv_pem_bytes)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(enc_key)

def rsa_sign(priv_pem_bytes: bytes, data: bytes) -> bytes:
    priv = RSA.import_key(priv_pem_bytes)
    h = SHA256.new(data)
    return pss.new(priv).sign(h)

def rsa_verify(pub_pem_bytes: bytes, data: bytes, signature: bytes) -> bool:
    pub = RSA.import_key(pub_pem_bytes)
    h = SHA256.new(data)
    try:
        pss.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def pubkey_fingerprint(pub_pem_bytes: bytes) -> str:
    der = RSA.import_key(pub_pem_bytes).export_key(format="DER")
    import hashlib
    return hashlib.sha256(der).hexdigest()

def build_package(orig_name: str, aes_mode: str, key_bits: int, enc_key: bytes, aes_meta: dict, ciphertext: bytes, signer_priv_pem: bytes = None, signer_pub_pem: bytes = None) -> bytes:
    payload = {
        "version": 1,
        "meta": {"orig_name": orig_name},
        "aes": {
            "mode": aes_mode.upper(),
            "key_size": key_bits,
            "nonce": b64e(aes_meta.get("nonce")) if aes_meta.get("nonce") else None,
            "iv": b64e(aes_meta.get("iv")) if aes_meta.get("iv") else None,
            "tag": b64e(aes_meta.get("tag")) if aes_meta.get("tag") else None,
        },
        "rsa": {"recipient_fingerprint": pubkey_fingerprint(aes_meta.get("recipient_pub_pem")) if aes_meta.get("recipient_pub_pem") else None},
        "enc_key": b64e(enc_key),
        "ciphertext": b64e(ciphertext),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if signer_priv_pem:
        sig = rsa_sign(signer_priv_pem, canonical)
        payload["signature"] = b64e(sig)
        if signer_pub_pem:
            payload["signer_pubkey"] = signer_pub_pem.decode("utf-8")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

def parse_package(package_bytes: bytes) -> dict:
    return json.loads(package_bytes.decode("utf-8"))
