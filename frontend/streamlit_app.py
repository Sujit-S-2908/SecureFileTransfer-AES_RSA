# frontend/streamlit_app.py
import streamlit as st
import requests
from pathlib import Path

BACKEND_URL = st.secrets.get("backend_url", "http://localhost:8000")

st.set_page_config(page_title="AES+RSA Secure Transfer", layout="centered")

st.title("AES + RSA Secure File Transfer")

mode = st.sidebar.selectbox("Page", ["Encrypt / Send", "Decrypt / Receive"])

if mode == "Encrypt / Send":
    st.header("Encrypt file and wrap AES key with recipient's RSA public key")
    uploaded_file = st.file_uploader("File to encrypt", type=None)
    recipient_pub = st.file_uploader("Recipient public key (PEM)", type=["pem", "txt"])    
    aes_mode = st.selectbox("AES mode", ["gcm", "ctr", "cbc"], index=0)
    aes_key_bits = st.selectbox("AES key size (bits)", [128, 192, 256], index=2)

    sign_flag = st.checkbox("Sign package with my private key (optional)")
    signer_priv = None
    signer_pub = None
    if sign_flag:
        signer_priv = st.file_uploader("Your private key (PEM) for signing", type=["pem", "txt"])        
        signer_pub = st.file_uploader("(Optional) Your public key (PEM) to include", type=["pem", "txt"])        

    if st.button("Encrypt and Download Package"):
        if not uploaded_file or not recipient_pub:
            st.error("Please provide both the file and recipient's public key")
        else:
            files = {
                "file": (uploaded_file.name, uploaded_file.getvalue()),
                "recipient_pubkey": (recipient_pub.name, recipient_pub.getvalue()),
            }
            data = {"aes_mode": aes_mode, "aes_key_bits": str(aes_key_bits)}
            if sign_flag:
                data["sign"] = "1"
                if signer_priv:
                    files["signer_privkey"] = (signer_priv.name, signer_priv.getvalue())
                if signer_pub:
                    files["signer_pubkey"] = (signer_pub.name, signer_pub.getvalue())

            try:
                with st.spinner("Encrypting — contacting backend..."):
                    r = requests.post(f"{BACKEND_URL}/encrypt", files=files, data=data, timeout=120)
                if r.status_code == 200:
                    st.success("Package ready — click to download")
                    st.download_button("Download package", r.content, file_name=(uploaded_file.name + ".hybrid.json"), mime="application/json")
                else:
                    st.error(f"Encrypt failed: {r.status_code} — {r.text}")
            except Exception as e:
                st.error(f"Error contacting backend: {e}")

else:
    st.header("Upload package and recipient private key to restore file")
    pkg = st.file_uploader("Package (.hybrid.json)", type=["json", "hybrid.json"])    
    recipient_priv = st.file_uploader("Your private key (PEM)", type=["pem", "txt"])    
    verify_sig = st.checkbox("Verify signer signature (optional)")
    signer_pub = None
    if verify_sig:
        signer_pub = st.file_uploader("Signer public key (PEM)", type=["pem", "txt"])    

    if st.button("Decrypt and Download Restored File"):
        if not pkg or not recipient_priv:
            st.error("Please provide the package and your private key")
        else:
            files = {"package": (pkg.name, pkg.getvalue()), "recipient_privkey": (recipient_priv.name, recipient_priv.getvalue())}
            data = {}
            if verify_sig:
                data["verify_signer"] = "1"
                if signer_pub:
                    files["signer_pubkey"] = (signer_pub.name, signer_pub.getvalue())

            try:
                with st.spinner("Decrypting — contacting backend..."):
                    r = requests.post(f"{BACKEND_URL}/decrypt", files=files, data=data, timeout=120)
                if r.status_code == 200:
                    suggested = pkg.name.replace('.hybrid.json', '.restored')
                    st.success("File decrypted — click to download")
                    st.download_button("Download restored file", r.content, file_name=suggested, mime="application/octet-stream")
                else:
                    st.error(f"Decrypt failed: {r.status_code} — {r.text}")
            except Exception as e:
                st.error(f"Error contacting backend: {e}")
