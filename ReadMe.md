# Deploy & Run (local)

1. Create virtualenv and install dependencies

```bash
python -m venv .venv
source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2. Start the backend Flask server

```bash
cd backend
python app.py
# server will listen on http://0.0.0.0:8000
```

3. Start Streamlit frontend (in project root)

```bash
streamlit run frontend/streamlit_app.py
```

4. In the Streamlit UI select the right page (Encrypt / Decrypt) and provide keys & files.

Notes:
- Backend expects a recipient public key PEM for encryption and a recipient private key PEM for decryption.
- If you want to test the full flow locally quickly, you can create sample keys with the included `sample/generate_sample_keys.sh` script.
- Never ship private keys in plaintext or commit them into git. Use secure storage for private keys in production.
