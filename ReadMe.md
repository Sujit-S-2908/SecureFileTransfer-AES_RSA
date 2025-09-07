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

## Secure File Transfer (AES + RSA)

This project is a hybrid web application combining Streamlit (frontend) and Flask (backend) to enable secure file transfer using AES and RSA encryption. It demonstrates how to encrypt files with AES, securely exchange keys using RSA, and transfer files between users.

### Project Structure

-   `backend/`: Flask backend for encryption, decryption, and file handling
    -   `app.py`: Main Flask server
    -   `crypto_utils.py`: Cryptographic utilities (AES/RSA)
    -   `keys/`: Stores RSA key pairs
-   `frontend/`: Streamlit app for user interface
    -   `streamlit_app.py`: Main Streamlit UI
-   `sample/`: Sample scripts for key generation
    -   `generate_sample_keys.sh`: Bash script to generate RSA keys

### Setup Instructions

1. **Install dependencies**

    ```bash
    pip install -r requirements.txt
    ```

2. **Generate RSA Keys**

    - Use the provided script in `sample/generate_sample_keys.sh` (Linux/macOS):
        ```bash
        bash sample/generate_sample_keys.sh
        ```
    - Or generate manually using `openssl`:
        ```bash
        openssl genpkey -algorithm RSA -out frontend/keys/recipient_private.pem -pkeyopt rsa_keygen_bits:2048
        openssl rsa -pubout -in frontend/keys/recipient_private.pem -out frontend/keys/recipient_public.pem
        ```

3. **Run the Flask Backend**

    ```bash
    cd backend
    python app.py
    ```

4. **Run the Streamlit Frontend**
    ```bash
    cd frontend
    streamlit run streamlit_app.py
    ```

### Usage

1. Upload a file via the Streamlit UI.
2. The backend encrypts the file using AES, encrypts the AES key with RSA, and returns the encrypted file and key.
3. Download and decrypt files using the provided keys.

### Requirements

See `requirements.txt` for Python dependencies.

### License

MIT License
