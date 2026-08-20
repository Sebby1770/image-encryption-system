# Image Encryption System

A local Flask vault that encrypts digital photos **before** they are written to
disk. Authenticated users pick a wrapping mode, ciphertext lives in a directory
the app owns, and decrypted bytes are streamed back — never saved as plaintext.

**Version 1.0.0**

## Features

- AES-256-GCM for image contents with a fresh 256-bit data key per upload.
- RSA-OAEP hybrid mode: RSA wraps the per-image AES key.
- Per-user RSA-3072 key pair generated at registration; private key encrypted
  with the account password and stored mode `0600`.
- AES-GCM passphrase mode: Scrypt → wrapping key → AES-GCM wrap of the data key.
- Login-protected dashboard, CSRF on browser POSTs, owner checks on every read.
- Sliding-window throttle + account lockout on `/login` and `/api/token` (HTTP 429).
- JWT API for list / upload / decrypt / delete / audit.
- Audit log, password change (re-wraps the RSA key), vault backup export, delete.
- CLI for the same encryption scheme without running the web app.

## Tech Stack

- Python 3.10+
- Flask
- Cryptography.io
- Pillow
- SQLite
- PyJWT

PyCrypto is intentionally not used because it is deprecated.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python run.py
```

Open `http://127.0.0.1:5000`, create an account, and upload an image.

Debug mode is **off**. For the Werkzeug debugger locally:

```bash
IES_DEBUG=1 python run.py
```

## Environment

Copy `.env.example` to `.env` for deployment-style settings:

```bash
cp .env.example .env
```

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Flask session signing (set a long random value in production) |
| `JWT_SECRET` | JWT signing key |
| `IES_INSTANCE_DIR` | SQLite DB, vault files, and key directory |
| `IES_DEBUG` / `FLASK_DEBUG` | Opt-in debug server |
| `IES_SECURE_COOKIES` | Mark the session cookie `Secure` (use with HTTPS) |
| `IES_AUTH_MAX_FAILURES` | Failures before 429 / lockout (default 5) |
| `IES_AUTH_WINDOW_SECONDS` | Sliding window for the in-memory throttle |
| `IES_AUTH_LOCKOUT_SECONDS` | Persistent lockout duration |

## How Encryption Works

Every uploaded image is encrypted with a random 256-bit data key using
AES-GCM. The selected algorithm controls how that data key is protected:

- `AES-GCM passphrase`: Scrypt → AES-GCM wrap of the data key.
- `RSA hybrid`: RSA-OAEP-SHA256 wrap of the data key with the user's public key.
  Decryption needs the encrypted private key and the account password.

Associated data binds ciphertext to the owning user, original filename, and
MIME type. Tampering fails closed.

## API

Create a JWT:

```bash
curl -X POST http://127.0.0.1:5000/api/token \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"correct horse battery staple"}'
```

List encrypted images:

```bash
curl http://127.0.0.1:5000/api/images \
  -H "Authorization: Bearer <token>"
```

Health check: `GET /health`.

## CLI

```bash
python -m image_encryption_system encrypt photo.png --passphrase 'a long passphrase'
python -m image_encryption_system decrypt photo.png.enc --meta photo.png.enc.json \
  --out photo-out.png --passphrase 'a long passphrase'
```

After `pip install -e .` the `image-vault` command is equivalent.

## Tests

```bash
pytest
```

## Docker

```bash
docker build -t image-vault .
docker run --rm -p 5000:5000 -v vault-data:/data \
  -e SECRET_KEY=... -e JWT_SECRET=... image-vault
```

## Project Structure

```text
image-encryption-system/
  src/image_encryption_system/
    crypto.py          # AES-GCM, RSA-OAEP, key wrapping
    storage.py         # SQLite, 0600 key files, audit, lockout
    throttle.py        # In-memory credential throttle
    web.py             # Flask app
    cli.py             # encrypt / decrypt CLI
    templates/         # HTML views
    static/            # CSS + dashboard JS
  tests/               # Pytest coverage
  docs/                # Security model
  CHANGELOG.md
  SECURITY.md
```

## License

MIT
