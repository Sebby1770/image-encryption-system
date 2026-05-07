# Image Encryption System

A Flask-based cybersecurity project that encrypts digital photos before storing
them locally. It demonstrates practical image privacy controls: authenticated
users, algorithm selection, secure key wrapping, encrypted file storage, and
real-time decryption for authorized users.

## Features

- AES-256-GCM encryption for image contents.
- RSA-OAEP hybrid mode where RSA wraps a per-image AES key.
- Per-user RSA key pair generated at registration time.
- Private keys encrypted with the user's password.
- AES mode passphrase-based key wrapping with Scrypt.
- Login-protected dashboard and ownership checks.
- JWT API token endpoint for integrations.
- Supports common image formats handled by Pillow: PNG, JPEG, WEBP, GIF, BMP,
  and TIFF.
- Encrypted local vault using SQLite metadata and binary encrypted files.
- Owner-only file permissions for generated key and vault files on POSIX hosts.
- Tests for AES and RSA encryption/decryption flows.

## Tech Stack

- Python 3.10+
- Flask
- Cryptography.io
- Pillow
- SQLite
- PyJWT

PyCrypto is intentionally not used because it is deprecated. The
`cryptography` package uses OpenSSL-backed primitives and is the recommended
Python choice for this kind of project.

## Quick Start

```bash
cd image-encryption-system
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`, create an account, and upload an image.

## Environment

Copy `.env.example` to `.env` for deployment-style settings:

```bash
cp .env.example .env
```

For local development, the app will run with development defaults. For any
shared or public deployment, set strong values for:

- `SECRET_KEY`
- `JWT_SECRET`
- `IES_INSTANCE_DIR`

Debug mode is disabled by default. To run with Flask's debugger on your own
machine only:

```bash
FLASK_DEBUG=1 python run.py
```

Repeated bad login and API token attempts are throttled by default. API clients
receive a `429` response with `Retry-After` guidance while locked out. Tune the
`AUTH_RATE_LIMIT_*` environment variables if you need a stricter or looser local
policy.

## How Encryption Works

Every uploaded image is encrypted with a random 256-bit data key using
AES-GCM. The selected algorithm controls how that data key is protected:

- `AES-GCM passphrase`: derives a wrapping key from the user-entered passphrase
  using Scrypt, then wraps the image data key with AES-GCM.
- `RSA hybrid`: encrypts the image data key with the user's RSA public key using
  RSA-OAEP-SHA256. Decryption requires the encrypted private key and its
  password.

The decrypted image is streamed back to the authenticated owner and is not saved
to disk.

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

## Tests

```bash
pytest
```

## Project Structure

```text
image-encryption-system/
  src/image_encryption_system/
    crypto.py          # AES-GCM, RSA-OAEP, key wrapping
    storage.py         # SQLite metadata and encrypted vault files
    web.py             # Flask app, auth, upload, decrypt, API routes
    templates/         # HTML views
    static/css/        # UI styling
  tests/               # Pytest coverage for crypto flows
  docs/                # Security model and design notes
  scripts/             # Utility scripts
```

## Add To GitHub

```bash
git init
git add .
git commit -m "Initial image encryption system"
git branch -M main
git remote add origin https://github.com/<your-username>/image-encryption-system.git
git push -u origin main
```

## Security Notes

This is a portfolio-ready educational project, not a complete production
security product. Before using it with real sensitive data, add production-grade
secret management, HTTPS, rate limiting, audit logging, backups, malware
scanning for uploads, and hardened deployment settings.
