# Image Encryption System

A Flask image vault that encrypts photos with **AES-256-GCM** before they touch
disk. Per-image data keys are wrapped with Scrypt+AES or RSA-OAEP. Version
**2.1.0** adds share revoke, password change with RSA PEM re-wrap, CSRF on
forms, persistent login lockout, and passphrase-wrap rotation.

## Features

- AES-256-GCM encryption for image bytes (cryptography.io / OpenSSL).
- RSA-OAEP hybrid mode: RSA wraps a fresh 256-bit AES data key.
- Per-user RSA-3072 key pair generated at registration; private keys are
  encrypted with the account password.
- Share with another username by re-wrapping the **same** AES data key with
  their RSA public key. Recipients decrypt with **their** password.
- Revoke a share from the dashboard; the recipient immediately loses decrypt
  access.
- Change password: new hash plus RSA private key PEM re-encrypted with the new
  password (`BestAvailableEncryption`).
- Rotate the passphrase wrap on an AES-GCM image (old passphrase required).
- CSRF tokens on every HTML POST form.
- Owner-only audit log (web + `GET /api/audit`).
- Encrypted backup zip (ciphertext + metadata, never private keys) and restore.
- `ies` CLI for offline encrypt / decrypt / keygen.
- Login rate limit (5 / 10 minutes, IP+user) and lockout after 8 failures,
  persisted in SQLite so a restart does not reset the counter.
- 8 MB default upload limit; download ciphertext as `.ies`.
- JWT API for listing images and reading the audit trail.
- Tests for crypto, sharing, revoke, backup, CLI, CSRF, and lockout.

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
cd image-encryption-system
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python run.py
```

Open `http://127.0.0.1:5000`, create an account, and upload an image.

## CLI

```bash
ies encrypt IN.png --passphrase 'a long secret' --out out.bin
ies decrypt out.bin --passphrase 'a long secret' --out restored.png
ies keygen --passphrase 'account password' --out-private key.pem --out-public pub.pem
ies encrypt IN.png --public-key pub.pem --out photo.ies
ies decrypt photo.ies --private-key key.pem --passphrase 'account password' --out restored.png
```

The CLI talks only to `crypto.py`. It does not start Flask or write decrypted
images unless you pass `--out`.

## Sharing

On the dashboard, choose **Share** and enter another username. The server:

1. Unwraps the AES data key with your passphrase (AES-GCM mode) or your RSA
   private key (hybrid mode).
2. Re-wraps that **same** key with the recipient's RSA public key.
3. Stores the new wrap in `shares`. The ciphertext file is unchanged.

The recipient sees the image under **Shared with me** and decrypts it with their
account password. A third user cannot unwrap the shared key. The owner can
**Revoke** a recipient at any time; that deletes the `shares` row so decrypt
fails for them.

AES-GCM passphrase assets also have **Rotate passphrase**: the server unwraps
the data key with the old passphrase and writes a new wrap. Shares stay valid
because they hold their own RSA wrap of the same data key.

## Audit

`GET /audit` lists your events only: login, upload, decrypt, share, revoke,
rotate, password change, delete, and backup. `GET /api/audit` returns the same
data as JSON.

## Account password

`GET/POST /account/password` verifies the current password, stores a new hash,
and re-encrypts `user-<id>-private.pem` with the new password. RSA-hybrid
decrypt then uses the new password, not the old one. Image ciphertext is never
rewritten.

## Backup

- `GET /backup` downloads a zip of your encrypted blobs plus `manifest.json`.
- `POST /restore` (dashboard form) imports that zip into the current account.
- Private keys and password hashes are never included.
- Each vault item can also be downloaded as a portable `.ies` file.

## Environment

```bash
cp .env.example .env
```

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Flask session signing |
| `JWT_SECRET` | JWT HMAC secret |
| `IES_INSTANCE_DIR` | SQLite, vault blobs, and RSA keys |
| `IES_MAX_UPLOAD_BYTES` | Upload cap (default 8 MiB) |

Use strong secrets for any shared deployment.

## How Encryption Works

Every uploaded image is encrypted with a random 256-bit data key using AES-GCM.
The selected algorithm controls how that data key is protected:

- `AES-GCM passphrase`: Scrypt derives a wrapping key, then AES-GCM wraps the
  data key.
- `RSA hybrid`: RSA-OAEP-SHA256 wraps the data key with the user's public key.

The decrypted image is streamed to the authorized user and is **not** written to
disk by the web app.

## Threat model

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for goals, non-goals,
trust boundaries, and production hardening notes.

## API

Create a JWT:

```bash
curl -X POST http://127.0.0.1:5000/api/token \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"correct horse battery staple"}'
```

List encrypted images (owned + shared):

```bash
curl http://127.0.0.1:5000/api/images \
  -H "Authorization: Bearer <token>"
```

Read your audit log:

```bash
curl http://127.0.0.1:5000/api/audit \
  -H "Authorization: Bearer <token>"
```

## Tests

```bash
pytest
```

CI runs pytest on Python 3.11 and 3.12.

## Project Structure

```text
image-encryption-system/
  src/image_encryption_system/
    crypto.py          # AES-GCM, RSA-OAEP, .ies container, key re-wrap
    storage.py         # SQLite, shares, audit, backup zip
    web.py             # Flask app, auth, share, revoke, audit, API
    cli.py             # ies console script
    security.py        # persistent login rate limit and lockout
    templates/         # HTML views
    static/css/        # UI styling
  tests/               # pytest coverage
  docs/                # Threat model
```

## Security Notes

This is a portfolio-ready educational project, not a complete production
security product. Review the threat model before storing real sensitive photos.
