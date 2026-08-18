# Image Encryption System

A Flask image vault that encrypts photos with **AES-256-GCM** before they touch
disk. Per-image data keys are wrapped with Scrypt+AES or RSA-OAEP. Version
**2.3.0** adds capability link shares, notes/favorites, ciphertext integrity
checks, session idle timeout, audit CSV, and CLI rewrap/hash.

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
  password (`BestAvailableEncryption`). Other sessions and JWTs stop working.
- Delete account (`POST /account/delete`): password confirm + CSRF removes
  assets, shares, keys, and the user row.
- Share expiry: optional `expires_hours` / `expires_days`; decrypt fails after
  the deadline (treated like revoke).
- EXIF is stripped before encryption so GPS/camera tags never enter ciphertext.
- Rotate the passphrase wrap on an AES-GCM image (old passphrase required).
- CSRF tokens on every HTML POST form.
- Owner-only audit log (web + `GET /api/audit`).
- Encrypted backup zip (ciphertext + metadata, never private keys) and restore.
- Capability links (`/l/<token>`) for people without accounts; optional expiry
  and download cap. Token is stored hashed.
- Rename, notes, and favorites on vault items.
- Ciphertext SHA-256 integrity check before decrypt.
- Session idle timeout (default 30 minutes).
- `ies` CLI for offline encrypt / decrypt / keygen / inspect / verify / rewrap / hash.
- Login rate limit (5 / 10 minutes, IP+user) and lockout after 8 failures,
  persisted in SQLite so a restart does not reset the counter.
- 8 MB default upload limit; download ciphertext as `.ies`.
- JWT API for listing images and reading the audit trail (`ver` claim).
- Tests for crypto, sharing, revoke, expiry, backup, CLI, CSRF, and lockout.

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
ies inspect out.bin
ies verify out.bin --passphrase 'a long secret'
ies hash out.bin
ies rewrap out.bin --old-passphrase 'a long secret' --new-passphrase 'rotated' --out rotated.ies
ies keygen --passphrase 'account password' --out-private key.pem --out-public pub.pem
ies encrypt IN.png --public-key pub.pem --out photo.ies
ies decrypt photo.ies --private-key key.pem --passphrase 'account password' --out restored.png
```

The CLI talks only to `crypto.py`. It does not start Flask or write decrypted
images unless you pass `--out`. `inspect` prints algorithm and version only.
`verify` unwraps the data key and exits 0 or 1.

## Sharing

On the dashboard, choose **Share** and enter another username. The server:

1. Unwraps the AES data key with your passphrase (AES-GCM mode) or your RSA
   private key (hybrid mode).
2. Re-wraps that **same** key with the recipient's RSA public key.
3. Stores the new wrap in `shares`. The ciphertext file is unchanged.

The recipient sees the image under **Shared with me** and decrypts it with their
account password. A third user cannot unwrap the shared key. The owner can
**Revoke** a recipient at any time; that deletes the `shares` row so decrypt
fails for them. Optional `expires_hours` (or `expires_days`) stores `expires_at`;
an expired share is treated as revoked on decrypt. The dashboard shows the
expiry.

AES-GCM passphrase assets also have **Rotate passphrase**: the server unwraps
the data key with the old passphrase and writes a new wrap. Shares stay valid
because they hold their own RSA wrap of the same data key.

## Audit

`GET /audit` lists your events only: login, upload, decrypt, share, revoke,
rotate, password change, delete, and backup. `GET /api/audit` returns the same
data as JSON.

## Account password

`GET/POST /account/password` verifies the current password, stores a new hash,
increments `token_version`, and re-encrypts `user-<id>-private.pem` with the
new password. Other browser sessions and JWTs whose `ver` claim no longer
matches are rejected. RSA-hybrid decrypt then uses the new password, not the
old one. Image ciphertext is never rewritten.

`POST /account/delete` confirms the password (and CSRF) then deletes the
account: vault blobs, shares, RSA keys, audit rows, and the user.

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

Uploaded images are re-saved without EXIF when metadata is present, then
encrypted with a random 256-bit data key using AES-GCM.
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
