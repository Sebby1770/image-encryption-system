# Image Encryption System

**Live site:** [https://sebby1770.github.io/image-encryption-system/](https://sebby1770.github.io/image-encryption-system/)

A Flask image vault that encrypts photos with **AES-256-GCM** before they touch
disk. Per-image data keys are wrapped with Scrypt+AES or RSA-OAEP. Version
**2.3.0** adds capability link shares, notes/favorites, ciphertext integrity
checks, session idle timeout, audit CSV, and CLI rewrap/hash.

## Features

- AES-256-GCM encryption for PNG, JPEG, WEBP, GIF, BMP, and TIFF images, with a
  fresh 256-bit data key per image.
- Data keys wrapped with Scrypt + AES-GCM (passphrase mode) or RSA-OAEP-SHA256
  (hybrid mode, 3072-bit per-user key pair generated at registration; the
  private key is encrypted with the account password).
- Share with another username by re-wrapping the **same** data key with their
  RSA public key. Recipients decrypt with **their** password. Revoke at any time,
  with optional expiry (`expires_hours` / `expires_days`).
- Capability links (`/l/<token>`) for people without accounts, with optional
  expiry and download cap. Only the SHA-256 of the token is stored.
- Rotate the passphrase wrap of an image without rewriting its ciphertext.
- Change password: new hash, RSA private key re-encrypted, `token_version`
  bumped so other sessions and JWTs stop working.
- Delete account (`POST /account/delete`) with password confirmation.
- Envelope version 3 seals the image's owner, asset id, algorithm, wrap type,
  MIME type, format, and dimensions into the AES-GCM AAD, so ciphertext cannot
  be swapped between records or accounts. Version 1 files stay decryptable.
- Capture metadata is stripped before encryption: EXIF (including GPS), XMP,
  IPTC, PNG text chunks, and JPEG/GIF comments.
- Uploads are identified from their header and bounded (format allow-list,
  64 MP pixel ceiling across all frames, 8 MB byte limit) before anything
  decodes them.
- Decrypted images are served only as the allow-listed type they parse as,
  with `no-store`, `nosniff`, and a sandboxing CSP.
- Ciphertext SHA-256 recorded at save time and checked before decrypt.
- CSRF tokens on every HTML POST form; strict CSP (no inline script).
- Server-side session registry: logout and password changes really end
  sessions; 30-minute idle and 7-day absolute timeouts.
- Login rate limit (5 / 10 minutes per IP+username) and lockout after 8
  failures, persisted in SQLite.
- Throttles beyond the login form: registration per address (each one mints an
  RSA-3072 key pair, so it is a CPU amplifier reachable without an account),
  decrypt attempts per account, and capability-link requests per address.
- Password policy enforced in storage, so registration, rotation, and the CLI
  all clear the same bar; a register-page meter mirrors the same rules.
- Scrypt at `n=2^16` for new passphrase wrappings. The accepted floor (`2^14`)
  is a separate constant, so older files stay readable.
- API tokens carry and require an audience, alongside `exp`, `iat`, `iss`,
  `sub`, and `ver`.
- Permissions-Policy, COOP, CORP, and HSTS (on HTTPS requests) alongside the
  CSP; `GET /healthz` for probes; a non-root Docker image.
- Owner-only audit log, HMAC-chained and verified on every view (web, CSV
  export, and `GET /api/audit`).
- Encrypted backup zip (ciphertext + metadata, never private keys) and restore.
- Rename, notes, and favorites on vault items.
- JWT API for listing images, sharing, links, and the audit trail.
- `ies` CLI for offline encrypt / decrypt / keygen / inspect / verify / rewrap / hash.

## Stack

Python 3.10+, Flask, cryptography (OpenSSL), Pillow, SQLite, PyJWT. PyCrypto is
intentionally not used because it is unmaintained.

## Quick Start

```bash
git clone https://github.com/Sebby1770/image-encryption-system.git
cd image-encryption-system
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python run.py
```

Open <http://127.0.0.1:5000>, create an account, and upload an image.

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
  Every entry is validated first, so a bad backup restores nothing. Restoring
  the same backup twice does not duplicate images. Images in the current
  (version 3) format can only be restored into the account that exported
  them; version 1 images can be restored anywhere.
- Private keys and password hashes are never included.
- Each vault item can also be downloaded as a portable `.ies` file.

## Environment

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Flask session signing (generated and persisted in the instance dir if unset) |
| `JWT_SECRET` | JWT HMAC secret (derived from `SECRET_KEY` if unset) |
| `AUDIT_HMAC_KEY` | Audit chain key; keep it off the database host (generated if unset) |
| `IES_SECURE_COOKIES` | `1` behind HTTPS to mark the session cookie `Secure` |
| `IES_INSTANCE_DIR` | SQLite, vault blobs, and RSA keys |
| `IES_MAX_UPLOAD_BYTES` | Upload cap (default 8 MiB) |
| `IES_HSTS_SECONDS` | HSTS max-age, sent only on HTTPS requests (default one year; `0` disables) |
| `IES_MIN_PASSWORD_LENGTH` | Minimum password length (default 10) |
| `IES_REGISTER_RATE_LIMIT` / `_WINDOW` | Registrations per address per window (default 5 / 3600 s) |
| `IES_DECRYPT_RATE_LIMIT` / `_WINDOW` | Decrypt attempts per account per window (default 30 / 300 s) |
| `IES_LINK_RATE_LIMIT` / `_WINDOW` | Capability-link requests per address per window (default 20 / 300 s) |

A throttle limit of `0` disables that throttle.

Use strong secrets for any shared deployment.

## How Encryption Works

Uploaded images are re-encoded without capture metadata when any is present,
then encrypted with a random 256-bit data key using AES-GCM. The AAD seals the
image's context (owner, asset id, type, and size).
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

```bash
curl -X POST http://127.0.0.1:5000/api/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery staple"}'
```

List encrypted images (owned + shared):

```bash
curl http://127.0.0.1:5000/api/images \
  -H 'Authorization: Bearer <token>'
```

Read your audit log:

```bash
curl http://127.0.0.1:5000/api/audit \
  -H "Authorization: Bearer <token>"
```

## Tests

```bash
python -m pip install -e '.[dev]'
ruff check src tests scripts run.py
ruff format --check src tests scripts run.py
mypy
pytest
```

The suite includes Hypothesis property tests (`tests/test_properties.py`):
flipping any byte of an `.ies` file must make decryption fail, CLI and web
uploads must round-trip, and out-of-bounds KDF parameters must be rejected
cheaply. There is also a Playwright browser test that registers two users,
uploads, views, shares, revokes, and checks that the recipient is locked out:

```bash
pip install -e '.[e2e]' && python -m playwright install chromium
pytest -m e2e tests/e2e
```

CI runs lint, format, mypy, and pytest (85% coverage gate, 200 Hypothesis
examples per property) on Python 3.10 through 3.13, the browser test in its own
job, and a `pip-audit` dependency scan.

## Project Structure

```text
image-encryption-system/
  src/image_encryption_system/
    crypto.py          # AES-GCM, RSA-OAEP, .ies container, key re-wrap
    storage.py         # SQLite, shares, audit, backup zip
    web.py             # Flask app, auth, share, revoke, audit, API
    cli.py             # ies console script
    security.py        # login guard, request throttles, password policy
    templates/         # HTML views
    static/css/        # UI styling
  tests/               # pytest coverage
  docs/                # Threat model
```

## Docker

```bash
docker compose up --build
```

The image builds the wheel in a throwaway stage and runs it with gunicorn as a
non-root user, with a `HEALTHCHECK` against `/healthz`. The vault database,
ciphertext, encrypted private keys, and the generated secrets all live in the
`vault-data` volume mounted at `/data`. `compose.yaml` sets `IES_SECURE_COOKIES=1`
(serve it behind TLS) and a memory limit, because Scrypt holds ~64 MiB per
in-flight passphrase decrypt.

## License

This is a portfolio-ready educational project, not a complete production
security product. Review the threat model before storing real sensitive photos.
