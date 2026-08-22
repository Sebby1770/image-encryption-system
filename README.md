# Image Encryption System

A local-first encrypted image vault built with Flask, SQLite, and modern
cryptographic primitives. Every image receives an independent AES-256-GCM data
key; only ciphertext is written to the vault.

Version 1.0 hardens the complete envelope: owner and file context are
authenticated, hostile metadata is bounded before key derivation, decrypted
responses are non-cacheable, audit history is HMAC-sealed, and password changes
revoke older sessions and API tokens.

## Highlights

- AES-256-GCM encryption for PNG, JPEG, WEBP, GIF, BMP, and TIFF images.
- Scrypt + AES-GCM passphrase wrapping or 3072-bit RSA-OAEP-SHA256 wrapping.
- Authenticated owner, algorithm, MIME type, format, dimensions, filename, and
  optional workflow time-lock.
- Encrypted per-user RSA private keys and owner-only vault files.
- Search, tags, notes, rename, duplicate detection, previews, bulk actions,
  vault exports, and bounded import inspection.
- HMAC-SHA256 audit chain with complete-chain verification and export.
- JWT API with issuer, audience, expiry, and credential-version validation.
- Portable, overwrite-safe `ies` CLI with secure prompting and passphrase files.

## Quick start

```bash
git clone https://github.com/Sebby1770/image-encryption-system.git
cd image-encryption-system
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:5000>, create an account, and upload an image.

For hosted use, copy `.env.example` to `.env` and replace every placeholder.
`run.py` loads this file without overriding variables already supplied by the
host. At minimum, set distinct strong values for `SECRET_KEY`, `JWT_SECRET`, and
`AUDIT_HMAC_KEY`, enable `IES_REQUIRE_STRONG_SECRETS`, use HTTPS, and set
`SESSION_COOKIE_SECURE=true`.

Do not rotate `AUDIT_HMAC_KEY` casually: a key change correctly makes the
existing audit chain fail verification. Back up `instance/` before migrations or
secret rotation.

## How encryption works

1. The app validates and fully decodes the image under a configurable pixel
   ceiling.
2. It generates a random 256-bit data key and 96-bit AES-GCM nonce.
3. It serializes immutable asset context and supplies it as authenticated
   associated data.
4. It encrypts the original bytes with AES-256-GCM.
5. It wraps the data key using Scrypt + AES-GCM or RSA-OAEP-SHA256.
6. It atomically stores ciphertext with owner-only permissions, then commits the
   database record.

Version 2 envelopes are written by default; version 1 assets and CLI bundles
remain decryptable.

The optional time-lock is a server-side workflow control bound to the encrypted
context. It is not trusted-time hardware and cannot prevent an owner from
exporting ciphertext and decrypting it with another implementation.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Browser-session signing | local development value |
| `JWT_SECRET` | API-token signing | `SECRET_KEY` |
| `AUDIT_HMAC_KEY` | Audit-chain sealing; keep stable | `SECRET_KEY` |
| `IES_INSTANCE_DIR` | Database, key, and ciphertext directory | `instance/` |
| `JWT_LIFETIME_SECONDS` | API-token lifetime | `3600` |
| `MAX_IMAGE_PIXELS` | Image decompression ceiling | `20000000` |
| `MAX_VAULT_MANIFEST_BYTES` | Expanded import-manifest limit | `1048576` |

Authentication, decryption, and registration throttles are configured with the
`AUTH_RATE_LIMIT_*`, `DECRYPT_RATE_LIMIT_*`, and `REGISTER_RATE_LIMIT_*`
variables listed in `.env.example`.

## Command line

```bash
python -m pip install -e .
ies encrypt photo.png -o photo.ies
ies decrypt photo.ies -o recovered.png
```

An interactive terminal prompts for omitted secrets without echo. For
automation, prefer `--passphrase-file` and `--private-key-passphrase-file`;
command-line secret arguments may appear in shell history or process listings.

The CLI refuses to replace files unless `--force` is present, sanitizes embedded
default filenames, writes owner-only files on POSIX, strictly validates bundle
identity/base64/version, and rejects unsafe KDF parameters before derivation.

## API

```bash
curl -X POST http://127.0.0.1:5000/api/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery staple"}'

curl http://127.0.0.1:5000/api/images \
  -H 'Authorization: Bearer <token>'
```

`GET /api/docs` returns the endpoint catalog. Changing a password increments the
account credential version and invalidates older browser sessions and bearer
tokens.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check src tests scripts run.py
pytest
```

Tests cover AES/RSA round trips, hostile envelope parameters, context tampering,
CSRF, throttling, token/session revocation, archive decompression bounds,
owner-only permissions, long audit chains, and CLI path/overwrite safety.

```text
src/image_encryption_system/
  crypto.py       encryption and key wrapping
  uploads.py      image validation and canonical asset context
  storage.py      SQLite, atomic writes, and HMAC audit chain
  web.py          browser and API routes
  cli.py          portable .ies bundle commands
  templates/      accessible server-rendered views
  static/         CSP-compatible CSS and JavaScript
tests/             crypto, web, storage, and CLI regressions
docs/              detailed security model
```

## Security scope

This is a polished educational project, not a substitute for an independently
audited production vault or managed KMS. A public deployment still needs TLS,
distributed rate limiting, managed secrets, backups, malware scanning,
monitoring, and a reviewed recovery/rotation plan. See
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for exact guarantees and
non-goals.

## License

[MIT](LICENSE)
