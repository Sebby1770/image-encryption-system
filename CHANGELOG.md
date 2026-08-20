# Changelog

All notable changes to the Image Encryption System.

## [1.0.0] — 2026-08-20

### Security
- Flask debug mode is now **off by default**. Enable it only with `IES_DEBUG=1` or `FLASK_DEBUG=1`.
- Generated RSA private/public key files and ciphertext objects are written with mode `0600`; the key and vault directories are restricted to `0700`.
- Login and `/api/token` now share a sliding-window throttle and a persistent account lockout. Repeated failures return **429** with `Retry-After`.
- Browser POST routes require a CSRF token. API routes continue to use JWT and skip CSRF.
- Session cookies are `HttpOnly` + `SameSite=Lax`, and `Secure` when `IES_SECURE_COOKIES=1`.
- Responses send `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and a strict Content-Security-Policy.
- Account passwords are hashed with scrypt. Changing a password re-wraps the RSA private key.

### Added
- Delete encrypted images and download raw `.enc` ciphertext.
- Account page with password change and a per-user audit log.
- Encrypted vault backup export (zip of ciphertext + manifest, no private keys).
- JWT API for upload, decrypt, delete, and audit (`POST /api/images`, `POST /api/images/<id>/decrypt`, `DELETE /api/images/<id>`, `GET /api/audit`).
- `GET /health` version probe.
- CLI: `python -m image_encryption_system encrypt|decrypt` (also `image-vault` after install).
- GitHub Actions CI, Dockerfile, and `SECURITY.md`.

### Changed
- Dashboard UI is a dark local-vault layout with vault / account navigation.
- Uploads record ciphertext byte size and reject tiny non-image files earlier.

### Tests
- Coverage for key-file permissions, throttling, CSRF, password re-wrap, delete/audit, and the CLI.
