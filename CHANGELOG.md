# Changelog

## 2.2.0 - 2026-08-18

### Added

- Session and JWT versioning via `users.token_version` (default 1). A password
  change increments the version. The session cookie stores the version and JWT
  tokens carry a `ver` claim; mismatches are treated as signed-out / invalid.
- Optional share expiry: `POST /images/<id>/share` and the JSON share API accept
  `expires_hours` or `expires_days`. Expired shares cannot be decrypted by the
  recipient (same as revoked). The dashboard shows the expiry.
- `POST /account/delete` with password confirmation and CSRF. Deletes vault
  blobs, shares, RSA keys, audit rows, and the user.
- EXIF is stripped on upload: images with EXIF are re-saved with Pillow without
  EXIF before encryption so camera/GPS tags never enter ciphertext.
- CLI: `ies inspect file.ies` prints algorithm and version (no secrets).
  `ies verify file.ies --passphrase` unwraps the data key only and exits 0/1.

### Changed

- Package version is 2.2.0.

## 2.1.0 - 2026-08-18

### Added

- Revoke a share with `POST /share/<id>/revoke`. The shares row is deleted so
  the recipient can no longer unwrap the data key. The dashboard shows a Revoke
  button per recipient.
- Change the account password at `GET/POST /account/password`. The new hash is
  stored and the RSA private key PEM is re-encrypted with
  `BestAvailableEncryption` using the new password.
- CSRF tokens on every HTML POST form (session `csrf_token`). POSTs without a
  valid token return 400. JSON `/api/*` routes stay token-based.
- Persistent login guard in the `login_guard` SQLite table. Rate limit
  (5 / 10 minutes) and lockout (8 failures) survive process restart.
- Rotate the passphrase wrap on an AES-GCM asset: unwrap the data key with the
  old passphrase, re-wrap it, and update metadata. Ciphertext is unchanged.

### Changed

- Package version is 2.1.0.

## 2.0.0 - 2026-08-18

### Added

- Share an encrypted image with another username by unwrapping the AES data key
  and re-wrapping it with the recipient's RSA-OAEP public key. Recipients decrypt
  with their own account password. The original ciphertext is never rewritten.
- `shares` table stores per-recipient key wraps (`asset_id`, `recipient_user_id`,
  `key_wrap` JSON, `created_at`).
- Audit log (`audit_events`) for login, upload, decrypt, share, delete, and
  backup, with an owner-only `/audit` page and `GET /api/audit`.
- `ies` CLI: `encrypt`, `decrypt`, and `keygen` using the same AES-256-GCM and
  RSA-OAEP primitives, without starting Flask.
- Encrypted backup and restore: `GET /backup` exports ciphertext plus metadata
  JSON (no private keys); `POST /restore` imports that zip.
- Download a single file's ciphertext as a portable `.ies` vault blob.
- Dashboard search/filter by filename and algorithm, a Shared with me inbox, and
  a share modal.
- Login rate limit (5 attempts / 10 minutes per IP+username) and lockout after
  8 failed passwords.
- GitHub Actions CI on Python 3.11 and 3.12.

### Changed

- Default maximum upload size is 8 MB (`IES_MAX_UPLOAD_BYTES`).
- Package version is 2.0.0.
- Decryption selects the unwrap path from key-wrap metadata so a shared RSA wrap
  works even when the original asset used a passphrase wrap.
