# Changelog

## [Unreleased]

### Fixed
- **Repaired a broken merge that left the package non-functional.** Commit
  `4149200` spliced two independently-developed lineages (both branched from the
  initial commit) whose modules were incompatible. The textual merge succeeded
  while the result did not: 30 undefined names across `crypto.py`, `storage.py`,
  and `web.py`, so `encrypt_image_bytes()` and `decrypt_image_bytes()` both
  raised `NameError` on every call and the whole test suite failed to collect.
  Restored the coherent module set and re-applied the hardening on top.
- `pyproject.toml` declared `[project.scripts]` twice, which made the project
  metadata unparseable and broke `pip install -e .` and `pytest` alike.
- Removed `uploads.py`, an unreferenced 56-statement module left behind by the
  same merge.

### Security
- **Bounded attacker-controlled Scrypt parameters.** `_unwrap_key_with_passphrase()`
  read `n`, `r`, and `p` straight from key-wrap metadata and passed them to the
  KDF unchecked. Because that metadata ships inside every `.ies` file and backup,
  a crafted blob naming `n = 2**30` forced roughly a terabyte of allocation on
  `ies decrypt`/`inspect`/`verify` and `POST /restore`. Parameters are now
  validated against explicit CPU and memory ceilings, and may not be weakened
  below the vault's own baseline. Salt, nonce, and wrapped-key lengths are
  checked before use.
- **Added decompression-bomb protection to uploads.** `MAX_CONTENT_LENGTH` only
  bounds the compressed bytes, and EXIF stripping calls `Image.load()`, which
  fully decodes. Uploads are now identified and bounded from their header
  *before* any decode, capped by a configurable `MAX_IMAGE_PIXELS` (64 MP).
- **Cross-checked the decoded image format** against `ALLOWED_IMAGE_FORMATS`
  rather than trusting the filename extension, so a renamed file cannot reach an
  unexpected Pillow decoder.

### Added
- `tests/test_crypto_hardening.py` (15 tests) covering oversized, downgraded,
  non-power-of-two, and out-of-range KDF parameters plus truncated wrap fields.
- `tests/test_upload_hardening.py` (7 tests) covering the pixel ceiling, the
  format allow-list, and the check-before-decode ordering.
- `SECURITY.md`, and a security model section documenting both trust boundaries.

### Changed
- CI now runs a 3.10-3.13 matrix, `ruff check`, `ruff format --check`, coverage
  gated at 80%, and a `pip-audit` dependency scan.

## 2.3.0 - 2026-08-18

### Added

- Capability link shares: `POST /images/<id>/link` and `POST /api/images/<id>/link`
  wrap the AES data key with a random token. Anyone with `/l/<token>` can decrypt
  without an account. Optional `expires_hours` and `max_downloads`. The token is
  stored only as SHA-256; revoke with `POST /link/<id>/revoke`.
- Rename, notes, and favorites on vault items (`POST /images/<id>/meta`).
  Dashboard search matches notes; `?favorites=1` filters starred images.
- Ciphertext SHA-256 recorded at save time and checked before decrypt. Tampered
  blobs fail closed. CLI `ies hash` prints the digest.
- Session idle timeout (`IES_SESSION_IDLE_SECONDS`, default 30 minutes).
- Audit CSV export at `GET /audit.csv`. RSA public key download at
  `GET /account/public-key`.
- CLI `ies rewrap` rotates the passphrase wrap on a portable `.ies` file without
  rewriting ciphertext.
- Expired user shares and capability links are swept on dashboard load.

### Changed

- Package version is 2.3.0.

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
