# Changelog

## [Unreleased]

### Security (phase 1 adversarial review)
Each item has a regression test in `tests/test_security_review.py` that failed
before the fix.

- **Stored XSS through backup restore (high).** Restore accepted any
  `mime_type`, and decrypt served plaintext inline with that type, so a
  crafted backup could plant HTML that ran on this origin when a share
  recipient opened it. Restore now accepts only allow-listed image types. The
  served `Content-Type` comes from the allow-list, the bytes must parse as that
  format, and responses are sandboxed with a CSP.
- **Published default secrets were live (high).** With `SECRET_KEY`/`JWT_SECRET`
  unset, the app signed sessions and JWTs with the default string in
  `config.py`, so anyone could forge an API token. Unset or placeholder secrets
  are now replaced with a generated key persisted under the instance
  directory, and the JWT key is derived separately.
- **AAD did not bind file identity, algorithm, format, or dimensions
  (medium).** Ciphertext and metadata could be swapped between records, and a
  row's type or size edited, without detection. New **envelope version 3**
  seals owner, asset id, algorithm, wrap type, MIME type, format, and
  dimensions, and the web app checks the row against that sealed context
  before unwrapping. Version 1 files still decrypt (fixtures in
  `tests/fixtures/`).
- **Capability-link download cap raced (medium).** Check-then-increment let
  concurrent requests exceed `max_downloads`. The download is now reserved
  with one atomic `UPDATE` before decryption, and handed back if decryption
  fails.
- **Location metadata survived stripping (medium).** GPS in XMP (JPEG, PNG),
  PNG text chunks, and JPEG/GIF comments all passed through. Stripping now
  covers every metadata container, re-encodes TIFF and GIF always, keeps
  animation frames, and applies EXIF orientation.
- **Backup restore amplification (medium).** One blob could be referenced many
  times, turning a 64 MiB zip into unbounded disk writes. Each blob may now be
  referenced once, a restore is capped at 1000 assets, and every entry is
  validated before anything is written.
- **The documented HMAC audit chain did not exist (medium).** The README and
  security model promised it, but the code wrote plain rows. Events are now
  HMAC-chained per account, verified on `/audit` and `/api/audit`, and legacy
  rows are sealed once on upgrade.
- **Logout did not end the session (low).** Sessions lived only in the signed
  cookie, so a copied cookie kept working after logout. Sessions are now bound
  to a server-side row that logout and password changes delete, with a 7-day
  absolute lifetime.
- **Hostile image headers caused HTTP 500 (low).** Pillow's
  `DecompressionBombError` and truncated-file errors escaped the upload
  handler. They are now clean rejections, and only allow-listed decoders run.
- **Login timing revealed whether a username exists (low).** Unknown users now
  get a dummy hash check.
- **Malformed envelope fields crashed the CLI (low).** A non-string nonce or a
  non-dict wrap raised `AttributeError`. `validate_envelope()` now checks every
  field (strict base64, bounded sizes) first.
- **JWTs without a `ver` claim were accepted (low, hardening).** `ver`
  defaulted to 1. `exp`, `iat`, `iss`, `sub`, and an integer `ver` are now
  required.

### Changed
- Every HTML page sends a strict CSP (no inline script), `X-Frame-Options:
  DENY`, and `Referrer-Policy: no-referrer`. Session cookies are `SameSite=Lax`,
  plus `Secure` with `IES_SECURE_COOKIES=1`. The dashboard script moved to
  `static/js/`.
- Restoring the same backup twice no longer duplicates images. Version 3
  images can only be restored into the account that exported them.
- `ies inspect` prints the sealed context.
- `JWT_SECRET` now defaults to a key derived from `SECRET_KEY` rather than the
  same value, so JWTs issued before upgrading (2-hour lifetime) stop working
  once.
- Existing browser sessions sign in again once after upgrading (they have no
  server-side session row).
- `docs/SECURITY_MODEL.md` was rewritten to match the code claim for claim.

### Fixed
- **`ies decrypt` could not open a `.ies` file downloaded from the web vault.**
  The CLI only rebuilt the AAD for files it had written itself and used empty
  AAD for everything else, so every web download and capability-link blob failed
  authentication. AAD reconstruction now lives in `crypto.aad_from_metadata()`
  and is shared by the CLI and the web app.
- Passing a non-RSA PEM to `ies encrypt --public-key` (or storing one as a
  user key) crashed with `AttributeError`; it is now a clean `CryptoError`.
- Removed `static/js/auth.js` and `static/js/dashboard.js`, orphaned by the
  merge: no template loaded them and they targeted elements that do not exist.
- README listed features from the discarded v1.0 lineage (tags, time-locks, an
  HMAC audit chain, JWT audience checks) that this codebase does not have; the
  feature list now matches the code. `SECURITY.md` claimed new assets use a
  "version 2" envelope; they use version 1.
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
- mypy now runs in CI and is clean; fixing it surfaced the RSA key-type bug
  above. `hypothesis` and `mypy` join the `dev` extra.
- The `pip-audit` CI job could never pass: with `--strict` it tried to audit
  this package itself, which is not on PyPI. It now audits `requirements.txt`.
- Added a Claude Code SessionStart hook (`.claude/settings.json`,
  `scripts/session-start.sh`) that builds a project venv with Pillow and the
  dev tools in cloud sessions, and a `CLAUDE.md` describing the layout,
  commands, and envelope format.
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
