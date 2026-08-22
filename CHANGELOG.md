# Changelog

## 1.0.0 — 2026-08-22

### Security
- Added version 2 envelopes that authenticate ownership, algorithm, detected file
  properties, and workflow time-locks alongside ciphertext.
- Bounded and strictly validated Scrypt, nonce, key, base64, bundle, image, and
  ZIP-manifest inputs before expensive processing.
- Replaced the forgeable plain-hash event chain with HMAC-SHA256 and fixed
  verification/export beyond 500 events.
- Added password-change revocation for older sessions and JWTs, decryption and
  registration throttles, no-store responses, and a restrictive CSP.
- Made vault, CLI bundle, and decrypted-output writes atomic and owner-only;
  embedded CLI filenames can no longer select an output path.

### Experience
- Redesigned the responsive vault and authentication views with clearer security
  guarantees, accessible focus states, reduced-motion handling, stronger status
  feedback, and CSP-compatible external JavaScript.
- Added secure CLI prompting, passphrase-file support, overwrite protection, and
  more actionable validation errors.

### Quality
- Added regression coverage for hostile KDF metadata, context tampering, archive
  decompression, credential revocation, long audit chains, and CLI path safety.
- Added Ruff configuration, expanded documentation, and a production-ready
  environment template.

## 0.7.0 — 2026-07-07

### Added
- **Vault health score** (A–D) from chain validity, entropy, tags, and asset count (`GET /api/vault/health`)
- **Audit chain JSON export** for offline verification (`GET /api/audit/export` and `/audit/export`)
- **Failed decrypt audit** events (`decrypt_failed`) on bad passphrase or time-lock
- **Live time-lock countdown** on locked asset cards
- **Entropy heat bars** visualizing per-asset randomness

### Improved
- Dashboard security summary shows chain status, average entropy, and locked asset count

## 0.6.0 — 2026-07-07

### Added
- **Tamper-evident audit chain** — each audit event links to the previous via SHA-256 (`GET /api/audit/verify`)
- **Image entropy meter** stored per asset and shown on vault cards
- **Time-lock decrypt** — optional `unlock_after` datetime blocks preview/decrypt until then
- **Burn-after-read preview** — decrypted modal auto-clears after 30 seconds

### Improved
- API asset payloads include `entropy_bits` and `unlock_after`
- Existing audit logs backfilled into the hash chain on startup

## 0.5.0 — 2026-07-07

### Added
- **Asset notes** on upload and per-card inline editing
- **Bulk tag update** for selected vault assets
- **Password change** with RSA private key re-wrapping
- **`GET /api/docs`** catalog of REST endpoints
- **Duplicate detection** via SHA-256 content hash on upload (web + API 409)

### Improved
- Vault search matches notes in addition to filenames and tags
- API asset payloads include `notes` and `content_hash`

## 0.4.0 — 2026-07-07

### Added
- **Inline tag editing** and **asset rename** on vault cards
- **Vault import validation** for exported ZIP manifests
- **`GET /api/stats`** with assets, algorithms, tags, and audit summary
- **Password strength meter** on registration form

### Improved
- Export/import workflow with audit logging for import validation

## 0.3.0 — 2026-07-07

### Added
- **Asset tags** on upload with comma-separated labels and tag-based vault filtering
- **In-page decrypt preview** modal (no new tab)
- **Vault ZIP export** with ciphertext files and JSON manifest
- **Security summary** panel with audit action counts
- **API search** supports filename and tag query parameters

### Improved
- Search now matches both filenames and tags
- Health endpoint reports version `0.3.0`

## 0.2.0 — 2026-07-07

### Added
- **Vault search** by filename with algorithm filter and sort options (newest, oldest, name, largest)
- **Bulk delete** for selected encrypted images with audit logging
- **Encrypted thumbnail placeholders** showing dimensions and format without decrypting
- **Algorithm breakdown metrics** on dashboard (AES-GCM vs RSA hybrid counts)
- **REST API** endpoints for upload, decrypt, delete, audit, and vault stats
- **CLI** (`ies encrypt` / `ies decrypt`) for portable `.ies` bundles
- **Drag-and-drop upload** zone with activity log panel

### Improved
- CSRF protection and credential throttling with lockout backoff
- Vault file permissions hardening (POSIX `0o700`/`0o600`)
- Health endpoint reports version `0.2.0`

### Tests
- Vault search, sort, and bulk delete integration test
- API upload/delete and audit event coverage
