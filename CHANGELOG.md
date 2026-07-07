# Changelog

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