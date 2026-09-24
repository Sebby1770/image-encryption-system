# Security model

This document states what the vault protects, against whom, and how. Every
guarantee below has a test; if you change behaviour, change this file and the
test together.

## Protected assets

- **Image confidentiality at rest.** Image bytes are encrypted before they are
  written to disk. The database and vault directory never hold plaintext.
- **Image integrity and binding.** A ciphertext cannot be edited, or moved to a
  different vault record or account, without decryption failing.
- **Access control.** Only the owner, recipients the owner shares with, and
  holders of an unexpired capability link can decrypt.
- **Capture metadata.** GPS and camera metadata are removed before encryption.
- **Audit history.** Each account's event log is HMAC-chained, so edits are
  detectable.

## Adversaries considered

| Adversary | Can | Must not be able to |
| --- | --- | --- |
| Another vault user | Hold an account, share with you, craft backups and `.ies` files | Read your images, run script on this origin, change what you see |
| Anyone with a capability link | Use the link | Use it past its expiry, download cap, or revocation |
| Network attacker without TLS termination | Nothing, with HTTPS | — |
| Someone with a copied session cookie | Replay the cookie | Use it after logout, password change, or 7 days |
| Someone with read access to the database and vault directory | Read ciphertext and metadata | Decrypt without passphrases or account passwords |
| Someone with write access to the database | Edit rows | Make a tampered row decrypt, or edit the audit log undetected (if `AUDIT_HMAC_KEY` is kept elsewhere) |

## Non-goals

- The server sees plaintext during upload and decrypt (server-side mode). It
  is not protected against a compromised or malicious server process. Phase 3's
  client-side mode addresses this.
- No malware scanning, OAuth, or managed KMS.
- Decrypted images are not protected once they reach the user's browser.
- Filenames, notes, dimensions, and sharing relationships are visible to the
  operator.
- Truncating the newest audit events is not detectable (see below).

## Cryptographic envelope

Each image gets a fresh random 256-bit data key and 96-bit nonce and is sealed
with AES-256-GCM. The data key is wrapped by one of:

- **Passphrase (`AES-GCM`):** Scrypt (`n=2^14, r=8, p=1`, 16-byte salt) derives a
  wrapping key; AES-GCM seals the data key with AAD `b"image-data-key"`.
- **RSA hybrid (`RSA-HYBRID`):** RSA-OAEP-SHA256/MGF1-SHA256 with the owner's
  3072-bit key. The private key PEM is encrypted with the account password.

Sharing unwraps the data key in memory and wraps it again to the recipient's
RSA public key. A capability link wraps it with Scrypt, using the 256-bit link
token as the passphrase. Neither touches the ciphertext.

### Envelope versions and AAD

| Version | Written by | AAD |
| --- | --- | --- |
| 1 | Everything before the phase 1 review | web: `user=<id>\|filename=<name>\|mime=<mime>`; CLI: `cli\|filename=<name>`; rebuilt from the envelope's own `aad` dict |
| 2 | Never by this codebase (reserved: the discarded v1.0 lineage used it) | — |
| 3 | Current web and CLI | `b"IES-CONTEXT-V3\0"` + canonical JSON of `context` |

A version 3 `context` seals:

| Field | Web | CLI |
| --- | --- | --- |
| `asset` | random 128-bit id, also the vault filename | random id |
| `algorithm`, `wrap` | yes | yes |
| `owner` | user id | — |
| `mime`, `format`, `width`, `height` | yes (after metadata stripping) | — |
| `filename` | name at upload | input file name |
| `source` | `web` | `cli` |

Canonical JSON means sorted keys, `,`/`:` separators, and UTF-8 without ASCII
escaping. A browser's `JSON.stringify` over the same sorted object produces
identical bytes.

Before unwrapping any key, the web app checks the row against the sealed context:
the asset id must equal the vault filename, and the owner, algorithm, MIME type,
format, and dimensions must match the row. On the owner's path the wrap type
must match too. So:

- Swapping ciphertext and metadata between two records fails.
- Moving a record to another account fails.
- Editing a row's recorded type or size fails.

Editing the context itself breaks the GCM tag. Mutable labels (display name,
notes, favorite) are intentionally outside the seal.

**Version 1 files remain decryptable** through the legacy AAD path
(`tests/fixtures/legacy-v1-*`). Version 1 rows get the serving checks below
but not the row/context binding, because they never sealed one.

### Untrusted envelope fields

Envelopes arrive in `.ies` files and backups, so every field is hostile until
`validate_envelope()` has checked it. Validation covers the type and version,
the algorithm, the nonce length, the wrap type, and the context fields' types,
lengths and total size. Base64 is decoded strictly, and metadata is capped at
64 KiB. Scrypt parameters are bounded before the KDF runs:

| Rule | Reason |
| --- | --- |
| `n` is a power of two, `n >= 2^14`, `n <= 2^22` | Blocks downgrade below the vault's baseline and CPU exhaustion |
| `128 * n * r <= 256 MiB`, `1 <= r <= 32`, `1 <= p <= 16` | Bounds the allocation |

Version 3 envelopes are closed. Unknown top-level or wrap keys are rejected,
so renaming a key cannot make a default value apply. Base64 must be canonical,
and `ciphertext_sha256` is verified, so every byte of a `.ies` header
influences decryption. A Hypothesis property test flips every byte position
with every XOR mask class and requires decryption to fail.

Salt, nonce, and wrapped-key lengths are checked before use. Malformed input
raises `CryptoError`, so the CLI exits 1 and the web app returns a clean error
rather than a traceback.

## Uploads

- The byte limit is 8 MB (`MAX_CONTENT_LENGTH`).
- Pillow is only asked to try the allow-listed decoders (PNG, JPEG, WEBP, GIF,
  BMP, TIFF), and the decoded format must be on the list. SVG and anything else
  is refused.
- The pixel ceiling (64 MP, summed over all frames) is applied from the header
  **before** any decode. Pillow's own decompression-bomb errors, truncated
  files, and parser exceptions become a clean rejection, never an HTTP 500.
- **Metadata stripping.** Every upload is fully decoded. If it carries any
  capture metadata, it is re-encoded keeping only rendering information (ICC
  profile, transparency, timing). Capture metadata here means EXIF (including
  GPS), XMP, IPTC/Photoshop blocks, PNG text chunks, JPEG `COM` segments, or GIF
  comments. TIFF and GIF are always re-encoded. EXIF orientation is applied to
  the pixels first. Animated images keep their frames.

## Serving decrypted images

Decrypted bytes are served only if the recorded format is allow-listed and the
bytes actually parse as that format. The `Content-Type` comes from the
allow-list, never from the stored row. Responses carry:

- `Cache-Control: no-store, private`
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy: default-src 'none'; …; sandbox`

So even content that reached a row by some other route cannot run script on
this origin. Backups are also validated on restore (see below).

## Authentication and sessions

- Passwords use Werkzeug's salted hash. Unknown usernames still run a dummy
  hash check, so login timing does not reveal whether an account exists.
- Login is rate limited (5 per 10 minutes per IP+username). Eight failures lock
  the username for 15 minutes. Both counters are stored in SQLite, so a restart
  does not reset them. Usernames are normalised with `strip().lower()` for
  both the lockout key and the account lookup, so case or whitespace variants
  cannot dodge the lockout, and look-alike Unicode names are separate accounts
  that do not authenticate as the original.
- **Sessions** are signed cookies bound to a server-side `sessions` row.
  - Logout deletes the row, so a copied cookie stops working.
  - A password change deletes every other session and bumps `token_version`.
  - Sessions expire after 30 minutes idle and 7 days absolute.
  - Cookies are `HttpOnly` and `SameSite=Lax`. Set `IES_SECURE_COOKIES=1` behind
    HTTPS to add `Secure`.
- **JWTs** (`/api/*`) are HS256 only. `exp`, `iat`, `iss`, `sub`, and an integer
  `ver` are required, and `ver` must equal the user's current
  `token_version`. `alg=none`, other algorithms, and other keys are rejected.
- **CSRF.** Every state-changing HTML route requires the session CSRF token
  (tested across the whole URL map). `/api/*` routes ignore cookies entirely and
  need a bearer token, so they cannot be driven cross-site.
  `/l/<token>/decrypt` is exempt because the token in its URL is the credential.
- **Secrets.** If `SECRET_KEY` is unset, or set to a value that has ever shipped
  in this repository, a random key is generated once and persisted (mode 0600)
  under the instance key directory. `JWT_SECRET` defaults to an HMAC-derived key,
  not a copy of `SECRET_KEY`.
- **Page headers.** Every HTML page sends a CSP with no inline script or style,
  `frame-ancestors 'none'`, and `form-action 'self'`. It also sends
  `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, so link tokens
  cannot leak through Referer.

## Sharing and capability links

- Shares are checked on every decrypt. Revoking deletes the recipient's wrap
  row. An expired share is treated as revoked. There is no cache to go stale.
- Link tokens are 256-bit random values, shown once, and stored only as
  SHA-256. The lookup is an equality match on the hash of a high-entropy token,
  which leaks nothing useful about other tokens.
- The download cap is enforced by one atomic `UPDATE … WHERE download_count <
  max_downloads` **before** decryption. Concurrent requests cannot exceed it,
  and a failed decryption hands the download back.
- Revocation cannot recall plaintext a recipient already downloaded, or a data
  key they extracted. To fully cut off a recipient, re-upload the image under a
  new key.

## Backup and restore

Backups contain ciphertext and envelopes only, never private keys. A restore
validates **every** entry before writing anything:

- zip members must be relative with no `..`;
- the uncompressed total is at most 64 MiB, with at most 1000 assets;
- each blob may be referenced only once;
- each envelope must be well formed, and each asset an allow-listed image whose
  MIME type matches its format.

Version 3 assets must be sealed to the restoring account, and one whose asset
id already exists in this vault is skipped, so restoring twice is harmless.
Restores never overwrite existing files, because vault filenames are the random
asset ids.

## Audit log

Each account's events form an HMAC-SHA256 chain. Each event's digest covers
its id, user, action, asset, IP, and timestamp, plus the previous digest.
`GET /audit` and `GET /api/audit` verify the whole chain, which detects edits,
insertions, reordering, and deletions anywhere except at the very end.

The key comes from `AUDIT_HMAC_KEY`. If that is unset, a random key is
persisted in the instance key directory. Keep `AUDIT_HMAC_KEY` outside the
database host, or someone with disk access can re-seal an edited log.

Events written before the chain existed are sealed once on upgrade. That
vouches for them only from that moment on.

## Deployment checklist

- Serve over HTTPS and set `IES_SECURE_COOKIES=1`.
- Set `SECRET_KEY`, `JWT_SECRET`, and `AUDIT_HMAC_KEY` from a secret store.
- Back up the instance directory: it holds the user RSA keys and any generated
  secrets.
- Run a single app process per instance directory, or put the SQLite database
  on storage that supports its locking.
