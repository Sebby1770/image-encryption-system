# Security model

This document states what the vault protects, against whom, and how. Every
guarantee below has a test; if you change behaviour, change this file and the
test together.

## Protected assets

- **Image confidentiality at rest.** Image bytes are encrypted before they are
  written to disk. The database and vault directory never hold plaintext.
- **Image confidentiality from the server (end-to-end mode).** Images encrypted
  in the browser are never seen by the server, in plaintext or as a key.
- **Image integrity and binding.** A ciphertext cannot be edited, or moved to a
  different vault record or account, without decryption failing.
- **One image per ciphertext.** A version 4 envelope opens under exactly one
  data key, so nobody who controls the wraps (an owner choosing what each
  recipient gets, say) can make one stored ciphertext show different pictures
  to different people.
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
| Someone with read access to the database and vault directory | Read ciphertext, metadata, and sealed private keys | Decrypt without passphrases or account passwords, or guess them cheaply: every secret on disk is behind Scrypt |
| The server operator, or anyone who takes over the running server *after* an end-to-end image was uploaded | Read requests, logs, memory, and storage | Read an end-to-end image or its data key |
| Someone with write access to the database | Edit rows | Make a tampered row decrypt, or edit the audit log undetected (if `AUDIT_HMAC_KEY` is kept elsewhere) |

## Non-goals

- **Server mode** sends plaintext to the server during upload and decrypt, so
  it is not protected against a compromised server process. End-to-end mode
  is.
- **An actively malicious server defeats end-to-end mode too.** The browser
  runs whatever JavaScript the server sends, and the account password that
  opens the RSA private key is also the password the server checks at sign-in.
  End-to-end mode protects against a server that is honest-but-curious, that is
  compromised later, or whose storage leaks; it does not protect against one
  that is malicious *while you use it*. Closing that gap needs signed,
  independently served client code and a sign-in that never reveals the
  password (OPAQUE or SRP); neither is built.
- No malware scanning, OAuth, or managed KMS.
- Decrypted images are not protected once they reach the user's browser.
- Filenames, notes, dimensions, and sharing relationships are visible to the
  operator.
- Truncating the newest audit events is not detectable (see below).

## End-to-end mode

The dashboard defaults to encrypting in the browser once its module has loaded
(`static/js/ies-crypto.js`, `ies-image.js`, `vault-e2e.js`). Without
JavaScript the option stays disabled, so the form cannot post plaintext while
claiming to encrypt locally; the server also refuses a plain upload that says
it came from end-to-end mode.

**What the browser does.** It strips capture metadata (below), generates the
data key and nonce with `crypto.getRandomValues`, seals a version 4 envelope
with WebCrypto AES-256-GCM, and wraps the data key either with Scrypt (a pure
JavaScript implementation, run in a Web Worker, checked against RFC 7914 and
`hashlib.scrypt`) or with RSA-OAEP-SHA256 to the account's public key. The
envelope is byte-compatible with the server and the CLI: canonical JSON, the
same AAD prefix, the same bounds. `tests/test_browser_crypto.py` runs the real
modules under Node and checks both directions.

**What the server receives and checks.** Only ciphertext and the envelope. It
cannot decrypt them, so it checks everything else before storing anything:

- a closed version 4 envelope (key-committing; a version 3 one from a page
  loaded before version 4 shipped is refused with a request to reload) whose
  context is complete, marked
  `source: "browser"`, and sealed to the uploading account;
- an allow-listed format the browser can display again (PNG, JPEG, WebP, GIF,
  BMP; TIFF is server-mode only) with a matching MIME type, within the pixel
  ceiling;
- a well-formed wrap that matches the sealed algorithm, with Scrypt at no less
  than today's cost (`SCRYPT_N`), so a browser cannot store a weaker wrap than
  the server would write;
- a `ciphertext_sha256` that matches the bytes received, and an asset id not
  already in use. The vault file is created exclusively, so a reused id can
  never overwrite another account's ciphertext.

**The server never offers to unwrap an end-to-end key.** Server-side decrypt,
share, link, rotate, the API share and link routes, and server-side link
decryption all refuse end-to-end images, even when given the correct secret.
Such a route would exist only to collect the secret the mode keeps from the
server.

**Opening, sharing, linking, rotating.** All happen in the page:

- `GET /images/<id>/sealed` returns the `.ies` with the caller's own wrap (the
  owner's, or the recipient's share wrap; expired or revoked shares get 403).
  `GET /images/<id>/envelope` returns the same envelope without the
  ciphertext, which is all that sharing, linking, and rotating need.
- RSA wraps need the account private key. `POST /account/private-key` (CSRF,
  throttled with decryption, `no-store`) returns the Scrypt-sealed key; the
  password that opens it is typed into the page and never sent. The opened key
  is kept for the page's lifetime as a non-extractable `CryptoKey`.
- Sharing re-wraps the data key to the recipient's public key in the browser
  and shows its fingerprint, the first 128 bits of SHA-256 over the
  SubjectPublicKeyInfo, which the recipient's Account page also shows. Compare
  them out of band: it is the check against a server that substitutes its own
  key.
- Links: the server stores the hash of a path token, as for server links. The
  data key is wrapped under a separate 256-bit secret that the browser puts in
  the URL fragment, which browsers never send. The server counts downloads but
  cannot open what it hands out. Scrypt runs at the floor for link wraps, since
  their secret is random. The link page checks the key's shape (43 base64url
  characters) before fetching, so a link cut short in copy-paste does not spend
  a capped download on a key that cannot work.
- Rotation re-wraps in the browser and proves the new wrap opens before the
  server replaces the only primary wrap.
- **Re-keying** (below) re-encrypts the image under a new data key.

**Re-keying.** Revoking a share deletes the recipient's wrap, but a recipient
could have kept the data key, and the key opens the stored ciphertext for as
long as it exists, whether they reach it later through a link, a leaked backup,
or a breached server. Re-keying closes that: the owner's browser decrypts the
image, encrypts it again under a fresh data key and nonce, re-wraps the new key
for the recipients the owner keeps, and proves the new envelope opens before
sending it. `POST /images/<id>/rekey` then checks the envelope like an upload,
plus:

- it must seal exactly the same context (asset id, owner, filename, type, and
  size), so a re-key can only replace an image with itself;
- its digest, nonce, and wrap must all differ from the current ones, so a
  client cannot "re-key" by sending the old ciphertext back;
- every kept share must belong to a current, unexpired recipient and wrap the
  new key to an RSA public key. Kept shares keep their dates; every other
  share and every link is deleted.

The swap is all-or-nothing. The new ciphertext is staged beside the old one
under a name unique to that re-key, so two overlapping re-keys of one image
cannot swap in each other's bytes. The database changes run in one
transaction; the old file is kept until that transaction commits and is put
back if anything fails; and the live file is replaced atomically, so a
concurrent reader gets the old image or the new one, never neither.
Re-keying cannot recall copies already downloaded, in plaintext or as `.ies`
files with their old wraps: it protects what the server stores from then on.

**A request can never fail silently.** When the session has ended (idle
timeout, sign-out elsewhere, password change), the end-to-end routes answer a
request that accepts JSON with a `401` and a JSON error rather than a redirect,
and the page treats any answer that is redirected, or is not the JSON or
ciphertext it asked for, as a failure. Before this, `fetch()` followed the
redirect to the sign-in page, received status 200, and a batch upload could
report "Encrypted 3 of 3" having stored nothing.

**After decryption** the browser shows the image only as the allow-listed type
its bytes really are, and only when that matches the sealed format, through an
`<img>` element and a `blob:` URL, the same rule the server applies before
serving plaintext.

**Trade-off: stolen sessions.** Someone holding a live session cookie can fetch
the sealed private key and guess the account password offline, instead of
online against the decrypt throttle. Scrypt at `2^16` and the password policy
bound that; logout, idle timeout, and password change end the session as
before.

### Metadata stripping in the browser

The server never sees end-to-end plaintext, so metadata must be removed before
encryption. `ies-image.js` works on container structure, against allow-lists
of rendering structures, and copies image data unchanged (pixels are
identical, which the tests check with Pillow):

- **PNG:** keeps only rendering chunks (`IHDR`, `PLTE`, `IDAT`, `IEND`, colour
  and APNG chunks); drops text, `eXIf`, `tIME`, and every unknown ancillary
  chunk such as C2PA manifests; refuses unknown critical chunks.
- **JPEG:** walks every segment, including those between progressive scans,
  and stops at EOI, so data appended after the image (motion-photo video) is
  dropped. Keeps tables, frame headers, JFIF without its thumbnail, ICC, and
  Adobe colour-transform segments; drops EXIF, XMP, IPTC, MPF, other APPn, and
  comments. A photo whose EXIF orientation is not upright is drawn upright and
  re-encoded once, as the server does.
- **WebP:** drops `EXIF`, `XMP `, and unknown chunks; clears their VP8X flags.
- **GIF:** drops comments and every application extension except looping and
  ICC (XMP lives in one).
- **BMP:** has no capture-metadata container and passes through.

## Account private keys

Each account has an RSA-3072 key pair. The private key is sealed with Scrypt
(`n=2^16, r=8, p=1`) and AES-256-GCM over the unencrypted PKCS#8 DER:

```text
{"format": "ies-private-key", "version": 1, "owner": <user id>,
 "kdf": {"type": "scrypt", "salt", "n", "r", "p"}, "nonce", "ciphertext"}
```

The AAD is `b"IES-PRIVATE-KEY-V1\0"` plus the canonical JSON of the header
(everything but the nonce and ciphertext), so the owner and KDF cost are
authenticated. The file is closed (unknown fields are refused), KDF parameters
are bounded before any work, and a key file moved into another account's slot
is refused by its owner field. Files are written atomically with mode `0600`.

Releases before this one wrote OpenSSL encrypted PKCS#8 PEM, whose PBKDF2
runs only 2,048 iterations: about a thousand times cheaper per guess than the
Scrypt used everywhere else, which made the private key the weakest secret on
disk. Those files still open, and each is resealed the next time its owner
signs in (the one moment the server holds the verified password). The Account
page says which format a key is in. `ies keygen` writes the sealed format;
`--pem` keeps the OpenSSL format for interoperability.

## Cryptographic envelope

Each image gets a fresh random 256-bit data key and 96-bit nonce and is sealed
with AES-256-GCM. The data key is wrapped by one of:

- **Passphrase (`AES-GCM`):** Scrypt (`n=2^16, r=8, p=1`, 16-byte salt) derives a
  wrapping key; AES-GCM seals the data key with AAD `b"image-data-key"`. Files
  written before 3.1 used `n=2^14` and remain readable: the accepted floor below
  is a separate constant from the cost written today.
- **RSA hybrid (`RSA-HYBRID`):** RSA-OAEP-SHA256/MGF1-SHA256 with the owner's
  3072-bit key. The private key is sealed under the account password (see
  "Account private keys").

Sharing unwraps the data key in memory and wraps it again to the recipient's
RSA public key. A capability link wraps it with Scrypt, using the 256-bit link
token as the passphrase. Neither touches the ciphertext.

### Key commitment (version 4)

AES-GCM is not key-committing: knowing two keys, anyone can solve one
GF(2^128) equation and build a single ciphertext whose tag verifies under both,
each decrypting to different bytes (Dodis et al. 2018; Albertini et al. 2022).
In this vault that would let an owner wrap one key for Alice and another for
Bob, so that the same stored ciphertext, with the same digest, shows each a
different picture. Every wrap of an image (owner, shares, links) carries a key
the owner chose.

Version 4 closes that. From the 32-byte data key `DK`, nonce `N` and AAD `A`:

```text
image_key  = HKDF-SHA256(DK, salt="IES-V4", info="IES-V4\0image-key")
commitment = HKDF-SHA256(DK, salt="IES-V4", info="IES-V4\0key-commitment\0" || N || SHA-256(A))
```

The image is sealed under `image_key` and the 32-byte `commitment` is stored as
`key_commitment`. Decryption recomputes it from the unwrapped key and compares
in constant time before AES-GCM runs; any other key is refused there. The AAD
prefix is `IES-CONTEXT-V4\0`, so a context sealed under one version is never
valid AAD for the other. `tests/test_key_commitment.py` builds the forgery: a
version 3 envelope opens for both keys as two different images; under version
4 the same forgery against the derived GCM keys still satisfies AES-GCM, but
the second key fails the commitment. The browser twin is checked against
Python in both directions (`tests/test_browser_crypto.py`).

Version 1 and 3 images remain readable, so an image stored before version 4
keeps version 3's weaker guarantee until its owner re-keys it; the server only
accepts version 4 for new browser uploads and re-keys.

### Envelope versions and AAD

| Version | Written by | AAD |
| --- | --- | --- |
| 1 | Everything before the phase 1 review | web: `user=<id>\|filename=<name>\|mime=<mime>`; CLI: `cli\|filename=<name>`; rebuilt from the envelope's own `aad` dict |
| 2 | Never by this codebase (reserved: the discarded v1.0 lineage used it) | — |
| 3 | Web, browser, and CLI before key commitment; still read and restored | `b"IES-CONTEXT-V3\0"` + canonical JSON of `context` |
| 4 | Current web, browser, CLI, and re-keys | `b"IES-CONTEXT-V4\0"` + canonical JSON of `context`, plus `key_commitment` |

A version 3 or 4 `context` seals:

| Field | Web | CLI |
| --- | --- | --- |
| `asset` | random 128-bit id, also the vault filename | random id |
| `algorithm`, `wrap` | yes | yes |
| `owner` | user id | — |
| `mime`, `format`, `width`, `height` | yes (after metadata stripping) | — |
| `filename` | name at upload | input file name |
| `source` | `web` (`browser` for end-to-end uploads, which seal every field above) | `cli` |

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
| `n` is a power of two, `n >= 2^14` (`MIN_SCRYPT_N`), `n <= 2^22` | Blocks downgrade below the vault's baseline and CPU exhaustion. The floor is deliberately below the `2^16` written today, so raising the default never strands an existing file |
| A wrap that omits `n` uses `2^14` (`LEGACY_SCRYPT_N`) | Such wraps predate explicit parameters; falling back to the *current* default would derive the wrong key |
| `128 * n * r <= 256 MiB`, `1 <= r <= 32`, `1 <= p <= 16` | Bounds the allocation |

Version 3 and 4 envelopes are closed (version 4 adds exactly `key_commitment`,
32 bytes of canonical base64). Unknown top-level or wrap keys are rejected,
so renaming a key cannot make a default value apply. Base64 must be canonical,
and `ciphertext_sha256` is verified, so every byte of a `.ies` header
influences decryption. A Hypothesis property test flips every byte position
with every XOR mask class and requires decryption to fail.

Salt, nonce, and wrapped-key lengths are checked before use. Malformed input
raises `CryptoError`, so the CLI exits 1 and the web app returns a clean error
rather than a traceback. That includes JSON nested deeply enough to exhaust
Python's recursive decoder (`"[" * 50000`), in `.ies` headers, envelopes,
request bodies, kept-share lists, and backup manifests, and request bodies
that are JSON but not an object.

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
- **Password policy**, enforced in `VaultStore` so registration, rotation and the
  CLI all apply it: at least 10 characters, at least five distinct characters,
  not containing the username, not one of a short list of the most common
  choices. The account password also encrypts the RSA private key, so a weak one
  weakens every image shared to that account. A breach-corpus check is out of
  scope; a deployment that needs one should add it.
- **Throttles beyond login**, all SQLite-backed so a restart does not reset them:
  - registration: 5 per hour per address. Each registration generates an
    RSA-3072 key pair, so without a limit it is a CPU amplifier that needs no
    account;
  - decrypt attempts: 30 per 5 minutes per account. Keyed on the account rather
    than the asset, so one user cannot lock another out of a shared image;
  - capability-link requests: 20 per 5 minutes per address, bounding token
    guessing on the one surface whose only credential is the URL.
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
- **JWTs** (`/api/*`) are HS256 only. `exp`, `iat`, `iss`, `aud`, `sub`, and an
  integer `ver` are required; `aud` must be `image-encryption-system/api`, so a
  token minted for another service that shares the key is refused; and `ver`
  must equal the user's current `token_version`. `alg=none`, other algorithms,
  and other keys are rejected.
- **CSRF.** Every state-changing HTML route requires the session CSRF token
  (tested across the whole URL map), as a form field or, for the end-to-end
  page's `fetch()` calls, an `X-CSRF-Token` header that a cross-site page
  cannot set without a CORS preflight this app never answers. `/api/*` routes ignore cookies entirely and
  need a bearer token, so they cannot be driven cross-site.
  `/l/<token>/decrypt` is exempt because the token in its URL is the credential.
- **Secrets.** If `SECRET_KEY` is unset, or set to a value that has ever shipped
  in this repository, a random key is generated once and persisted (mode 0600)
  under the instance key directory. `JWT_SECRET` defaults to an HMAC-derived key,
  not a copy of `SECRET_KEY`.
- **Page headers.** Every HTML page sends a CSP with no inline script or style,
  `frame-ancestors 'none'`, and `form-action 'self'`. It also sends
  `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, so link tokens
  cannot leak through Referer, plus a restrictive `Permissions-Policy`,
  `Cross-Origin-Opener-Policy: same-origin`, and
  `Cross-Origin-Resource-Policy: same-origin`. HSTS is sent on HTTPS requests
  only, so a plain-HTTP development run is never pinned to a scheme it lacks.

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
  key they extracted. For an end-to-end image, **Re-key** retires that key so
  it no longer opens what the server stores (see "Re-keying"); for a
  server-mode image, re-upload it.

## Backup and restore

Backups contain ciphertext and envelopes only, never private keys. A restore
validates **every** entry before writing anything:

- zip members must be relative with no `..`;
- the uncompressed total is at most 64 MiB, with at most 1000 assets;
- each blob may be referenced only once;
- each envelope must be well formed, and each asset an allow-listed image whose
  MIME type matches its format;
- each blob must match its envelope's `ciphertext_sha256`, so a damaged backup
  restores nothing instead of an image that can never be opened.

Version 3 assets must be sealed to the restoring account, and one whose asset
id already exists in this vault is skipped, so restoring twice is harmless.
Restores never overwrite existing files, because vault filenames are the random
asset ids.

## Cloaked exports

`POST /images/<id>/cloak` (owner only, CSRF, throttled per account) returns the
image's `.ies` bytes, the same ones the `.ies` download returns, hidden in a PNG
(`cloak.py`). It touches no key, so it adds nothing to what the owner could
already download, and it works for end-to-end images.

- **What it is not.** The cloak adds no confidentiality or integrity: the
  AES-GCM envelope inside provides both. Its slot order and header are public,
  and the header is whitened with a public ChaCha20 key only so the embedded
  bits are not JSON-shaped. Steganalysis can tell that a picture is cloaked.
- **Covers.** A generated landscape, or a picture of the owner's that first
  passes the upload checks (allow-list, pixel ceiling, decompression-bomb
  handling); only its pixels are used, so its metadata is never carried over.
  Covers are limited to `CLOAK_MAX_PIXELS` (24 MP).
- **Extraction** (`ies uncloak`, and every CLI command that reads an `.ies`)
  refuses anything that is not a PNG within the pixel ceiling before decoding,
  bounds the declared length by the capacity and 64 MiB before allocating, and
  checks the payload's SHA-256, so recompression, resizing or editing gives a
  clean error and never a wrong file (`tests/test_cloak.py`). What comes out
  is an ordinary `.ies` file and is validated like one.

## Cipher Lab

`/lab` and `ies lab` run deliberately weak image ciphers for comparison. They
are not a security boundary and never touch vault data: the lab has no access
to rows, blobs or keys, and its ciphers use keys generated for the run.

- Uploads pass the same image checks as vault uploads, are cropped and resized
  in memory, and are never written to disk, stored in the database, or audited
  (`tests/test_lab_web.py`). They do reach the server, as server-mode uploads
  do; the page says so.
- A run encrypts and attacks one image eleven ways (a few seconds of CPU), so
  it is login-only and throttled per account (`LAB_RATE_LIMIT`, default 6 per
  10 minutes), and its size is fixed by `LAB_IMAGE_SIZE`.
- Results are rendered once with `Cache-Control: no-store`; nothing is kept.

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
- Give the process a memory limit: each in-flight passphrase decrypt holds
  ~64 MiB for Scrypt. `compose.yaml` sets one.
