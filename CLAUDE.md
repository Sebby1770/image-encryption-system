# CLAUDE.md

Flask image vault: images are encrypted with AES-256-GCM before they touch disk,
and each image's data key is wrapped with Scrypt + AES-GCM (passphrase) or
RSA-OAEP-SHA256 (per-user key pair). There is also an `ies` CLI that reads and
writes the same `.ies` envelope offline.

## Layout

```text
src/image_encryption_system/
  crypto.py      # AES-GCM, key wrapping, .ies pack/unpack, AAD. No Flask imports.
  storage.py     # VaultStore: SQLite schema, users, assets, shares, links, audit, backup zip
  security.py    # LoginGuard, RequestThrottle (register/decrypt/link), password policy
  web.py         # create_app(): routes, CSRF, sessions, JWT API, upload checks
  lab_routes.py  # /lab and /images/<id>/cloak, registered at the end of create_app()
  cli.py         # `ies` console script: crypto, cloak and lab; never Flask
  iwt.py         # one level of integer Haar lifting (exact on integers)
  quality.py     # PSNR and SSIM, banded so big images stay small in memory
  covers.py      # generated landscape covers (ChaCha20-seeded, values in [10, 245])
  cloak.py       # hide an .ies file in a PNG's wavelet detail bits, and get it back
  lab/           # Cipher Lab: base/ciphers registry, classic/linear/neural/aes ciphers,
                 # keys, chaos, transforms, imaging, metrics, attacks, gcm, runner, report
  config.py      # Config defaults, all overridable via env vars
  templates/     # Jinja views (layout, auth, dashboard, account, audit, link)
  static/css/    # styles
  static/js/     # ies-crypto.js (browser twin of crypto.py), ies-image.js (metadata
                 # stripping), scrypt-worker.js, vault-e2e.js / link-e2e.js (pages)
tests/           # pytest; tests/helpers.py has make_app/register/login/encrypt_png
tests/js/        # node --test suite + harness.mjs, which test_browser_crypto.py drives
docs/SECURITY_MODEL.md  # threat model — keep it in sync with the code
docs/CIPHER_LAB.md      # every lab cipher, metric and attack, with references
docs/superpowers/       # the design spec and implementation plan for v4, cloak and lab
web/             # static GitHub Pages marketing site, unrelated to the Flask app
```

## Running things

Always work in the project venv. The container's system Python has
Debian-managed PyJWT/cryptography that pip cannot replace, so a global
`pip install -e .` fails. The SessionStart hook (`scripts/session-start.sh`)
creates `.venv` and installs `.[dev]` automatically in cloud sessions.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

python run.py                     # web app on http://127.0.0.1:5000 (FLASK_DEBUG=1 for debug)
ies --help                        # CLI
pytest                            # full suite (includes the browser test if Playwright is installed)
pytest -m "not e2e"               # skip the browser test
pytest -m "not slow"              # skip the full-size Cipher Lab run
ies lab run --size 64 --seed x    # the lab from the CLI (--json, --html for reports)
pytest -m e2e tests/e2e           # Playwright end-to-end flow (pip install -e ".[e2e]")
HYPOTHESIS_PROFILE=ci pytest tests/test_properties.py   # 200 examples per property, as CI runs
pytest --cov=image_encryption_system --cov-fail-under=85
node --test tests/js/*.test.mjs   # browser crypto (Node 20+; leave the glob unquoted)
ruff check src tests scripts run.py && ruff format --check src tests scripts run.py
mypy                              # configured in pyproject.toml, checks src/
```

Instance data (SQLite, ciphertext blobs, RSA keys) lives in `instance/` or
`$IES_INSTANCE_DIR`. Tests use `helpers.make_app(tmp_path)`, which sets
`TESTING=True` and disables CSRF unless a test passes `CSRF_ENABLED=True`.

## Envelope format

A `.ies` file is:

```text
b"IES1" | uint32 big-endian metadata length | metadata JSON (sorted keys) | ciphertext
```

`ciphertext` is the raw AES-256-GCM output (encrypted bytes followed by the
16-byte tag). In the web vault the same ciphertext is stored as
`instance/vault/<uuid>.enc` and the metadata as `encrypted_assets.metadata_json`.

Metadata (version 4, current; version 3 is the same without `key_commitment`):

| Key | Meaning |
| --- | --- |
| `version` | `4` (versions `1` and `3` are still read; `2` is reserved, see below) |
| `algorithm` | `AES-GCM` (passphrase wrap) or `RSA-HYBRID` (RSA wrap) |
| `image_nonce` | base64, 12-byte GCM nonce for the image |
| `key_wrap` | how the 32-byte data key is protected (below) |
| `context` | the sealed context; the AAD is `b"IES-CONTEXT-V4\0"` (`V3` for version 3) + canonical JSON of it |
| `key_commitment` | v4 only: base64 of 32 bytes, checked before AES-GCM runs (below) |
| `ciphertext_sha256` | hex digest checked before decrypt |
| `original_filename` | CLI only |

`context` always has `asset` (32 hex chars; the web vault stores the blob as
`<asset>.enc`), `algorithm`, and `wrap`. Web uploads add `owner`, `filename`,
`mime`, `format`, `width`, `height`, and `source: "web"`. CLI files add
`filename` and `source: "cli"`. Canonical JSON means sorted keys, `(",", ":")`
separators, and UTF-8 with `ensure_ascii=False` (`crypto.context_aad`). The web
app refuses a row whose fields disagree with its sealed context
(`web._check_sealed_context`).

`key_wrap` is one of:

- `{"type": "scrypt-aes-gcm", "salt", "nonce", "wrapped_key", "n", "r", "p"}` —
  Scrypt derives a wrapping key; the data key is sealed with AES-GCM and the
  fixed AAD `b"image-data-key"`. `n`, `r`, `p` are attacker-controlled on any
  imported file and are bounded by `_validate_scrypt_parameters()`.
- `{"type": "rsa-oaep-sha256", "wrapped_key"}` — RSA-OAEP with SHA-256/MGF1.

Shares and capability links do not touch the ciphertext: they store a second
wrap of the same data key (RSA to the recipient, or Scrypt with the link token
as the passphrase).

Version 1 envelopes have no `context`. Their AAD is rebuilt from a legacy `aad`
dict by `crypto.aad_from_metadata()`:

- web upload: `{"user_id", "original_filename", "mime_type"}` →
  `user=<id>|filename=<name>|mime=<mime>`
- CLI: `{"source": "cli", "filename"}` → `cli|filename=<name>`

`tests/fixtures/legacy-v1-*` are real version 1 files; tests prove they still
decrypt. Version 2 is never written: the discarded v1.0 lineage used that
number for an incompatible layout.

Version 4 commits to its key. From the data key `DK`, nonce `N` and AAD `A`,
`crypto.derive_v4_keys()` returns `image_key = HKDF-SHA256(DK, salt="IES-V4",
info="IES-V4\0image-key")` (AES-GCM runs under it, never under `DK`) and
`commitment = HKDF-SHA256(DK, salt="IES-V4", info="IES-V4\0key-commitment\0" ||
N || SHA-256(A))`. Plain AES-GCM lets one ciphertext authenticate under two keys
(`tests/test_key_commitment.py` builds that forgery with `lab/gcm.py`); the
commitment makes every other key fail before decryption. `encrypt_image_bytes`
takes `version=3` only so tests can build legacy envelopes.

`crypto.validate_envelope()` must run before any field is used; it bounds and
type-checks everything. Version 3 and 4 envelopes are closed: only the keys above
are allowed (exact key sets for each wrap type too), base64 must be canonical,
and `ciphertext_sha256` is verified, so flipping any byte of a `.ies` file makes
decryption fail (`tests/test_properties.py` proves it with Hypothesis).

## End-to-end (browser) mode

`static/js/ies-crypto.js` must stay byte-compatible with `crypto.py`: same
canonical JSON, AAD prefixes, base64 strictness, and Scrypt bounds. Change both
together; `tests/test_browser_crypto.py` checks them against each other under
Node (it skips without Node 20+, so run it locally when touching either side).
Browser uploads are version 4 envelopes with `context.source == "browser"`
(`EncryptedAsset.end_to_end`). The server must never unwrap their keys: every
route that takes a passphrase or account password calls
`web._require_server_side()`. Wraps a browser sends are checked with
`crypto.validate_key_wrap()` (structure only; the server cannot open them).
New browser uploads and re-keys must be version 4 (a stale page sending version
3 is told to reload); stored version 3 images still open and still restore, and
a re-key upgrades them. Because restore can bring in a crafted version 3
envelope, browser-made shares and links (`_require_key_commitment`) are refused
on anything but version 4.

Account private keys are `user-<id>-private.key`, sealed by
`crypto.wrap_private_key()` (Scrypt + AES-GCM over PKCS#8 DER, owner in the
AAD). `user-<id>-private.pem` is the legacy PBKDF2 format, still read and
resealed at sign-in by `VaultStore.upgrade_private_key()`.

Re-keying replaces an image's ciphertext in place (`VaultStore.rekey_asset`):
staging names are unique per call, the old file is kept (hard link, or a copy)
until the transaction commits and is restored on any failure, and the live file
is replaced atomically. Keep that ordering if you touch it: `tests/test_rekey.py`
fails the swap, fails the commit, and interleaves two re-keys on purpose.

Page modules run at import time, so keep start-up code at the bottom of the
module: a `const` declared below the call that uses it throws at load (the
browser tests fail on any console error).

The e2e tests launch Playwright's bundled Chromium and fall back to
`/opt/pw-browsers/chromium` (preinstalled in cloud sessions) or
`$IES_CHROMIUM_EXECUTABLE`. Do not run `playwright install` in cloud sessions.

Never change these byte layouts silently: existing blobs must stay decryptable.
Add a new `version` instead and keep a test that decrypts the old one.

## Test-suite KDF cost

`tests/conftest.py` runs every test at the cheapest accepted Scrypt cost
(`MIN_SCRYPT_N`), because the production default (`SCRYPT_N`, 2^16) costs
~300 ms per derivation and the property tests wrap hundreds of keys. Mark a test
`@pytest.mark.production_kdf` when it must see the real default.

## Conventions

- Security fixes are test-first: add the failing regression test, then fix.
- HTML templates must not contain inline `<script>` or `on*=` handlers: the page
  CSP forbids them. Put behaviour in `static/js/` (a test enforces this).
- Every colour in `styles.css` is a `:root` token with a dark-mode value in the
  `prefers-color-scheme: dark` block. Add new colours to both, never inline.
- Read request JSON with `web._json_payload()` (bodies) or `web._loads()`
  (form fields): they turn non-object bodies and nesting deep enough to exhaust
  Python's recursive decoder into clean 400s instead of 500s.
- Routes the page calls with `fetch()` sit behind `login_required`, which answers
  JSON-accepting requests with a 401 instead of a redirect; page modules must
  treat a redirected or non-JSON answer as failure (`readJSON` in vault-e2e.js).
- Tests never contain secret-shaped literals (GitHub push protection rejects
  them); build fake keys and tokens at runtime.
- Update `CHANGELOG.md`, `README.md`, and `docs/SECURITY_MODEL.md` when
  behaviour or guarantees change.
- Templates may not carry inline `style=` attributes either (CSP). Pages outside
  the vault's core (lab, cloak) load `static/css/lab.css` through the layout's
  `styles` block; it uses the `styles.css` tokens and defines none
  (`tests/test_styles.py` checks every stylesheet).
- Cloak layout is a byte format like the envelope: never change the slot order,
  header, whitening key or margins without a new cloak version.
- Lab ciphers cache key material per instance (`LabCipher._memo`), never
  globally by key: every web run uses a fresh key. Each lab statistic is a 5%
  test, so tests that expect a randomised cipher to pass fix its nonces
  (`lab.aes._new_nonce`).
