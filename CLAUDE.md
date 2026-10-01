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
  web.py         # create_app(): every route, CSRF, sessions, JWT API, upload checks
  cli.py         # `ies` console script; talks only to crypto.py
  config.py      # Config defaults, all overridable via env vars
  templates/     # Jinja views (layout, auth, dashboard, account, audit, link)
  static/        # CSS and favicon
tests/           # pytest; tests/helpers.py has make_app/register/login/encrypt_png
docs/SECURITY_MODEL.md  # threat model — keep it in sync with the code
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
pytest -m e2e tests/e2e           # Playwright end-to-end flow (pip install -e ".[e2e]")
HYPOTHESIS_PROFILE=ci pytest tests/test_properties.py   # 200 examples per property, as CI runs
pytest --cov=image_encryption_system --cov-fail-under=80
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

Metadata (version 3, current):

| Key | Meaning |
| --- | --- |
| `version` | `3` (version `1` is still read; `2` is reserved, see below) |
| `algorithm` | `AES-GCM` (passphrase wrap) or `RSA-HYBRID` (RSA wrap) |
| `image_nonce` | base64, 12-byte GCM nonce for the image |
| `key_wrap` | how the 32-byte data key is protected (below) |
| `context` | the sealed context; the AAD is `b"IES-CONTEXT-V3\0"` + canonical JSON of it |
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

`crypto.validate_envelope()` must run before any field is used; it bounds and
type-checks everything. Version 3 envelopes are closed: only the keys above
are allowed (exact key sets for each wrap type too), base64 must be canonical,
and `ciphertext_sha256` is verified, so flipping any byte of a `.ies` file makes
decryption fail (`tests/test_properties.py` proves it with Hypothesis).

The e2e test launches Playwright's bundled Chromium and falls back to
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
- Tests never contain secret-shaped literals (GitHub push protection rejects
  them); build fake keys and tokens at runtime.
- Update `CHANGELOG.md`, `README.md`, and `docs/SECURITY_MODEL.md` when
  behaviour or guarantees change.
