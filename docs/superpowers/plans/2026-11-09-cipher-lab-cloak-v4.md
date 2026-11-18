# Cipher Lab, Cloak, and v4 Envelopes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add key-committing v4 envelopes, a "cloak" export that hides the real `.ies` file inside an ordinary-looking PNG, and a Cipher Lab that implements, scores, and breaks chaos/transform/neural image ciphers next to the vault's AES-256-GCM.

**Architecture:** v4 is a new envelope version in `crypto.py` and its browser twin `ies-crypto.js` (HKDF-derived image key plus a 32-byte commitment). The cloak is a numpy module (`iwt.py`, `covers.py`, `cloak.py`) with web and CLI surfaces. The lab is a self-contained `lab/` package that never touches vault data. Its web pages live in `lab_routes.py`, registered from `create_app()`, so `web.py` and the shared templates change by only a few lines.

**Tech Stack:** Python 3.10+, Flask, `cryptography` (AES-GCM, HKDF, ChaCha20), Pillow, numpy (new), Hypothesis, pytest, Node 20+ WebCrypto, Playwright.

**Spec:** `docs/superpowers/specs/2026-11-09-cipher-lab-cloak-v4-design.md`

## Global Constraints

- Python ≥ 3.10 (CI runs 3.10–3.13); Node ≥ 20 locally, 22 in CI.
- The only new runtime dependency is `numpy>=1.26`, in `pyproject.toml` and `requirements.txt`.
- Lab ciphers never read or write vault rows, blobs, or keys.
- Templates: no inline `<script>`, no `on*=` handlers, no `style=` attributes (the page CSP is `script-src 'self'; style-src 'self'`). SVG presentation attributes such as `height="…"` are fine.
- Every colour is a `:root` token in `styles.css` with a dark-mode value. `lab.css` uses `var(--…)` only and defines no colours or tokens.
- v1 and v3 envelopes stay decryptable; every new write is v4. Exact v4 values: AAD prefix `b"IES-CONTEXT-V4\x00"`; HKDF-SHA256 with salt `b"IES-V4"`; image key info `b"IES-V4\x00image-key"`; commitment info `b"IES-V4\x00key-commitment\x00" + nonce + sha256(aad)`; 32 bytes each; envelope field `key_commitment`, canonical base64.
- Cloak values: magic `b"IESK"`, version `1`, a 44-byte header at 1 bit per slot in slots 0–351, whitening by ChaCha20 under key `sha256(b"IES-CLOAK-V1")` with a 16-byte zero nonce, margins `{1: 2, 2: 5, 3: 10}`, generated covers drawn inside [10, 245] at 3:2 aspect and at least 960×640, `CLOAK_MAX_PIXELS = 24_000_000`, payload ceiling 64 MiB.
- Lab values: image sizes `(32, 64, 128, 256, 512)` (web uses `LAB_IMAGE_SIZE = 256`), HKDF info `b"IES-LAB/" + name`.
- Throttles follow the existing `{NAME}_RATE_LIMIT` / `{NAME}_RATE_WINDOW_SECONDS` convention: `lab` 6 per 600 s and `cloak` 10 per 600 s, keyed `user:<id>`.
- Commits are authored by Sebby1770: `git -c user.name=Sebby1770 -c user.email=sebforbes03@gmail.com commit …`, with the message ending `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Tests contain no secret-shaped literals.
- Every command runs from the worktree root with the venv's tools: `.venv/bin/pytest`, `.venv/bin/ruff`, `.venv/bin/mypy`.

## Review Focus

1. **A page loaded before the deploy** uploads or re-keys with a v3 envelope. Expect a 400 that says "Reload the page", not a generic error. Tested in Task 3.
2. **A cloaked PNG re-saved without loss** (RGBA with opaque alpha, or a different zlib level) must still uncloak. A palette-quantised or JPEG re-save must give the clean `CloakError`. Tested in Task 7.
3. **An ordinary photo passed to the CLI** (`ies decrypt` or `ies uncloak`) must exit 1 with "does not carry a vault file" and no traceback. Tested in Task 9.
4. **Lab uploads in unusual modes** (grayscale, palette, transparent RGBA, 16-bit, animated GIF, 10×10, a 400×50 panorama) must prepare without error. Tested in Task 10.
5. **Tampered lab form posts** (no ciphers, an unknown cipher or sample, upload chosen with no file, a non-image) must get a 400 with a message, never a 500. Tested in Task 17.

---

## Phase A — Envelope version 4

### Task 1: v4 envelopes in `crypto.py`

**Files:**
- Modify: `src/image_encryption_system/crypto.py` (constants near lines 52–80; `encrypt_image_bytes` 317; `decrypt_image_bytes` 361; `validate_envelope` 409; `context_aad` 448; `aad_from_metadata` 594)
- Modify: `tests/test_envelope_v3.py:54,141,154` (new envelopes now report `4`)
- Create: `tests/test_envelope_v4.py`

**Interfaces:**
- Produces: `ENVELOPE_V4 = 4`, `CURRENT_ENVELOPE_VERSION = ENVELOPE_V4`, `SUPPORTED_ENVELOPE_VERSIONS = {1, 3, 4}`, `SEALED_CONTEXT_VERSIONS = frozenset({3, 4})`, `CONTEXT_AAD_PREFIX_V4`, `KEY_COMMITMENT_BYTES = 32`, `V4_ENVELOPE_KEYS`
- Produces: `context_aad(context, *, version: int = ENVELOPE_V3) -> bytes`
- Produces: `derive_v4_keys(data_key: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]`, returning `(image_key, commitment)`
- Produces: `encrypt_image_bytes(..., version: int = CURRENT_ENVELOPE_VERSION)`, accepting only 3 or 4
- Produces: `is_key_committing(metadata: Any) -> bool`

- [ ] **Step 1: Set up the worktree venv.** Run `python3 -m venv .venv && .venv/bin/pip install -q -e ".[dev,e2e]"`, then `.venv/bin/pytest -q -m "not e2e" -x`. Expected: the existing suite passes (baseline).
- [ ] **Step 2: Write the failing tests** in `tests/test_envelope_v4.py`:

```python
def test_new_envelopes_are_v4_with_a_32_byte_commitment():       # both algorithms; set(metadata) <= V4_ENVELOPE_KEYS; decrypt round-trips
def test_commitment_and_image_key_follow_the_spec_construction():
    # unwrap the data key, recompute both with HKDF from the exact constants above;
    # AESGCM(image_key) opens the ciphertext with context_aad(ctx, version=4), AESGCM(data_key) does not
def test_a_key_that_fails_the_commitment_is_refused_before_gcm(monkeypatch):
    # key_wrap re-wrapped around a different data key -> CryptoError matching "key commitment";
    # monkeypatch AESGCM.decrypt to raise AssertionError, proving GCM never ran
def test_v4_envelopes_are_closed():                               # missing, 31-byte, or non-canonical key_commitment and extra fields are refused
def test_version_3_can_still_be_written_and_read():               # encrypt(version=3) has no key_commitment, uses the V3 prefix, decrypts
def test_relabelling_a_v4_envelope_as_v3_fails():                 # version=3 with key_commitment dropped -> CryptoError
def test_only_versions_3_and_4_can_be_written():                  # version=1, 2, 5 -> CryptoError
```

- [ ] **Step 3: Run them.** `.venv/bin/pytest tests/test_envelope_v4.py -q`. Expected: FAIL (`ImportError: derive_v4_keys`).
- [ ] **Step 4: Implement.**
  - Encrypt: build `aad = context_aad(sealed, version=v)`. For v4, `image_key, commitment = derive_v4_keys(data_key, nonce, aad)`, AES-GCM runs under `image_key`, and the metadata gets `key_commitment`.
  - Decrypt (v4): after the digest check and the unwrap, compare commitments with `hmac.compare_digest` and raise `CryptoError("This key does not match the image's key commitment.")` on a mismatch, then run AES-GCM under `image_key`.
  - `validate_envelope`: v4 uses the closed `V4_ENVELOPE_KEYS`, the same wrap and context rules as v3, and `len(_b64decode(key_commitment)) == 32`.
  - `aad_from_metadata`: v4 returns `context_aad(ctx, version=4)`.
- [ ] **Step 5: Change** `tests/test_envelope_v3.py:54,141,154` from `== 3` to `== 4`.
- [ ] **Step 6: Run** `.venv/bin/pytest tests/test_envelope_v4.py tests/test_envelope_v3.py tests/test_properties.py tests/test_crypto.py -q`. Expected: PASS. The byte-flip property test now exercises v4.
- [ ] **Step 7: Commit** `crypto.py` and both test files: "Add key-committing version 4 envelopes".

### Task 2: Two-key AES-GCM collision builder and the salamander regression

**Files:**
- Create: `src/image_encryption_system/lab/__init__.py` (docstring only; Task 16 adds exports)
- Create: `src/image_encryption_system/lab/gcm.py`
- Create: `tests/test_lab_gcm.py`, `tests/test_key_commitment.py`

**Interfaces:**
- Consumes: `crypto.derive_v4_keys`, `crypto.context_aad`, `crypto.encrypt_image_bytes`
- Produces: `gf_mul(x: int, y: int) -> int`, `gf_inv(x: int) -> int`, `ghash(h: int, aad: bytes, ciphertext: bytes) -> int`
- Produces: `forge_two_key_ciphertext(key1: bytes, key2: bytes, nonce: bytes, aad: bytes, plaintext1: bytes, plaintext2: bytes) -> bytes`. It returns `ciphertext‖tag`, valid under both keys. The plaintexts have equal length, a multiple of 16 and at least 32. Under `key1`, blocks `[0, n//2 − 1)` decrypt to `plaintext1`; under `key2`, blocks `[n//2, n)` decrypt to `plaintext2`. Block `n//2 − 1` is the solved block.

- [ ] **Step 1: Write the failing tests.** In `tests/test_lab_gcm.py`:
  - `test_gf_identity_and_inverse`: in GCM bit order the identity is `1 << 127`, so `gf_mul(x, 1 << 127) == x` and `gf_mul(x, gf_inv(x)) == 1 << 127` for random non-zero `x`.
  - `test_ghash_reproduces_cryptography_tags`: `S ⊕ ghash(H, aad, ct)` equals the tag `AESGCM.encrypt` produces, for random keys, nonces, AAD and lengths, including non-multiples of 16.
  - `test_forged_ciphertext_authenticates_under_both_keys`: `AESGCM(k1).decrypt` and `AESGCM(k2).decrypt` both succeed, the halves match as specified, and the two outputs differ.

  In `tests/test_key_commitment.py`, `test_v3_opens_under_two_keys_but_v4_refuses_the_second`:
  - Build a v3 envelope whose ciphertext comes from `forge_two_key_ciphertext(k1, k2, …, context_aad(ctx))`. Wrapping `k1` and then `k2` with `wrap_data_key_passphrase` both open, to different bytes.
  - Then forge for the v4 image keys of `k1` and `k2` and store `k1`'s commitment. `k1` opens; `k2` raises `CryptoError` matching "key commitment", while `AESGCM(image_key_2).decrypt` alone would have accepted it.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_lab_gcm.py tests/test_key_commitment.py -q`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement `lab/gcm.py`.** Use SP 800-38D multiplication:

  ```text
  R = 0xE1 << 120; Z = 0; V = y
  for i in range(128): if (x >> (127 - i)) & 1: Z ^= V; V = (V >> 1) ^ R if V & 1 else V >> 1
  ```

  - **Inverse:** `x^(2^128 − 2)`.
  - **Per-key values:** `H = AES_K(0^128)` and `S = AES_K(nonce‖0^31‖1)`. The keystream is AES-CTR from `nonce‖00000002`.
  - **GHASH input:** `pad(A)‖pad(C)‖[len(A)·8]₆₄‖[len(C)·8]₆₄`, evaluated by Horner's rule.
  - **Solving the free block:**
    - Set the free block `c_f` to zero, so `G = ghash₁ ⊕ ghash₂ ⊕ S₁ ⊕ S₂`.
    - `c_f = G · (H₁^e ⊕ H₂^e)⁻¹`, where `e` is the free block's power: the number of GHASH blocks from it to the end, inclusive.
    - Tag = `S₁ ⊕ ghash₁(final C)`.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit**: "Prove v4 stops the two-key AES-GCM attack".

### Task 3: Server, storage, and CLI accept v4

**Files:**
- Modify: `src/image_encryption_system/web.py`:
  - the sealed-upload check, near line 1345: require v4 with the message `"End-to-end uploads must use envelope version 4. Reload the page to get the current encryption code."`
  - `_check_sealed_context`, near line 2081: use `not in SEALED_CONTEXT_VERSIONS`
- Modify: `src/image_encryption_system/storage.py:1396`: use `version in SEALED_CONTEXT_VERSIONS`
- Modify: `src/image_encryption_system/cli.py` `_inspect`: print `key commitment: yes` for v4, or `key commitment: no (version N)`
- Modify: `tests/helpers.py` `browser_envelope(...)`: a `version` keyword passed to `encrypt_image_bytes`
- Modify: `tests/test_zero_knowledge.py:116`: the expected message becomes "version 4"
- Create: `tests/test_envelope_v4_web.py`

**Interfaces:**
- Consumes: `SEALED_CONTEXT_VERSIONS`, `ENVELOPE_V4`, `is_key_committing` from Task 1

- [ ] **Step 1: Write the failing tests.**
  - `test_server_mode_uploads_are_v4`: `helpers.encrypt_png`, then the stored metadata version is 4 and decrypting through the route works.
  - `test_a_stale_page_sending_v3_is_told_to_reload` (Review Focus 1): `post_sealed(browser_envelope(1, version=3))` returns 400 and the JSON error contains "Reload the page".
  - `test_rekey_upgrades_a_v3_image_to_v4`: create a v3 browser asset with `store.save_asset(...)` and `encrypt_image_bytes(version=3, context=<browser context>)`, re-key it through the route with a v4 envelope sealing the same context, then the asset reports version 4.
  - `test_rekey_with_a_v3_envelope_is_refused`
  - `test_restore_accepts_v3_and_v4_assets`: back up one v4 and one v3 asset, delete both, restore, and both decrypt.
  - `test_cli_inspect_reports_key_commitment`: `ies encrypt` then `ies inspect` prints "key commitment: yes"; `tests/fixtures/legacy-v1-cli.ies` prints "no (version 1)".
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement** the edits listed under Files.
- [ ] **Step 4: Run** `.venv/bin/pytest -q -m "not e2e"`. Expected: the whole suite passes.
- [ ] **Step 5: Commit**: "Write v4 everywhere the server and CLI seal images".

### Task 4: Browser twin of v4

**Files:**
- Modify: `src/image_encryption_system/static/js/ies-crypto.js` (constants near line 12; `contextAAD` 176; `encryptImage` 470; `decryptImage` 502; `validateEnvelope` 521)
- Modify: `tests/js/crypto.test.mjs`, `tests/js/harness.mjs`, `tests/test_browser_crypto.py`

**Interfaces:**
- Produces: `ENVELOPE_V4`; `contextAAD(context, version = ENVELOPE_V3)`; `deriveV4Keys(dataKey, nonce, aad) -> Promise<{ imageKey: Uint8Array, commitment: Uint8Array }>` using WebCrypto HKDF `deriveBits`; `encryptImage(plaintext, { …, version = ENVELOPE_V4 })`
- Produces: `decryptImage` and `validateEnvelope`, which accept v3 and v4
- Produces: harness op `v4keys({ data_key, nonce, aad }) -> { image_key, commitment }` (base64); the `encrypt` op forwards `version`

- [ ] **Step 1: Write the failing tests.**
  - Node tests:
    - "v4 envelopes carry a 32-byte commitment and round-trip"
    - "a key that fails the commitment is refused"
    - "version 3 envelopes still open" (written with `version: 3`)
  - Python tests:
    - `test_v4_key_derivation_matches_python`: the `v4keys` op equals `crypto.derive_v4_keys` for 20 random inputs.
    - `test_browser_writes_v4`
    - `test_python_v3_envelopes_open_in_the_browser`
- [ ] **Step 2: Run** `node --test tests/js/*.test.mjs` and `.venv/bin/pytest tests/test_browser_crypto.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement.** Mirror Task 1 byte for byte. The commitment comparison is constant-time: XOR every byte into an accumulator. Then `grep -n "version" src/image_encryption_system/static/js/vault-e2e.js src/image_encryption_system/static/js/link-e2e.js` and confirm neither page pins version 3.
- [ ] **Step 4: Run both suites.** Expected: PASS, including the existing two-way round-trip tests, which now cover v4.
- [ ] **Step 5: Commit**: "Seal and open v4 envelopes in the browser".

## Phase B — Cloak

### Task 5: Integer Haar lifting, quality metrics, numpy

**Files:**
- Modify: `pyproject.toml` (`dependencies` gains `"numpy>=1.26"`), `requirements.txt`
- Create: `src/image_encryption_system/iwt.py`, `src/image_encryption_system/quality.py`
- Create: `tests/test_iwt.py`, `tests/test_quality.py`

**Interfaces:**
- Produces: `iwt.forward(channel: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]`, returning `(ll, lh, hl, hh)` as int32 with shape `(H/2, W/2)`. Input is 2-D with even dimensions.
  - The rows step is applied first, then the columns. On rows, `a = x[:, 0::2]`, `b = x[:, 1::2]`, `d = a − b`, `s = b + (d >> 1)`.
  - Columns of `s` give `ll` (the s part) and `lh` (the d part); columns of `d` give `hl` (s) and `hh` (d).
- Produces: `iwt.inverse(ll, lh, hl, hh) -> np.ndarray` (int32, exact)
- Produces: `quality.psnr(a, b) -> float` (`inf` when equal; uint8, peak 255)
- Produces: `quality.ssim(a, b) -> float`: mean SSIM over sliding 8×8 uniform windows (integral images), `C1 = (0.01·255)²`, `C2 = (0.03·255)²`, averaged over channels.

- [ ] **Step 1: Write the failing tests.**
  - `test_inverse_undoes_forward_exactly`: Hypothesis over uint8 arrays with even shapes up to 64.
  - `test_constant_image_has_no_detail`
  - `test_detail_changes_respect_the_cloak_margins`: Hypothesis for k ∈ {1,2,3}. Take pixels in `[m, 255−m]`, replace the low k bits of every detail coefficient at random, invert. Every pixel stays in [0, 255] and moves at most `m(k) = 2, 5, 10`. This pins the spec's margin claim.
  - `test_psnr_identical_is_inf_and_known_value`: one channel off by 1 at one pixel of 8×8×3 gives `10·log10(255² / (1/192))`.
  - `test_ssim_is_one_for_identical_and_low_for_noise`: noise against a gradient is below 0.5.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement** both modules. Add numpy, then run `.venv/bin/pip install -q -e ".[dev,e2e]"`.
- [ ] **Step 4: Run them.** Expected: PASS. Also run `.venv/bin/mypy`: clean.
- [ ] **Step 5: Commit**: "Add exact integer Haar lifting and image quality metrics".

### Task 6: Procedural landscape covers

**Files:**
- Create: `src/image_encryption_system/covers.py`, `tests/test_covers.py`

**Interfaces:**
- Produces: `PALETTES = ("dusk", "alpine", "desert", "ocean")`
- Produces: `generate_cover(width: int, height: int, *, seed: bytes, palette: str = "dusk") -> np.ndarray`, returning uint8 `(H, W, 3)` with every value in [10, 245]. It raises `ValueError` for an unknown palette or a side under 16.

- [ ] **Step 1: Write the failing tests.**
  - `test_cover_is_deterministic_and_seed_dependent`
  - `test_cover_stays_inside_the_safe_range`: every palette at 160×96.
  - `test_cover_looks_like_a_picture`: per-channel standard deviation above 10, horizontal neighbour correlation above 0.9.
  - `test_unknown_palette_and_tiny_sizes_are_refused`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.** Random lattices come from a ChaCha20 keystream keyed with `sha256(b"IES-COVER\x00" + palette + b"\x00" + seed)`, not numpy's RNG, whose streams can change between versions.
  - The picture: a sky gradient, a soft sun, three fractal value-noise ridgelines (five octaves, bilinear) blended toward the sky colour with distance, foreground hills, and ±2 levels of grain.
  - Finally map into [10, 245].
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Generate landscape covers for cloaked exports".

### Task 7: `cloak.py` — embed and extract

**Files:**
- Create: `src/image_encryption_system/cloak.py`, `tests/test_cloak.py`

**Interfaces:**
- Consumes: `iwt.forward` / `iwt.inverse`, `quality.psnr` / `quality.ssim`, `covers.generate_cover`
- Produces:

```python
class CloakError(ValueError): ...
@dataclass(frozen=True)
class CloakReport: width: int; height: int; bits: int; payload_bytes: int; capacity_bytes: int; psnr: float; ssim: float
def capacity(width: int, height: int, bits: int) -> int                       # ((2.25*W*H) - 352) * bits // 8
def is_png(data: bytes) -> bool
def load_cover(image_bytes: bytes) -> np.ndarray                             # RGB uint8; alpha flattened on white
def cloak(payload: bytes, *, cover: np.ndarray | None = None, bits: int | None = None,
          seed: bytes = b"", palette: str = "dusk", max_pixels: int = 24_000_000) -> tuple[bytes, CloakReport]
def uncloak(png_bytes: bytes, *, max_pixels: int = 64_000_000) -> bytes
```

- **Slot layout:** channel, then subband (LH, HL, HH), then row-major. `M = 2.25·W·H`.
- **Slot order:** stream slot `s` is coefficient `(a·s + b) mod M`, where `a` is the smallest integer ≥ `int(M · 0.6180339887)` with `gcd(a, M) = 1`, and `b = M // 3`.
- **Bits:** MSB first. The header occupies slots 0–351 at 1 bit each; the payload starts at slot 352 in k-bit groups, embedded with `c' = (c & ~(2^k−1)) | v`.
- **Bit choice:** with `bits=None` and a generated cover, k = 2 at the smallest 3:2 size of at least 960×640 that fits. With `bits=None` and a custom cover, the smallest k that fits; if none does, upscale (Lanczos) to fit at k = 2. Either way, raise `CloakError` above `max_pixels`.
- **Messages:**
  - Capacity: `f"The vault file ({n:,} bytes) does not fit this cover at {k} bit(s) per coefficient; use a larger cover."`
  - Every extraction failure: `"This image does not carry a vault file, or it was recompressed or edited."`

- [ ] **Step 1: Write the failing tests.**
  - `test_round_trip_property`: Hypothesis over payloads of 0–4,000 bytes, `bits` in {1, 2, 3}, and covers that are random 32–96 px arrays (odd sizes included) or all 0 / all 255.
  - `test_capacity_formula`: `capacity(960, 640, 2) == 345_512`.
  - `test_generated_cover_quality`: a 50 KB payload gives `bits == 2`, `psnr >= 40`, `ssim >= 0.9`.
  - `test_full_capacity_psnr`: on the generated cover, k = 1, 2, 3 give PSNR of at least 50, 44 and 38 dB.
  - `test_payload_too_large_is_refused`
  - `test_tiny_cover_is_upscaled_or_refused`: a 16×16 cover is upscaled and round-trips, but with `max_pixels=4096` it raises `CloakError`.
  - `test_odd_sized_cover_is_cropped`: 101×67 becomes 100×66.
  - `test_lossless_resaves_still_uncloak_and_lossy_ones_are_detected` (Review Focus 2): an RGBA (alpha 255) re-save and a `compress_level=9` re-save both work. A palette `quantize()` re-save, a JPEG q95 re-save, and painting over a 40×40 block of a near-full image all raise `CloakError`.
  - `test_hostile_inputs_are_refused_cleanly`: non-PNG bytes, a truncated PNG, a PNG whose IHDR declares 100,000×100,000, and a 1×1 PNG all raise `CloakError` and nothing else.
  - `test_slot_order_is_a_permutation`
  - `test_header_bits_are_whitened`: reading slots 0–31 without whitening never spells `b"IESK"`.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - In `uncloak`, open with `Image.open(BytesIO(data), formats=["PNG"])` and check the declared size before `load()`.
  - Convert to RGB and crop to even dimensions.
  - Check length ≤ capacity and ≤ 64 MiB before reading the payload.
  - Wrap every Pillow and decoding exception in `CloakError`.
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Hide vault files inside ordinary-looking PNGs".

### Task 8: Cloak page, `lab_routes.py`, and `lab.css`

**Files:**
- Create: `src/image_encryption_system/lab_routes.py` (`register(app: Flask, store: VaultStore) -> None`)
- Create: `src/image_encryption_system/templates/cloak.html`, `src/image_encryption_system/static/css/lab.css`
- Modify: `web.py` (throttle tuple near line 189 gains `("lab", 6, 600), ("cloak", 10, 600)`; call `lab_routes.register(app, store)` at the end of `create_app`)
- Modify: `config.py`:
  - `LAB_RATE_LIMIT`, `LAB_RATE_WINDOW_SECONDS`, `CLOAK_RATE_LIMIT`, `CLOAK_RATE_WINDOW_SECONDS`
  - `CLOAK_MAX_PIXELS = 24_000_000`, `LAB_IMAGE_SIZE = 256`
  - environment overrides `IES_LAB_RATE_LIMIT`, etc.
- Modify: `layout.html` (one `{% block styles %}{% endblock %}` line in `<head>`), `dashboard.html:216` (one "Cloak" link beside the `.ies` link)
- Modify: `tests/test_styles.py` (scan every `static/css/*.css` for raw colours; token rules stay on `styles.css`), `tests/test_envelope_v3.py` template test (also refuse `\sstyle=`)
- Create: `tests/test_cloak_web.py`

**Interfaces:**
- Consumes: `web.login_required`, `web._require_user`, `web._owned_asset`, `web._throttle`, `web._inspect_image`, `crypto.pack_ies`, `cloak.cloak`, `cloak.load_cover`, `covers.PALETTES`
- Produces endpoints:
  - `cloak_form` — `GET /images/<int:asset_id>/cloak`
  - `cloak_download` — `POST /images/<int:asset_id>/cloak`
  - Form fields: `cover` (`generated` or `upload`), `palette`, `seed` (≤ 64 characters; blank means `os.urandom(16)`), `bits` (`auto`, `1`, `2`, `3`), `cover_file`

- [ ] **Step 1: Write the failing tests.**
  - `test_owner_gets_a_png_that_uncloaks_to_the_ies_download`: `uncloak(post.data)` equals `GET /images/<id>/download`; `image/png`; `Cache-Control: no-store`; filename `*.cloaked.png`.
  - `test_end_to_end_images_can_be_cloaked`
  - `test_custom_cover_is_validated`: a PNG cover works; a text file as cover gets a flash error and a redirect (303), not a 500.
  - `test_only_the_owner_can_cloak`: GET and POST from another account redirect with an error and return no PNG.
  - `test_cloak_requires_csrf_and_is_throttled`: `CSRF_ENABLED=True`; `CLOAK_RATE_LIMIT=1` makes the second POST refused.
  - `test_dashboard_links_to_the_cloak_page`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Errors (`CloakError`, `UnsupportedImageError`, `ValueError`) flash and redirect to `cloak_form`.
  - `cloak.html` extends `layout.html`, fills `styles` with `lab.css`, and shows the image name and payload size.
  - The page explains that the cloak hides only that the image carries a vault file and that any re-compression breaks it.
- [ ] **Step 4: Run** `.venv/bin/pytest -q -m "not e2e"`. Expected: PASS.
- [ ] **Step 5: Commit**: "Add the cloak page for vault images".

### Task 9: CLI `cloak`, `uncloak`, and cloaked input everywhere

**Files:**
- Modify: `src/image_encryption_system/cli.py`
- Create: `tests/test_cli_cloak.py`

**Interfaces:**
- Produces: `ies cloak IN -o OUT [--cover IMG] [--bits auto|1|2|3] [--palette NAME] [--seed TEXT]`, printing the `CloakReport`
- Produces: `ies uncloak IN -o OUT`
- Produces: `_read_vault_file(path: Path) -> bytes`, which uncloaks when `is_png(...)`; used by `decrypt`, `inspect`, `verify`, `rewrap`, `hash`. `CloakError` is a `ValueError`, so `main` already turns it into exit 1.

- [ ] **Step 1: Write the failing tests.**
  - `test_cloak_then_uncloak_round_trips`
  - `test_decrypt_accepts_a_cloaked_png`
  - `test_cloak_with_a_custom_cover_and_one_bit`: output contains "PSNR".
  - `test_inspect_and_hash_accept_cloaked_files`
  - `test_an_ordinary_photo_is_not_mistaken_for_a_vault_file` (Review Focus 3): a normal PNG and a JPEG passed to `decrypt` and to `uncloak` exit 1, stderr contains "does not carry a vault file", and there is no traceback.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Cloak and uncloak from the CLI".

## Phase C — Cipher Lab core

### Task 10: Lab foundations

**Files:**
- Create: `lab/imaging.py`, `lab/keys.py`, `lab/chaos.py`, `lab/transforms.py` (all under `src/image_encryption_system/lab/`)
- Create: `tests/test_lab_foundations.py`

**Interfaces:**
- Produces (`imaging`):
  - `LAB_SIZES = (32, 64, 128, 256, 512)`, `SAMPLES = ("test-card", "gradient", "landscape")`
  - `prepare(image_bytes: bytes, size: int = 256) -> np.ndarray`, using formats PNG/JPEG/WEBP/GIF/BMP/TIFF
  - `sample(name: str, size: int = 256) -> np.ndarray`
  - `to_png(img) -> bytes`, `to_jpeg(img, quality=85) -> bytes`, `data_uri(data: bytes, mime: str) -> str`
  - `prepare` steps:
    - apply EXIF orientation and take the first frame;
    - composite modes with alpha or palette transparency onto white;
    - convert to RGB, centre-crop to a square, and resize with Lanczos;
    - raise `ValueError("This file is not an image the lab can read.")` on any decode error.
- Produces (`keys`): `derive(key: bytes, label: str, length: int) -> bytes` (HKDF-SHA256, info `b"IES-LAB/" + label`); `unit_floats(key, label, count) -> list[float]` (56-bit slices / 2⁵⁶); `stream(key, label, length) -> bytes` (ChaCha20 under `derive(key, label, 32)`, zero nonce)
- Produces (`chaos`):
  - `logistic_sequence(x0, mu, count, *, burn_in=1000) -> np.ndarray` (one orbit, a Python loop)
  - `chaos_bytes(values) -> np.ndarray`, computed as `floor(|v|·1e14) mod 256` (uint8)
  - `chen_sequence(state0: tuple[float, float, float, float], k: float, count: int, *, lanes=1024, h=0.002, burn_in=1000) -> np.ndarray`
  - The Chen system: `ẋ=36(y−x)`, `ẏ=−xz−16x+28y−w`, `ż=xy−3z`, `ẇ=x+k`, integrated with RK4. Lane `l` starts at `state0 + l·1e−6`; output interleaves the lanes' four variables step by step.
- Produces (`transforms`):
  - `arnold_destinations(size, a, b, iterations) -> np.ndarray`, where `out.reshape(-1, 3)[dest] = img.reshape(-1, 3)`; computed as the matrix power mod `size`
  - `haar_mod256_forward(channel, levels) -> np.ndarray` and `haar_mod256_inverse(coeffs, levels) -> np.ndarray`: uint8 Mallat layout, with every lifting step taken mod 256
  - `haar_mod256_subbands(size, levels) -> list[tuple[slice, slice]]`
  - `walsh_hadamard_2d(x) -> np.ndarray` (unnormalised, `wht(wht(x)) == size²·x`)

- [ ] **Step 1: Write the failing tests.**
  - `test_prepare_handles_unusual_modes` (Review Focus 4): L, P, transparent RGBA (becomes white), 16-bit `I;16`, a 3-frame GIF, 10×10 and 400×50 all give `(64, 64, 3)` uint8.
  - `test_prepare_refuses_non_images`
  - `test_samples_are_deterministic_and_sized`: the test card has at least 30% repeated 4×4 patches at 64 px.
  - `test_key_material_is_label_separated`
  - `test_logistic_matches_the_recurrence`
  - `test_chen_sequence_is_bounded_and_key_sensitive`: 50k values are finite with `|v| < 1000`; changing `k` by 1e−9 changes the output.
  - `test_arnold_destinations_are_a_bijection`
  - `test_mod256_haar_is_a_bijection` (Hypothesis, sizes 8–32, 1–2 levels)
  - `test_walsh_hadamard_inverse_scale`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.** The `landscape` sample is `covers.generate_cover(size, size, seed=b"lab", palette="dusk")`.
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Lay the Cipher Lab's foundations".

### Task 11: Cipher interface and the permutation/chaos ciphers

**Files:**
- Create: `lab/base.py`, `lab/classic.py`, `lab/ciphers.py`
- Create: `tests/test_lab_ciphers.py`

**Interfaces:**
- Produces (`base`):

```python
class LabDecryptError(Exception): ...
@dataclass(frozen=True)
class Ciphertext:
    payload: bytes
    shape: tuple[int, int, int]
    pixels: np.ndarray | None      # exact uint8 body for byte-image ciphers, else None
    view: np.ndarray               # uint8 rendering for display and metrics
class LabCipher:
    name: ClassVar[str]; title: ClassVar[str]; family: ClassVar[str]; summary: ClassVar[str]
    randomized: ClassVar[bool] = False; authenticated: ClassVar[bool] = False
    key_bits: ClassVar[int] = 256; key_note: ClassVar[str] = ""
    transform: ClassVar[str | None] = None        # None or "haar-mod256"
    linear_domain: ClassVar[str | None] = None    # None, "wht" or "fourier"
    def __init__(self, key: bytes) -> None        # exactly 32 bytes
    def encrypt(self, image: np.ndarray, *, nonce: bytes | None = None) -> Ciphertext
    def decrypt(self, ct: Ciphertext) -> np.ndarray
    def tamper_position(self, ct: Ciphertext) -> tuple[int, int]   # (byte index, xor mask); default (len//2, 0x10)
def check_image(image: np.ndarray) -> int         # returns S; ValueError unless uint8 (S, S, 3), S in LAB_SIZES
```

- Produces (`ciphers`): `CIPHER_NAMES = ("arnold", "logistic-xor", "hyperchaos", "wavelet", "wht", "drpe", "neural", "aes-ecb", "aes-ctr-fixed-iv", "aes-gcm", "aes-gcm-v4")` and `make_cipher(name: str, key: bytes) -> LabCipher` (`ValueError` for an unknown name). Tasks 12–13 register their classes here.
- Produces (`classic`), with the parameter derivation pinned (`d = keys.derive`, `u = keys.unit_floats`):
  - `ArnoldCipher`: `d(key, "arnold", 5)` gives `a = 1 + int(d[0:2]) % (S−1)`, `b = 1 + int(d[2:4]) % (S−1)`, `t = 1 + d[4] % 255`. `key_bits = 24`.
  - `LogisticXorCipher`: `u(key, "logistic-xor", 2)` gives `x0 = 0.1 + 0.8·u0`, `μ = 3.99 + 0.01·u1`. The keystream is `chaos_bytes(logistic_sequence(...))` over the `3S²` bytes. `key_bits = 100`.
  - `HyperchaosCipher`: `u(key, "hyperchaos", 5)` gives a state of `10·f − 5` for the first four values and `k = 1.4·f4 − 0.7`. One Chen sequence of `25·S²` values is consumed in order: `S²` for the permutation (argsort, stable), then for each pass in (rows forward, columns forward, rows backward, columns backward) `k1` and `k2` of `3S²` bytes each.
    - The passes run on `M = permuted.reshape(S, 3S)`: `y_t = x_t ⊕ k1_t ⊕ ((y_prev + k2_t) mod 256)` with `y_prev` starting at 0.
    - Inverse passes are fully vectorised.
  - `WaveletCipher`: `transform = "haar-mod256"`, 2 levels. `u(key, "wavelet", 2)` seeds one logistic orbit of `6S²` values: the first `3S²` permute each channel's subband (argsort per subband in canonical order); the next `3S²`, as `chaos_bytes`, XOR the permuted coefficients. `key_bits = 100`.
  - Every cipher caches its keystreams and permutations per instance and size.

- [ ] **Step 1: Write the failing tests** (parametrised over the classic names now; Tasks 12–13 add theirs to the same parameter list):
  - `test_round_trip_exact(name, sample, size)` for every sample at 32 and 64 px.
  - `test_round_trip_property(name)`: Hypothesis, 10 examples at 32 px.
  - `test_wrong_key_does_not_decrypt(name)`: at least 50% of pixels differ.
  - `test_registry_lists_the_eleven_ciphers_in_order`
  - `test_hyperchaos_diffuses_one_pixel_over_the_whole_image`: more than 99% of bytes change.
  - `test_check_image_refuses_bad_shapes`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Add the permutation and chaos lab ciphers".

### Task 12: Linear transform ciphers and the neural cipher

**Files:**
- Create: `lab/linear.py`, `lab/neural.py`
- Modify: `lab/ciphers.py` (register), `tests/test_lab_ciphers.py`

**Interfaces:**
- Produces: `WalshHadamardCipher` (`linear_domain = "wht"`):
  - Masks: `m ∈ {±1}^{3×S×S}` from the bits of `keys.stream(key, "wht", 3S²/8)`.
  - Encrypt: `C_c = wht(m_c·wht(P_c)) / S²` in float64. The payload is `C.astype("<f8")` in channel-major `(3, S, S)` order.
  - `coefficients(ct) -> np.ndarray`
  - `tamper_position`: byte 6 of the middle element, mask `0x08` (the top mantissa bit).
- Produces: `DrpeCipher` (`linear_domain = "fourier"`):
  - Phases: `φ1, φ2` from `keys.stream(key, "drpe", 24·S²)`, as uint32 / 2³² in two `(3, S, S)` blocks.
  - Encrypt: `C = ifft2(fft2((P/255)·e^{i2πφ1})·e^{i2πφ2})`. The payload is `C.astype("<c16")`.
  - Decrypt: `rint(255·Re(ifft2(fft2(C)·e^{−i2πφ2})·e^{−i2πφ1}))`.
  - The view is the per-channel min–max of `|C|`. `coefficients(ct)` and `tamper_position` work as for `WalshHadamardCipher`.
- Produces: `NeuralCipher`, 8 layers on `(P, 48)` patches (`img.reshape(S/4, 4, S/4, 4, 3).transpose(0, 2, 1, 3, 4)`):
  - Per-layer material, drawn in this order from `keys.stream(key, "neural", …)`:
    - `shuffle`: argsort of 48 uint32
    - `W1`: 32×24 uint8; `b1`: 32
    - `sigma`: argsort of 256 uint32
    - `W2`: 24×32 uint8; `b2`: 24
  - Forward layer: `X = X[:, shuffle]; A, B = X[:, :24], X[:, 24:]; f = (sigma[(A @ W1.T + b1) % 256] @ W2.T + b2) % 256; B = (B + f) % 256`, all in int64.

- [ ] **Step 1: Add the failing tests.**
  - Add `wht`, `drpe` and `neural` to the round-trip, property and wrong-key parameters.
  - `test_float_payload_sizes`: `8·3S²` and `16·3S²`; `pixels is None`.
  - `test_neural_cipher_maps_equal_patches_equally`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Add Walsh-Hadamard, Fourier DRPE, and neural lab ciphers".

### Task 13: AES baselines, including the vault's v3 and v4

**Files:**
- Create: `lab/aes.py`
- Modify: `lab/ciphers.py`, `tests/test_lab_ciphers.py`

**Interfaces:**
- Consumes: `crypto.derive_v4_keys`
- Produces: `AesEcbCipher` and `AesCtrFixedIvCipher`. Keys are `keys.derive(key, name, 32)`; the CTR IV is `keys.derive(key, "aes-ctr-fixed-iv/iv", 16)` and is reused for every image.
- Produces: `AesGcmCipher` and `AesGcmV4Cipher` (`randomized = authenticated = True`), with `AAD: ClassVar[bytes] = b"IES-LAB"`:
  - `gcm_key_for(nonce: bytes) -> bytes`: v3 returns the cipher's GCM key; v4 returns `derive_v4_keys(data_key, nonce, AAD)[0]`.
  - `pack(nonce: bytes, sealed: bytes) -> bytes`: v3 is `nonce‖sealed`; v4 is `nonce‖commitment‖sealed`, using the instance's own commitment.
  - `pixels` is the body without the tag.
  - Failures raise `LabDecryptError`: an `InvalidTag` from either cipher, or a commitment mismatch under v4.

- [ ] **Step 1: Add the failing tests.**
  - Add the four ciphers to the round-trip, property and wrong-key parameters; for the GCM ciphers, `LabDecryptError` counts as "does not decrypt".
  - `test_aes_ecb_matches_cryptography`
  - `test_gcm_payload_layouts`: `12 + 3S² + 16` and `12 + 32 + 3S² + 16`.
  - `test_v4_lab_cipher_uses_the_vault_construction`: opening with `AESGCM(derive_v4_keys(...)[0])` succeeds.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** Expected: PASS for all 11 ciphers.
- [ ] **Step 5: Commit**: "Add the AES baselines to the lab".

### Task 14: Metrics

**Files:**
- Create: `lab/metrics.py`, `tests/test_lab_metrics.py`

**Interfaces:**
- Consumes: `make_cipher`, `Ciphertext`, `LabCipher`
- Produces:

```python
@dataclass(frozen=True)
class MetricResult: key: str; label: str; value: float | None; per_channel: tuple[float, ...]; passed: bool | None; detail: str
CHI_SQUARE_CRITICAL_255 = 293.2478
LOCAL_ENTROPY_INTERVAL = (7.901901305, 7.903037329)
def entropy(view) -> list[float]
def local_entropy(view, *, blocks=30, block_pixels=1936, seed=0) -> list[float] | None   # None when N < 58,080
def chi_square(view) -> list[float]
def correlations(view) -> dict[str, list[float]]        # "horizontal", "vertical", "diagonal"
def npcr_uaci(a, b) -> tuple[float, float]               # percent, mean over channels
def npcr_critical(pixels: int, alpha: float = 0.05) -> float
def uaci_critical(pixels: int, alpha: float = 0.05) -> tuple[float, float]
def score(cipher: LabCipher, image, ct: Ciphertext, *, key: bytes, seconds: float) -> list[MetricResult]
```

- Formulas (`F = 255`, using `NormalDist().inv_cdf`):
  - `N* = (F − z_{1−α}·√(F/N)) / (F+1)`
  - `μ_U = (F+2)/(3F+3)`; `σ_U² = (F+2)(F²+2F+3) / (18(F+1)²·N·F)`; interval `μ_U ∓ z_{1−α/2}·σ_U`
- `score` returns these keys in order: `entropy`, `local_entropy`, `chi_square`, `correlation`, `npcr_uaci`, `key_sensitivity`, `round_trip`, `speed`, `expansion`.
  - The pass rules are the spec's §4.4 table.
  - Key sensitivity flips bit 0 of `key[31]` and holds the nonce fixed with `nonce=b"\x00" * 12`.

- [ ] **Step 1: Write the failing tests.**
  - `test_critical_values_match_wu_2011`: `npcr_critical(65536)` ≈ 99.5693 and `uaci_critical(65536)` ≈ (33.2824, 33.6447), each within 1e−4.
  - `test_entropy_extremes`: a constant image gives 0; `np.arange(256)` tiled to 256×256 gives exactly 8.
  - `test_fixed_noise_passes_every_statistic`: ChaCha20 noise under a fixed key, chosen so the probabilistic tests pass (deterministic, not flaky).
  - `test_gradient_is_strongly_correlated`: r > 0.9.
  - `test_score_reports_every_metric`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Score lab ciphers with the standard image-encryption metrics".

### Task 15: Attacks

**Files:**
- Create: `lab/attacks.py`, `tests/test_lab_attacks.py`

**Interfaces:**
- Consumes: `make_cipher`, `LabCipher` attributes (`transform`, `linear_domain`, `authenticated`), `coefficients()`, `gcm_key_for()` / `pack()`, `gcm.forge_two_key_ciphertext`, `transforms.*`
- Produces:

```python
@dataclass(frozen=True)
class AttackResult:
    key: str; label: str; applicable: bool; success: bool; queries: int; oracle_calls: int
    finding: str; recovered: np.ndarray | None = None; extra: np.ndarray | None = None
def structure_attack(cipher, target: Ciphertext, *, truth: np.ndarray) -> AttackResult   # truth only grades the result
def impulse_attack(cipher, target: Ciphertext, *, truth: np.ndarray) -> AttackResult
def pattern_leak(cipher, probe: np.ndarray) -> AttackResult
def determinism(cipher, image: np.ndarray) -> AttackResult
def tamper(cipher, image: np.ndarray) -> AttackResult
def salamander(name: str, top: np.ndarray, bottom: np.ndarray) -> AttackResult
def run_attacks(cipher, image: np.ndarray, *, probe: np.ndarray, decoy: np.ndarray) -> list[AttackResult]
```

- **`success` means the attacker won.** The scorecard shows it as a ✗ for the cipher.
- **The structure attack** runs the spec's §4.5 hypothesis ladder.
  - Each hypothesis is confirmed against the encryption of one random image (`numpy.random.default_rng(7)`).
  - Oracle results are cached by image bytes, so the zero image is queried once.
  - Joint coding puts digits 0–2 of the index in R, G and B. Per-channel coding uses `⌈log₂₅₆ n⌉` images, each carrying one digit in every channel.
  - It needs `pixels`; otherwise it reports `applicable=False`.
- **The salamander attack:**
  - Uses two attacker keys `keys.derive(b"\x00" * 32, "attacker-1", 32)` and `keys.derive(b"\x00" * 32, "attacker-2", 32)` and a random nonce.
  - The forged payload is `c1.pack(nonce, forge(...))`.
  - `recovered` / `extra` hold the two decryptions. It reports `applicable=False` for unauthenticated ciphers.

- [ ] **Step 1: Write the failing tests** at 64 px, asserting the spec's outcomes exactly:
  - `test_structure_attack_breaks(name, queries)` for `(arnold, 1), (logistic-xor, 1), (aes-ctr-fixed-iv, 1), (wavelet, 3)`: `recovered == truth`.
  - `test_structure_attack_fails_on(name)` for `hyperchaos, neural, aes-ecb, aes-gcm, aes-gcm-v4`.
  - `test_structure_attack_needs_byte_ciphertexts` for `wht, drpe`: `applicable is False`.
  - `test_impulse_attack_breaks_linear_ciphers`: `queries == 1`, exact recovery.
  - `test_pattern_leak_flags_only_ecb_and_neural`
  - `test_determinism_flags_every_cipher_but_gcm`
  - `test_tamper_is_refused_only_by_gcm`: for `wht` and `drpe`, at least one pixel changes.
  - `test_salamander_succeeds_on_gcm_and_fails_on_v4`: on `aes-gcm`, the top half of `recovered` equals the target's top half outside the solved block, and the bottom half of `extra` equals the decoy's bottom half.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Break the weak lab ciphers with real attacks".

### Task 16: Runner, verdicts, and the standalone report

**Files:**
- Create: `lab/runner.py`, `lab/report.py`
- Create: `templates/_lab_scorecard.html`, `templates/lab_report_standalone.html`
- Modify: `lab/__init__.py` (re-export `CIPHER_NAMES, make_cipher, run_lab, LabReport, SAMPLES, sample, prepare`)
- Modify: `pyproject.toml` (register a `slow` marker)
- Create: `tests/test_lab_report.py`

**Interfaces:**
- Produces:

```python
@dataclass
class CipherResult:
    name: str; title: str; family: str; summary: str; key_bits: int; key_note: str
    randomized: bool; authenticated: bool; metrics: list[MetricResult]; attacks: list[AttackResult]
    verdict: str; seconds: float; images: dict[str, bytes]   # "cipher" (JPEG), "recovered", "tampered", "salamander-1", "salamander-2" (PNG)
@dataclass
class LabReport:
    size: int; source: str; plaintext_png: bytes; results: list[CipherResult]; created: str
    def to_dict(self) -> dict[str, Any]                       # JSON-safe: images as data URIs, no NaN or inf
def verdict(result: CipherResult) -> str
def run_lab(image, *, ciphers: Sequence[str] | None = None, key: bytes | None = None, source: str = "custom") -> LabReport
def render_standalone_html(report: LabReport) -> str          # report.py; CSS from styles.css + lab.css inlined
```

- **Verdict rules:**
  1. `"Broken"` if the structure or impulse attack succeeded.
  2. Otherwise `"Leaks"` if the pattern, determinism or tamper attack succeeded.
  3. Otherwise `"Strong, not key-committing"` if the salamander attack succeeded.
  4. Otherwise `"Strong + committing"`.
- **Inputs to the attacks:** the probe is `sample("test-card", size)` and the salamander decoy is `sample("gradient", size)`.

- [ ] **Step 1: Write the failing tests.**
  - `test_verdicts_on_the_test_card`: at 64 px with a fixed key, the verdicts are:
    - `arnold`, `logistic-xor`, `wavelet`, `wht`, `drpe`, `aes-ctr-fixed-iv`: Broken
    - `aes-ecb`, `neural`, `hyperchaos`: Leaks
    - `aes-gcm`: Strong, not key-committing
    - `aes-gcm-v4`: Strong + committing
  - `test_report_is_json_safe`: `json.dumps(report.to_dict(), allow_nan=False)` works.
  - `test_standalone_html_is_self_contained`: it has a `<style>` block and `data:image/` URIs, and no `http`, `src="/` or `href="/`.
  - `test_run_lab_validates_its_inputs`: an unknown cipher or a bad shape raises `ValueError`; `ciphers=["arnold"]` gives one result.
  - `@pytest.mark.slow test_full_run_at_256`: local entropy is computed and the total time is under 20 s.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.** The standalone page is rendered by a Jinja `Environment(loader=PackageLoader("image_encryption_system"), autoescape=True)` and includes `_lab_scorecard.html`, the same partial the web page uses.
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Run the whole lab and render its scorecard".

## Phase D — Lab surfaces

### Task 17: The `/lab` page

**Files:**
- Modify: `lab_routes.py` (endpoints `lab_form` — `GET /lab` — and `lab_run` — `POST /lab`)
- Create: `templates/lab.html`, `templates/lab_report.html`
- Modify: `layout.html` (one "Lab" nav link), `lab.css`
- Create: `tests/test_lab_web.py`

**Interfaces:**
- Consumes: `run_lab`, `SAMPLES`, `CIPHER_NAMES`, `prepare`, `web._inspect_image`, `web._throttle`, `LAB_IMAGE_SIZE`
- Form fields: `source` (`sample` or `upload`), `sample`, `image`, and repeated `cipher` checkboxes, all checked by default.
- Responses: `Cache-Control: no-store`. Nothing is stored or audited.

- [ ] **Step 1: Write the failing tests.** The app runs with `LAB_IMAGE_SIZE=64`.
  - `test_lab_requires_login`
  - `test_lab_form_lists_samples_and_ciphers`
  - `test_running_a_sample_renders_the_scorecard`: all 11 titles, "Broken" and "Strong + committing", `data:image/`, and no-store.
  - `test_an_uploaded_image_is_used_and_never_stored`: the vault directory and the `encrypted_assets` count are unchanged.
  - `test_bad_lab_requests_get_clean_errors` (Review Focus 5, parametrised): no ciphers, `cipher=bogus`, `sample=bogus`, upload with no file, a text file, and a PNG whose IHDR declares 100,000×100,000. Each gets a 400 with a message.
  - `test_lab_requires_csrf_and_is_throttled`: `LAB_RATE_LIMIT=1`.
  - `test_nav_links_to_the_lab`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - `lab_report.html` shows:
    - the lesson banner from spec §4.5 (hyperchaos passes every statistic and is still breakable; Rhouma & Belghith 2008; Preishuber et al. 2018);
    - the scorecard partial;
    - per-cipher `<details>` with the image grid;
    - 64-bin SVG histograms whose bars are styled by `lab.css` classes.
- [ ] **Step 4: Run** `.venv/bin/pytest -q -m "not e2e"`. Expected: PASS.
- [ ] **Step 5: Commit**: "Add the Cipher Lab page".

### Task 18: `ies lab`

**Files:**
- Modify: `cli.py`
- Create: `tests/test_cli_lab.py`

**Interfaces:**
- Produces: `ies lab list`, printing name, family and title.
- Produces: `ies lab run [--image PATH | --sample NAME] [--size {32,64,128,256,512}] [--cipher NAME ...] [--seed TEXT] [--json PATH] [--html PATH]`. It prints one line per cipher (name, verdict, and the deciding finding). `--seed` sets the key to `sha256(seed)`.

- [ ] **Step 1: Write the failing tests.**
  - `test_lab_list_names_every_cipher`
  - `test_lab_run_writes_json_and_html`: 64 px with `--seed demo` gives 11 results.
  - `test_lab_run_with_a_non_image_exits_1`
  - `test_lab_run_rejects_a_bad_size`: argparse exits 2.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** Expected: PASS.
- [ ] **Step 5: Commit**: "Run the Cipher Lab from the CLI".

## Phase E — Docs, verification, delivery

### Task 19: Documentation

**Files:**
- Modify: `README.md` (features, CLI), `CHANGELOG.md` (an Unreleased section for v4, the cloak and the lab), `docs/SECURITY_MODEL.md`, `CLAUDE.md` (layout, envelope table with v4 and `key_commitment`, `lab_routes.py`, `lab.css` token rule)
  - `SECURITY_MODEL.md` gets: v4 in "Cryptographic envelope" and its versions table; a "Cloaked exports" section; a "Cipher Lab" section (in memory, never stored, throttled, not a security boundary).
- Create: `docs/CIPHER_LAB.md`: each cipher, metric and attack with its references, plus the float-determinism note.

- [ ] **Step 1: Write the docs.** Every claim names the test that proves it, matching the existing SECURITY_MODEL style.
- [ ] **Step 2: Check the details.** Run `grep -n "version 3\|IES-CONTEXT-V3" README.md CLAUDE.md docs/SECURITY_MODEL.md`: each remaining mention should be historical. Run `.venv/bin/pytest -q -m "not e2e"`: PASS.
- [ ] **Step 3: Commit**: "Document v4, cloaked exports, and the Cipher Lab".

### Task 20: Browser end-to-end checks and the full gates

**Files:**
- Create: `tests/e2e/test_lab_flow.py`. Its own `live_app` fixture adds `LAB_IMAGE_SIZE=64`.

- [ ] **Step 1: Write the end-to-end tests.**
  - `test_lab_runs_from_the_browser`: register, open `/lab`, run the test card, see the scorecard, and get no console errors.
  - `test_cloak_download_from_the_browser`: upload in end-to-end mode, open the cloak page, download the PNG, and `uncloak` equals the `.ies` download.
- [ ] **Step 2: Run them.** `IES_CHROMIUM_EXECUTABLE=$HOME/Library/Caches/ms-playwright/chromium_headless_shell-1228/chrome-headless-shell-mac-arm64/chrome-headless-shell .venv/bin/pytest -m e2e tests/e2e -q`. Expected: every e2e test passes, including the existing flows, which now write v4.
- [ ] **Step 3: Run the full gates.**
  - `.venv/bin/pytest --cov=image_encryption_system --cov-fail-under=85 -q`
  - `node --test tests/js/*.test.mjs`
  - `.venv/bin/ruff check src tests scripts run.py && .venv/bin/ruff format --check src tests scripts run.py`
  - `.venv/bin/mypy`
  - `.venv/bin/pip-audit --strict -r requirements.txt`, if `pip-audit` is installed; otherwise install it in the venv.
  - Expected: all pass.
- [ ] **Step 4: Take screenshots** with a headless Playwright script kept in the scratchpad: the lab report and the cloak page in light and dark mode, plus a cloaked PNG beside its cover. Read the PNGs to check them.
- [ ] **Step 5: Commit** the e2e tests: "Drive the lab and cloak pages in a real browser".

### Task 21: Push and open the PR

- [ ] **Step 1: Push.** `git -c credential.helper= -c 'credential.helper=!f() { echo username=Sebby1770; echo "password=$(gh auth token --user Sebby1770)"; }; f' push -u origin feat/cipher-lab-cloak-v4`
- [ ] **Step 2: Open the PR.** `GH_TOKEN=$(gh auth token --user Sebby1770) gh pr create --base main --title "Cipher Lab, cloaked exports, and key-committing v4 envelopes" --body-file <scratchpad>/pr-body.md`. The body gives a summary of each part, the gate results and the screenshots' findings, and ends with "🤖 Generated with [Claude Code](https://claude.com/claude-code)".
- [ ] **Step 3: Check nothing is left local.** `git log --branches --not --remotes` prints nothing.

### Optional Task 22: Lab report on the GitHub Pages site

- [ ] Generate `web/lab.html` with `ies lab run --sample test-card --size 256 --seed pages --html web/lab.html` and link it from `web/index.html`. Commit: "Publish a sample Cipher Lab report on the project site".
