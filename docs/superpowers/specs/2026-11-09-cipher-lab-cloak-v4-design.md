# Cipher Lab, Cloak, and key-committing v4 envelopes — design

- **Date:** 2026-11-09
- **Status:** design approved in chat; this spec is awaiting review
- **Branch:** `feat/cipher-lab-cloak-v4` (worktree `~/Desktop/CODE/work/ies-cipher-lab`), from `main` at `ff49212`

## 1. Why

The owner asked to "massively improve" the image encryption system and to involve
four techniques: authenticated block ciphers (AES-GCM) instead of pixel shuffling,
domain transforms (DWT, Walsh–Hadamard, Arnold/Fourier), chaos theory (logistic and
hyperchaotic maps), and deep generative models for visually meaningful encryption or
neural obfuscation, "and much more".

What exists today:

- The vault already does the first item properly. Every image is sealed with
  AES-256-GCM under a fresh 256-bit data key and a random 96-bit nonce, the sealed
  context is authenticated as AAD, and data keys are wrapped with Scrypt + AES-GCM
  or RSA-OAEP-SHA256. End-to-end browser mode is the default.
- The other three techniques are weaker than what the vault has. Chaos-based,
  transform-domain and neural image ciphers have no security proofs, most published
  designs have been broken (often with a handful of chosen images), and none of them
  authenticate. Replacing or layering them into the vault would weaken it or add
  attack surface for no gain.
- There is one real gap: AES-GCM is not key-committing. One ciphertext can be built
  to decrypt, with a valid tag, to two different images under two different keys
  ("invisible salamanders"; Dodis et al. 2018, Albertini et al. 2022, who built such
  image files). In this vault an owner could give two share recipients two different
  keys for the same stored ciphertext, and each would see a different picture.

The project is also one of the owner's featured CV projects, so the improvement
should be substantial and demonstrable, without weakening the real encryption.

## 2. Goals and success criteria

1. **Cipher Lab.** Implement the requested technique families plus baselines as
   lossless lab ciphers; score them with the standard metrics from the image
   encryption literature; break the weak ones with real attacks that output the
   recovered image. Success: every lab cipher round-trips exactly; every attack in
   §4.5 produces the stated outcome on its target and fails on AES-GCM; the published
   NPCR/UACI thresholds for 256×256 are reproduced from the formulas.
2. **Cloak.** Hide the real `.ies` file inside an ordinary-looking PNG using an
   integer wavelet embedding. Success: exact round trip of any `.ies` that fits;
   PSNR ≥ 40 dB against the cover at k ≤ 2 bits on the generated cover; recompression
   or editing is reported as a clean error, never a wrong file.
3. **Envelope version 4.** Key- and context-committing AES-GCM written by the server,
   the browser, the CLI and re-keying. Success: Python and JavaScript open each
   other's v4 envelopes; a key that does not match the commitment is refused before
   AES-GCM runs; a real two-key AES-GCM collision opens under both keys as v3 and
   under only one as v4; every v1 and v3 fixture still decrypts.
4. **No regressions.** Existing tests pass (updated only where they assert that new
   envelopes are version 3); ruff, ruff format, mypy, node tests, coverage ≥ 85%,
   pip-audit, and the Playwright e2e suite pass.

## 3. Non-goals

- Lab ciphers never protect real data and never touch vault rows, blobs or keys.
- No CycleGAN or other trained generative model: it needs PyTorch, a GPU and a
  training set, it is lossy (the original cannot be recovered exactly), and it has
  no security argument. The lab's keyed integer neural cipher covers "neural
  obfuscation" losslessly; the cloak covers "visually meaningful" output securely.
- No post-quantum key wrapping (the installed `cryptography` 46 has no ML-KEM).
- The cloak is not a secret layer and does not resist steganalysis (see §5.5).
- No uncloaking in the browser; the CLI uncloaks.
- No dashboard badge for v3 versus v4 envelopes (possible follow-up).

## 4. Cipher Lab

### 4.1 Layout

```text
src/image_encryption_system/
  iwt.py               # integer Haar lifting, exact; used by cloak.py
  quality.py           # PSNR and SSIM; used by cloak.py and the lab
  covers.py            # generated landscape covers; used by cloak.py and the lab
  cloak.py             # embed/extract an .ies file in a cover PNG
  lab/
    __init__.py        # public API: CIPHER_NAMES, make_cipher(), run_lab(), samples
    imaging.py         # prepare lab images; built-in samples; PNG/JPEG data URIs
    keys.py            # per-cipher parameter derivation (HKDF-SHA256 from a 32-byte key)
    chaos.py           # logistic map; hyperchaotic Chen system (RK4, lane-parallel)
    transforms.py      # modular integer Haar, Walsh–Hadamard, Arnold cat map
    base.py            # Ciphertext, LabCipher, LabDecryptError
    classic.py         # arnold, logistic-xor, hyperchaos, wavelet
    linear.py          # wht, drpe
    neural.py          # neural
    aes.py             # aes-ecb, aes-ctr-fixed-iv, aes-gcm, aes-gcm-v4
    ciphers.py         # registry: CIPHER_NAMES, make_cipher()
    metrics.py         # entropy, local entropy, chi-square, correlation, NPCR/UACI
    attacks.py         # structure, impulse, pattern, determinism, tamper, salamander
    gcm.py             # GF(2^128) arithmetic, GHASH, two-key AES-GCM collision builder
    runner.py          # run_lab(), CipherResult, LabReport (JSON-safe), verdicts
    report.py          # standalone HTML report
  lab_routes.py        # /lab and /images/<id>/cloak, registered from create_app()
```

Lab images are numpy `uint8` arrays of shape `(S, S, 3)`. `S` is a power of two
between 32 and 512 (web: 256; CLI: `--size`, default 256), which satisfies every
cipher's shape constraint (Arnold needs a square, Walsh–Hadamard a power of two, the
neural cipher a multiple of 4, AES block alignment a multiple of 16 bytes).

`imaging.prepare(image_bytes, size)` flattens alpha onto white, converts to RGB,
centre-crops to a square and resizes with Lanczos. Built-in samples are generated
with numpy (no binary assets):

- `test-card`: colour bars, flat discs, ramps and a checkerboard. Flat regions make
  pattern leaks visible.
- `gradient`: a smooth two-axis colour gradient (high pixel correlation).
- `landscape`: the cloak's generated cover (§5.3) with a fixed seed.

### 4.2 Cipher interface

```python
@dataclass(frozen=True)
class Ciphertext:
    payload: bytes                 # exactly what the cipher emits (stored or sent)
    shape: tuple[int, int, int]
    pixels: np.ndarray | None      # uint8 (S,S,3) when the ciphertext body is a byte image
    view: np.ndarray               # uint8 (S,S,3) rendering for display and metrics

class LabCipher:                   # each cipher is a small class built by make_cipher(name, key)
    name, title, family, summary   # e.g. "arnold", "Arnold cat map", "permutation", ...
    randomized: bool               # fresh nonce per encryption
    authenticated: bool
    key_bits: int; key_note: str   # effective key size and why
    transform: str | None          # public transform the structure attack may assume
    linear_domain: str | None      # "wht" or "fourier" for the impulse attack
    def encrypt(self, image, *, nonce: bytes | None = None) -> Ciphertext
    def decrypt(self, ct: Ciphertext) -> np.ndarray   # LabDecryptError if authentication fails
```

`decrypt` reads only `payload` and `shape`, so tampering with `payload` is a real
test. `pixels` is the exact ciphertext body for byte-image ciphers (and the GCM
body); float and complex ciphertexts have `pixels=None` and a `view` made by
per-channel min–max scaling of the real part or magnitude. `nonce` is only used by
the key-sensitivity metric, which must hold the nonce fixed.

Keys are 32 random bytes per run (or `SHA-256(seed)` with `--seed`, for reproducible
reports). Parameters are derived with HKDF-SHA256 (`info = b"IES-LAB/" + name`).
Chaotic parameters are mapped into their valid ranges from 56-bit slices of HKDF
output. Keystreams and permutations depend only on the key and size, so each cipher
instance caches them; later encryptions are fast.

### 4.3 The 11 ciphers

| Name | Family | Construction | Ciphertext |
| --- | --- | --- | --- |
| `arnold` | permutation | Generalised cat map `(x,y) → (x + a·y, b·x + (ab+1)·y) mod S`, `t` iterations computed as a matrix power; one joint permutation of pixel positions. `a, b ∈ [1, S−1]`, `t ∈ [1, 255]` | uint8 |
| `logistic-xor` | chaos | Logistic map `x ← μx(1−x)`, `μ ∈ [3.99, 4)`, `x0 ∈ (0.1, 0.9)`, 1,000 burn-in steps; keystream byte `⌊x·10^14⌋ mod 256`; XOR with the image; no nonce | uint8 |
| `hyperchaos` | chaos | Hyperchaotic Chen system (`a=36, b=3, c=28, d=−16, k ∈ [−0.7, 0.7]`, RK4, 256 lanes stepped together) drives a joint pixel permutation (argsort) and four directional diffusion passes (rows forward, columns forward, rows backward, columns backward), each `y_t = x_t ⊕ k1_t ⊕ ((y_{t−1} + k2_t) mod 256)` over rows of interleaved RGB. Follows the Gao & Chen (2008) design family | uint8 |
| `wavelet` | transform + chaos | Two-level integer Haar lifting computed mod 256 (a bijection on bytes), then, per channel and subband, a logistic-driven permutation of coefficients and a logistic XOR; inverse transform | uint8 |
| `wht` | transform | Per channel `C = H⁻¹(m ⊙ H(P))`, `H` the unnormalised 2-D Walsh–Hadamard transform, `m ∈ {±1}^{S×S}` from the key. Exact in float64 (denominator `S²`) | float64 (8×) |
| `drpe` | transform (Fourier) | Double random phase encoding: `C = IFFT2(FFT2(P·e^{i2πφ1})·e^{i2πφ2})`, `φ1, φ2` uniform from the key, `P` scaled to [0, 1] | complex128 (16×) |
| `neural` | neural | Keyed integer neural network on 4×4×3 patches (48 bytes): 8 additive coupling layers `B ← (B + f(A)) mod 256`, `f(A) = (W2·σ((W1·A + b1) mod 256) + b2) mod 256`, `σ` a keyed byte permutation, `W1` 32×24 and `W2` 24×32 integer weights, a keyed shuffle of the 48 positions between layers. Exactly invertible, integer-only (portable), deterministic (integer discrete flows, Hoogeboom et al. 2019) | uint8 |
| `aes-ecb` | block cipher | AES-256 in ECB mode over the raw RGB bytes | uint8 |
| `aes-ctr-fixed-iv` | stream cipher | AES-256-CTR with one key-derived IV reused for every image | uint8 |
| `aes-gcm` | vault v3 | AES-256-GCM, random 96-bit nonce per encryption; payload `nonce ‖ body ‖ tag` | uint8 body |
| `aes-gcm-v4` | vault v4 | The vault's v4 construction from `crypto.py` (§6): HKDF subkeys and a 32-byte key commitment; payload `nonce ‖ commitment ‖ body ‖ tag` | uint8 body |

Declared effective key size (`key_bits`, shown with its note): `arnold` ≈ 24 bits
(brute-forceable in seconds); `logistic-xor` and `wavelet` ≈ 100 bits (two IEEE
doubles in restricted ranges); the rest 256 bits. The impulse and structure attacks
make key size irrelevant where they apply.

### 4.4 Metrics

Computed on `view` per channel, reported per channel and as a mean, each with a
pass rule. `N = S·S`.

| Metric | Definition | Pass |
| --- | --- | --- |
| Entropy | Shannon entropy of the 256-bin histogram | ≥ 7.99 bits (for `S ≥ 128`) |
| Local entropy | Mean entropy of 30 randomly chosen, non-overlapping, contiguous row-major runs of 1,936 pixels (Wu et al. 2013; the statistic's null distribution does not depend on block shape); only when `N ≥ 58,080` | within (7.901901305, 7.903037329), α = 0.05 |
| χ² histogram | `Σ (o − N/256)² / (N/256)`, 255 d.o.f. | < 293.2478 (α = 0.05) |
| Correlation | Pearson r over all horizontal, vertical and diagonal neighbour pairs | `|r| ≤ 4/√pairs` for each direction |
| NPCR / UACI | One pixel of the plaintext changed by +1 mod 256, two encryptions with the same key (randomised ciphers keep fresh nonces, as deployed) | NPCR ≥ N\*₀.₀₅ and UACI ∈ (U\*⁻, U\*⁺)₀.₀₅, critical values from Wu, Noonan & Agaian (2011), computed for `N` with `statistics.NormalDist` |
| Key sensitivity | NPCR between encryptions under `K` and `K` with its last bit flipped (fixed nonce) | same NPCR rule |
| Round trip | `decrypt(encrypt(P)) == P` | exact |
| Speed | Cold first encryption (includes keystream generation), MB/s | informational |
| Expansion | `len(payload) / (3N)` | informational |

PSNR and SSIM (sliding uniform 8×8 windows, the usual constants) live in
`quality.py`, shared by the cloak and the lab. For 256×256, the formulas must give
NPCR\* = 99.5693% and UACI ∈ (33.2824%, 33.6447%), matching the published tables.

### 4.5 Attacks

Each attack returns `applicable`, `success`, `queries` (chosen images the winning
hypothesis needed, excluding its verification), `oracle_calls` (all encryptions made),
a one-line finding, and the attacker's recovered image when there is one. The
attacker has the target ciphertext and an encryption oracle under the same key, never
the key or the target plaintext. Success means the recovered image equals the
target exactly.

1. **Structure attack (permutation + XOR, chosen plaintext).** Under the cipher's
   declared public transform `T` (identity unless `transform` says otherwise), try
   hypotheses in order, confirming each by predicting the ciphertext of one random
   image:
   1. pure XOR: `K = T(E(0))` from the all-zero image;
   2. pure joint permutation: one image whose R, G, B values are the base-256 digits
      of each position's index;
   3. joint permutation + XOR: both of the above;
   4. per-channel permutation + XOR: the zero image plus `⌈log₂₅₆ n⌉` digit images,
      where `n` is the size of the largest set the permutation acts on (all pixels
      for the identity transform, the largest subband for the wavelet).

   Applicable to byte-image ciphertexts. Expected at 256×256: `arnold` broken with 1
   image, `logistic-xor` and `aes-ctr-fixed-iv` with 1, `wavelet` with 3 (zero image
   plus two digit images for its 128×128 subbands); `hyperchaos`, `neural`,
   `aes-ecb`, `aes-gcm`, `aes-gcm-v4` not broken.
2. **Impulse attack (linear ciphers, chosen plaintext).** Encrypt a one-pixel impulse
   image. For `wht`, `H(C_δ) = m` exactly; for `drpe`, `FFT2(C_δ)` is `e^{i2πφ2}` up
   to a constant phase, and `|IFFT2(FFT2(C)·conj(M2))|` recovers the plaintext.
   Expected: both broken with 1 image, exact after rounding.
3. **Pattern leak.** Fraction of repeated 16-byte blocks and of repeated 4×4 patches
   in the ciphertext of the `test-card` probe, against the plaintext's. Leaks if
   above 1%. Expected: `aes-ecb` and `neural` leak; the cipher view is the evidence.
4. **Determinism.** Encrypt the same image twice. Deterministic ciphers leak equality
   (not IND-CPA). Expected: everything except the two GCM ciphers.
5. **Tamper.** Flip one bit in the middle of the ciphertext body (for float
   ciphertexts, a high-order mantissa bit, so the change is not lost to rounding)
   and decrypt. Pass only if decryption refuses. Expected: only the two GCM ciphers refuse; the others return a
   silently damaged image, shown with the share of pixels changed.
6. **Key-commitment ("invisible salamander") attack.** For authenticated ciphers:
   with two attacker-chosen keys, solve one ciphertext block in GF(2^128) so a single
   ciphertext carries a tag valid under both. The top half is built to decrypt to the
   target under key 1 and the bottom half to the test card under key 2. Expected:
   succeeds on `aes-gcm` (both keys authenticate, two different pictures); fails on
   `aes-gcm-v4` (the second key fails the commitment); not applicable to
   unauthenticated ciphers, which "decrypt" under any key.

The page states the main lesson explicitly: `hyperchaos` passes every statistical
test and is still deterministic and unauthenticated, and its design family has been
broken with chosen plaintexts in the literature (Rhouma & Belghith 2008). Statistics
are necessary, not sufficient (Preishuber et al. 2018).

Verdict per cipher: **Broken** (an attack recovered the image), **Leaks** (pattern,
determinism, silent tampering or key commitment failed), **Strong** (`aes-gcm`, with
"not key-committing"), **Strong + committing** (`aes-gcm-v4`).

### 4.6 Report and surfaces

- `run_lab(image, *, ciphers=None, key=None) -> LabReport`. `LabReport.to_dict()` is
  JSON-safe. Images are PNG for the plaintext and recoveries and JPEG (quality 85)
  for noise-like cipher views, keeping a full web report around 1–2 MB.
- **Web.** `GET /lab` shows the form: a built-in sample or an upload (checked by
  `web._inspect_image` with the vault's allow-list and pixel ceiling, prepared in
  memory, never stored or logged), plus cipher checkboxes. `POST /lab` runs the lab
  and renders `lab_report.html`: a scorecard table (✓/✗/n/a with the measured value),
  the image grid (plaintext, cipher view, attacker's recovery, tampered decryption,
  salamander pair) and 64-bin SVG histograms. Server-rendered, no JavaScript.
  Login required. Throttled per account (`LAB_RATE_LIMIT` = 6 per
  `LAB_RATE_WINDOW_SECONDS` = 600, the app's existing throttle naming). The global
  CSRF hook already covers the POST.
- **CLI.** `ies lab list`; `ies lab run [--image PATH | --sample NAME] [--size N]
  [--cipher NAME ...] [--seed TEXT] [--json PATH] [--html PATH]` prints a text
  scorecard and optionally writes JSON and a standalone HTML report (same scorecard
  partial, CSS inlined).
- Budget: a full 11-cipher run at 256×256 in under 8 s on a laptop (target 3–5 s).
  Tests run at 32–64 px; one test runs at 256 to exercise local entropy.

## 5. Cloak: visually meaningful export

### 5.1 Format

- The cover is RGB 8-bit with even width and height (an odd edge is cropped by one
  pixel). Its pixels are clamped to `[m, 255 − m]` with margin `m(k) = 2, 5, 10` for
  `k = 1, 2, 3`. These margins are the worst-case pixel change for a one-level 2-D
  integer Haar inverse when each detail coefficient moves by at most `2^k − 1`, so no
  stego pixel can leave [0, 255]; `cloak()` also asserts it. Clamping touches only
  near-black and near-white pixels (scaling the whole range instead would cost about
  8 dB of PSNR on its own), and generated covers are drawn inside [10, 245], so they
  are never clamped. Expected distortion at full capacity: about 53, 47 and 40 dB
  PSNR for `k = 1, 2, 3`.
- Per channel, a one-level integer Haar (S-transform) lifting (`iwt.forward` /
  `iwt.inverse`, int16). Slots are every LH, HL and HH coefficient of every channel,
  in canonical order (channel, subband, row-major): `M = 2.25·W·H` slots.
- Slot `s` of the stream maps to coefficient `(a·s + b) mod M`, with `a` coprime to
  `M` and `a, b` fixed functions of `M`, which spreads changes evenly over the image.
- Header, 44 bytes, embedded at 1 bit per slot in the first 352 slots:
  `b"IESK" ‖ version (1) ‖ k (1) ‖ reserved (2) ‖ payload length (uint32 BE) ‖ SHA-256(payload)`.
- The payload follows at `k` bits per slot (MSB first, last group zero-padded).
- Header and payload bytes are XORed with a ChaCha20 keystream under the public key
  `SHA-256(b"IES-CLOAK-V1")`, so the embedded bits look uniform rather than
  JSON-shaped. This is whitening, not encryption.
- Embedding sets the low `k` bits: `c' = (c & ~(2^k − 1)) | v`.
- Output: PNG, RGB, no metadata.
- Capacity: `⌊(M − 352)·k / 8⌋` bytes.

### 5.2 Extraction and errors

`uncloak(png_bytes)` refuses anything that is not a PNG within the pixel ceiling
(checked from the header before decoding), converts to RGB, runs the forward lifting,
reads and unwhitens the header, checks the magic, version, `k ∈ {1,2,3}`, and the
length against the capacity and a 64 MiB ceiling before allocating, then reads the
payload and checks its SHA-256. Every failure is a `CloakError` with a plain message
("This image does not carry a vault file, or it was recompressed or edited.").
The extracted bytes are an ordinary `.ies` and go through `validate_envelope()` like
any other.

### 5.3 Covers

- **Custom cover.** Any allow-listed image (validated like an upload; its metadata is
  dropped because only pixels are kept). With `bits=auto`, the smallest `k` whose
  capacity fits; if none fits at `k = 3`, the cover is upscaled (Lanczos, aspect kept)
  to the smallest size that fits at `k = 2`, up to `CLOAK_MAX_PIXELS` (24 MP).
- **Generated cover.** A deterministic procedural landscape from a seed and a palette
  (`dusk`, `alpine`, `desert`, `ocean`): sky gradient, soft sun, three fractal
  value-noise ridgelines with atmospheric perspective, foreground hills, and light
  grain. 3:2 aspect, at least 960×640, sized to fit at `k = 2` by default. The lab's
  `landscape` sample uses the same generator.
- `cloak()` returns the PNG plus a report: cover size, `k`, capacity used, PSNR and
  SSIM against the cover.

### 5.4 Surfaces

- **Web.** `GET /images/<id>/cloak` (owner only) shows the image name, payload size
  and options: generated cover (palette, optional seed) or an uploaded cover, and
  `k` (auto, 1, 2, 3). `POST /images/<id>/cloak` packs the same bytes as the `.ies`
  download (`pack_ies(ciphertext, metadata)`), cloaks them and returns
  `<name>.cloaked.png` with `Cache-Control: no-store`. It needs only ciphertext, so
  it works for end-to-end images without touching a key. Throttled per account
  (`CLOAK_RATE_LIMIT` = 10 per `CLOAK_RATE_WINDOW_SECONDS` = 600). Not audited, like
  the `.ies` download. The dashboard gets one "Cloak" link per owned image.
- **CLI.** `ies cloak IN.ies -o OUT.png [--cover IMG] [--bits auto|1|2|3]
  [--palette NAME] [--seed TEXT]` prints the report; `ies uncloak IN.png -o OUT.ies`;
  `decrypt`, `inspect`, `verify`, `hash` and `rewrap` accept a cloaked PNG wherever
  they accept an `.ies` (detected by the PNG signature).

### 5.5 What the cloak does and does not do

It hides from a casual viewer that an image carries a vault file. It adds no
confidentiality or integrity (the AES-GCM envelope inside provides both), its
positions and header are public, steganalysis can detect it, and any lossy
recompression, resize or edit destroys it, which is detected. This goes in
`docs/SECURITY_MODEL.md`.

## 6. Envelope version 4

- Constants: `ENVELOPE_V4 = 4`, `CURRENT_ENVELOPE_VERSION = 4`, supported
  `{1, 3, 4}`; AAD prefix `b"IES-CONTEXT-V4\0"`; `V4_ENVELOPE_KEYS = V3 keys ∪
  {"key_commitment"}`.
- Subkeys, from the 32-byte data key `DK`, nonce `N` and AAD `A`:
  - `image_key = HKDF-SHA256(IKM=DK, salt=b"IES-V4", info=b"IES-V4\0image-key", L=32)`
  - `commitment = HKDF-SHA256(IKM=DK, salt=b"IES-V4", info=b"IES-V4\0key-commitment\0" ‖ N ‖ SHA-256(A), L=32)`
- Encrypt: as v3, but the AAD uses the v4 prefix, AES-256-GCM runs under
  `image_key`, and `key_commitment` (canonical base64 of 32 bytes) is stored in the
  envelope.
- Decrypt: after `validate_envelope()`, the digest check and the key unwrap, recompute
  the commitment and compare in constant time; a mismatch raises
  `CryptoError("This key does not match the image's key commitment.")` before AES-GCM
  runs. Then GCM under `image_key`.
- Validation: v4 is closed like v3; `key_commitment` is required, canonical base64,
  32 bytes; the context rules are the same.
- Effect: HKDF/HMAC-SHA256 collision resistance means one envelope opens under at most
  one data key, and the commitment also binds the nonce and the sealed context. Shares
  and links wrap the same data key, so they inherit it.
- Who writes v4: server-mode uploads, browser uploads, re-keys, and `ies encrypt`.
  Share, link and rotate re-wrap the key and leave the commitment valid.
- Who accepts what: decryption opens v1, v3 and v4; restore accepts all three; the
  server requires v4 for new browser uploads and for re-keys ("Reload the page to get
  the current encryption code." for a stale page sending v3), so re-keying upgrades
  an older image to v4. `_check_sealed_context()` and the restore checks treat v4 like
  v3.
- Browser: `ies-crypto.js` gets the same construction with WebCrypto HKDF
  (`deriveBits`) and a constant-time byte comparison; `validateEnvelope` and
  `decryptImage` accept v3 and v4. `tests/test_browser_crypto.py` checks both
  directions.
- CLI: `ies inspect` prints whether an envelope is key-committing.

## 7. Shared changes

- `numpy>=1.26` in `pyproject.toml` dependencies and `requirements.txt` (wheels for
  Python 3.10–3.13).
- New templates: `lab.html`, `lab_report.html`, `_lab_scorecard.html`,
  `lab_report_standalone.html` (CLI), `cloak.html`. No inline script, style or `on*`
  handler (existing test).
- New stylesheet `static/css/lab.css`, loaded only by the lab and cloak pages. It uses
  the tokens defined in `styles.css` and defines no colours; `tests/test_styles.py`
  is extended to check every CSS file.
- `lab_routes.register(app, store)` is called once from `create_app()`. Two throttles
  join the existing table. One "Lab" link in `layout.html`, one "Cloak" link per
  owned image in `dashboard.html`. Keeping the rest in new files limits conflicts
  with the uncommitted frontend redesign on another branch.
- Docs: `README.md`, `CHANGELOG.md`, `docs/SECURITY_MODEL.md` (v4, cloak, lab),
  `CLAUDE.md` (layout, envelope table, `lab_routes.py`), and a new
  `docs/CIPHER_LAB.md` explaining each cipher, metric and attack with references.
- Stretch, if time allows: a pre-rendered lab report on the GitHub Pages site
  (`web/lab.html`, linked from `web/index.html`).

## 8. Testing

- **Lab ciphers:** exact round trip for all 11 on every sample at 32 and 64 px, plus a
  Hypothesis property over random images; a wrong key does not decrypt; GCM ciphers
  raise on tamper.
- **Metrics:** entropy of a constant image is 0 and of uniform noise ≥ 7.99;
  correlation of the gradient > 0.9 and of noise within the bound; χ² of noise passes;
  NPCR/UACI critical values for 256×256 equal the published values to four decimals;
  `PSNR(x, x) = inf`, `SSIM(x, x) = 1`.
- **Attacks:** each expected outcome in §4.5, asserted exactly (recovered image equal
  to the target, query counts as stated); the salamander ciphertext is accepted by
  `cryptography`'s own `AESGCM.decrypt` under both keys.
- **Report and web:** `run_lab` end to end at 64 px; JSON round-trips through
  `json.dumps`; `/lab` requires login, CSRF and the throttle; samples and uploads
  work; non-images, oversized images and decompression bombs get clean errors.
- **Cloak:** Hypothesis round trip over payload sizes, `k`, and covers including
  all-black and all-white (margin checks); capacity errors; JPEG recompression and a
  one-pixel edit give `CloakError`; PSNR ≥ 40 dB at `k ≤ 2` on the generated cover;
  generated covers are deterministic; hostile PNGs (huge declared size, truncated,
  palette, 16-bit, not a PNG) are refused cleanly; web route owner-only, CSRF,
  throttle, end-to-end assets, custom covers; CLI `cloak`, `uncloak`, and `decrypt`
  of a cloaked PNG.
- **v4:** Python⇄JavaScript round trips; commitment mismatch refused before GCM;
  two-key collision regression (v3 opens under both keys, v4 under one); v1/v3
  fixtures still decrypt; server refuses v3 browser uploads and re-keys; re-key turns
  a v3 image into v4; restore accepts v3 and v4; the byte-flip property test covers
  v4.
- Full gates: `pytest` (with coverage ≥ 85%), `node --test tests/js/*.test.mjs`,
  `ruff check`, `ruff format --check`, `mypy`, `pip-audit -r requirements.txt`,
  Playwright e2e (existing flows now write v4; new smoke tests for `/lab` and the
  cloak download), and screenshots of the lab report and cloak page in light and
  dark mode.

## 9. Delivery

Order (each depends on the previous): v4 envelopes → cloak (with `iwt.py` and the
cover generator) → lab core → lab web/CLI/report → docs. One commit per piece, one PR
to `main` on `Sebby1770/image-encryption-system`, pushed as Sebby1770.

## 10. Risks

- **Merge conflicts with the uncommitted frontend redesign** (`web.py`,
  `layout.html`, `dashboard.html`, `styles.css`): limited to a few small hunks by
  keeping new behaviour in new files.
- **Stale browser code** sending v3 after deploy: refused with a clear reload message.
- **Test runtime:** lab tests run at small sizes; only one runs at 256.
- **Float determinism** (chaos, WHT, DRPE): lab-only and decrypted in the same process,
  so platform differences cannot strand data. Noted in `docs/CIPHER_LAB.md`.

## References

- Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg. *How to Abuse and Fix
  Authenticated Encryption Without Key Commitment.* USENIX Security 2022.
- Dodis, Grubbs, Ristenpart, Woodage. *Fast Message Franking: From Invisible
  Salamanders to Encryptment.* CRYPTO 2018.
- Li, Li, Chen, Bourbakis, Lo. *A general quantitative cryptanalysis of
  permutation-only multimedia ciphers against plaintext attacks.* Signal Processing:
  Image Communication, 2008.
- Gao, Chen. *A new image encryption algorithm based on hyper-chaos.* Physics
  Letters A, 2008. Rhouma, Belghith. *Cryptanalysis of a new image encryption
  algorithm based on hyper-chaos.* Physics Letters A, 2008.
- Frauel, Castro, Naughton, Javidi. *Resistance of the double random phase encryption
  against various attacks.* Optics Express, 2007.
- Wu, Noonan, Agaian. *NPCR and UACI randomness tests for image encryption.* 2011.
- Wu, Zhou, Noonan, Agaian, Chen. *Local Shannon entropy measure with statistical
  tests for image randomness.* Information Sciences, 2013.
- Preishuber, Hütter, Katzenbeisser, Uhl. *Depreciating motivation and empirical
  security analysis of chaos-based image and video encryption.* IEEE TIFS, 2018.
- Hoogeboom, Peters, van den Berg, Welling. *Integer Discrete Flows and Lossless
  Compression.* NeurIPS 2019.
