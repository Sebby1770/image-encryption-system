# Cipher Lab

The Cipher Lab (`/lab` in the vault, `ies lab` on the command line) encrypts
one image with eleven ciphers, scores each with the statistics the
image-encryption literature reports, and attacks each for real. It exists to
answer a question the literature often gets wrong: does a cipher that scrambles
pixels convincingly, and scores well on those statistics, actually protect the
image?

Nothing in the lab protects vault data. Vault images are sealed with AES-256-GCM
under a fresh key, and new envelopes are key-committing (version 4); see
[SECURITY_MODEL.md](SECURITY_MODEL.md).

## Results at a glance

Measured on the built-in landscape and test card at 256×256
(`ies lab run --sample landscape --size 256 --seed ...`). A full run of all
eleven ciphers takes about 3 seconds; the HTML report is about 1 MB.

| Cipher | Verdict | What decides it |
| --- | --- | --- |
| Arnold cat map | Broken | 1 chosen image recovers the permutation |
| Logistic-map XOR | Broken | 1 chosen image recovers the keystream |
| Hyperchaotic permutation + diffusion | Leaks | Deterministic and unauthenticated; passes every statistic |
| Integer-wavelet scrambling | Broken | 3 chosen images recover the per-subband permutations and masks |
| Walsh-Hadamard mask | Broken | 1 impulse image recovers the sign mask |
| Double random phase encoding | Broken | 1 impulse image recovers the Fourier-plane mask |
| Keyed neural network | Leaks | A fixed codebook on 4×4 patches: the outline survives |
| AES-256-ECB | Leaks | A fixed codebook on 16-byte blocks: the outline survives |
| AES-256-CTR, reused IV | Broken | 1 chosen image recovers the keystream |
| AES-256-GCM (vault v3) | Strong, not key-committing | One forged ciphertext opens under two keys as two pictures |
| AES-256-GCM + commitment (vault v4) | Strong + committing | Nothing in the lab works |

## The ciphers

Every cipher is lossless (`decrypt(encrypt(P)) == P` exactly, tested with
Hypothesis) and derives all of its parameters from one 32-byte lab key, by HKDF
under its own label. Key material is cached per cipher instance.

**Arnold cat map** (`arnold`, permutation). The generalised cat map moves pixel
`(x, y)` to `(x + a·y, b·x + (ab+1)·y) mod S`, iterated `t` times (computed as a
matrix power). Pixel values are untouched, so the histogram survives exactly.
With `a, b ∈ [1, S−1]` and `t ∈ [1, 255]` there are about 2^24 keys at 256 px.

**Logistic-map XOR** (`logistic-xor`, chaos). One orbit of `x ← μx(1−x)`
(`μ ∈ [3.99, 4)`, 1,000 burn-in steps) quantised with the literature's
`floor(x·10^14) mod 256` and XORed onto the image. There is no nonce, so every
image is encrypted with the same keystream.

**Hyperchaotic permutation + diffusion** (`hyperchaos`, chaos). The hyperchaotic
Chen system (`a=36, b=3, c=28, d=−16, |k| ≤ 0.7`, the system of Gao & Chen 2008,
integrated by RK4 over 1,024 lanes stepped together) drives a pixel permutation,
a chaotic S-box, and two rounds of four directional diffusion passes
`y_t = S[x_t ⊕ k1_t ⊕ ((y_{t−1} + k2_t) mod 256)]`. Both refinements were
needed for it to behave like the designs papers report. With XOR-and-add alone,
a small plaintext difference stays in the low bits, and with one round a single
cancellation at the edge of the changed region leaves a whole chain unchanged.
Over 20 keys the one-round version failed NPCR/UACI 14 times; unchanged bytes
swung from 562 to 1,332 where independent bytes give 768 ± 28. The final
version gives 772 ± 27.

**Integer-wavelet scrambling** (`wavelet`, transform + chaos). Two levels of
integer Haar lifting computed mod 256 (a bijection on bytes), then, per channel
and subband, a logistic-driven permutation of the coefficients and a logistic
XOR, then the inverse transform. The transform scatters each pixel's energy, but
it is public.

**Walsh-Hadamard mask** (`wht`, transform). Per channel
`C = H⁻¹(m ⊙ H(P))`, with `H` the unnormalised 2-D Walsh-Hadamard transform and
`m ∈ {±1}` from the key. Exact in float64; the ciphertext is 8× the image.

**Double random phase encoding** (`drpe`, Fourier). The optical-encryption
classic: `C = IFFT2(FFT2(P·e^{i2πφ1})·e^{i2πφ2})` with two random phase masks.
The ciphertext is complex, 16× the image.

**Keyed neural network** (`neural`). Eight additive coupling layers of a keyed
integer network over every 4×4×3 patch: `B ← (B + f(A)) mod 256` with
`f(A) = (W2·σ((W1·A + b1) mod 256) + b2) mod 256`, `σ` a keyed byte permutation
and a keyed shuffle between layers. This is the structure of integer discrete
flows (Hoogeboom et al. 2019): "neural obfuscation" that inverts exactly on any
machine, because no floating point is involved. A GAN-based scheme such as
CycleGAN cannot do that, since it is lossy, which is why the lab does not include one.

**AES-256-ECB** (`aes-ecb`) and **AES-256-CTR with a reused IV**
(`aes-ctr-fixed-iv`): a real block cipher used without a mode, and a real
stream cipher used with one IV for every image.

**AES-256-GCM (vault v3)** (`aes-gcm`) and **AES-256-GCM + commitment (vault v4)**
(`aes-gcm-v4`): the vault's own sealing, with a fresh 96-bit nonce per image;
v4 is built on `crypto.derive_v4_keys` exactly as envelopes are.

## The statistics

Computed on each ciphertext's rendering (`view`; float ciphertexts are shown by
per-channel min-max scaling, as papers do). Per-channel values are reported,
but pass/fail uses statistics pooled over the three channels: testing each
channel separately at the 5% level would fail a perfect cipher about 14% of the
time.

| Metric | Pass rule |
| --- | --- |
| Entropy | at least 7.99 bits per byte (judged from 128 px) |
| Local entropy | within `7.902472 ± 1.96 × 0.008693 / √(blocks)`, 30 random 1,936-pixel blocks per channel |
| Chi-square (255 d.o.f.) | below 293.2478 |
| Neighbour correlation | largest of horizontal, vertical, diagonal `|r|` at most `4/√pairs`, each channel centred on its own mean before pooling |
| NPCR / UACI | NPCR ≥ N\*₀.₀₅ and UACI in the two-sided 5% interval, Wu, Noonan & Agaian (2011) |
| Key sensitivity | the same rule, between encryptions under keys one bit apart (same nonce) |

The critical values are computed, not copied, and checked:

- **NPCR/UACI.** The formulas reproduce Wu, Noonan & Agaian's published table
  at all three significance levels (for 256×256: NPCR\* 99.5693% at α = 0.05,
  UACI in (33.2824%, 33.6447%)). Over 400 runs AES-GCM's NPCR averaged 99.6098%
  (theory 99.6094%) with standard deviation 0.0141 (theory 0.0141), and passed
  94.5% of the time.
- **Chi-square.** 293.2478 is exactly the 95th percentile of chi-square with 255
  degrees of freedom (checked with the regularised incomplete gamma function).
- **Local entropy.** Simulating two million blocks of 1,936 uniform bytes gives
  a mean block entropy of 7.902472 (published: 7.902469317) and a block standard
  deviation of 0.008693. The interval commonly quoted for 30 blocks at α = 0.05,
  (7.901901305, 7.903037329), equals `mean ± z·sd/30`, dividing the deviation by
  the number of blocks rather than its square root; truly random data passes it
  only about 28% of the time. The lab uses `mean ± z·sd/√blocks`, which passes
  94.9% of random block sets.

Every row is a 5% test, so a strong cipher misses one now and then by chance.
That is why verdicts come only from the attacks.

## The attacks

The attacker never sees a key. It has the target ciphertext and may encrypt
images of its choice under the same key: the chosen-plaintext model. The true
image is passed in only to grade the result.

**Structure attack.** Many image ciphers are, under a public transform `T`,
`T(E(P)) = permute(T(P)) ⊕ K`. The attack tries the cheapest explanation first
and confirms each by predicting the ciphertext of one random image:

1. pure XOR: the all-zero image gives `K`;
2. a joint pixel permutation: one image whose R, G, B values are the base-256
   digits of each position's index;
3. both together;
4. per-channel permutations plus XOR: the zero image plus one image per base-256
   digit of the largest region (subbands, under the wavelet transform).

The mod-256 wavelet makes this easy, because any coefficient array is a valid
image to submit. This generalises the analysis of permutation-only ciphers by
Li, Li, Chen, Bourbakis & Lo (2008).

**Impulse attack.** A linear cipher is defined by its impulse response. One
image with a single bright pixel reveals the Walsh-Hadamard sign mask exactly
(`H(C_δ) = 255·m`), or the DRPE Fourier-plane mask up to a constant phase that
cancels when the attacker takes the magnitude (Frauel, Castro, Naughton & Javidi 2007).

**Pattern leak (codebook test).** Does every class of equal plaintext pieces
map to exactly one class of equal ciphertext pieces, wherever it appears? On
the test card at 256 px, ECB scores 1.000 on 16-byte blocks and the neural
network 1.000 on 4×4 patches; every other cipher scores at most 0.036. (Repeated
blocks alone are not the test: Arnold's output of the test card repeats 59% of
its blocks, only because the card has few colours.)

**Determinism.** The same image encrypted twice gives the same ciphertext, so
equal images are recognisable. Only the GCM ciphers draw a fresh nonce.

**Tamper.** One flipped bit in the middle of the ciphertext (for float
ciphertexts, a high mantissa bit). Only the GCM ciphers refuse; every other
cipher decrypts a damaged image without complaint.

**Key-commitment attack.** With two keys of its own, the attacker solves one
GF(2^128) equation so that a single AES-GCM ciphertext carries a tag valid
under both (`lab/gcm.py`; Dodis et al. 2018, Albertini et al. 2022). Against
plain GCM both keys authenticate and each shows a different picture. Against
v4 the same forgery still satisfies AES-GCM, but the commitment names only one
key.

## Verdicts

1. **Broken**: the structure or impulse attack recovered the image exactly.
2. **Leaks**: it acts as a codebook, encrypts identically twice, or decrypts a
   tampered ciphertext without noticing.
3. **Strong, not key-committing**: only the two-key forgery worked.
4. **Strong + committing**: nothing worked.

## Limits

- The attacks are general-purpose. The hyperchaotic cipher resists them, but
  its design family has been broken by attacks tailored to it (Rhouma &
  Belghith 2008), and passing the lab is no evidence of security.
- The chaos and transform ciphers use floating point. They decrypt in the same
  process that encrypted, so platform differences cannot strand data here, but
  in a real system they could.
- A web run processes the upload on the server (in memory, never stored).

## References

- Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg. *How to Abuse and Fix
  Authenticated Encryption Without Key Commitment.* USENIX Security 2022.
- Dodis, Grubbs, Ristenpart, Woodage. *Fast Message Franking: From Invisible
  Salamanders to Encryptment.* CRYPTO 2018.
- Frauel, Castro, Naughton, Javidi. *Resistance of the double random phase
  encryption against various attacks.* Optics Express, 2007.
- Gao, Chen. *A new image encryption algorithm based on hyper-chaos.* Physics
  Letters A, 2008.
- Hoogeboom, Peters, van den Berg, Welling. *Integer Discrete Flows and Lossless
  Compression.* NeurIPS 2019.
- Li, Li, Chen, Bourbakis, Lo. *A general quantitative cryptanalysis of
  permutation-only multimedia ciphers against plaintext attacks.* Signal
  Processing: Image Communication, 2008.
- Preishuber, Hütter, Katzenbeisser, Uhl. *Depreciating motivation and empirical
  security analysis of chaos-based image and video encryption.* IEEE TIFS, 2018.
- Rhouma, Belghith. *Cryptanalysis of a new image encryption algorithm based on
  hyper-chaos.* Physics Letters A, 2008.
- Wu, Noonan, Agaian. *NPCR and UACI randomness tests for image encryption.* 2011.
- Wu, Zhou, Noonan, Agaian, Chen. *Local Shannon entropy measure with statistical
  tests for image randomness.* Information Sciences, 2013.
