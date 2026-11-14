"""Attacks on the lab ciphers, each producing the attacker's recovered image.

The attacker never gets a key. It sees the target ciphertext and may encrypt
images of its choice under the same key (an encryption oracle): the
chosen-plaintext model under which every cipher here is judged. The truth is
passed in only to grade the result.

- **Structure attack.** Many image ciphers are, under a public transform T,
  ``T(E(P)) = permute(T(P)) XOR K``. The attack tries the cheapest explanation
  first, and confirms each by predicting the ciphertext of one random image:
  pure XOR (one all-zero image gives K), a joint pixel permutation (one image
  whose RGB values are the base-256 digits of each position), both together,
  and per-channel permutations plus XOR (the zero image plus one image per
  base-256 digit of the largest region). This follows the general analysis of
  permutation-only ciphers by Li, Li, Chen, Bourbakis and Lo (2008).
- **Impulse attack.** A linear cipher is determined by its impulse response:
  one chosen single-pixel image reveals the Walsh-Hadamard sign mask exactly,
  or the Fourier-plane phase mask of double random phase encoding up to a
  constant phase that cancels (Frauel, Castro, Naughton & Javidi, 2007).
- **Pattern leak.** Equal blocks or patches that stay equal (ECB, the neural
  cipher) give the picture's outline away.
- **Determinism.** A cipher that encrypts the same image the same way twice
  leaks equality between images.
- **Tamper.** One flipped ciphertext bit: refused, or silently decrypted?
- **Key-commitment attack.** With two keys of its own, the attacker builds one
  AES-GCM ciphertext that authenticates under both ("invisible salamanders").
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from . import keys, transforms
from .base import Ciphertext, Image, LabCipher, LabDecryptError
from .ciphers import make_cipher
from .gcm import forge_two_key_ciphertext

ATTACKS = ("structure", "impulse", "pattern", "determinism", "tamper", "salamander")
LABELS = {
    "structure": "Chosen-plaintext structure attack",
    "impulse": "Impulse (linearity) attack",
    "pattern": "Pattern leak",
    "determinism": "Determinism",
    "tamper": "Tamper test",
    "salamander": "Key-commitment attack",
}
PATTERN_FLOOR = 0.01  # the probe must itself repeat


@dataclass(frozen=True)
class AttackResult:
    key: str
    label: str
    applicable: bool
    success: bool
    queries: int
    oracle_calls: int
    finding: str
    recovered: Image | None = None
    extra: Image | None = None


def _result(key: str, **fields: object) -> AttackResult:
    defaults: dict[str, object] = {"queries": 0, "oracle_calls": 0}
    return AttackResult(key=key, label=LABELS[key], **(defaults | fields))  # type: ignore[arg-type]


class _Oracle:
    """Encrypts chosen images under the target's key, counting distinct requests."""

    def __init__(self, cipher: LabCipher) -> None:
        self._cipher = cipher
        self._seen: dict[bytes, Ciphertext] = {}

    @property
    def calls(self) -> int:
        return len(self._seen)

    def __call__(self, image: Image) -> Ciphertext:
        fingerprint = image.tobytes()
        if fingerprint not in self._seen:
            self._seen[fingerprint] = self._cipher.encrypt(image)
        return self._seen[fingerprint]


# ---------------------------------------------------------------------------
# Structure attack


Regions = list[tuple[slice, slice]]


@dataclass(frozen=True)
class _Domain:
    """The public transform the attack assumes, and the regions it permutes within."""

    name: str
    forward: Callable[[Image], Image]
    inverse: Callable[[Image], Image]
    regions: Regions


def _domain(cipher: LabCipher, size: int) -> _Domain:
    if cipher.transform == "haar-mod256":
        levels = int(getattr(cipher, "levels", 2))

        def forward(image: Image) -> Image:
            return np.stack(
                [transforms.haar_mod256_forward(image[..., c], levels) for c in range(3)], axis=-1
            )

        def inverse(coefficients: Image) -> Image:
            return np.stack(
                [transforms.haar_mod256_inverse(coefficients[..., c], levels) for c in range(3)],
                axis=-1,
            )

        return _Domain(
            "integer-wavelet", forward, inverse, transforms.haar_mod256_subbands(size, levels)
        )
    return _Domain("pixel", lambda x: x, lambda x: x, [(slice(0, size), slice(0, size))])


def _region_size(region: tuple[slice, slice]) -> int:
    rows, cols = region
    return int((rows.stop - rows.start) * (cols.stop - cols.start))


def _digits_image(size: int, regions: Regions, digit_for_channel: Callable[[int], int]) -> Image:
    """Coefficients where each region's position index is spelled out in base 256."""
    coefficients = np.zeros((size, size, 3), dtype=np.uint8)
    for rows, cols in regions:
        shape = (rows.stop - rows.start, cols.stop - cols.start)
        index = np.arange(shape[0] * shape[1], dtype=np.int64).reshape(shape)
        for channel in range(3):
            digit = digit_for_channel(channel)
            coefficients[rows, cols, channel] = (index // 256**digit) % 256
    return coefficients


def _same_digit(digit: int) -> Callable[[int], int]:
    """Every channel spells the same base-256 digit of the position index."""
    return lambda _channel: digit


# A permutation per (region, channel), in gather form: output j takes source order[j].
Orders = list[list[NDArray[np.int64]]]


def _decode(values: list[Image], regions: Regions, joint: bool) -> Orders | None:
    """Read each region's permutation back from the digit images (None if it is not one)."""
    orders: Orders = []
    for rows, cols in regions:
        count = _region_size((rows, cols))
        per_channel = []
        for channel in range(3):
            if joint:
                digits = [values[0][rows, cols, c].astype(np.int64).ravel() for c in range(3)]
            else:
                digits = [v[rows, cols, channel].astype(np.int64).ravel() for v in values]
            order = sum(d * 256**i for i, d in enumerate(digits))
            if int(np.max(order)) >= count or np.unique(order).size != count:
                return None
            per_channel.append(order)
        orders.append(per_channel)
    return orders


def _apply(coefficients: Image, regions: Regions, orders: Orders | None, mask: Image) -> Image:
    out = coefficients.copy()
    if orders is not None:
        for (rows, cols), per_channel in zip(regions, orders, strict=True):
            for channel, order in enumerate(per_channel):
                flat = coefficients[rows, cols, channel].ravel()
                out[rows, cols, channel] = flat[order].reshape(out[rows, cols, channel].shape)
    return out ^ mask


def _undo(coefficients: Image, regions: Regions, orders: Orders | None, mask: Image) -> Image:
    unmasked = coefficients ^ mask
    if orders is None:
        return unmasked
    out = unmasked.copy()
    for (rows, cols), per_channel in zip(regions, orders, strict=True):
        for channel, order in enumerate(per_channel):
            flat = unmasked[rows, cols, channel].ravel()
            restored = np.empty_like(flat)
            restored[order] = flat
            out[rows, cols, channel] = restored.reshape(out[rows, cols, channel].shape)
    return out


def structure_attack(cipher: LabCipher, target: Ciphertext, *, truth: Image) -> AttackResult:
    """Break permutation-and-XOR ciphers with a handful of chosen images."""
    if target.pixels is None:
        return _result(
            "structure",
            applicable=False,
            success=False,
            finding="Needs a byte-image ciphertext; this one is floating point.",
        )
    size = target.shape[0]
    domain = _domain(cipher, size)
    oracle = _Oracle(cipher)

    def encrypt_coefficients(coefficients: Image) -> Image:
        pixels = oracle(domain.inverse(coefficients)).pixels
        assert pixels is not None
        return domain.forward(pixels)

    zero = np.zeros(target.shape, dtype=np.uint8)
    check = np.random.default_rng(7).integers(0, 256, target.shape, dtype=np.uint8)
    largest = max(_region_size(region) for region in domain.regions)
    digits = max(1, math.ceil(math.log(largest, 256)))
    joint_image = _digits_image(size, domain.regions, lambda channel: channel)

    hypotheses: list[tuple[str, int, Callable[[], tuple[Orders | None, Image] | None]]] = []

    def pure_xor() -> tuple[Orders | None, Image] | None:
        return None, encrypt_coefficients(zero)

    def joint_permutation(with_xor: bool) -> tuple[Orders | None, Image] | None:
        mask = encrypt_coefficients(zero) if with_xor else zero
        orders = _decode([encrypt_coefficients(joint_image) ^ mask], domain.regions, joint=True)
        return None if orders is None else (orders, mask)

    def channel_permutation() -> tuple[Orders | None, Image] | None:
        mask = encrypt_coefficients(zero)
        values = [
            encrypt_coefficients(_digits_image(size, domain.regions, _same_digit(i))) ^ mask
            for i in range(digits)
        ]
        orders = _decode(values, domain.regions, joint=False)
        return None if orders is None else (orders, mask)

    hypotheses = [
        ("XOR with a fixed keystream", 1, pure_xor),
        ("a fixed pixel permutation", 1, lambda: joint_permutation(False)),
        ("a fixed permutation plus a fixed XOR", 2, lambda: joint_permutation(True)),
        ("a per-channel permutation plus XOR", 1 + digits, channel_permutation),
    ]
    for description, queries, solve in hypotheses:
        solved = solve()
        if solved is None:
            continue
        orders, mask = solved
        predicted = domain.inverse(_apply(domain.forward(check), domain.regions, orders, mask))
        if not np.array_equal(oracle(check).pixels, predicted):
            continue
        recovered = domain.inverse(
            _undo(domain.forward(target.pixels), domain.regions, orders, mask)
        )
        exact = bool(np.array_equal(recovered, truth))
        where = "" if domain.name == "pixel" else f" in the {domain.name} domain"
        return _result(
            "structure",
            applicable=True,
            success=exact,
            queries=queries,
            oracle_calls=oracle.calls,
            finding=(
                f"Broken with {queries} chosen image{'s' if queries > 1 else ''}: the cipher is "
                f"{description}{where}."
                if exact
                else "The structure was found, but the recovered image does not match."
            ),
            recovered=recovered,
        )
    return _result(
        "structure",
        applicable=True,
        success=False,
        oracle_calls=oracle.calls,
        finding=(
            f"No permutation-plus-XOR structure explains it ({oracle.calls} chosen images tried)."
        ),
    )


# ---------------------------------------------------------------------------
# Impulse attack


def _clip(planes: NDArray[np.float64]) -> Image:
    values = np.nan_to_num(planes, nan=0.0, posinf=255.0, neginf=0.0)
    return np.ascontiguousarray(np.moveaxis(np.clip(np.rint(values), 0, 255), 0, -1)).astype(
        np.uint8
    )


def impulse_attack(cipher: LabCipher, target: Ciphertext, *, truth: Image) -> AttackResult:
    """Recover a linear cipher's mask from the ciphertext of one single-pixel image."""
    coefficients = getattr(cipher, "coefficients", None)
    if cipher.linear_domain not in {"wht", "fourier"} or coefficients is None:
        return _result(
            "impulse",
            applicable=False,
            success=False,
            finding="Not a linear transform-domain cipher.",
        )
    size = target.shape[0]
    impulse = np.zeros(target.shape, dtype=np.uint8)
    impulse[0, 0] = 255
    oracle = _Oracle(cipher)
    response = coefficients(oracle(impulse))
    observed = coefficients(target)
    if cipher.linear_domain == "wht":
        # H(C_impulse) = 255 * mask: the signs are the mask.
        mask = np.sign(np.asarray(transforms.walsh_hadamard_2d(response), dtype=np.float64))
        planes = np.asarray(
            transforms.walsh_hadamard_2d(mask * transforms.walsh_hadamard_2d(observed)),
            dtype=np.float64,
        ) / (size * size)
        how = "its Walsh-Hadamard sign mask"
    else:
        # FFT2(C_impulse) is the Fourier-plane mask times a constant phase.
        spectrum = np.fft.fft2(response, axes=(-2, -1))
        phase = spectrum / np.maximum(np.abs(spectrum), 1e-300)
        restored = np.fft.ifft2(
            np.fft.fft2(observed, axes=(-2, -1)) * np.conj(phase), axes=(-2, -1)
        )
        planes = 255.0 * np.abs(restored)
        how = "its Fourier-plane phase mask (the input mask cancels in |.|)"
    recovered = _clip(planes)
    exact = bool(np.array_equal(recovered, truth))
    return _result(
        "impulse",
        applicable=True,
        success=exact,
        queries=1,
        oracle_calls=oracle.calls,
        finding=(
            f"Broken with 1 chosen image: a single bright pixel reveals {how}."
            if exact
            else "The impulse response did not recover the image."
        ),
        recovered=recovered,
    )


# ---------------------------------------------------------------------------
# Leaks


def _rows(image: Image) -> tuple[NDArray[np.uint8], NDArray[np.uint8]]:
    """The image as 16-byte blocks, and as 4x4x3 patches."""
    size = image.shape[0]
    blocks = np.frombuffer(image.tobytes(), dtype=np.uint8).reshape(-1, 16)
    patches = image.reshape(size // 4, 4, size // 4, 4, 3).transpose(0, 2, 1, 3, 4).reshape(-1, 48)
    return blocks, patches


def _codebook(plain: NDArray[np.uint8], cipher: NDArray[np.uint8]) -> tuple[float, int, int]:
    """How exactly equal plaintext pieces map to equal ciphertext pieces.

    Returns ``(consistency, plaintext classes, pieces)``. Consistency is 1.0
    when every class of equal plaintext pieces encrypts to exactly one class of
    equal ciphertext pieces, wherever it appears (a fixed codebook, as in ECB),
    and falls toward 0 when position or a nonce changes the outcome.
    """
    _values, plain_ids = np.unique(plain, axis=0, return_inverse=True)
    _values, cipher_ids = np.unique(cipher, axis=0, return_inverse=True)
    pairs = np.stack([plain_ids.ravel(), cipher_ids.ravel()], axis=1)
    joint = np.unique(pairs, axis=0).shape[0]
    plain_classes = int(np.max(plain_ids)) + 1
    cipher_classes = int(np.max(cipher_ids)) + 1
    return min(plain_classes, cipher_classes) / joint, plain_classes, plain.shape[0]


def pattern_leak(cipher: LabCipher, probe: Image) -> AttackResult:
    """Does the cipher act as a fixed codebook on 16-byte blocks or 4x4 patches?"""
    ct = cipher.encrypt(probe)
    findings = []
    leaks = False
    for name, plain, coded in zip(
        ("16-byte blocks", "4x4 patches"), _rows(probe), _rows(ct.view), strict=True
    ):
        consistency, classes, pieces = _codebook(plain, coded)
        repeats = 1 - classes / pieces
        if repeats > PATTERN_FLOOR and consistency >= 0.99:
            leaks = True
            findings.append(
                f"{name}: the image's {classes} distinct pieces encrypt to {classes} distinct "
                "pieces, the same wherever they appear"
            )
    if leaks:
        finding = (
            "Acts as a fixed codebook (" + "; ".join(findings) + "), so the picture's outline "
            "shows through."
        )
    else:
        finding = "Equal pieces of the image do not encrypt to equal pieces of ciphertext."
    return _result(
        "pattern", applicable=True, success=leaks, finding=finding, recovered=ct.view.copy()
    )


def determinism(cipher: LabCipher, image: Image) -> AttackResult:
    """Encrypt the same image twice: identical ciphertexts reveal equal images."""
    same = cipher.encrypt(image).payload == cipher.encrypt(image).payload
    return _result(
        "determinism",
        applicable=True,
        success=same,
        finding=(
            "The same image always encrypts the same way, so equal images are recognisable."
            if same
            else "Each encryption is different (a fresh nonce every time)."
        ),
    )


def tamper(cipher: LabCipher, image: Image) -> AttackResult:
    """Flip one ciphertext bit and see whether decryption notices."""
    ct = cipher.encrypt(image)
    index, mask = cipher.tamper_position(ct)
    damaged = bytearray(ct.payload)
    damaged[index] ^= mask
    try:
        opened = cipher.decrypt(Ciphertext(bytes(damaged), ct.shape, None, ct.view))
    except LabDecryptError:
        return _result(
            "tamper",
            applicable=True,
            success=False,
            finding="Refused: one flipped bit and the tag no longer verifies.",
        )
    changed = float(np.mean(np.any(opened != image, axis=-1)))
    return _result(
        "tamper",
        applicable=True,
        success=True,
        finding=(
            f"Decrypted without complaint after one flipped bit; {changed:.2%} of pixels changed."
        ),
        recovered=opened,
    )


def salamander(name: str, top: Image, bottom: Image) -> AttackResult:
    """Build one ciphertext that authenticates under two of the attacker's own keys."""
    probe = make_cipher(name, keys.derive(bytes(32), "attacker-1", 32))
    if not probe.authenticated:
        return _result(
            "salamander",
            applicable=False,
            success=False,
            finding="No authentication to defeat: any key 'decrypts' any ciphertext.",
        )
    first = probe
    second = make_cipher(name, keys.derive(bytes(32), "attacker-2", 32))
    nonce = keys.derive(bytes(32), "attacker-nonce", 12)
    gcm_key = getattr(first, "gcm_key_for")  # noqa: B009 - only GCM ciphers have it
    forged = forge_two_key_ciphertext(
        gcm_key(nonce),
        second.gcm_key_for(nonce),  # type: ignore[attr-defined]
        nonce,
        first.AAD,  # type: ignore[attr-defined]
        top.tobytes(),
        bottom.tobytes(),
    )
    payload = first.pack(nonce, forged)  # type: ignore[attr-defined]
    body = np.frombuffer(forged[:-16], dtype=np.uint8).reshape(top.shape).copy()
    ct = Ciphertext(payload, top.shape, body, body)
    shown_first = first.decrypt(ct)
    try:
        shown_second = second.decrypt(ct)
    except LabDecryptError:
        return _result(
            "salamander",
            applicable=True,
            success=False,
            finding=(
                "Defeated by the key commitment: the forgery still satisfies AES-GCM under both "
                "keys, but only the key the commitment names opens it."
            ),
            recovered=shown_first,
        )
    return _result(
        "salamander",
        applicable=True,
        success=True,
        finding=(
            "One ciphertext, two valid keys: both authenticate, and each shows a different "
            "picture. AES-GCM alone does not commit to its key."
        ),
        recovered=shown_first,
        extra=shown_second,
    )


def run_attacks(
    cipher: LabCipher, image: Image, *, probe: Image, decoy: Image
) -> list[AttackResult]:
    """Every attack on one cipher, in display order."""
    target = cipher.encrypt(image)
    return [
        structure_attack(cipher, target, truth=image),
        impulse_attack(cipher, target, truth=image),
        pattern_leak(cipher, probe),
        determinism(cipher, image),
        tamper(cipher, image),
        salamander(cipher.name, image, decoy),
    ]
