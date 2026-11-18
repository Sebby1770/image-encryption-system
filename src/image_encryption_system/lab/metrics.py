"""The statistics image-encryption papers report, each with a pass rule.

They are computed on a ciphertext's ``view``. Per-channel values are reported,
but pass/fail uses statistics pooled over the three channels: testing each
channel separately at the 5% level would fail a perfect cipher about 14% of
the time.

Critical values are computed rather than copied:

- NPCR and UACI follow Wu, Noonan and Agaian (2011). For 256 x 256 the
  formulas reproduce their published table (NPCR* 99.5693% at alpha 0.05;
  UACI in (33.2824%, 33.6447%)), see ``tests/test_lab_metrics.py``.
- Local Shannon entropy follows Wu et al. (2013): mean entropy over randomly
  chosen 1,936-pixel blocks. The null mean and spread come from simulating
  two million blocks of uniform bytes: mean 7.902472 (the paper's published
  mean is 7.902469) and block standard deviation 0.008693. The interval is
  ``mean +/- z * sd / sqrt(blocks)``, which truly random data passes 95% of
  the time. The interval commonly quoted for 30 blocks at alpha 0.05,
  (7.901901305, 7.903037329), equals ``mean +/- z * sd / 30``; random data
  passes that only about 28% of the time.
- The chi-square critical value for 255 degrees of freedom at 0.05 is
  293.2478 (checked against the regularised incomplete gamma function).

None of these can show a cipher is secure. The lab's attacks make that point:
ciphers that pass every row here are broken by them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from statistics import NormalDist

import numpy as np
from numpy.typing import NDArray

from .base import Ciphertext, Image, LabCipher, LabDecryptError
from .ciphers import make_cipher

F = 255
CHI_SQUARE_CRITICAL_255 = 293.2478
ENTROPY_FLOOR = 7.99
ENTROPY_MIN_SIDE = 128
LOCAL_BLOCK_PIXELS = 1936
LOCAL_BLOCKS_PER_CHANNEL = 30
LOCAL_ENTROPY_MEAN = 7.902472
LOCAL_ENTROPY_BLOCK_SD = 0.008693
ALPHA = 0.05


@dataclass(frozen=True)
class MetricResult:
    key: str
    label: str
    value: float | None
    per_channel: tuple[float, ...]
    passed: bool | None
    detail: str
    extra: dict[str, float] = field(default_factory=dict)


def _histogram_entropy(values: NDArray[np.uint8]) -> float:
    counts = np.bincount(values.ravel(), minlength=256).astype(np.float64)
    p = counts[counts > 0] / values.size
    return float(abs(-np.sum(p * np.log2(p))))


def entropy(view: Image) -> list[float]:
    """Shannon entropy of each channel's 256-bin histogram (bits)."""
    return [_histogram_entropy(view[..., c]) for c in range(view.shape[2])]


def pooled_entropy(view: Image) -> float:
    return _histogram_entropy(view)


def _chi_square(values: NDArray[np.uint8]) -> float:
    counts = np.bincount(values.ravel(), minlength=256).astype(np.float64)
    expected = values.size / 256
    return float(np.sum((counts - expected) ** 2) / expected)


def chi_square(view: Image) -> list[float]:
    return [_chi_square(view[..., c]) for c in range(view.shape[2])]


def pooled_chi_square(view: Image) -> float:
    return _chi_square(view)


def _block_entropies(
    plane: NDArray[np.uint8], blocks: int, rng: np.random.Generator
) -> list[float]:
    flat = plane.ravel()
    runs = flat.size // LOCAL_BLOCK_PIXELS
    chosen = rng.choice(runs, size=blocks, replace=False)
    return [
        _histogram_entropy(flat[i * LOCAL_BLOCK_PIXELS : (i + 1) * LOCAL_BLOCK_PIXELS])
        for i in sorted(chosen)
    ]


def _has_room(view: Image) -> bool:
    return view.shape[0] * view.shape[1] >= LOCAL_BLOCKS_PER_CHANNEL * LOCAL_BLOCK_PIXELS


def local_entropy(view: Image, *, seed: int = 0) -> list[float] | None:
    """Per channel: mean entropy of 30 random, non-overlapping 1,936-pixel runs."""
    if not _has_room(view):
        return None
    rng = np.random.default_rng(seed)
    return [
        float(np.mean(_block_entropies(view[..., c], LOCAL_BLOCKS_PER_CHANNEL, rng)))
        for c in range(view.shape[2])
    ]


def pooled_local_entropy(view: Image, *, seed: int = 0) -> float | None:
    """Mean over all channels' blocks (90 for an RGB image)."""
    per_channel = local_entropy(view, seed=seed)
    return None if per_channel is None else float(np.mean(per_channel))


def local_entropy_interval(blocks: int, alpha: float = ALPHA) -> tuple[float, float]:
    half = NormalDist().inv_cdf(1 - alpha / 2) * LOCAL_ENTROPY_BLOCK_SD / math.sqrt(blocks)
    return LOCAL_ENTROPY_MEAN - half, LOCAL_ENTROPY_MEAN + half


def _pairs(plane: NDArray[np.uint8]) -> dict[str, tuple[NDArray[np.float64], NDArray[np.float64]]]:
    x = plane.astype(np.float64)
    return {
        "horizontal": (x[:, :-1].ravel(), x[:, 1:].ravel()),
        "vertical": (x[:-1, :].ravel(), x[1:, :].ravel()),
        "diagonal": (x[:-1, :-1].ravel(), x[1:, 1:].ravel()),
    }


def _pearson(a: NDArray[np.float64], b: NDArray[np.float64]) -> float:
    if a.std() == 0 or b.std() == 0:
        return 1.0  # a flat image is perfectly predictable
    return float(np.corrcoef(a, b)[0, 1])


def correlations(view: Image) -> dict[str, list[float]]:
    """Pearson r between neighbours, per direction and channel."""
    out: dict[str, list[float]] = {"horizontal": [], "vertical": [], "diagonal": []}
    for c in range(view.shape[2]):
        for direction, (a, b) in _pairs(view[..., c]).items():
            out[direction].append(_pearson(a, b))
    return out


def pooled_correlations(view: Image) -> dict[str, float]:
    """Pearson r per direction over the neighbour pairs of every channel.

    Each channel's pairs are centred on that channel's own means before they
    are pooled: otherwise the spread between channel means (a reddish picture)
    would read as neighbour correlation even when every channel is noise.
    """
    pooled: dict[str, float] = {}
    for direction in ("horizontal", "vertical", "diagonal"):
        pairs = [_pairs(view[..., c])[direction] for c in range(view.shape[2])]
        a = np.concatenate([p[0] - p[0].mean() for p in pairs])
        b = np.concatenate([p[1] - p[1].mean() for p in pairs])
        pooled[direction] = _pearson(a, b)
    return pooled


def correlation_bound(view: Image) -> float:
    """``4 / sqrt(pairs)``: four standard errors of r for independent pixels."""
    rows, cols, channels = view.shape
    pairs = channels * (rows - 1) * (cols - 1)
    return 4 / math.sqrt(pairs)


def npcr_uaci(a: Image, b: Image) -> tuple[float, float]:
    """Percent of values that differ, and mean absolute difference over 255, in percent."""
    left, right = a.astype(np.int16), b.astype(np.int16)
    npcr = float(np.mean(left != right) * 100)
    uaci = float(np.mean(np.abs(left - right)) / F * 100)
    return npcr, uaci


def npcr_critical(values: int, alpha: float = ALPHA) -> float:
    """One-sided NPCR critical value, in percent (Wu, Noonan & Agaian, 2011)."""
    z = NormalDist().inv_cdf(1 - alpha)
    return (F - z * math.sqrt(F / values)) / (F + 1) * 100


def uaci_critical(values: int, alpha: float = ALPHA) -> tuple[float, float]:
    """Two-sided UACI acceptance interval, in percent (Wu, Noonan & Agaian, 2011)."""
    mean = (F + 2) / (3 * F + 3)
    sigma = math.sqrt((F + 2) * (F * F + 2 * F + 3) / (18 * (F + 1) ** 2 * values * F))
    z = NormalDist().inv_cdf(1 - alpha / 2)
    return (mean - z * sigma) * 100, (mean + z * sigma) * 100


def _differential(a: Image, b: Image) -> tuple[float, float, bool]:
    npcr, uaci = npcr_uaci(a, b)
    low, high = uaci_critical(a.size)
    return npcr, uaci, npcr >= npcr_critical(a.size) and low < uaci < high


def _flipped(key: bytes) -> bytes:
    return key[:-1] + bytes([key[-1] ^ 0x01])


def score(
    cipher: LabCipher, image: Image, ct: Ciphertext, *, key: bytes, seconds: float
) -> list[MetricResult]:
    """Every metric for one cipher on one image, in display order."""
    view = ct.view
    size = image.shape[0]
    values = image.size
    results: list[MetricResult] = []

    pooled = pooled_entropy(view)
    big_enough = size >= ENTROPY_MIN_SIDE
    results.append(
        MetricResult(
            "entropy",
            "Entropy",
            pooled,
            tuple(entropy(view)),
            pooled >= ENTROPY_FLOOR if big_enough else None,
            f"bits per byte; ideal 8, pass at {ENTROPY_FLOOR} or more"
            + ("" if big_enough else f" (only judged from {ENTROPY_MIN_SIDE} px)"),
        )
    )

    local = local_entropy(view)
    low, high = local_entropy_interval(LOCAL_BLOCKS_PER_CHANNEL * view.shape[2])
    local_mean = None if local is None else float(np.mean(local))
    results.append(
        MetricResult(
            "local_entropy",
            "Local entropy",
            local_mean,
            tuple(local or ()),
            None if local_mean is None else low < local_mean < high,
            f"mean of 30 random 1,936-pixel blocks per channel; pass in ({low:.5f}, {high:.5f})"
            if local_mean is not None
            else "needs at least 58,080 pixels (256 px)",
        )
    )

    chi = pooled_chi_square(view)
    results.append(
        MetricResult(
            "chi_square",
            "Histogram (chi-square)",
            chi,
            tuple(chi_square(view)),
            chi < CHI_SQUARE_CRITICAL_255,
            f"255 degrees of freedom; pass below {CHI_SQUARE_CRITICAL_255}",
        )
    )

    pooled_r = pooled_correlations(view)
    bound = correlation_bound(view)
    worst = max(abs(r) for r in pooled_r.values())
    results.append(
        MetricResult(
            "correlation",
            "Neighbour correlation",
            worst,
            tuple(pooled_r.values()),
            worst <= bound,
            f"largest |r| of horizontal, vertical, diagonal; pass at {bound:.4f} or less",
            extra=dict(pooled_r),
        )
    )

    nudged = image.copy()
    nudged[size // 2, size // 2, 0] = (int(nudged[size // 2, size // 2, 0]) + 1) % 256
    npcr, uaci, passed = _differential(view, cipher.encrypt(nudged).view)
    results.append(
        MetricResult(
            "npcr_uaci",
            "Differential (NPCR / UACI)",
            npcr,
            (),
            passed,
            f"one plaintext pixel +1; pass at NPCR {npcr_critical(values):.4f}% or more "
            f"and UACI in ({uaci_critical(values)[0]:.4f}%, {uaci_critical(values)[1]:.4f}%)",
            extra={"uaci": uaci},
        )
    )

    fixed = bytes(12)
    first = make_cipher(cipher.name, key).encrypt(image, nonce=fixed).view
    second = make_cipher(cipher.name, _flipped(key)).encrypt(image, nonce=fixed).view
    npcr, uaci, passed = _differential(first, second)
    results.append(
        MetricResult(
            "key_sensitivity",
            "Key sensitivity",
            npcr,
            (),
            passed,
            "NPCR between encryptions under keys one bit apart (same nonce); same pass rule",
            extra={"uaci": uaci},
        )
    )

    try:
        exact = bool(np.array_equal(cipher.decrypt(ct), image))
    except LabDecryptError:
        exact = False
    results.append(
        MetricResult(
            "round_trip",
            "Round trip",
            None,
            (),
            exact,
            "decrypting gives back the exact image" if exact else "decryption did not match",
        )
    )

    megabytes = values / 1e6
    results.append(
        MetricResult(
            "speed",
            "Speed",
            megabytes / seconds if seconds > 0 else math.inf,
            (),
            None,
            "MB/s for the first encryption, including key setup",
        )
    )
    results.append(
        MetricResult(
            "expansion",
            "Ciphertext size",
            len(ct.payload) / values,
            (),
            None,
            "bytes of ciphertext per byte of image",
        )
    )
    return results
