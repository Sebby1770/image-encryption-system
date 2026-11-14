"""The statistics image-encryption papers report, with honest pass rules.

Critical values are computed, not copied: NPCR/UACI from Wu, Noonan & Agaian
(2011), whose published 256x256 table they must reproduce, and local entropy
from a simulated null distribution (see the module docstring).
"""

from __future__ import annotations

import math

import numpy as np
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from image_encryption_system.lab import imaging, metrics
from image_encryption_system.lab.ciphers import make_cipher

KEY = bytes(range(32))


def _noise(size: int, seed: int) -> np.ndarray:
    key = bytes([seed]) * 32
    stream = Cipher(algorithms.ChaCha20(key, bytes(16)), mode=None).encryptor()
    data = stream.update(bytes(size * size * 3))
    return np.frombuffer(data, np.uint8).reshape(size, size, 3).copy()


@pytest.mark.parametrize(
    ("alpha", "npcr", "uaci"),
    [
        (0.05, 99.5693, (33.2824, 33.6447)),
        (0.01, 99.5527, (33.2255, 33.7016)),
        (0.001, 99.5341, (33.1594, 33.7677)),
    ],
)
def test_critical_values_match_wu_2011(alpha, npcr, uaci) -> None:
    assert metrics.npcr_critical(65536, alpha) == pytest.approx(npcr, abs=1e-4)
    low, high = metrics.uaci_critical(65536, alpha)
    assert (low, high) == (pytest.approx(uaci[0], abs=1e-4), pytest.approx(uaci[1], abs=1e-4))


def test_entropy_extremes() -> None:
    assert metrics.entropy(np.zeros((32, 32, 3), np.uint8)) == [0.0, 0.0, 0.0]
    uniform = np.tile(np.arange(256, dtype=np.uint8), 48).reshape(64, 64, 3)
    assert metrics.entropy(uniform) == pytest.approx([8.0, 8.0, 8.0])
    assert metrics.pooled_entropy(uniform) == pytest.approx(8.0)


def test_chi_square_of_a_flat_histogram_is_zero() -> None:
    uniform = np.tile(np.arange(256, dtype=np.uint8), 48).reshape(64, 64, 3)
    assert metrics.pooled_chi_square(uniform) == pytest.approx(0.0)
    assert abs(metrics.CHI_SQUARE_CRITICAL_255 - 293.2478) < 1e-9


def test_local_entropy_constants_reproduce_the_published_mean_and_a_5_percent_test() -> None:
    assert abs(metrics.LOCAL_ENTROPY_MEAN - 7.902469317) < 2e-5
    low, high = metrics.local_entropy_interval(90)
    rng = np.random.default_rng(90)
    passes = []
    for _ in range(300):
        image = rng.integers(0, 256, (256, 256, 3), dtype=np.uint8)
        passes.append(
            low < metrics.pooled_local_entropy(image, seed=int(rng.integers(1 << 30))) < high
        )
    assert 0.9 <= np.mean(passes) <= 0.99


def test_local_entropy_needs_enough_pixels() -> None:
    assert metrics.local_entropy(_noise(64, 1)) is None
    assert metrics.pooled_local_entropy(_noise(64, 1)) is None
    assert len(metrics.local_entropy(_noise(256, 1))) == 3


def test_fixed_noise_passes_every_statistic() -> None:
    noise = _noise(256, 7)
    assert metrics.pooled_entropy(noise) >= 7.99
    low, high = metrics.local_entropy_interval(90)
    assert low < metrics.pooled_local_entropy(noise) < high
    assert metrics.pooled_chi_square(noise) < metrics.CHI_SQUARE_CRITICAL_255
    bound = metrics.correlation_bound(noise)
    for value in metrics.pooled_correlations(noise).values():
        assert abs(value) <= bound


def test_gradient_is_strongly_correlated() -> None:
    correlations = metrics.pooled_correlations(imaging.sample("gradient", 64))
    assert all(value > 0.9 for value in correlations.values())
    assert set(correlations) == {"horizontal", "vertical", "diagonal"}


def test_npcr_and_uaci() -> None:
    a = _noise(32, 2)
    assert metrics.npcr_uaci(a, a) == (0.0, 0.0)
    npcr, uaci = metrics.npcr_uaci(a, 255 - a)
    assert npcr == 100.0
    assert uaci == pytest.approx(float(np.mean(np.abs(2 * a.astype(float) - 255))) / 255 * 100)


def _by_key(results):
    return {result.key: result for result in results}


@pytest.fixture()
def repeatable_nonces(monkeypatch):
    """Each statistical test fails a perfect cipher 5% of the time by design, and
    AES-GCM draws a fresh nonce per encryption; fix the nonces so runs repeat."""
    import hashlib
    import itertools

    from image_encryption_system.lab import aes

    counter = itertools.count()
    monkeypatch.setattr(
        aes, "_new_nonce", lambda: hashlib.sha256(b"lab-nonce-%d" % next(counter)).digest()[:12]
    )


@pytest.mark.usefixtures("repeatable_nonces")
def test_score_reports_every_metric_in_order() -> None:
    image = imaging.sample("landscape", 256)
    cipher = make_cipher("aes-gcm", KEY)
    ciphertext = cipher.encrypt(image)
    results = metrics.score(cipher, image, ciphertext, key=KEY, seconds=0.01)
    assert [r.key for r in results] == [
        "entropy",
        "local_entropy",
        "chi_square",
        "correlation",
        "npcr_uaci",
        "key_sensitivity",
        "round_trip",
        "speed",
        "expansion",
    ]
    scored = _by_key(results)
    for key in (
        "entropy",
        "local_entropy",
        "chi_square",
        "correlation",
        "npcr_uaci",
        "key_sensitivity",
    ):
        assert scored[key].passed is True, (key, scored[key])
    assert scored["round_trip"].passed is True
    assert scored["npcr_uaci"].extra["uaci"] == pytest.approx(33.46, abs=0.3)
    assert scored["expansion"].value == pytest.approx((3 * 256 * 256 + 28) / (3 * 256 * 256))
    assert scored["speed"].passed is None and scored["speed"].value > 0
    assert all(r.label and r.detail for r in results)


def test_permutation_keeps_the_histogram_so_entropy_fails() -> None:
    image = imaging.sample("gradient", 256)
    cipher = make_cipher("arnold", KEY)
    scored = _by_key(metrics.score(cipher, image, cipher.encrypt(image), key=KEY, seconds=0.01))
    assert scored["entropy"].passed is False
    assert scored["chi_square"].passed is False
    assert scored["entropy"].value == pytest.approx(metrics.pooled_entropy(image))
    assert scored["npcr_uaci"].passed is False  # one moved pixel, nothing diffused


def test_small_images_skip_the_size_dependent_tests() -> None:
    image = imaging.sample("landscape", 64)
    cipher = make_cipher("aes-gcm", KEY)
    scored = _by_key(metrics.score(cipher, image, cipher.encrypt(image), key=KEY, seconds=0.01))
    assert scored["entropy"].passed is None
    assert scored["local_entropy"].passed is None and scored["local_entropy"].value is None
    assert math.isfinite(scored["entropy"].value)


def test_hyperchaos_passes_the_differential_test_like_a_good_cipher() -> None:
    # The lab's lesson is that a cipher can pass these statistics and still be
    # weak; its stand-in must therefore pass them at the 95% a 5% test allows.
    # XOR-and-add diffusion alone keeps differences in the low bits (UACI too low).
    image = imaging.sample("landscape", 256)
    nudged = image.copy()
    nudged[128, 128, 0] = (int(nudged[128, 128, 0]) + 1) % 256
    floor = metrics.npcr_critical(image.size)
    low, high = metrics.uaci_critical(image.size)
    passes = 0
    for i in range(20):
        cipher = make_cipher("hyperchaos", bytes([i]) * 32)
        npcr, uaci = metrics.npcr_uaci(cipher.encrypt(image).view, cipher.encrypt(nudged).view)
        passes += npcr >= floor and low < uaci < high
    assert passes >= 16, passes
