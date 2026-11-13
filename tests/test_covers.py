"""Generated landscape covers for cloaked exports.

A cover has to look like an ordinary picture, stay inside [10, 245] so the
cloak never has to clamp it, and be reproducible from its seed.
"""

from __future__ import annotations

import numpy as np
import pytest

from image_encryption_system import covers
from image_encryption_system.covers import PALETTES, generate_cover


def test_cover_is_deterministic_and_seed_dependent() -> None:
    first = generate_cover(120, 80, seed=b"one")
    assert first.shape == (80, 120, 3)
    assert first.dtype == np.uint8
    assert np.array_equal(first, generate_cover(120, 80, seed=b"one"))
    assert not np.array_equal(first, generate_cover(120, 80, seed=b"two"))
    assert not np.array_equal(first, generate_cover(120, 80, seed=b"one", palette="alpine"))


@pytest.mark.parametrize("palette", PALETTES)
def test_cover_stays_inside_the_safe_range(palette) -> None:
    cover = generate_cover(160, 96, seed=b"range", palette=palette)
    assert cover.min() >= 10
    assert cover.max() <= 245


@pytest.mark.parametrize("palette", PALETTES)
def test_cover_looks_like_a_picture(palette) -> None:
    cover = generate_cover(240, 160, seed=b"picture", palette=palette).astype(np.float64)
    for channel in range(3):
        plane = cover[..., channel]
        assert plane.std() > 10
        left, right = plane[:, :-1].ravel(), plane[:, 1:].ravel()
        assert np.corrcoef(left, right)[0, 1] > 0.9
    # Sky above, land below: the top and bottom bands differ clearly.
    top, bottom = cover[: 160 // 6].mean(axis=(0, 1)), cover[-160 // 6 :].mean(axis=(0, 1))
    assert np.abs(top - bottom).max() > 20


def test_band_size_does_not_change_the_picture(monkeypatch) -> None:
    # Rows are rendered in bands to bound memory; the bands must not show.
    reference = generate_cover(64, 600, seed=b"bands")
    monkeypatch.setattr(covers, "_BAND_ROWS", 7)
    assert np.array_equal(generate_cover(64, 600, seed=b"bands"), reference)


def test_unknown_palette_and_tiny_sizes_are_refused() -> None:
    with pytest.raises(ValueError):
        generate_cover(64, 64, seed=b"x", palette="neon")
    with pytest.raises(ValueError):
        generate_cover(15, 64, seed=b"x")
    with pytest.raises(ValueError):
        generate_cover(64, 8, seed=b"x")
