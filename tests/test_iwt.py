"""The integer Haar lifting (S-transform) the cloak hides data in.

It must be exactly invertible on integers, and changing the low bits of the
detail coefficients must move pixels by no more than the cloak's margins, or
a cloaked image could need values outside 0-255.
"""

from __future__ import annotations

import numpy as np
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.extra.numpy import arrays

from image_encryption_system import iwt

MARGINS = {1: 2, 2: 5, 3: 10}


@st.composite
def even_images(draw, low: int = 0, high: int = 255):
    height = 2 * draw(st.integers(1, 32))
    width = 2 * draw(st.integers(1, 32))
    return draw(arrays(np.int32, (height, width), elements=st.integers(low, high)))


@given(even_images())
def test_inverse_undoes_forward_exactly(channel) -> None:
    bands = iwt.forward(channel)
    assert all(band.shape == (channel.shape[0] // 2, channel.shape[1] // 2) for band in bands)
    assert np.array_equal(iwt.inverse(*bands), channel)


def test_constant_image_has_no_detail() -> None:
    ll, lh, hl, hh = iwt.forward(np.full((8, 6), 7, dtype=np.uint8))
    assert np.all(ll == 7)
    assert not lh.any() and not hl.any() and not hh.any()


def test_odd_or_flat_input_is_refused() -> None:
    import pytest

    with pytest.raises(ValueError):
        iwt.forward(np.zeros((3, 4)))
    with pytest.raises(ValueError):
        iwt.forward(np.zeros(16))


def _replace_low_bits(band: np.ndarray, bits: int, rng: np.random.Generator) -> np.ndarray:
    mask = (1 << bits) - 1
    values = rng.integers(0, 1 << bits, size=band.shape, dtype=np.int32)
    return (band & ~mask) | values


def _check_margin(channel: np.ndarray, bits: int, rng: np.random.Generator) -> None:
    ll, lh, hl, hh = iwt.forward(channel)
    changed = iwt.inverse(
        ll,
        _replace_low_bits(lh, bits, rng),
        _replace_low_bits(hl, bits, rng),
        _replace_low_bits(hh, bits, rng),
    )
    margin = MARGINS[bits]
    assert changed.min() >= 0 and changed.max() <= 255
    assert np.abs(changed - channel).max() <= margin


@given(st.sampled_from([1, 2, 3]), st.data())
def test_detail_changes_respect_the_cloak_margins(bits, data) -> None:
    margin = MARGINS[bits]
    channel = data.draw(even_images(margin, 255 - margin))
    seed = data.draw(st.integers(0, 2**32 - 1))
    _check_margin(channel, bits, np.random.default_rng(seed))


def test_margins_hold_over_a_million_random_blocks() -> None:
    rng = np.random.default_rng(2026)
    for bits, margin in MARGINS.items():
        channel = rng.integers(margin, 256 - margin, size=(1024, 1024), dtype=np.int32)
        _check_margin(channel, bits, rng)
        # The extremes of the allowed range, where overflow would show first.
        edges = rng.choice([margin, 255 - margin], size=(512, 512)).astype(np.int32)
        _check_margin(edges, bits, rng)
