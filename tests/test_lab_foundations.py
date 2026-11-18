"""Foundations of the Cipher Lab: images, key material, chaos, and transforms."""

from __future__ import annotations

from io import BytesIO

import numpy as np
import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.extra.numpy import arrays
from PIL import Image

from image_encryption_system.lab import chaos, imaging, keys, transforms

KEY = bytes(range(32))


def _encode(image: Image.Image, fmt: str = "PNG", **options) -> bytes:
    buffer = BytesIO()
    image.save(buffer, format=fmt, **options)
    return buffer.getvalue()


def _unusual_inputs() -> dict[str, bytes]:
    rgba = Image.new("RGBA", (40, 30), (200, 10, 10, 0))
    gif = BytesIO()
    frames = [Image.new("P", (24, 24), i * 40) for i in range(3)]
    frames[0].save(gif, format="GIF", save_all=True, append_images=frames[1:])
    sixteen = Image.fromarray(np.arange(48 * 48, dtype=np.uint16).reshape(48, 48) * 20)
    return {
        "grayscale": _encode(Image.new("L", (50, 70), 90)),
        "palette": _encode(Image.new("RGB", (64, 64), "#3366aa").quantize(16)),
        "transparent": _encode(rgba),
        "sixteen-bit": _encode(sixteen),
        "animated-gif": gif.getvalue(),
        "tiny": _encode(Image.new("RGB", (10, 10), "#123456")),
        "panorama": _encode(Image.new("RGB", (400, 50), "#654321")),
        "jpeg": _encode(Image.new("RGB", (90, 60), "#a0b0c0"), "JPEG"),
    }


@pytest.mark.parametrize("name", list(_unusual_inputs()))
def test_prepare_handles_unusual_modes(name) -> None:
    prepared = imaging.prepare(_unusual_inputs()[name], size=64)
    assert prepared.shape == (64, 64, 3)
    assert prepared.dtype == np.uint8


def test_transparent_pixels_become_white() -> None:
    prepared = imaging.prepare(_unusual_inputs()["transparent"], size=32)
    assert (prepared == 255).all()


def test_prepare_refuses_non_images_and_bad_sizes() -> None:
    with pytest.raises(ValueError, match="not an image"):
        imaging.prepare(b"definitely not an image", size=64)
    with pytest.raises(ValueError):
        imaging.prepare(_unusual_inputs()["tiny"], size=100)


@pytest.mark.parametrize("name", imaging.SAMPLES)
@pytest.mark.parametrize("size", [64, 256])
def test_samples_are_deterministic_and_sized(name, size) -> None:
    sample = imaging.sample(name, size)
    assert sample.shape == (size, size, 3)
    assert sample.dtype == np.uint8
    assert np.array_equal(sample, imaging.sample(name, size))
    assert sample.std() > 10


def test_the_test_card_has_flat_regions_for_pattern_leaks() -> None:
    card = imaging.sample("test-card", 64)
    patches = card.reshape(16, 4, 16, 4, 3).transpose(0, 2, 1, 3, 4).reshape(-1, 48)
    repeated = 1 - len(np.unique(patches, axis=0)) / len(patches)
    assert repeated >= 0.3


def test_png_jpeg_and_data_uris() -> None:
    card = imaging.sample("test-card", 32)
    with Image.open(BytesIO(imaging.to_png(card))) as image:
        assert image.format == "PNG" and np.array_equal(np.asarray(image), card)
    with Image.open(BytesIO(imaging.to_jpeg(card))) as image:
        assert image.format == "JPEG"
    assert imaging.data_uri(b"\x00\x01", "image/png") == "data:image/png;base64,AAE="


def test_key_material_is_label_separated() -> None:
    assert keys.derive(KEY, "a", 32) != keys.derive(KEY, "b", 32)
    assert keys.derive(KEY, "a", 32) == keys.derive(KEY, "a", 32)
    assert keys.derive(KEY, "a", 32) != keys.derive(bytes(32), "a", 32)
    floats = keys.unit_floats(KEY, "floats", 50)
    assert len(floats) == 50 and all(0 <= f < 1 for f in floats)
    long = keys.stream(KEY, "long", 100_000)
    assert len(long) == 100_000 and long != keys.stream(KEY, "other", 100_000)
    with pytest.raises(ValueError):
        keys.derive(b"short key", "a", 32)


def test_logistic_matches_the_recurrence() -> None:
    x, mu = 0.3, 3.995
    expected = []
    for _ in range(20):
        x = mu * x * (1 - x)
        expected.append(x)
    assert chaos.logistic_sequence(0.3, 3.995, 20, burn_in=0).tolist() == expected
    with_burn_in = chaos.logistic_sequence(0.3, 3.995, 5, burn_in=15)
    assert with_burn_in.tolist() == expected[15:20]


def test_chaos_bytes_quantise_the_low_digits() -> None:
    values = np.array([0.123456789012345, -0.5, 0.0])
    assert chaos.chaos_bytes(values).tolist() == [
        int(np.floor(0.123456789012345 * 1e14)) % 256,
        int(np.floor(0.5 * 1e14)) % 256,
        0,
    ]


def test_chen_sequence_is_bounded_and_key_sensitive() -> None:
    values = chaos.chen_sequence((1.0, -2.0, 3.0, 0.5), 0.2, 50_000)
    assert values.shape == (50_000,)
    assert np.isfinite(values).all()
    assert np.abs(values).max() < 1000
    assert np.array_equal(values, chaos.chen_sequence((1.0, -2.0, 3.0, 0.5), 0.2, 50_000))
    nudged = chaos.chen_sequence((1.0, -2.0, 3.0, 0.5), 0.2 + 1e-9, 50_000)
    assert not np.array_equal(chaos.chaos_bytes(values), chaos.chaos_bytes(nudged))


@pytest.mark.parametrize("size", [8, 32, 256])
def test_arnold_destinations_are_a_bijection(size) -> None:
    destinations = transforms.arnold_destinations(size, 3, 5, 7)
    assert np.array_equal(np.sort(destinations), np.arange(size * size))
    # One iteration with a = b = 1 is the classic cat map (x, y) -> (x + y, x + 2y).
    classic = transforms.arnold_destinations(size, 1, 1, 1)
    row, col = 1, 2
    new_col, new_row = (col + row) % size, (col + 2 * row) % size
    assert classic[row * size + col] == new_row * size + new_col
    # Iterating t times is the t-th power of one iteration.
    once = transforms.arnold_destinations(size, 3, 5, 1)
    assert np.array_equal(transforms.arnold_destinations(size, 3, 5, 2), once[once])


@given(
    st.sampled_from([8, 16, 32]).flatmap(
        lambda n: arrays(np.uint8, (n, n), elements=st.integers(0, 255))
    ),
    st.sampled_from([1, 2]),
)
def test_mod256_haar_is_a_bijection(channel, levels) -> None:
    coefficients = transforms.haar_mod256_forward(channel, levels)
    assert coefficients.dtype == np.uint8 and coefficients.shape == channel.shape
    assert np.array_equal(transforms.haar_mod256_inverse(coefficients, levels), channel)


def test_mod256_subbands_partition_the_square() -> None:
    cover = np.zeros((64, 64), dtype=np.int64)
    for rows, cols in transforms.haar_mod256_subbands(64, 2):
        cover[rows, cols] += 1
    assert (cover == 1).all()
    assert len(transforms.haar_mod256_subbands(64, 2)) == 7


def test_walsh_hadamard_inverse_scale_and_impulse() -> None:
    rng = np.random.default_rng(4)
    x = rng.integers(-300, 300, size=(16, 16)).astype(np.float64)
    assert np.array_equal(transforms.walsh_hadamard_2d(transforms.walsh_hadamard_2d(x)), 256 * x)
    impulse = np.zeros((16, 16))
    impulse[0, 0] = 1
    assert (transforms.walsh_hadamard_2d(impulse) == 1).all()
