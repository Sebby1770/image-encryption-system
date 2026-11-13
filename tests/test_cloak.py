"""Cloaked exports: a vault file hidden in an ordinary-looking PNG.

The cloak changes the low bits of a cover's integer-wavelet detail
coefficients. It must give back exactly the bytes it was given, look like the
cover, and fail cleanly (never with a wrong file) when the image has been
recompressed, edited, or was never cloaked.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from io import BytesIO

import numpy as np
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.extra.numpy import arrays
from PIL import Image

from image_encryption_system import iwt
from image_encryption_system.cloak import (
    CloakError,
    capacity,
    cloak,
    is_png,
    load_cover,
    slot_order,
    uncloak,
)

NOT_CLOAKED = "does not carry a vault file"


def _random_cover(rng: np.random.Generator, width: int, height: int) -> np.ndarray:
    return rng.integers(0, 256, size=(height, width, 3), dtype=np.uint8)


def _decode(png: bytes) -> np.ndarray:
    with Image.open(BytesIO(png)) as image:
        return np.asarray(image.convert("RGB"))


def _encode(rgb: np.ndarray, **options) -> bytes:
    buffer = BytesIO()
    Image.fromarray(rgb).save(buffer, **({"format": "PNG"} | options))
    return buffer.getvalue()


covers = st.one_of(
    st.tuples(st.integers(32, 96), st.integers(32, 96), st.integers(0, 2**32 - 1)).map(
        lambda t: _random_cover(np.random.default_rng(t[2]), t[0], t[1])
    ),
    st.sampled_from([0, 255]).map(lambda v: np.full((48, 64, 3), v, dtype=np.uint8)),
)


@settings(max_examples=40)
@given(payload=st.binary(max_size=4000), bits=st.sampled_from([1, 2, 3]), cover=covers)
def test_round_trip_property(payload, bits, cover) -> None:
    png, report = cloak(payload, cover=cover, bits=bits)
    assert is_png(png)
    assert report.bits == bits
    assert report.payload_bytes == len(payload)
    assert report.capacity_bytes >= len(payload)
    assert uncloak(png) == payload


def test_capacity_formula() -> None:
    assert capacity(960, 640, 2) == 345_512
    assert capacity(961, 641, 2) == 345_512  # odd edges are cropped
    assert capacity(960, 640, 1) == (9 * 480 * 320 - 352) // 8
    assert capacity(4, 4, 1) == 0


def test_generated_cover_quality() -> None:
    payload = np.random.default_rng(1).bytes(50_000)
    png, report = cloak(payload, seed=b"quality")
    assert report.bits == 2
    assert (report.width, report.height) == (960, 640)
    assert report.psnr >= 40
    assert report.ssim >= 0.9
    assert uncloak(png) == payload


@pytest.mark.parametrize(("bits", "floor"), [(1, 50), (2, 44), (3, 38)])
def test_full_capacity_psnr(bits, floor) -> None:
    payload = np.random.default_rng(bits).bytes(capacity(960, 640, bits))
    png, report = cloak(payload, bits=bits, seed=b"full")
    assert (report.width, report.height) == (960, 640)
    assert report.psnr >= floor
    assert uncloak(png) == payload


def test_generated_covers_grow_to_fit() -> None:
    payload = bytes(capacity(960, 640, 2) + 1)
    _png, report = cloak(payload, seed=b"grow")
    assert report.width > 960 and report.height > 640
    assert report.width * 2 == report.height * 3 or abs(report.width / report.height - 1.5) < 0.01


def test_payload_too_large_is_refused() -> None:
    with pytest.raises(CloakError, match="does not fit"):
        cloak(bytes(700_000), seed=b"big", max_pixels=1_000_000)
    with pytest.raises(CloakError, match="does not fit"):
        cloak(bytes(10_000), cover=_random_cover(np.random.default_rng(2), 64, 64), max_pixels=8192)


def test_tiny_cover_is_upscaled_or_refused() -> None:
    tiny = _random_cover(np.random.default_rng(3), 16, 16)
    payload = b"a vault file that cannot fit in sixteen pixels" * 4
    png, report = cloak(payload, cover=tiny)
    assert report.width > 16 and report.height > 16
    assert report.bits == 2
    assert uncloak(png) == payload
    with pytest.raises(CloakError):
        cloak(payload, cover=tiny, max_pixels=256)


def test_auto_bits_prefers_the_gentlest_embedding() -> None:
    cover = _random_cover(np.random.default_rng(4), 128, 96)
    _png, small = cloak(bytes(100), cover=cover)
    _png, medium = cloak(bytes(capacity(128, 96, 1) + 10), cover=cover)
    assert (small.bits, medium.bits) == (1, 2)
    assert (medium.width, medium.height) == (128, 96)


def test_odd_sized_cover_is_cropped() -> None:
    png, report = cloak(b"odd", cover=_random_cover(np.random.default_rng(5), 101, 67))
    assert (report.width, report.height) == (100, 66)
    assert _decode(png).shape == (66, 100, 3)


def test_cloaked_pixels_stay_close_to_the_cover() -> None:
    cover = _random_cover(np.random.default_rng(6), 96, 64)
    clamped = np.clip(cover, 5, 250).astype(np.int16)
    png, _report = cloak(bytes(capacity(96, 64, 2)), cover=cover, bits=2)
    assert np.abs(_decode(png).astype(np.int16) - clamped).max() <= 5


def test_lossless_resaves_still_uncloak_and_lossy_ones_are_detected() -> None:
    payload = np.random.default_rng(7).bytes(capacity(160, 120, 2) - 8)
    cover = _random_cover(np.random.default_rng(8), 160, 120)
    png, _report = cloak(payload, cover=cover, bits=2)
    rgb = _decode(png)

    rgba = np.dstack([rgb, np.full(rgb.shape[:2], 255, np.uint8)])
    assert uncloak(_encode(rgba)) == payload
    assert uncloak(_encode(rgb, compress_level=9)) == payload

    with Image.open(BytesIO(png)) as image:
        quantized = image.convert("RGB").quantize(colors=256)
        buffer = BytesIO()
        quantized.save(buffer, format="PNG")
    jpeg = BytesIO()
    Image.fromarray(rgb).save(jpeg, format="JPEG", quality=95)
    with Image.open(BytesIO(jpeg.getvalue())) as image:
        recompressed = _encode(np.asarray(image.convert("RGB")))
    painted = rgb.copy()
    painted[40:80, 60:100] = (200, 30, 30)

    for damaged in (buffer.getvalue(), recompressed, _encode(painted)):
        with pytest.raises(CloakError, match=NOT_CLOAKED):
            uncloak(damaged)


def _png_with_size(width: int, height: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00" * 16))
        + chunk(b"IEND", b"")
    )


def test_hostile_inputs_are_refused_cleanly() -> None:
    ordinary = _encode(_random_cover(np.random.default_rng(9), 64, 48))
    for hostile in (
        b"not a png at all",
        b"",
        ordinary[: len(ordinary) // 2],
        _png_with_size(100_000, 100_000),
        _png_with_size(30_000, 30_000),
        _encode(np.zeros((1, 1, 3), np.uint8)),
        ordinary,
    ):
        with pytest.raises(CloakError):
            uncloak(hostile)


def test_huge_declared_sizes_are_refused_before_decoding() -> None:
    with pytest.raises(CloakError, match="too large"):
        uncloak(_png_with_size(9_000, 9_000), max_pixels=1_000_000)


def test_slot_order_is_a_permutation() -> None:
    for total in (2304, 9 * 48 * 32, 1_000_003, 9 * 480 * 320):
        order = slot_order(total)
        assert order.size == total
        assert np.array_equal(np.sort(order), np.arange(total))


def test_header_bits_are_whitened() -> None:
    png, _report = cloak(b"whitened", cover=_random_cover(np.random.default_rng(10), 64, 64))
    rgb = _decode(png)
    detail = np.concatenate(
        [band.ravel() for channel in range(3) for band in iwt.forward(rgb[..., channel])[1:]]
    )
    raw = np.packbits(detail[slot_order(detail.size)[:32]] & 1).tobytes()
    assert raw[:4] != b"IESK"

    stream = Cipher(
        algorithms.ChaCha20(hashlib.sha256(b"IES-CLOAK-V1").digest(), bytes(16)), mode=None
    ).encryptor()
    unwhitened = bytes(a ^ b for a, b in zip(raw, stream.update(bytes(4)), strict=True))
    assert unwhitened == b"IESK"


def test_load_cover_flattens_transparency_and_refuses_junk() -> None:
    rgba = np.zeros((20, 30, 4), np.uint8)
    rgba[..., 0] = 200
    rgba[:10, :, 3] = 255  # top half opaque red, bottom half transparent
    cover = load_cover(_encode(rgba))
    assert cover.shape == (20, 30, 3)
    assert tuple(cover[0, 0]) == (200, 0, 0)
    assert tuple(cover[-1, -1]) == (255, 255, 255)
    with pytest.raises(CloakError):
        load_cover(b"not an image")


@given(arrays(np.uint8, st.tuples(st.integers(2, 40), st.integers(2, 40), st.just(3))))
def test_any_rgb_cover_is_accepted(cover) -> None:
    png, _report = cloak(b"x", cover=cover)
    assert uncloak(png) == b"x"


def test_bad_arguments_are_refused() -> None:
    with pytest.raises(CloakError):
        cloak(b"x", bits=4)
    with pytest.raises(CloakError):
        cloak(b"x", cover=np.zeros((32, 32), np.uint8))
    with pytest.raises(CloakError):
        cloak(b"x", palette="neon")
