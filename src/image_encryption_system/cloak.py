"""Cloaked exports: hide a vault file inside an ordinary-looking PNG.

This is "visually meaningful encryption" done without weakening anything: the
image is still protected by the AES-256-GCM envelope inside the ``.ies`` file.
The cloak only changes what the file looks like. It writes the ``.ies`` bytes
into the low bits of a cover image's integer-wavelet detail coefficients, so
the result looks like the cover.

Layout (all of it public; the cloak is not a secret layer):

- The cover is RGB with even sides (an odd edge is cropped) and pixels clamped
  to ``[m, 255 - m]``, ``m = 2, 5, 10`` for ``k = 1, 2, 3`` bits per
  coefficient. That is the worst-case pixel change when every detail
  coefficient's low ``k`` bits change (``tests/test_iwt.py``), so no cloaked
  pixel leaves 0-255.
- Slots are every LH, HL and HH coefficient of every channel, in order
  (channel, band, row-major): ``M = 2.25 * width * height``. Stream slot ``s``
  is coefficient ``(a * s + b) mod M``, ``a`` the first integer from
  ``0.618 * M`` that is coprime to ``M`` and ``b = M // 3``, which spreads a
  small payload evenly over the picture.
- A 44-byte header goes in slots 0-351 at one bit each: ``b"IESK"``, version,
  ``k``, two reserved bytes, the payload length (uint32, big-endian) and the
  payload's SHA-256. The payload follows at ``k`` bits per slot, most
  significant bit first.
- Header and payload are XORed with a ChaCha20 keystream under the public key
  ``SHA-256(b"IES-CLOAK-V1")``, so the embedded bits look uniform rather than
  JSON-shaped. That is whitening, not encryption.

Anything that changes pixels (JPEG, resizing, palette reduction, editing)
destroys the payload, and the checksum turns that into a clean error rather
than a wrong file. Steganalysis can still tell that an image is cloaked.
"""

from __future__ import annotations

import hashlib
import math
import struct
import warnings
from dataclasses import dataclass
from io import BytesIO

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from numpy.typing import NDArray
from PIL import Image, ImageOps, UnidentifiedImageError

from . import iwt
from .covers import PALETTES, generate_cover
from .quality import psnr, ssim

CLOAK_MAGIC = b"IESK"
CLOAK_VERSION = 1
HEADER_BYTES = 44
HEADER_SLOTS = HEADER_BYTES * 8
BITS = (1, 2, 3)
MARGINS = {1: 2, 2: 5, 3: 10}
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
# One cloak's memory grows with the cover: at 12 MP and int16 coefficients an
# 8 MiB vault file stays well inside a 1 GB container shared by two workers.
DEFAULT_MAX_PIXELS = 12_000_000
DEFAULT_MAX_INPUT_PIXELS = 64_000_000
MIN_GENERATED_WIDTH, MIN_GENERATED_HEIGHT = 960, 640
COVER_FORMATS = ("PNG", "JPEG", "WEBP", "GIF", "BMP", "TIFF")

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_WHITENING_KEY = hashlib.sha256(b"IES-CLOAK-V1").digest()
_GOLDEN = 0.6180339887
_CHUNK = 1 << 20
_NOT_CLOAKED = "This image does not carry a vault file, or it was recompressed or edited."
_HEADER = struct.Struct(">4sBBHI32s")
_IMAGE_ERRORS = (
    OSError,
    ValueError,
    SyntaxError,
    struct.error,
    EOFError,
    IndexError,
    UnidentifiedImageError,
    Image.DecompressionBombError,
    Image.DecompressionBombWarning,
)

RGB = NDArray[np.uint8]


class CloakError(ValueError):
    """The image cannot be cloaked, or does not carry a cloaked vault file."""


@dataclass(frozen=True)
class CloakReport:
    width: int
    height: int
    bits: int
    payload_bytes: int
    capacity_bytes: int
    psnr: float
    ssim: float


def capacity(width: int, height: int, bits: int) -> int:
    """How many payload bytes a ``width`` x ``height`` cover holds at ``bits``."""
    slots = 9 * (width // 2) * (height // 2)
    return max(0, (slots - HEADER_SLOTS) * bits // 8)


def is_png(data: bytes) -> bool:
    return data[:8] == _PNG_SIGNATURE


def _multiplier(total: int) -> int:
    a = max(1, int(total * _GOLDEN))
    while math.gcd(a, total) != 1:
        a += 1
    return a


def slot_order(total: int) -> NDArray[np.int64]:
    """Coefficient index of every stream slot, in stream order (a permutation)."""
    return _slots(total, 0, total)


def _slots(total: int, start: int, stop: int) -> NDArray[np.int64]:
    a, b = _multiplier(total), total // 3
    return (np.arange(start, stop, dtype=np.int64) * a + b) % total


def _whitening(length: int) -> bytes:
    encryptor = Cipher(algorithms.ChaCha20(_WHITENING_KEY, bytes(16)), mode=None).encryptor()
    return encryptor.update(bytes(length))


def _xor(data: bytes, stream: bytes) -> bytes:
    return (np.frombuffer(data, np.uint8) ^ np.frombuffer(stream[: len(data)], np.uint8)).tobytes()


def _too_big(length: int, bits: int) -> CloakError:
    return CloakError(
        f"The vault file ({length:,} bytes) does not fit this cover at {bits} bit(s) "
        "per coefficient; use a larger cover."
    )


def _even(rgb: RGB) -> RGB:
    height, width = rgb.shape[0] - rgb.shape[0] % 2, rgb.shape[1] - rgb.shape[1] % 2
    return rgb[:height, :width]


def _size_to_fit(width: int, height: int, length: int, bits: int) -> tuple[int, int]:
    """The smallest even size of this shape whose capacity holds ``length`` bytes."""
    needed = HEADER_SLOTS + math.ceil(length * 8 / bits)
    scale = math.sqrt(needed / 2.25 / max(width * height, 1))
    width = max(width, math.ceil(width * scale))
    height = max(height, math.ceil(height * scale))
    width, height = width + width % 2, height + height % 2
    while capacity(width, height, bits) < length:
        width, height = width + 2, height + 2
    return width, height


def _generated_size(length: int, bits: int) -> tuple[int, int]:
    height = MIN_GENERATED_HEIGHT
    while True:
        width = math.ceil(height * 1.5)
        width += width % 2
        if capacity(width, height, bits) >= length:
            return width, height
        needed = HEADER_SLOTS + math.ceil(length * 8 / bits)
        height = max(height + 2, math.ceil(math.sqrt(needed / 2.25 / 1.5)))
        height += height % 2


def _resize(rgb: RGB, width: int, height: int) -> RGB:
    resized = Image.fromarray(rgb, "RGB").resize((width, height), Image.Resampling.LANCZOS)
    return np.asarray(resized, dtype=np.uint8)


def _validated_cover(cover: object) -> RGB:
    if (
        not isinstance(cover, np.ndarray)
        or cover.dtype != np.uint8
        or cover.ndim != 3
        or cover.shape[2] != 3
    ):
        raise CloakError(
            "A cover must be an RGB image (a uint8 array of shape height x width x 3)."
        )
    return _even(cover)


def _plan(
    length: int,
    cover: object | None,
    bits: int | None,
    seed: bytes,
    palette: str,
    max_pixels: int,
) -> tuple[RGB, int]:
    # Automatic bits prefer 2 and step up to 3 when that keeps the cover under
    # the pixel ceiling (a full 8 MiB vault file needs about 15 MP at 2 bits).
    candidates = (bits,) if bits is not None else (2, 3)
    if cover is None:
        if palette not in PALETTES:
            raise CloakError(f"Unknown palette {palette!r}; choose one of {', '.join(PALETTES)}.")
        for chosen in candidates:
            width, height = _generated_size(length, chosen)
            if width * height <= max_pixels:
                return generate_cover(width, height, seed=seed, palette=palette), chosen
        raise _too_big(length, candidates[-1])

    rgb = _validated_cover(cover)
    height, width = rgb.shape[:2]
    if width * height > max_pixels:
        raise CloakError(f"The cover is larger than {max_pixels:,} pixels; use a smaller picture.")
    allowed = BITS if bits is None else (bits,)
    fitting = [k for k in allowed if capacity(width, height, k) >= length]
    if fitting:
        chosen = fitting[0]
    else:
        for chosen in candidates:
            grown = _size_to_fit(max(width, 2), max(height, 2), length, chosen)
            if grown[0] * grown[1] <= max_pixels:
                break
        else:
            raise _too_big(length, candidates[-1])
        width, height = grown
        rgb = _resize(rgb, width, height)
    if rgb.shape[0] < 2 or rgb.shape[1] < 2:
        raise CloakError("The cover is too small.")
    return rgb, chosen


def _symbols(data: bytes, bits: int) -> NDArray[np.uint8]:
    """``data``'s bits, most significant first, grouped ``bits`` to a slot.

    Built with shifts in uint8: a weighted sum would promote to 8 bytes per slot.
    """
    stream = np.unpackbits(np.frombuffer(data, np.uint8))
    if bits == 1:
        return stream
    grouped = np.concatenate([stream, np.zeros(-stream.size % bits, np.uint8)]).reshape(-1, bits)
    symbols = np.zeros(grouped.shape[0], dtype=np.uint8)
    for column in range(bits):
        symbols |= grouped[:, column] << np.uint8(bits - 1 - column)
    return symbols


def _unsymbols(symbols: NDArray[np.integer], bits: int, length: int) -> bytes:
    shifts = np.arange(bits - 1, -1, -1)
    stream = ((symbols.astype(np.uint8)[:, None] >> shifts) & 1).astype(np.uint8).ravel()
    return np.packbits(stream[: length * 8]).tobytes()


def _forward(rgb: RGB, margin: int = 0) -> tuple[list[NDArray[np.int16]], NDArray[np.int16]]:
    """Per-channel LL bands, and every detail coefficient in slot order (flat).

    Pixels are clamped to ``[margin, 255 - margin]`` one channel at a time, and
    the detail array is allocated once and filled in place.
    """
    height, width = rgb.shape[:2]
    quarter = (height // 2) * (width // 2)
    lows: list[NDArray[np.int16]] = []
    details = np.empty(9 * quarter, dtype=np.int16)
    for channel in range(3):
        plane = rgb[..., channel]
        if margin:
            plane = np.clip(plane, margin, 255 - margin)
        ll, lh, hl, hh = iwt.forward(plane, dtype=np.int16)
        lows.append(ll.astype(np.int16, copy=False))
        for band_index, band in enumerate((lh, hl, hh)):
            start = (3 * channel + band_index) * quarter
            details[start : start + quarter] = band.ravel()
    return lows, details


def _embed(details: NDArray[np.int16], symbols: NDArray[np.uint8], bits: int) -> None:
    total = details.size
    for start in range(0, symbols.size, _CHUNK):
        stop = min(start + _CHUNK, symbols.size)
        where = _slots(total, start, stop)
        positions = np.arange(start, stop)
        masks = np.where(positions < HEADER_SLOTS, 1, (1 << bits) - 1).astype(np.int16)
        details[where] = (details[where] & ~masks) | symbols[start:stop].astype(np.int16)


def _read(details: NDArray[np.int16], start: int, stop: int, mask: int) -> NDArray[np.int16]:
    total = details.size
    pieces = [
        details[_slots(total, at, min(at + _CHUNK, stop))] & mask
        for at in range(start, stop, _CHUNK)
    ]
    return np.concatenate(pieces) if pieces else np.zeros(0, np.int16)


def cloak(
    payload: bytes,
    *,
    cover: object | None = None,
    bits: int | None = None,
    seed: bytes = b"",
    palette: str = "dusk",
    max_pixels: int = DEFAULT_MAX_PIXELS,
) -> tuple[bytes, CloakReport]:
    """Hide ``payload`` in ``cover`` (or a generated landscape) and return the PNG."""
    if not isinstance(payload, bytes):
        raise CloakError("The payload must be bytes.")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise CloakError("The vault file is too large to cloak.")
    if bits is not None and bits not in BITS:
        raise CloakError("Bits per coefficient must be 1, 2, or 3.")
    rgb, chosen = _plan(len(payload), cover, bits, seed, palette, max_pixels)
    height, width = rgb.shape[:2]

    stream = _whitening(HEADER_BYTES + len(payload))
    header = _HEADER.pack(
        CLOAK_MAGIC, CLOAK_VERSION, chosen, 0, len(payload), hashlib.sha256(payload).digest()
    )
    symbols = np.concatenate(
        [
            _symbols(_xor(header, stream[:HEADER_BYTES]), 1),
            _symbols(_xor(payload, stream[HEADER_BYTES:]), chosen),
        ]
    )
    lows, details = _forward(rgb, MARGINS[chosen])
    _embed(details, symbols, chosen)
    del symbols

    quarter = (height // 2) * (width // 2)
    shape = (height // 2, width // 2)
    stego = np.empty_like(rgb)
    for channel in range(3):
        offset = channel * 3 * quarter
        bands = [
            details[offset + i * quarter : offset + (i + 1) * quarter].reshape(shape)
            for i in range(3)
        ]
        pixels = iwt.inverse(lows[channel], *bands, dtype=np.int16)
        if int(np.min(pixels)) < 0 or int(np.max(pixels)) > 255:  # the margins rule this out
            raise CloakError("Internal error: a cloaked pixel left the 0-255 range.")
        stego[..., channel] = pixels.astype(np.uint8)

    buffer = BytesIO()
    Image.fromarray(stego, "RGB").save(buffer, format="PNG", compress_level=6)
    report = CloakReport(
        width=width,
        height=height,
        bits=chosen,
        payload_bytes=len(payload),
        capacity_bytes=capacity(width, height, chosen),
        psnr=psnr(rgb, stego),
        ssim=ssim(rgb, stego),
    )
    return buffer.getvalue(), report


def _open(data: bytes, formats: tuple[str, ...], max_pixels: int) -> Image.Image:
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        image = Image.open(BytesIO(data), formats=list(formats))
        width, height = image.size
        if width * height > max_pixels:
            image.close()
            raise CloakError(f"The image is too large ({width}x{height}).")
        image.load()
    return image


def uncloak(png_bytes: bytes, *, max_pixels: int = DEFAULT_MAX_INPUT_PIXELS) -> bytes:
    """The vault file hidden in a cloaked PNG, exactly as it was cloaked."""
    if not isinstance(png_bytes, bytes | bytearray) or not is_png(bytes(png_bytes)):
        raise CloakError(_NOT_CLOAKED)
    try:
        with _open(bytes(png_bytes), ("PNG",), max_pixels) as image:
            rgb = _even(np.asarray(image.convert("RGB"), dtype=np.uint8))
    except CloakError:
        raise
    except _IMAGE_ERRORS as exc:
        raise CloakError(_NOT_CLOAKED) from exc
    height, width = rgb.shape[:2]
    if 9 * (width // 2) * (height // 2) < HEADER_SLOTS:
        raise CloakError(_NOT_CLOAKED)

    _lows, details = _forward(rgb)
    header_bits = _read(details, 0, HEADER_SLOTS, 1)
    header = _xor(_unsymbols(header_bits, 1, HEADER_BYTES), _whitening(HEADER_BYTES))
    magic, version, bits, reserved, length, digest = _HEADER.unpack(header)
    if (
        magic != CLOAK_MAGIC
        or version != CLOAK_VERSION
        or bits not in BITS
        or reserved != 0
        or length > min(capacity(width, height, bits), MAX_PAYLOAD_BYTES)
    ):
        raise CloakError(_NOT_CLOAKED)

    slots = math.ceil(length * 8 / bits)
    symbols = _read(details, HEADER_SLOTS, HEADER_SLOTS + slots, (1 << bits) - 1)
    whitened = _unsymbols(symbols, bits, length)
    payload = _xor(whitened, _whitening(HEADER_BYTES + length)[HEADER_BYTES:])
    if hashlib.sha256(payload).digest() != digest:
        raise CloakError(_NOT_CLOAKED)
    return payload


def load_cover(image_bytes: bytes, *, max_pixels: int = DEFAULT_MAX_INPUT_PIXELS) -> RGB:
    """Decode a cover picture to RGB: first frame, upright, transparency on white."""
    try:
        with _open(image_bytes, COVER_FORMATS, max_pixels) as image:
            upright = ImageOps.exif_transpose(image) or image
            if upright.mode in {"RGBA", "LA", "PA"} or (
                upright.mode == "P" and "transparency" in upright.info
            ):
                rgba = upright.convert("RGBA")
                canvas = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
                upright = Image.alpha_composite(canvas, rgba)
            return np.asarray(upright.convert("RGB"), dtype=np.uint8).copy()
    except CloakError:
        raise
    except _IMAGE_ERRORS as exc:
        raise CloakError("The cover image could not be read.") from exc
