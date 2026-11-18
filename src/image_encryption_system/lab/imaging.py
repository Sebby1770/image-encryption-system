"""Images for the lab: preparing uploads, built-in samples, and encodings.

Lab images are ``(S, S, 3)`` uint8 arrays with ``S`` a power of two from 32 to
512, which satisfies every lab cipher at once (Arnold needs a square,
Walsh-Hadamard a power of two, the neural cipher a multiple of 4, AES whole
16-byte blocks).
"""

from __future__ import annotations

import warnings
from base64 import b64encode
from functools import lru_cache
from io import BytesIO

import numpy as np
from numpy.typing import NDArray
from PIL import Image, ImageOps

from ..covers import generate_cover

LAB_SIZES = (32, 64, 128, 256, 512)
SAMPLES = ("test-card", "gradient", "landscape")
LAB_FORMATS = ["PNG", "JPEG", "WEBP", "GIF", "BMP", "TIFF"]
MAX_INPUT_PIXELS = 64_000_000
_UNREADABLE = "This file is not an image the lab can read."

RGB = NDArray[np.uint8]


def _check_size(size: int) -> None:
    if size not in LAB_SIZES:
        raise ValueError(f"The lab works at {', '.join(map(str, LAB_SIZES))} pixels square.")


def _to_rgb(image: Image.Image) -> Image.Image:
    if image.mode.startswith("I;16") or image.mode in {"I", "F"}:
        values = np.asarray(image, dtype=np.float64)
        scale = 257.0 if image.mode != "F" and float(np.max(values)) > 255 else 1.0
        image = Image.fromarray(np.clip(np.rint(values / scale), 0, 255).astype(np.uint8), "L")
    if image.mode in {"RGBA", "LA", "PA"} or (image.mode == "P" and "transparency" in image.info):
        rgba = image.convert("RGBA")
        image = Image.alpha_composite(Image.new("RGBA", rgba.size, (255, 255, 255, 255)), rgba)
    return image.convert("RGB")


def prepare(image_bytes: bytes, size: int = 256) -> RGB:
    """An uploaded image as a lab image: first frame, upright, square, ``size`` px."""
    _check_size(size)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(image_bytes), formats=LAB_FORMATS) as image:
                width, height = image.size
                if width * height > MAX_INPUT_PIXELS:
                    raise ValueError(f"{_UNREADABLE} It is too large.")
                image.seek(0)
                image.load()
                upright = ImageOps.exif_transpose(image) or image
                rgb = _to_rgb(upright)
    except ValueError:
        raise
    except Exception as exc:  # Pillow raises many types for damaged input
        raise ValueError(_UNREADABLE) from exc
    side = min(rgb.size)
    left, top = (rgb.width - side) // 2, (rgb.height - side) // 2
    square = rgb.crop((left, top, left + side, top + side))
    resized = square.resize((size, size), Image.Resampling.LANCZOS)
    return np.asarray(resized, dtype=np.uint8).copy()


def _test_card(size: int) -> RGB:
    """Colour bars, ramps, flat discs and a checkerboard: plenty of flat regions."""
    card = np.full((size, size, 3), 120, dtype=np.uint8)
    bars = [(235, 235, 235), (230, 210, 40), (40, 200, 210), (50, 180, 60),
            (200, 50, 190), (210, 40, 40), (40, 60, 200), (20, 20, 20)]  # fmt: skip
    top = size * 3 // 8
    width = size // len(bars)
    for i, colour in enumerate(bars):
        card[:top, i * width : (i + 1) * width] = colour
    ramp = np.linspace(0, 255, size).astype(np.uint8)
    card[top : top + size // 8] = ramp[None, :, None]
    lower = top + size // 8
    rows, cols = np.mgrid[lower:size, 0:size]
    for centre_col, colour in ((size // 4, (240, 120, 30)), (3 * size // 4, (30, 140, 230))):
        disc = (rows - (lower + size) // 2) ** 2 + (cols - centre_col) ** 2 <= (size // 7) ** 2
        card[lower:size][disc] = colour
    square = max(2, size // 16)
    checks = ((rows // square + cols // square) % 2).astype(bool) & (cols >= size * 3 // 8)
    checks &= cols < size * 5 // 8
    card[lower:size][checks] = 30
    card[lower:size][~checks & (cols >= size * 3 // 8) & (cols < size * 5 // 8)] = 225
    return card


def _gradient(size: int) -> RGB:
    ramp = np.linspace(0, 255, size)
    across, down = np.meshgrid(ramp, ramp)
    return np.stack([across, down, (across + down) / 2], axis=-1).astype(np.uint8)


@lru_cache(maxsize=32)
def _sample(name: str, size: int) -> RGB:
    if name == "test-card":
        image = _test_card(size)
    elif name == "gradient":
        image = _gradient(size)
    elif name == "landscape":
        image = generate_cover(size, size, seed=b"lab", palette="dusk")
    else:
        raise ValueError(f"Unknown sample {name!r}; choose one of {', '.join(SAMPLES)}.")
    image.setflags(write=False)
    return image


def sample(name: str, size: int = 256) -> RGB:
    """A built-in sample image (a fresh, writable copy)."""
    _check_size(size)
    return _sample(name, size).copy()


def to_png(image: RGB) -> bytes:
    buffer = BytesIO()
    Image.fromarray(image, "RGB").save(buffer, format="PNG")
    return buffer.getvalue()


def to_jpeg(image: RGB, quality: int = 85) -> bytes:
    buffer = BytesIO()
    Image.fromarray(image, "RGB").save(buffer, format="JPEG", quality=quality)
    return buffer.getvalue()


def data_uri(data: bytes, mime: str) -> str:
    return f"data:{mime};base64,{b64encode(data).decode('ascii')}"
