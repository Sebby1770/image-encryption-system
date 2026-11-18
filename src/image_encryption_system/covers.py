"""Procedural landscape covers: ordinary-looking pictures for cloaked exports.

A cloaked export hides a vault file inside a picture. When the owner brings no
photo of their own, this draws one: a sky gradient with a soft sun and clouds,
three ridgelines that fade into haze with distance, foreground hills, and light
film grain. Every value lands in [10, 245], so the cloak never has to clamp a
generated cover to make room for its embedding margins.

All randomness comes from a ChaCha20 keystream keyed by the seed and palette,
not from numpy's generators, whose streams may change between numpy versions;
the same seed draws the same picture. Rows are rendered in bands, so a large
cover never needs more than a few bands' worth of temporary arrays.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from numpy.typing import NDArray

PALETTES = ("dusk", "alpine", "desert", "ocean")
MIN_SIDE = 16
LOW, HIGH = 10, 245
_BAND_ROWS = 256

Floats = NDArray[np.float32]
Colour = NDArray[np.float32]


@dataclass(frozen=True)
class _Palette:
    sky_top: tuple[int, int, int]
    horizon: tuple[int, int, int]
    sun: tuple[int, int, int]
    cloud: tuple[int, int, int]
    mountain: tuple[int, int, int]
    ground: tuple[int, int, int]


_COLOURS = {
    "dusk": _Palette(
        (38, 44, 92), (236, 152, 112), (255, 214, 150), (250, 196, 170), (70, 58, 96), (40, 34, 56)
    ),
    "alpine": _Palette(
        (60, 120, 200),
        (190, 220, 240),
        (255, 250, 230),
        (245, 248, 252),
        (90, 110, 130),
        (62, 102, 62),
    ),
    "desert": _Palette(
        (90, 150, 210),
        (240, 210, 170),
        (255, 240, 200),
        (250, 240, 225),
        (180, 110, 70),
        (210, 160, 100),
    ),
    "ocean": _Palette(
        (30, 80, 140),
        (170, 210, 225),
        (255, 245, 220),
        (235, 242, 248),
        (40, 90, 110),
        (20, 70, 100),
    ),
}

# Far to near: (top of the ridge band as a fraction of the height, how tall the
# peaks may rise, base lattice cells, how much the horizon colour hazes it).
_RIDGES = (
    ((0.46, 0.54), 0.14, 3, 0.62),
    ((0.56, 0.63), 0.11, 4, 0.38),
    ((0.66, 0.72), 0.08, 5, 0.16),
)


class _Stream:
    """Uniform randomness from a ChaCha20 keystream."""

    def __init__(self, key: bytes) -> None:
        self._encryptor = Cipher(algorithms.ChaCha20(key, bytes(16)), mode=None).encryptor()

    def bytes(self, count: int) -> bytes:
        return self._encryptor.update(bytes(count))

    def uniform(self, count: int) -> NDArray[np.float64]:
        words = np.frombuffer(self.bytes(4 * count), dtype="<u4")
        return words.astype(np.float64) / 2.0**32

    def between(self, low: float, high: float) -> float:
        return low + (high - low) * float(self.uniform(1)[0])


def _smooth(t: NDArray[np.floating]) -> NDArray[np.floating]:
    return t * t * (3.0 - 2.0 * t)


def _fbm_1d(stream: _Stream, u: NDArray[np.float64], cells: int, octaves: int) -> Floats:
    """Fractal value noise along one axis, in [0, 1]."""
    total = np.zeros_like(u)
    weight, amplitude = 0.0, 1.0
    for _ in range(octaves):
        lattice = stream.uniform(cells + 2)
        x = u * cells
        index = np.floor(x).astype(np.int64)
        t = _smooth(x - index)
        total += amplitude * (lattice[index] * (1 - t) + lattice[index + 1] * t)
        weight += amplitude
        amplitude *= 0.5
        cells *= 2
    return (total / weight).astype(np.float32)


class _Noise2D:
    """Fractal value noise over the image, interpolated along x once, rows on demand."""

    def __init__(
        self, stream: _Stream, u: NDArray[np.float64], cells_x: int, cells_y: int, octaves: int
    ) -> None:
        self._octaves: list[tuple[Floats, int, float]] = []
        amplitude = 1.0
        for _ in range(octaves):
            lattice = stream.uniform((cells_y + 2) * (cells_x + 2)).reshape(
                cells_y + 2, cells_x + 2
            )
            x = u * cells_x
            index = np.floor(x).astype(np.int64)
            t = _smooth(x - index)
            across = lattice[:, index] * (1 - t) + lattice[:, index + 1] * t
            self._octaves.append((across.astype(np.float32), cells_y, amplitude))
            cells_x, cells_y, amplitude = cells_x * 2, cells_y * 2, amplitude * 0.5
        self._weight = float(sum(amplitude for _, _, amplitude in self._octaves))

    def rows(self, v: NDArray[np.float64]) -> Floats:
        width = self._octaves[0][0].shape[1]
        out = np.zeros((v.size, width), dtype=np.float32)
        for across, cells_y, amplitude in self._octaves:
            y = v * cells_y
            index = np.floor(y).astype(np.int64)
            t = _smooth(y - index).astype(np.float32)[:, None]
            out += amplitude * (across[index] * (1 - t) + across[index + 1] * t)
        return out / self._weight


def _colour(rgb: tuple[int, int, int]) -> Colour:
    return np.asarray(rgb, dtype=np.float32)


def generate_cover(
    width: int, height: int, *, seed: bytes, palette: str = "dusk"
) -> NDArray[np.uint8]:
    """An ``(height, width, 3)`` landscape, every value in [10, 245]."""
    if palette not in _COLOURS:
        raise ValueError(f"Unknown palette {palette!r}; choose one of {', '.join(PALETTES)}.")
    if width < MIN_SIDE or height < MIN_SIDE:
        raise ValueError(f"A cover must be at least {MIN_SIDE} pixels on each side.")
    if not isinstance(seed, bytes):
        raise ValueError("The cover seed must be bytes.")
    colours = _COLOURS[palette]
    stream = _Stream(hashlib.sha256(b"IES-COVER\x00" + palette.encode() + b"\x00" + seed).digest())

    aspect = width / height
    u = (np.arange(width, dtype=np.float64) + 0.5) / width
    sun_u, sun_v = stream.between(0.2, 0.8), stream.between(0.22, 0.42)
    ridges = []
    for (low, high), rise, cells, haze in _RIDGES:
        base = stream.between(low, high)
        # Averaged octaves cluster around 0.5; stretch each profile to its full
        # range so the peaks actually rise.
        profile = _fbm_1d(stream, u, cells, 6)
        low_point = float(np.min(profile))
        profile = (profile - low_point) / max(float(np.max(profile)) - low_point, 1e-6)
        top = base - rise * profile
        tint = (1 - haze) * _colour(colours.mountain) + haze * _colour(colours.horizon)
        ridges.append((top, tint))
    ground_top = 0.84 - 0.05 * _fbm_1d(stream, u, 3, 5)
    cloud_cells = max(2, round(2 * aspect))
    clouds = _Noise2D(stream, u, cloud_cells, 2, 4)
    texture = _Noise2D(stream, u, max(8, round(40 * aspect)), 40, 4)

    sky_top, horizon = _colour(colours.sky_top), _colour(colours.horizon)
    sun, cloud, ground = _colour(colours.sun), _colour(colours.cloud), _colour(colours.ground)
    across = u.astype(np.float32)[None, :]
    out = np.empty((height, width, 3), dtype=np.uint8)
    for start in range(0, height, _BAND_ROWS):
        rows = min(_BAND_ROWS, height - start)
        v = (np.arange(start, start + rows, dtype=np.float64) + 0.5) / height
        down = v.astype(np.float32)[:, None]

        mix = np.clip(down / 0.78, 0, 1)[..., None]
        image = np.broadcast_to((1 - mix) * sky_top + mix * horizon, (rows, width, 3)).copy()

        distance = np.sqrt(((across - sun_u) * aspect) ** 2 + (down - sun_v) ** 2)
        glow = 0.5 * np.exp(-((distance / 0.09) ** 2)) + 0.22 * np.exp(-((distance / 0.3) ** 2))
        disk = np.clip((0.036 - distance) / 0.006, 0, 1)
        image += (sun - image) * np.clip(glow + disk, 0, 1)[..., None]

        cloudiness = np.clip((clouds.rows(v) - 0.55) / 0.25, 0, 1)
        cover = _smooth(cloudiness) * np.clip(1 - down / 0.6, 0, 1) * 0.7
        image += (cloud - image) * cover[..., None]

        grain_texture = texture.rows(v)
        for top, tint in ridges:
            inside = down >= top[None, :]
            slope = np.clip((down - top[None, :]) * 3, 0, 1)
            shade = (0.84 + 0.3 * grain_texture) * (1 - 0.15 * slope)
            image = np.where(inside[..., None], tint * shade[..., None], image)

        inside = down >= ground_top[None, :]
        depth = np.clip((down - ground_top[None, :]) / 0.16, 0, 1)
        shade = (0.75 + 0.4 * grain_texture) * (1 - 0.35 * depth)
        image = np.where(inside[..., None], ground * shade[..., None], image)

        grain = np.frombuffer(stream.bytes(rows * width), dtype=np.uint8).reshape(rows, width)
        image += (grain.astype(np.float32) * (4 / 255) - 2)[..., None]
        scaled = LOW + np.clip(image, 0, 255) * ((HIGH - LOW) / 255)
        out[start : start + rows] = np.clip(np.rint(scaled), LOW, HIGH).astype(np.uint8)
    return out
