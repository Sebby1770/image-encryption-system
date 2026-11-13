"""Image fidelity: PSNR and SSIM, for cloaked images against their covers.

Both work through the image in bands of rows, so scoring a 24-megapixel cover
needs a few megabytes of temporaries rather than several gigabytes of float64
copies. Banding does not change either score.
"""

from __future__ import annotations

import math

import numpy as np
from numpy.typing import NDArray

PEAK = 255.0
# Wang, Bovik, Sheikh and Simoncelli (2004): K1 = 0.01, K2 = 0.03, L = 255.
_C1 = (0.01 * PEAK) ** 2
_C2 = (0.03 * PEAK) ** 2
WINDOW = 8
_BAND = 256


def _pair(a: NDArray[np.generic], b: NDArray[np.generic]) -> tuple[NDArray[np.generic], ...]:
    left, right = np.asarray(a), np.asarray(b)
    if left.shape != right.shape:
        raise ValueError("Images must have the same shape.")
    if left.ndim == 2:
        left, right = left[..., None], right[..., None]
    if left.ndim != 3:
        raise ValueError("Images must be 2-D or 3-D arrays.")
    return left, right


def psnr(a: NDArray[np.generic], b: NDArray[np.generic]) -> float:
    """Peak signal-to-noise ratio in dB for 8-bit images; ``inf`` when identical."""
    left, right = _pair(a, b)
    squared = 0.0
    for start in range(0, left.shape[0], _BAND):
        difference = left[start : start + _BAND].astype(np.float64) - right[
            start : start + _BAND
        ].astype(np.float64)
        squared += float(np.sum(difference * difference))
    mse = squared / left.size if left.size else 0.0
    return math.inf if mse == 0 else 10 * math.log10(PEAK**2 / mse)


def _box_mean(x: NDArray[np.float64], size: int) -> NDArray[np.float64]:
    """Mean over every ``size`` x ``size`` window (stride 1), from an integral image."""
    integral = np.pad(x, ((1, 0), (1, 0))).cumsum(axis=0).cumsum(axis=1)
    window = (
        integral[size:, size:]
        - integral[:-size, size:]
        - integral[size:, :-size]
        + integral[:-size, :-size]
    )
    return window / (size * size)


def ssim(a: NDArray[np.generic], b: NDArray[np.generic]) -> float:
    """Mean SSIM over sliding 8x8 uniform windows, averaged over channels."""
    left, right = _pair(a, b)
    size = min(WINDOW, left.shape[0], left.shape[1])
    window_rows = left.shape[0] - size + 1
    total, count = 0.0, 0
    for channel in range(left.shape[2]):
        for start in range(0, window_rows, _BAND):
            stop = min(start + _BAND, window_rows)
            rows = slice(start, stop + size - 1)
            x = left[rows, :, channel].astype(np.float64)
            y = right[rows, :, channel].astype(np.float64)
            mx, my = _box_mean(x, size), _box_mean(y, size)
            vx = _box_mean(x * x, size) - mx * mx
            vy = _box_mean(y * y, size) - my * my
            cov = _box_mean(x * y, size) - mx * my
            numerator = (2 * mx * my + _C1) * (2 * cov + _C2)
            denominator = (mx * mx + my * my + _C1) * (vx + vy + _C2)
            scores = numerator / denominator
            total += float(np.sum(scores))
            count += scores.size
    return total / count
