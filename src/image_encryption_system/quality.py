"""Image fidelity: PSNR and SSIM, for cloaked images against their covers."""

from __future__ import annotations

import math

import numpy as np
from numpy.typing import NDArray

PEAK = 255.0
# Wang, Bovik, Sheikh and Simoncelli (2004): K1 = 0.01, K2 = 0.03, L = 255.
_C1 = (0.01 * PEAK) ** 2
_C2 = (0.03 * PEAK) ** 2
WINDOW = 8


def _pair(a: NDArray[np.generic], b: NDArray[np.generic]) -> tuple[NDArray[np.float64], ...]:
    left, right = np.asarray(a, dtype=np.float64), np.asarray(b, dtype=np.float64)
    if left.shape != right.shape:
        raise ValueError("Images must have the same shape.")
    if left.ndim == 2:
        left, right = left[..., None], right[..., None]
    return left, right


def psnr(a: NDArray[np.generic], b: NDArray[np.generic]) -> float:
    """Peak signal-to-noise ratio in dB for 8-bit images; ``inf`` when identical."""
    left, right = _pair(a, b)
    mse = float(np.mean((left - right) ** 2))
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
    scores = []
    for channel in range(left.shape[2]):
        x, y = left[..., channel], right[..., channel]
        mx, my = _box_mean(x, size), _box_mean(y, size)
        vx = _box_mean(x * x, size) - mx * mx
        vy = _box_mean(y * y, size) - my * my
        cov = _box_mean(x * y, size) - mx * my
        numerator = (2 * mx * my + _C1) * (2 * cov + _C2)
        denominator = (mx * mx + my * my + _C1) * (vx + vy + _C2)
        scores.append(float(np.mean(numerator / denominator)))
    return float(np.mean(scores))
