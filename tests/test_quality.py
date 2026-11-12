"""PSNR and SSIM: how far a cloaked image is from its cover."""

from __future__ import annotations

import math

import numpy as np
import pytest

from image_encryption_system.quality import psnr, ssim


def test_psnr_identical_is_inf_and_known_value() -> None:
    image = np.full((8, 8, 3), 100, dtype=np.uint8)
    assert psnr(image, image) == math.inf
    changed = image.copy()
    changed[3, 4, 1] = 101
    assert psnr(image, changed) == pytest.approx(10 * math.log10(255**2 * 192))


def test_ssim_is_one_for_identical_and_low_for_noise() -> None:
    ramp = np.linspace(0, 255, 64 * 64).reshape(64, 64)
    gradient = np.stack([ramp, ramp.T, 255 - ramp], axis=-1).astype(np.uint8)
    noise = np.random.default_rng(3).integers(0, 256, gradient.shape, dtype=np.uint8)
    assert ssim(gradient, gradient) == pytest.approx(1.0)
    assert ssim(gradient, noise) < 0.5


def test_ssim_falls_as_noise_grows() -> None:
    rng = np.random.default_rng(5)
    ramp = np.linspace(20, 230, 48 * 48).reshape(48, 48)
    base = np.stack([ramp] * 3, axis=-1)
    scores = [
        ssim(
            base.astype(np.uint8),
            np.clip(base + rng.normal(0, sigma, base.shape), 0, 255).astype(np.uint8),
        )
        for sigma in (1, 8, 40)
    ]
    assert scores[0] > scores[1] > scores[2]


def test_shapes_must_match() -> None:
    with pytest.raises(ValueError):
        psnr(np.zeros((4, 4, 3), np.uint8), np.zeros((4, 5, 3), np.uint8))
    with pytest.raises(ValueError):
        ssim(np.zeros((4, 4), np.uint8), np.zeros((5, 4), np.uint8))
