"""Transform-domain ciphers that are linear, and so fall to one chosen image.

Both scramble an image in a transform domain with a keyed mask and transform
back. Neither is a byte image afterwards: the ciphertexts are float64
(Walsh-Hadamard) and complex128 (Fourier), 8 and 16 times larger than the
image. Both are linear in the plaintext, so encrypting a single impulse
reveals the whole mask (``attacks.impulse_attack``).
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from . import keys, transforms
from .base import Ciphertext, Image, LabCipher, min_max_view

Complex = NDArray[np.complex128]


def _planes(image: Image) -> NDArray[np.float64]:
    return np.moveaxis(image, -1, 0).astype(np.float64)


def _real(values: NDArray[np.number]) -> NDArray[np.float64]:
    return np.asarray(values, dtype=np.float64)


def _to_image(planes: NDArray[np.float64]) -> Image:
    # A tampered float can decode to inf or NaN: clamp, never crash.
    values = np.nan_to_num(planes, nan=0.0, posinf=255.0, neginf=0.0)
    return np.ascontiguousarray(np.moveaxis(np.clip(np.rint(values), 0, 255), 0, -1)).astype(
        np.uint8
    )


def _middle_element(ct: Ciphertext, width: int) -> tuple[int, int]:
    """Flip the top mantissa bit of the middle value, so the change is not lost to rounding."""
    middle = (len(ct.payload) // width) // 2
    return middle * width + 6, 0x08


class WalshHadamardCipher(LabCipher):
    """A keyed sign mask on every channel's Walsh-Hadamard coefficients."""

    name = "wht"
    title = "Walsh-Hadamard mask"
    family = "transform"
    summary = (
        "Flips the sign of a key-chosen half of each channel's Walsh-Hadamard "
        "coefficients, then transforms back."
    )
    key_note = (
        "One mask bit per coefficient, expanded from the 256-bit key; one chosen image "
        "recovers the whole mask."
    )
    linear_domain = "wht"

    def mask(self, size: int) -> NDArray[np.float64]:
        def build() -> NDArray[np.float64]:
            material = np.frombuffer(keys.stream(self.key, "wht", 3 * size * size // 8), np.uint8)
            bits = np.unpackbits(material).reshape(3, size, size)
            return 1.0 - 2.0 * bits.astype(np.float64)

        return self._memo(size, build)

    def coefficients(self, ct: Ciphertext) -> NDArray[np.float64]:
        size = ct.shape[0]
        return np.frombuffer(ct.payload, dtype="<f8").reshape(3, size, size).copy()

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        scrambled = self.mask(size) * transforms.walsh_hadamard_2d(_planes(image))
        cipher = _real(transforms.walsh_hadamard_2d(scrambled)) / (size * size)
        return Ciphertext(cipher.astype("<f8").tobytes(), image.shape, None, min_max_view(cipher))

    def _decrypt(self, ct: Ciphertext) -> Image:
        size = ct.shape[0]
        cipher = self.coefficients(ct)
        planes = _real(
            transforms.walsh_hadamard_2d(self.mask(size) * transforms.walsh_hadamard_2d(cipher))
        )
        return _to_image(planes / (size * size))

    def tamper_position(self, ct: Ciphertext) -> tuple[int, int]:
        return _middle_element(ct, 8)


class DrpeCipher(LabCipher):
    """Double random phase encoding: random phases before and after a Fourier transform."""

    name = "drpe"
    title = "Double random phase encoding"
    family = "transform (Fourier)"
    summary = (
        "Optical-style encryption: multiply by a random phase, Fourier transform, "
        "multiply by a second random phase, transform back."
    )
    key_note = (
        "Two phase masks expanded from the 256-bit key; one chosen impulse image "
        "recovers the Fourier-plane mask."
    )
    linear_domain = "fourier"

    def masks(self, size: int) -> tuple[Complex, Complex]:
        def build() -> tuple[Complex, Complex]:
            raw = np.frombuffer(keys.stream(self.key, "drpe", 24 * size * size), dtype="<u4")
            phases = raw.astype(np.float64).reshape(2, 3, size, size) / 2.0**32
            first, second = np.exp(2j * np.pi * phases)
            return first, second

        return self._memo(size, build)

    def coefficients(self, ct: Ciphertext) -> Complex:
        size = ct.shape[0]
        return np.frombuffer(ct.payload, dtype="<c16").reshape(3, size, size).copy()

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        first, second = self.masks(size)
        spectrum = np.fft.fft2(_planes(image) / 255.0 * first, axes=(-2, -1))
        cipher = np.fft.ifft2(spectrum * second, axes=(-2, -1))
        return Ciphertext(
            cipher.astype("<c16").tobytes(), image.shape, None, min_max_view(np.abs(cipher))
        )

    def _decrypt(self, ct: Ciphertext) -> Image:
        first, second = self.masks(ct.shape[0])
        cipher = self.coefficients(ct)
        restored = np.fft.ifft2(np.fft.fft2(cipher, axes=(-2, -1)) * np.conj(second), axes=(-2, -1))
        return _to_image(255.0 * np.real(restored * np.conj(first)))

    def tamper_position(self, ct: Ciphertext) -> tuple[int, int]:
        return _middle_element(ct, 16)
