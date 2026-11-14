"""The interface every lab cipher implements.

A cipher turns a lab image into a :class:`Ciphertext` and back. ``payload`` is
exactly what the cipher emits (what would be stored or sent), and decryption
reads nothing else, so flipping a payload bit is a real tamper test. ``pixels``
is that payload as an image when the ciphertext body is a byte image (what the
structure attack works on), and ``view`` is how the ciphertext is shown and
measured.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar, TypeVar

import numpy as np
from numpy.typing import NDArray

from . import keys
from .imaging import LAB_SIZES

Image = NDArray[np.uint8]
T = TypeVar("T")


class LabDecryptError(Exception):
    """An authenticated lab cipher refused to decrypt."""


@dataclass(frozen=True)
class Ciphertext:
    payload: bytes
    shape: tuple[int, int, int]
    pixels: Image | None
    view: Image


def check_image(image: object) -> int:
    """The side ``S`` of a valid lab image (uint8, ``S`` x ``S`` x 3, ``S`` a lab size)."""
    if (
        not isinstance(image, np.ndarray)
        or image.dtype != np.uint8
        or image.ndim != 3
        or image.shape[2] != 3
        or image.shape[0] != image.shape[1]
        or image.shape[0] not in LAB_SIZES
    ):
        raise ValueError(
            "A lab image is a uint8 array of shape S x S x 3, with S one of "
            f"{', '.join(map(str, LAB_SIZES))}."
        )
    return int(image.shape[0])


def byte_ciphertext(pixels: Image, payload: bytes | None = None) -> Ciphertext:
    """A ciphertext whose body is the byte image ``pixels``."""
    pixels = np.ascontiguousarray(pixels, dtype=np.uint8)
    shape = (int(pixels.shape[0]), int(pixels.shape[1]), int(pixels.shape[2]))
    return Ciphertext(
        payload=pixels.tobytes() if payload is None else payload,
        shape=shape,
        pixels=pixels,
        view=pixels,
    )


def payload_pixels(ct: Ciphertext) -> Image:
    """A byte-image payload back as an image (a fresh, writable array)."""
    return np.frombuffer(ct.payload, dtype=np.uint8).reshape(ct.shape).copy()


def min_max_view(values: NDArray[np.floating]) -> Image:
    """Show ``(3, S, S)`` real values as an ``(S, S, 3)`` image, each channel stretched."""
    low = values.min(axis=(1, 2), keepdims=True)
    span = np.maximum(values.max(axis=(1, 2), keepdims=True) - low, 1e-12)
    scaled = np.rint((values - low) / span * 255)
    return np.ascontiguousarray(np.moveaxis(scaled, 0, -1).astype(np.uint8))


class LabCipher:
    """One lab cipher, keyed by a 32-byte lab key."""

    name: ClassVar[str]
    title: ClassVar[str]
    family: ClassVar[str]
    summary: ClassVar[str]
    randomized: ClassVar[bool] = False
    authenticated: ClassVar[bool] = False
    key_bits: ClassVar[int] = 256
    key_note: ClassVar[str] = "Every parameter comes from the 256-bit key."
    transform: ClassVar[str | None] = None
    linear_domain: ClassVar[str | None] = None

    def __init__(self, key: bytes) -> None:
        keys.derive(key, "check", 1)  # validates the key
        self.key = key
        self._material: dict[Any, Any] = {}

    def _memo(self, size: int, build: Callable[[], T]) -> T:
        """Key material for one image size, built once per cipher instance.

        Cached on the instance, not globally by key: every web lab run uses a
        fresh key, and a global cache would keep each run's material forever.
        """
        if size not in self._material:
            self._material[size] = build()
        result: T = self._material[size]
        return result

    def encrypt(self, image: Image, *, nonce: bytes | None = None) -> Ciphertext:
        size = check_image(image)
        return self._encrypt(image, size, nonce)

    def decrypt(self, ct: Ciphertext) -> Image:
        return self._decrypt(ct)

    def tamper_position(self, ct: Ciphertext) -> tuple[int, int]:
        """The byte and bit mask the tamper test flips: the middle of the payload."""
        return len(ct.payload) // 2, 0x10

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        raise NotImplementedError

    def _decrypt(self, ct: Ciphertext) -> Image:
        raise NotImplementedError
