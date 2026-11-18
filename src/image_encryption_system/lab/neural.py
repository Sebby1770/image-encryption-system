"""A keyed integer neural network: "neural obfuscation" that is exactly invertible.

GAN-based image "encryption" is lossy: the original cannot be recovered
exactly. This cipher is the lossless alternative, built like an integer
discrete flow (Hoogeboom et al., 2019). Every 4x4x3 patch (48 bytes) passes
through eight additive coupling layers. Each layer shuffles the 48 values,
keeps half (A), and adds a keyed network's output to the other half (B):

    B <- (B + f(A)) mod 256,   f(A) = (W2 . sigma((W1 . A + b1) mod 256) + b2) mod 256

``sigma`` is a keyed byte permutation (the nonlinearity), and every weight is
an integer drawn from the key. Subtracting ``f(A)`` undoes a layer exactly,
on any machine, because no floating point is involved.

It still leaks: the network is the same for every patch, so equal patches
encrypt to equal patches, exactly like a block cipher in ECB mode.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from . import keys
from .base import Ciphertext, Image, LabCipher, byte_ciphertext, payload_pixels

PATCH = 4
WIDTH = PATCH * PATCH * 3  # 48 values per patch
HALF = WIDTH // 2
HIDDEN = 32
LAYERS = 8
# shuffle (48 uint32), W1 (32x24), b1 (32), sigma (256 uint32), W2 (24x32), b2 (24)
_LAYER_BYTES = WIDTH * 4 + HIDDEN * HALF + HIDDEN + 256 * 4 + HALF * HIDDEN + HALF

Ints = NDArray[np.int64]
Layer = tuple[Ints, Ints, Ints, Ints, Ints, Ints, Ints]


def _layers(key: bytes) -> list[Layer]:
    material = keys.stream(key, "neural", LAYERS * _LAYER_BYTES)
    cursor = 0

    def take(count: int, dtype: str) -> Ints:
        nonlocal cursor
        size = count * np.dtype(dtype).itemsize
        values = np.frombuffer(material[cursor : cursor + size], dtype=dtype).astype(np.int64)
        cursor += size
        return values

    layers = []
    for _ in range(LAYERS):
        shuffle = np.argsort(take(WIDTH, "<u4"), kind="stable")
        w1 = take(HIDDEN * HALF, "u1").reshape(HIDDEN, HALF)
        b1 = take(HIDDEN, "u1")
        sigma = np.argsort(take(256, "<u4"), kind="stable")
        w2 = take(HALF * HIDDEN, "u1").reshape(HALF, HIDDEN)
        b2 = take(HALF, "u1")
        layers.append((shuffle, np.argsort(shuffle), w1, b1, sigma, w2, b2))
    return layers


def _network(a: Ints, layer: Layer) -> Ints:
    _shuffle, _unshuffle, w1, b1, sigma, w2, b2 = layer
    hidden = sigma[(a @ w1.T + b1) % 256]
    return (hidden @ w2.T + b2) % 256


def _patches(image: Image) -> Ints:
    size = image.shape[0]
    blocks = image.reshape(size // PATCH, PATCH, size // PATCH, PATCH, 3).transpose(0, 2, 1, 3, 4)
    return blocks.reshape(-1, WIDTH).astype(np.int64)


def _unpatch(patches: Ints, size: int) -> Image:
    blocks = patches.reshape(size // PATCH, size // PATCH, PATCH, PATCH, 3).transpose(0, 2, 1, 3, 4)
    return np.ascontiguousarray(blocks.reshape(size, size, 3)).astype(np.uint8)


class NeuralCipher(LabCipher):
    """Eight keyed integer coupling layers over every 4x4 patch."""

    name = "neural"
    title = "Keyed neural network (integer flow)"
    family = "neural"
    summary = (
        "Eight invertible coupling layers of a keyed integer neural network transform "
        "every 4x4 patch, losslessly."
    )
    key_note = (
        "Weights expanded from the 256-bit key. Exactly invertible, but equal patches "
        "still encrypt alike."
    )

    def _network_layers(self) -> list[Layer]:
        return self._memo(0, lambda: _layers(self.key))

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        x = _patches(image)
        for layer in self._network_layers():
            x = x[:, layer[0]]
            x[:, HALF:] = (x[:, HALF:] + _network(x[:, :HALF], layer)) % 256
        return byte_ciphertext(_unpatch(x, size))

    def _decrypt(self, ct: Ciphertext) -> Image:
        x = _patches(payload_pixels(ct))
        for layer in reversed(self._network_layers()):
            x[:, HALF:] = (x[:, HALF:] - _network(x[:, :HALF], layer)) % 256
            x = x[:, layer[1]]
        return _unpatch(x, ct.shape[0])
