"""Permutation and chaos ciphers, in the forms the image-encryption literature uses."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from . import chaos, keys, transforms
from .base import Ciphertext, Image, LabCipher, byte_ciphertext, payload_pixels


class ArnoldCipher(LabCipher):
    """A fixed, key-chosen permutation of pixel positions. Values are untouched."""

    name = "arnold"
    title = "Arnold cat map"
    family = "permutation"
    summary = "Moves every pixel with the generalised cat map; pixel values are untouched."
    key_bits = 24
    key_note = (
        "a, b in [1, S-1] and t in [1, 255]: about 2^24 keys at 256 px, searchable in seconds."
    )

    def _destinations(self, size: int) -> NDArray[np.int64]:
        return self._memo(size, lambda: _arnold_destinations(self.key, size))

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        out = np.empty((size * size, 3), dtype=np.uint8)
        out[self._destinations(size)] = image.reshape(-1, 3)
        return byte_ciphertext(out.reshape(image.shape))

    def _decrypt(self, ct: Ciphertext) -> Image:
        flat = payload_pixels(ct).reshape(-1, 3)
        return flat[self._destinations(ct.shape[0])].reshape(ct.shape)


def _arnold_destinations(key: bytes, size: int) -> NDArray[np.int64]:
    material = keys.derive(key, "arnold", 5)
    a = 1 + int.from_bytes(material[0:2], "big") % (size - 1)
    b = 1 + int.from_bytes(material[2:4], "big") % (size - 1)
    t = 1 + material[4] % 255
    return transforms.arnold_destinations(size, a, b, t)


class LogisticXorCipher(LabCipher):
    """A logistic-map keystream XORed onto the pixels, the same for every image."""

    name = "logistic-xor"
    title = "Logistic-map XOR"
    family = "chaos"
    summary = "XORs every byte with a keystream from one logistic-map orbit; no nonce."
    key_bits = 100
    key_note = "x0 and mu are doubles in narrow ranges: roughly 2^100 distinct keys."

    def _keystream(self, size: int) -> Image:
        return self._memo(size, lambda: _logistic_keystream(self.key, size))

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        return byte_ciphertext(image ^ self._keystream(size))

    def _decrypt(self, ct: Ciphertext) -> Image:
        return payload_pixels(ct) ^ self._keystream(ct.shape[0])


def _logistic_keystream(key: bytes, size: int) -> Image:
    u0, u1 = keys.unit_floats(key, "logistic-xor", 2)
    values = chaos.logistic_sequence(0.1 + 0.8 * u0, 3.99 + 0.01 * u1, 3 * size * size)
    stream = chaos.chaos_bytes(values).reshape(size, size, 3)
    stream.setflags(write=False)
    return stream


# Two rounds of four diffusion passes, in encryption order: (axis scanned,
# direction). One round is not enough: each pass is a single chain per row or
# column, and when a difference happens to cancel where the changed region
# ends (1 time in 256), the rest of that chain stays unchanged. The second
# round revives such runs, because by then nearly every input byte differs.
_PASSES = ((1, 1), (0, 1), (1, -1), (0, -1)) * 2


def _scan(m: Image, axis: int) -> Image:
    """``m`` arranged so the scanned axis comes first (a view)."""
    return m if axis == 0 else m.T


def _diffuse(m: Image, k1: Image, k2: Image, sbox: Image, axis: int, direction: int) -> Image:
    """``y_t = S[x_t ^ k1_t ^ ((y_prev + k2_t) mod 256)]``, scanning along ``axis``.

    The chaotic S-box ``S`` matters: with XOR and addition alone, a small
    plaintext difference stays in the low bits and the UACI test fails.
    """
    x, a, b = _scan(m, axis), _scan(k1, axis), _scan(k2, axis)
    y = np.empty_like(x)
    previous = np.zeros(x.shape[1], dtype=np.uint8)
    order = range(x.shape[0]) if direction > 0 else range(x.shape[0] - 1, -1, -1)
    for t in order:
        previous = sbox[x[t] ^ a[t] ^ (previous + b[t])]
        y[t] = previous
    return np.ascontiguousarray(_scan(y, axis))


def _undiffuse(
    m: Image, k1: Image, k2: Image, inverse_sbox: Image, axis: int, direction: int
) -> Image:
    """The inverse pass. It needs no loop: each step's ``y_prev`` is ciphertext."""
    y, a, b = _scan(m, axis), _scan(k1, axis), _scan(k2, axis)
    previous = np.zeros_like(y)
    if direction > 0:
        previous[1:] = y[:-1]
    else:
        previous[:-1] = y[1:]
    return np.ascontiguousarray(_scan(inverse_sbox[y] ^ a ^ (previous + b), axis))


class HyperchaosCipher(LabCipher):
    """Hyperchaotic permutation plus four diffusion passes (the Gao-Chen family)."""

    name = "hyperchaos"
    title = "Hyperchaotic permutation + diffusion"
    family = "chaos"
    summary = (
        "A hyperchaotic Chen system shuffles the pixels, then two rounds of four "
        "diffusion passes through a chaotic S-box chain every byte to every other."
    )
    key_note = (
        "Five doubles from the key. The Gao-Chen design this follows was broken with "
        "chosen plaintexts (Rhouma & Belghith, 2008)."
    )

    def _keys_for(self, size: int) -> tuple[NDArray[np.int64], Image, Image, Image]:
        return self._memo(size, lambda: _hyperchaos_material(self.key, size))

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        order, passes, sbox, _inverse = self._keys_for(size)
        m = image.reshape(-1, 3)[order].reshape(size, 3 * size)
        for index, (axis, direction) in enumerate(_PASSES):
            m = _diffuse(m, passes[2 * index], passes[2 * index + 1], sbox, axis, direction)
        return byte_ciphertext(m.reshape(image.shape))

    def _decrypt(self, ct: Ciphertext) -> Image:
        size = ct.shape[0]
        order, passes, _sbox, inverse = self._keys_for(size)
        m = payload_pixels(ct).reshape(size, 3 * size)
        for index in reversed(range(len(_PASSES))):
            axis, direction = _PASSES[index]
            m = _undiffuse(m, passes[2 * index], passes[2 * index + 1], inverse, axis, direction)
        flat = np.empty((size * size, 3), dtype=np.uint8)
        flat[order] = m.reshape(-1, 3)
        return flat.reshape(ct.shape)


def _hyperchaos_material(key: bytes, size: int) -> tuple[NDArray[np.int64], Image, Image, Image]:
    f = keys.unit_floats(key, "hyperchaos", 5)
    state0 = (10 * f[0] - 5, 10 * f[1] - 5, 10 * f[2] - 5, 10 * f[3] - 5)
    pixels = size * size
    streams = 2 * len(_PASSES)  # k1 and k2 for every pass
    end = pixels + streams * 3 * pixels
    values = chaos.chen_sequence(state0, 1.4 * f[4] - 0.7, end + 256)
    order = np.argsort(values[:pixels], kind="stable")
    passes = chaos.chaos_bytes(values[pixels:end]).reshape(streams, size, 3 * size)
    # Rank the low digits, not the raw values: neighbouring lanes start close
    # together, and ranking raw values would give a smooth, weak S-box.
    digits = np.floor(np.abs(values[end:]) * 1e14) % 2**24
    sbox = np.argsort(digits, kind="stable").astype(np.uint8)
    inverse = np.argsort(sbox, kind="stable").astype(np.uint8)
    for array in (order, passes, sbox, inverse):
        array.setflags(write=False)
    return order, passes, sbox, inverse


class WaveletCipher(LabCipher):
    """Scrambles integer-wavelet coefficients inside each subband, then XORs them."""

    name = "wavelet"
    title = "Integer-wavelet scrambling"
    family = "transform + chaos"
    summary = (
        "Two levels of integer Haar wavelet (mod 256); a logistic map permutes and XORs "
        "the coefficients of every subband."
    )
    key_bits = 100
    key_note = "Driven by one logistic orbit: x0 and mu, roughly 2^100 distinct keys."
    transform = "haar-mod256"
    levels = 2

    def _keys_for(self, size: int) -> list[list[tuple[NDArray[np.int64], Image]]]:
        return self._memo(size, lambda: _wavelet_material(self.key, size, self.levels))

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        out = np.empty_like(image)
        bands = transforms.haar_mod256_subbands(size, self.levels)
        for channel, scramble in enumerate(self._keys_for(size)):
            coefficients = transforms.haar_mod256_forward(image[..., channel], self.levels)
            for (rows, cols), (order, mask) in zip(bands, scramble, strict=True):
                flat = coefficients[rows, cols].ravel()
                coefficients[rows, cols] = (flat[order] ^ mask).reshape(
                    coefficients[rows, cols].shape
                )
            out[..., channel] = transforms.haar_mod256_inverse(coefficients, self.levels)
        return byte_ciphertext(out)

    def _decrypt(self, ct: Ciphertext) -> Image:
        size = ct.shape[0]
        cipher = payload_pixels(ct)
        out = np.empty_like(cipher)
        bands = transforms.haar_mod256_subbands(size, self.levels)
        for channel, scramble in enumerate(self._keys_for(size)):
            coefficients = transforms.haar_mod256_forward(cipher[..., channel], self.levels)
            for (rows, cols), (order, mask) in zip(bands, scramble, strict=True):
                flat = coefficients[rows, cols].ravel() ^ mask
                restored = np.empty_like(flat)
                restored[order] = flat
                coefficients[rows, cols] = restored.reshape(coefficients[rows, cols].shape)
            out[..., channel] = transforms.haar_mod256_inverse(coefficients, self.levels)
        return out


def _wavelet_material(
    key: bytes, size: int, levels: int
) -> list[list[tuple[NDArray[np.int64], Image]]]:
    u0, u1 = keys.unit_floats(key, "wavelet", 2)
    total = 3 * size * size
    values = chaos.logistic_sequence(0.1 + 0.8 * u0, 3.99 + 0.01 * u1, 2 * total)
    masks = chaos.chaos_bytes(values[total:])
    bands = transforms.haar_mod256_subbands(size, levels)
    material, offset = [], 0
    for _channel in range(3):
        scramble = []
        for rows, cols in bands:
            count = (rows.stop - rows.start) * (cols.stop - cols.start)
            order = np.argsort(values[offset : offset + count], kind="stable")
            scramble.append((order, masks[offset : offset + count]))
            offset += count
        material.append(scramble)
    return material
