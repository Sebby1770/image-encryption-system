"""Public transforms the lab ciphers scramble in.

None of these is secret; image-encryption schemes use them to move pixels or
to scatter an image's energy before keyed steps. Every one is exact on
integers, so the lab ciphers built on them round-trip losslessly.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray


def _matrix_power(matrix: list[list[int]], exponent: int, modulus: int) -> list[list[int]]:
    result = [[1, 0], [0, 1]]
    base = [row[:] for row in matrix]
    while exponent:
        if exponent & 1:
            result = _multiply(result, base, modulus)
        base = _multiply(base, base, modulus)
        exponent >>= 1
    return result


def _multiply(p: list[list[int]], q: list[list[int]], modulus: int) -> list[list[int]]:
    return [[(p[i][0] * q[0][j] + p[i][1] * q[1][j]) % modulus for j in range(2)] for i in range(2)]


def arnold_destinations(size: int, a: int, b: int, iterations: int) -> NDArray[np.int64]:
    """Where each pixel goes under ``iterations`` of the generalised cat map.

    One iteration sends column ``x``, row ``y`` to ``(x + a y, b x + (a b + 1) y)``
    mod ``size``; the matrix has determinant 1, so the map is a bijection. Use it
    as ``out.reshape(-1, 3)[dest] = img.reshape(-1, 3)``.
    """
    m = _matrix_power([[1, a], [b, a * b + 1]], iterations, size)
    rows, cols = np.divmod(np.arange(size * size, dtype=np.int64), size)
    new_cols = (m[0][0] * cols + m[0][1] * rows) % size
    new_rows = (m[1][0] * cols + m[1][1] * rows) % size
    return new_rows * size + new_cols


def _lift_mod(a: NDArray[np.int64], b: NDArray[np.int64]) -> tuple[NDArray[np.int64], ...]:
    d = (a - b) % 256
    return (b + (d >> 1)) % 256, d


def _unlift_mod(s: NDArray[np.int64], d: NDArray[np.int64]) -> tuple[NDArray[np.int64], ...]:
    b = (s - (d >> 1)) % 256
    return (d + b) % 256, b


def haar_mod256_forward(channel: NDArray[np.uint8], levels: int) -> NDArray[np.uint8]:
    """Integer Haar lifting with every step taken mod 256, in the Mallat layout.

    Working mod 256 keeps the transform a bijection on bytes, so any array of
    coefficients is also a valid image (which is exactly what the lab's
    chosen-plaintext attack exploits). Each level transforms the top-left
    block: rows into ``[s | d]``, then columns into ``[s ; d]``.
    """
    out = np.asarray(channel, dtype=np.int64).copy()
    n = out.shape[0]
    for _ in range(levels):
        block = out[:n, :n]
        s, d = _lift_mod(block[:, 0::2], block[:, 1::2])
        block = np.concatenate([s, d], axis=1)
        s, d = _lift_mod(block[0::2, :], block[1::2, :])
        out[:n, :n] = np.concatenate([s, d], axis=0)
        n //= 2
    return out.astype(np.uint8)


def haar_mod256_inverse(coefficients: NDArray[np.uint8], levels: int) -> NDArray[np.uint8]:
    """The exact inverse of :func:`haar_mod256_forward`."""
    out = np.asarray(coefficients, dtype=np.int64).copy()
    size = out.shape[0]
    for level in reversed(range(levels)):
        n = size >> level
        half = n // 2
        block = out[:n, :n]
        a, b = _unlift_mod(block[:half, :], block[half:, :])
        rows = np.empty_like(block)
        rows[0::2, :], rows[1::2, :] = a, b
        a, b = _unlift_mod(rows[:, :half], rows[:, half:])
        restored = np.empty_like(rows)
        restored[:, 0::2], restored[:, 1::2] = a, b
        out[:n, :n] = restored
    return out.astype(np.uint8)


def haar_mod256_subbands(size: int, levels: int) -> list[tuple[slice, slice]]:
    """The detail subbands of every level, finest first, then the final LL."""
    bands: list[tuple[slice, slice]] = []
    n = size
    for _ in range(levels):
        half = n // 2
        bands += [
            (slice(0, half), slice(half, n)),
            (slice(half, n), slice(0, half)),
            (slice(half, n), slice(half, n)),
        ]
        n = half
    bands.append((slice(0, n), slice(0, n)))
    return bands


def _fwht(x: NDArray[np.number], axis: int) -> NDArray[np.number]:
    moved = np.moveaxis(x, axis, -1).copy()
    n = moved.shape[-1]
    h = 1
    while h < n:
        view = moved.reshape(*moved.shape[:-1], n // (2 * h), 2, h)
        first = view[..., 0, :].copy()
        second = view[..., 1, :]
        view[..., 0, :] = first + second
        view[..., 1, :] = first - second
        h *= 2
    return np.moveaxis(moved, -1, axis)


def walsh_hadamard_2d(x: NDArray[np.number]) -> NDArray[np.number]:
    """The unnormalised 2-D Walsh-Hadamard transform: applying it twice scales by n^2."""
    rows, cols = x.shape[-2], x.shape[-1]
    if rows & (rows - 1) or cols & (cols - 1):
        raise ValueError("The Walsh-Hadamard transform needs power-of-two sides.")
    return _fwht(_fwht(np.asarray(x), -1), -2)
