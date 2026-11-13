"""One level of the integer Haar wavelet (the "S-transform"), done by lifting.

For a pair of integers ``(a, b)`` the forward step is ``d = a - b`` and
``s = b + floor(d / 2)``; the inverse is ``b = s - floor(d / 2)``, ``a = b + d``.
It maps integers to integers and inverts exactly, which is what lets the cloak
change detail coefficients and still produce an image that decodes to the same
coefficients (Calderbank, Daubechies, Sweldens and Yeo, 1998).

The rows step runs first, then the columns: columns of the row-``s`` half give
``ll`` and ``lh``; columns of the row-``d`` half give ``hl`` and ``hh``.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

Band = NDArray[np.int32]


def _lift(a: Band, b: Band) -> tuple[Band, Band]:
    d = a - b
    return b + (d >> 1), d


def _unlift(s: Band, d: Band) -> tuple[Band, Band]:
    b = s - (d >> 1)
    return b + d, b


def forward(channel: NDArray[np.integer]) -> tuple[Band, Band, Band, Band]:
    """``(ll, lh, hl, hh)`` for a 2-D integer array with even dimensions."""
    x = np.asarray(channel)
    if x.ndim != 2 or x.shape[0] % 2 or x.shape[1] % 2:
        raise ValueError("The integer Haar transform needs a 2-D array with even dimensions.")
    x = x.astype(np.int32)
    s, d = _lift(x[:, 0::2], x[:, 1::2])
    ll, lh = _lift(s[0::2, :], s[1::2, :])
    hl, hh = _lift(d[0::2, :], d[1::2, :])
    return ll, lh, hl, hh


def _interleave_rows(top: Band, bottom: Band) -> Band:
    out = np.empty((top.shape[0] * 2, top.shape[1]), dtype=np.int32)
    out[0::2], out[1::2] = top, bottom
    return out


def inverse(
    ll: NDArray[np.integer],
    lh: NDArray[np.integer],
    hl: NDArray[np.integer],
    hh: NDArray[np.integer],
) -> Band:
    """The exact inverse of :func:`forward`."""
    s = _interleave_rows(*_unlift(ll.astype(np.int32), lh.astype(np.int32)))
    d = _interleave_rows(*_unlift(hl.astype(np.int32), hh.astype(np.int32)))
    a, b = _unlift(s, d)
    out = np.empty((s.shape[0], s.shape[1] * 2), dtype=np.int32)
    out[:, 0::2], out[:, 1::2] = a, b
    return out
