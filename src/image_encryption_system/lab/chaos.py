"""Chaotic generators, as image-encryption papers use them.

- The logistic map ``x <- mu * x * (1 - x)``, chaotic for ``mu`` near 4.
- The hyperchaotic Chen system (four variables, two positive Lyapunov
  exponents), integrated with fourth-order Runge-Kutta:

      dx/dt = a (y - x)
      dy/dt = -x z + d x + c y - w
      dz/dt = x y - b z
      dw/dt = x + k

  with a = 36, b = 3, c = 28, d = -16 and -0.7 <= k <= 0.7, the system used by
  Gao and Chen (2008).

Papers turn chaotic values into keystream bytes with ``floor(|x| * 1e14) mod 256``
(the low digits change chaotically even between nearby steps), and into
permutations by sorting. The Chen generator steps many independent orbits
("lanes") together, so numpy does the arithmetic: lane ``l`` starts at
``state0 + (2 l / lanes - 1)``, and the lanes decorrelate during burn-in.
"""

from __future__ import annotations

import math
from collections.abc import Iterator

import numpy as np
from numpy.typing import NDArray

CHEN_A, CHEN_B, CHEN_C, CHEN_D = 36.0, 3.0, 28.0, -16.0


def _orbit(x: float, mu: float, count: int) -> Iterator[float]:
    for _ in range(count):
        x = mu * x * (1.0 - x)
        yield x


def logistic_sequence(
    x0: float, mu: float, count: int, *, burn_in: int = 1000
) -> NDArray[np.float64]:
    """``count`` values of one logistic orbit, after ``burn_in`` discarded steps."""
    if not 0.0 < x0 < 1.0 or not 0.0 < mu <= 4.0:
        raise ValueError("The logistic map needs 0 < x0 < 1 and 0 < mu <= 4.")
    x = x0
    for x in _orbit(x0, mu, burn_in):  # noqa: B007 - only the final value matters
        pass
    return np.fromiter(_orbit(x, mu, count), dtype=np.float64, count=count)


def chaos_bytes(values: NDArray[np.floating]) -> NDArray[np.uint8]:
    """Keystream bytes from chaotic values: ``floor(|v| * 1e14) mod 256``."""
    return (np.floor(np.abs(values) * 1e14) % 256).astype(np.uint8)


def _chen(state: tuple[NDArray[np.float64], ...], k: float) -> tuple[NDArray[np.float64], ...]:
    x, y, z, w = state
    return (
        CHEN_A * (y - x),
        -x * z + CHEN_D * x + CHEN_C * y - w,
        x * y - CHEN_B * z,
        x + k,
    )


def _rk4(
    state: tuple[NDArray[np.float64], ...], k: float, h: float
) -> tuple[NDArray[np.float64], ...]:
    k1 = _chen(state, k)
    k2 = _chen(tuple(v + h / 2 * d for v, d in zip(state, k1, strict=True)), k)
    k3 = _chen(tuple(v + h / 2 * d for v, d in zip(state, k2, strict=True)), k)
    k4 = _chen(tuple(v + h * d for v, d in zip(state, k3, strict=True)), k)
    return tuple(
        v + h / 6 * (a + 2 * b + 2 * c + d)
        for v, a, b, c, d in zip(state, k1, k2, k3, k4, strict=True)
    )


def chen_sequence(
    state0: tuple[float, float, float, float],
    k: float,
    count: int,
    *,
    lanes: int = 1024,
    h: float = 0.002,
    burn_in: int = 1000,
) -> NDArray[np.float64]:
    """``count`` values from ``lanes`` hyperchaotic Chen orbits stepped together.

    Each step yields every lane's ``(x, y, z, w)`` in lane order.
    """
    if not -0.7 <= k <= 0.7:
        raise ValueError("The hyperchaotic Chen system needs -0.7 <= k <= 0.7.")
    offsets = 2.0 * np.arange(lanes, dtype=np.float64) / lanes - 1.0
    state = tuple(np.full(lanes, value, dtype=np.float64) + offsets for value in state0)
    for _ in range(burn_in):
        state = _rk4(state, k, h)
    steps = math.ceil(count / (4 * lanes))
    out = np.empty((steps, lanes, 4), dtype=np.float64)
    for step in range(steps):
        state = _rk4(state, k, h)
        out[step] = np.stack(state, axis=1)
    return out.reshape(-1)[:count]
