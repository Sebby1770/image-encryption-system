"""Key material for lab ciphers: every parameter comes from one 32-byte key.

Each cipher draws its parameters under its own label, so two ciphers given the
same lab key never share a keystream or a mask.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32
_INFO_PREFIX = b"IES-LAB/"
_FLOAT_BYTES = 7  # 56 bits per float: more than a double's 53-bit mantissa


def _check(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("A lab key is exactly 32 bytes.")


def derive(key: bytes, label: str, length: int) -> bytes:
    """``length`` bytes (at most 8160) of HKDF-SHA256 output for ``label``."""
    _check(key)
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=None, info=_INFO_PREFIX + label.encode()
    ).derive(key)


def unit_floats(key: bytes, label: str, count: int) -> list[float]:
    """``count`` floats in [0, 1), each from 56 bits of key material."""
    material = derive(key, label, _FLOAT_BYTES * count)
    return [
        int.from_bytes(material[i : i + _FLOAT_BYTES], "big") / 2**56
        for i in range(0, len(material), _FLOAT_BYTES)
    ]


def stream(key: bytes, label: str, length: int) -> bytes:
    """Any amount of key material: ChaCha20 under a key derived for ``label``."""
    encryptor = Cipher(
        algorithms.ChaCha20(derive(key, label, 32), bytes(16)), mode=None
    ).encryptor()
    return encryptor.update(bytes(length))
