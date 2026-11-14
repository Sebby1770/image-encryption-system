"""The lab's cipher registry: every cipher by name, in display order."""

from __future__ import annotations

from .base import LabCipher
from .classic import ArnoldCipher, HyperchaosCipher, LogisticXorCipher, WaveletCipher

CIPHER_NAMES = (
    "arnold",
    "logistic-xor",
    "hyperchaos",
    "wavelet",
    "wht",
    "drpe",
    "neural",
    "aes-ecb",
    "aes-ctr-fixed-iv",
    "aes-gcm",
    "aes-gcm-v4",
)

_CLASSES: dict[str, type[LabCipher]] = {
    cls.name: cls for cls in (ArnoldCipher, LogisticXorCipher, HyperchaosCipher, WaveletCipher)
}
IMPLEMENTED = tuple(name for name in CIPHER_NAMES if name in _CLASSES)


def make_cipher(name: str, key: bytes) -> LabCipher:
    """The named lab cipher, keyed with a 32-byte lab key."""
    cls = _CLASSES.get(name)
    if cls is None:
        raise ValueError(f"Unknown lab cipher {name!r}; choose from {', '.join(CIPHER_NAMES)}.")
    return cls(key)
