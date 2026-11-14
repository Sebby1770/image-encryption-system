"""Cipher Lab: classical, chaotic, transform-domain and neural image ciphers,
scored and attacked next to the vault's AES-256-GCM.

Nothing in this package reads or writes vault data. It exists to show, with
measurements and working attacks, why the vault relies on authenticated
encryption rather than on the techniques studied here.
"""

from .ciphers import CIPHER_NAMES, make_cipher
from .imaging import LAB_SIZES, SAMPLES, prepare, sample
from .runner import LabReport, run_lab

__all__ = [
    "CIPHER_NAMES",
    "LAB_SIZES",
    "SAMPLES",
    "LabReport",
    "make_cipher",
    "prepare",
    "run_lab",
    "sample",
]
