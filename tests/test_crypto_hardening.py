"""Regression tests for attacker-controlled key-wrap metadata.

Wrap metadata ships alongside the ciphertext in every ``.ies`` file and in every
restored backup, so its Scrypt cost parameters are fully attacker-controlled.
Before these bounds existed, a crafted blob could name a work factor large
enough to exhaust memory during ``decrypt``/``inspect``/``verify``.
"""

from __future__ import annotations

import pytest

from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    MAX_SCRYPT_MEMORY_BYTES,
    SCRYPT_N,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
)

PASSPHRASE = "a sufficiently long passphrase"
PLAINTEXT = b"\x89PNG\r\n\x1a\n" + b"pixels" * 32


def _wrapped():
    result = encrypt_image_bytes(PLAINTEXT, AES_GCM_PASSPHRASE, passphrase=PASSPHRASE)
    return result.ciphertext, result.metadata


def test_round_trip_still_works():
    ciphertext, metadata = _wrapped()
    assert decrypt_image_bytes(ciphertext, metadata, passphrase=PASSPHRASE) == PLAINTEXT


def test_wrong_passphrase_is_rejected():
    ciphertext, metadata = _wrapped()
    with pytest.raises(CryptoError):
        decrypt_image_bytes(ciphertext, metadata, passphrase="not the passphrase")


@pytest.mark.parametrize(
    "work_factor",
    [
        2**30,  # ~1 TiB of Scrypt state: the memory-exhaustion case
        2**23,  # just above MAX_SCRYPT_WORK_FACTOR
    ],
)
def test_oversized_scrypt_work_factor_is_refused_without_allocating(work_factor):
    ciphertext, metadata = _wrapped()
    metadata["key_wrap"]["n"] = work_factor

    # Must raise a CryptoError rather than attempting the allocation.
    with pytest.raises(CryptoError, match="Scrypt"):
        decrypt_image_bytes(ciphertext, metadata, passphrase=PASSPHRASE)


def test_downgraded_scrypt_work_factor_is_refused():
    """A blob may not weaken the KDF below the vault's own baseline."""
    ciphertext, metadata = _wrapped()
    metadata["key_wrap"]["n"] = 2  # trivially cheap to brute force

    with pytest.raises(CryptoError, match="Scrypt"):
        decrypt_image_bytes(ciphertext, metadata, passphrase=PASSPHRASE)


def test_non_power_of_two_work_factor_is_refused():
    ciphertext, metadata = _wrapped()
    metadata["key_wrap"]["n"] = SCRYPT_N + 1

    with pytest.raises(CryptoError, match="Scrypt"):
        decrypt_image_bytes(ciphertext, metadata, passphrase=PASSPHRASE)


@pytest.mark.parametrize("field,value", [("r", 0), ("r", 999), ("p", 0), ("p", 999)])
def test_out_of_range_block_and_parallelism_are_refused(field, value):
    ciphertext, metadata = _wrapped()
    metadata["key_wrap"][field] = value

    with pytest.raises(CryptoError, match="Scrypt"):
        decrypt_image_bytes(ciphertext, metadata, passphrase=PASSPHRASE)


def test_memory_ceiling_is_actually_enforceable():
    """The r-axis must be bounded too, not just n."""
    ciphertext, metadata = _wrapped()
    metadata["key_wrap"]["r"] = 32
    metadata["key_wrap"]["n"] = 2**20  # 128 * 2**20 * 32 = 4 GiB

    assert MAX_SCRYPT_MEMORY_BYTES < 128 * (2**20) * 32
    with pytest.raises(CryptoError, match="Scrypt"):
        decrypt_image_bytes(ciphertext, metadata, passphrase=PASSPHRASE)


@pytest.mark.parametrize("field", ["salt", "nonce", "wrapped_key"])
def test_truncated_wrap_fields_are_refused(field):
    ciphertext, metadata = _wrapped()
    metadata["key_wrap"][field] = "AAAA"

    with pytest.raises(CryptoError):
        decrypt_image_bytes(ciphertext, metadata, passphrase=PASSPHRASE)


def test_oversized_passphrase_is_refused():
    with pytest.raises(CryptoError, match="too long"):
        encrypt_image_bytes(PLAINTEXT, AES_GCM_PASSPHRASE, passphrase="x" * 2048)
