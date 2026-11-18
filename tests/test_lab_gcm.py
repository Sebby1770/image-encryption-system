"""GF(2^128) arithmetic and GHASH, checked against `cryptography`'s AES-GCM.

The lab builds AES-GCM ciphertexts that authenticate under two keys. That only
works if this arithmetic is GCM's exactly, so every piece is pinned against
the real implementation.
"""

from __future__ import annotations

import random

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from image_encryption_system.lab.gcm import forge_two_key_ciphertext, gf_inv, gf_mul, ghash

ONE = 1 << 127  # GCM's bit order: the polynomial 1 is the block 0x80 00 .. 00


def _aes_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def test_gf_identity_and_inverse() -> None:
    rng = random.Random(1)
    for _ in range(20):
        x = rng.getrandbits(128) or 1
        assert gf_mul(x, ONE) == x
        assert gf_mul(ONE, x) == x
        assert gf_mul(x, gf_inv(x)) == ONE
    with pytest.raises(ValueError):
        gf_inv(0)


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 64, 100])
@pytest.mark.parametrize("aad_length", [0, 5, 16, 33])
def test_ghash_reproduces_cryptography_tags(length, aad_length) -> None:
    rng = random.Random(length * 100 + aad_length)
    key, nonce = rng.randbytes(32), rng.randbytes(12)
    aad, plaintext = rng.randbytes(aad_length), rng.randbytes(length)
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = sealed[:-16], sealed[-16:]

    h = int.from_bytes(_aes_block(key, bytes(16)), "big")
    s = int.from_bytes(_aes_block(key, nonce + b"\x00\x00\x00\x01"), "big")

    assert (s ^ ghash(h, aad, ciphertext)).to_bytes(16, "big") == tag


def test_forged_ciphertext_authenticates_under_both_keys() -> None:
    rng = random.Random(7)
    key1, key2, nonce = rng.randbytes(32), rng.randbytes(32), rng.randbytes(12)
    aad = b"a sealed context"
    plaintext1, plaintext2 = rng.randbytes(256), rng.randbytes(256)

    sealed = forge_two_key_ciphertext(key1, key2, nonce, aad, plaintext1, plaintext2)
    opened1 = AESGCM(key1).decrypt(nonce, sealed, aad)
    opened2 = AESGCM(key2).decrypt(nonce, sealed, aad)

    blocks = len(plaintext1) // 16
    solved = blocks // 2 - 1
    assert opened1[: solved * 16] == plaintext1[: solved * 16]
    assert opened2[(blocks // 2) * 16 :] == plaintext2[(blocks // 2) * 16 :]
    assert opened1 != opened2


@pytest.mark.parametrize("length", [0, 16, 40])
def test_forging_needs_whole_blocks_and_room_for_the_solved_block(length) -> None:
    with pytest.raises(ValueError):
        forge_two_key_ciphertext(
            bytes(32), bytes(range(32)), bytes(12), b"", bytes(length), bytes(length)
        )
