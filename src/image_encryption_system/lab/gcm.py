"""AES-GCM's GHASH arithmetic, and the two-key forgery it allows.

AES-GCM authenticates with GHASH, a polynomial evaluated in GF(2^128). The tag
is linear in every ciphertext block, so for two keys an attacker can fix all
blocks but one and solve one linear equation for the last, getting a single
ciphertext whose tag is valid under both keys (Dodis et al. 2018; Albertini et
al. 2022). The vault's version 4 envelopes commit to their key to stop exactly
this; `tests/test_key_commitment.py` carries the attack out against both.

Field elements use GCM's bit order (NIST SP 800-38D): a 16-byte block read as
a big-endian integer, where the polynomial 1 is the block 0x80 00 .. 00.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
_R = 0xE1 << 120
_ONE = 1 << 127
_ORDER_MINUS_TWO = (1 << 128) - 2


def gf_mul(x: int, y: int) -> int:
    """Multiply two field elements (SP 800-38D, Algorithm 1)."""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _gf_pow(x: int, exponent: int) -> int:
    result = _ONE
    while exponent:
        if exponent & 1:
            result = gf_mul(result, x)
        x = gf_mul(x, x)
        exponent >>= 1
    return result


def gf_inv(x: int) -> int:
    """Multiplicative inverse: x^(2^128 - 2), since the group has order 2^128 - 1."""
    if x == 0:
        raise ValueError("Zero has no inverse.")
    return _gf_pow(x, _ORDER_MINUS_TWO)


def _blocks(data: bytes) -> list[int]:
    padded = data + bytes(-len(data) % BLOCK)
    return [int.from_bytes(padded[i : i + BLOCK], "big") for i in range(0, len(padded), BLOCK)]


def ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """GHASH over pad(A) || pad(C) || len(A) || len(C), by Horner's rule."""
    lengths = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    y = 0
    for block in [*_blocks(aad), *_blocks(ciphertext), lengths]:
        y = gf_mul(y ^ block, h)
    return y


def _aes_block(key: bytes, block: bytes) -> int:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return int.from_bytes(encryptor.update(block) + encryptor.finalize(), "big")


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    # The first plaintext block uses counter inc32(J0), i.e. nonce || 00000002.
    # A full 128-bit CTR counter equals inc32 until the low word overflows,
    # which needs 2^32 blocks.
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce + b"\x00\x00\x00\x02")).encryptor()
    return encryptor.update(bytes(length)) + encryptor.finalize()


def forge_two_key_ciphertext(
    key1: bytes,
    key2: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext1: bytes,
    plaintext2: bytes,
) -> bytes:
    """One ``ciphertext || tag`` that AES-GCM accepts under both keys.

    Both plaintexts have the same length, a multiple of 16 and at least 32
    bytes, split into ``n`` blocks. Under ``key1``, blocks ``[0, n//2 - 1)``
    decrypt to ``plaintext1``; under ``key2``, blocks ``[n//2, n)`` decrypt to
    ``plaintext2``. Block ``n//2 - 1`` is solved so the two tags agree, and
    every other block decrypts to noise under the key it was not built for.
    """
    length = len(plaintext1)
    if length != len(plaintext2) or length % BLOCK or length < 2 * BLOCK:
        raise ValueError("Plaintexts must match in length: whole blocks, at least two.")
    if len(nonce) != 12:
        raise ValueError("The nonce must be 96 bits.")
    blocks = length // BLOCK
    split = blocks // 2
    free = split - 1

    h1, h2 = _aes_block(key1, bytes(BLOCK)), _aes_block(key2, bytes(BLOCK))
    j0 = nonce + b"\x00\x00\x00\x01"
    s1, s2 = _aes_block(key1, j0), _aes_block(key2, j0)
    stream1 = _keystream(key1, nonce, length)
    stream2 = _keystream(key2, nonce, length)

    body = bytearray(length)
    cut = split * BLOCK
    body[:cut] = bytes(a ^ b for a, b in zip(plaintext1[:cut], stream1[:cut], strict=True))
    body[cut:] = bytes(a ^ b for a, b in zip(plaintext2[cut:], stream2[cut:], strict=True))
    body[free * BLOCK : (free + 1) * BLOCK] = bytes(BLOCK)

    # Tags agree when GHASH1 ^ GHASH2 == S1 ^ S2. With the free block at zero
    # the gap is G; setting it to c adds c * (H1^e ^ H2^e), where e is the free
    # block's power: how many GHASH blocks from it to the end, inclusive.
    gap = ghash(h1, aad, bytes(body)) ^ ghash(h2, aad, bytes(body)) ^ s1 ^ s2
    total = len(_blocks(aad)) + blocks + 1
    position = len(_blocks(aad)) + free + 1
    power = total - position + 1
    coefficient = _gf_pow(h1, power) ^ _gf_pow(h2, power)
    if coefficient == 0:  # only if H1^e == H2^e: probability ~2^-128
        raise ValueError("These keys cannot be forged together at this length.")
    solved = gf_mul(gap, gf_inv(coefficient))
    body[free * BLOCK : (free + 1) * BLOCK] = solved.to_bytes(BLOCK, "big")

    tag = s1 ^ ghash(h1, aad, bytes(body))
    return bytes(body) + tag.to_bytes(BLOCK, "big")
