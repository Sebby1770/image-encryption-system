"""AES baselines: two ways to misuse a real block cipher, and the vault's own.

- ``aes-ecb``: AES with no mode. Equal 16-byte blocks give equal ciphertext,
  so the outline of a flat image survives (the "ECB penguin").
- ``aes-ctr-fixed-iv``: AES as a stream cipher, but with one IV reused for
  every image, so one known image reveals the keystream for all of them.
- ``aes-gcm``: what the vault's version 3 envelopes do: AES-256-GCM with a
  fresh 96-bit nonce per image. Not key-committing.
- ``aes-gcm-v4``: the vault's version 4 construction from ``crypto.py``: the
  GCM key and a 32-byte commitment derived from the data key with HKDF.
"""

from __future__ import annotations

import hmac
import os
from typing import ClassVar

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import GCM_NONCE_BYTES, GCM_TAG_BYTES, KEY_COMMITMENT_BYTES, derive_v4_keys
from . import keys
from .base import Ciphertext, Image, LabCipher, LabDecryptError, byte_ciphertext


def _new_nonce() -> bytes:
    """A fresh 96-bit nonce (tests replace this to make runs repeatable)."""
    return os.urandom(GCM_NONCE_BYTES)


def _as_pixels(body: bytes, shape: tuple[int, int, int]) -> Image:
    return np.frombuffer(body, dtype=np.uint8).reshape(shape).copy()


class AesEcbCipher(LabCipher):
    name = "aes-ecb"
    title = "AES-256-ECB"
    family = "block cipher"
    summary = "A real block cipher with no mode: every 16-byte block is encrypted on its own."
    key_note = "A full 256-bit AES key; the weakness is the mode, not the key."

    def _cipher(self) -> Cipher[modes.ECB]:
        return Cipher(algorithms.AES(keys.derive(self.key, self.name, 32)), modes.ECB())

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        encryptor = self._cipher().encryptor()
        body = encryptor.update(image.tobytes()) + encryptor.finalize()
        return byte_ciphertext(_as_pixels(body, image.shape))

    def _decrypt(self, ct: Ciphertext) -> Image:
        decryptor = self._cipher().decryptor()
        body = decryptor.update(ct.payload) + decryptor.finalize()
        return _as_pixels(body, ct.shape)


class AesCtrFixedIvCipher(LabCipher):
    name = "aes-ctr-fixed-iv"
    title = "AES-256-CTR, reused IV"
    family = "stream cipher"
    summary = "AES as a stream cipher, with the same IV for every image: one keystream for all."
    key_note = "A full 256-bit AES key; the reused IV gives the keystream away."

    def _cipher(self) -> Cipher[modes.CTR]:
        iv = keys.derive(self.key, f"{self.name}/iv", 16)
        return Cipher(algorithms.AES(keys.derive(self.key, self.name, 32)), modes.CTR(iv))

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        encryptor = self._cipher().encryptor()
        body = encryptor.update(image.tobytes()) + encryptor.finalize()
        return byte_ciphertext(_as_pixels(body, image.shape))

    def _decrypt(self, ct: Ciphertext) -> Image:
        decryptor = self._cipher().decryptor()
        return _as_pixels(decryptor.update(ct.payload) + decryptor.finalize(), ct.shape)


class AesGcmCipher(LabCipher):
    """The vault's version 3 sealing: AES-256-GCM, fresh nonce, authenticated."""

    name = "aes-gcm"
    title = "AES-256-GCM (vault v3)"
    family = "vault"
    summary = "Authenticated encryption with a fresh 96-bit nonce per image, as vault v3 does."
    key_note = "A full 256-bit key and a fresh nonce: no shortcut is known."
    randomized = True
    authenticated = True
    AAD: ClassVar[bytes] = b"IES-LAB"
    _HEADER = GCM_NONCE_BYTES

    def _data_key(self) -> bytes:
        return keys.derive(self.key, self.name, 32)

    def gcm_key_for(self, nonce: bytes) -> bytes:
        """The AES-GCM key used with ``nonce``."""
        return self._data_key()

    def pack(self, nonce: bytes, sealed: bytes) -> bytes:
        """A payload from a nonce and AES-GCM output (ciphertext followed by tag)."""
        return nonce + sealed

    def _encrypt(self, image: Image, size: int, nonce: bytes | None) -> Ciphertext:
        nonce = _new_nonce() if nonce is None else nonce
        sealed = AESGCM(self.gcm_key_for(nonce)).encrypt(nonce, image.tobytes(), self.AAD)
        payload = self.pack(nonce, sealed)
        return byte_ciphertext(_as_pixels(sealed[:-GCM_TAG_BYTES], image.shape), payload)

    def _open(self, payload: bytes) -> tuple[bytes, bytes]:
        return payload[:GCM_NONCE_BYTES], payload[self._HEADER :]

    def _decrypt(self, ct: Ciphertext) -> Image:
        nonce, sealed = self._open(ct.payload)
        try:
            body = AESGCM(self.gcm_key_for(nonce)).decrypt(nonce, sealed, self.AAD)
        except InvalidTag as exc:
            raise LabDecryptError("Authentication failed: the ciphertext or key is wrong.") from exc
        return _as_pixels(body, ct.shape)


class AesGcmV4Cipher(AesGcmCipher):
    """The vault's version 4 sealing: HKDF-derived GCM key plus a key commitment."""

    name = "aes-gcm-v4"
    title = "AES-256-GCM + key commitment (vault v4)"
    summary = (
        "Version 4 envelopes: the GCM key and a 32-byte commitment derived from the data "
        "key, checked before decrypting."
    )
    _HEADER = GCM_NONCE_BYTES + KEY_COMMITMENT_BYTES

    def gcm_key_for(self, nonce: bytes) -> bytes:
        return derive_v4_keys(self._data_key(), nonce, self.AAD)[0]

    def pack(self, nonce: bytes, sealed: bytes) -> bytes:
        commitment = derive_v4_keys(self._data_key(), nonce, self.AAD)[1]
        return nonce + commitment + sealed

    def _decrypt(self, ct: Ciphertext) -> Image:
        nonce = ct.payload[:GCM_NONCE_BYTES]
        stored = ct.payload[GCM_NONCE_BYTES : self._HEADER]
        expected = derive_v4_keys(self._data_key(), nonce, self.AAD)[1]
        if not hmac.compare_digest(stored, expected):
            raise LabDecryptError("This key does not match the ciphertext's key commitment.")
        return super()._decrypt(ct)
