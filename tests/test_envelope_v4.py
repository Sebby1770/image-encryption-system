"""Version 4 envelopes: AES-256-GCM made key- and context-committing.

AES-GCM on its own lets one ciphertext authenticate under two different keys, so
an owner could give two share recipients two keys that open the same stored blob
as two different pictures. Version 4 derives the GCM key from the data key with
HKDF and stores a 32-byte commitment that binds the data key, the nonce, and the
sealed context. A key that does not reproduce it is refused before GCM runs.
"""

from __future__ import annotations

import copy
import hashlib
import os
from base64 import b64decode, b64encode

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from image_encryption_system import crypto
from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    context_aad,
    decrypt_image_bytes,
    derive_v4_keys,
    encrypt_image_bytes,
    generate_rsa_key_pair,
    is_key_committing,
    unwrap_data_key,
    validate_envelope,
    wrap_data_key_passphrase,
)

PASSPHRASE = "a passphrase for version four"
ACCOUNT_PASSWORD = "an account password for version four"
IMAGE = bytes(range(256)) * 3
CONTEXT = {
    "owner": 7,
    "filename": "v4.png",
    "mime": "image/png",
    "format": "PNG",
    "width": 16,
    "height": 12,
}


@pytest.fixture(scope="module")
def rsa_pair() -> tuple[bytes, bytes]:
    return generate_rsa_key_pair(ACCOUNT_PASSWORD)


def _passphrase_envelope(**kwargs):
    return encrypt_image_bytes(
        IMAGE, AES_GCM_PASSPHRASE, passphrase=PASSPHRASE, context=CONTEXT, **kwargs
    )


@pytest.mark.parametrize("algorithm", [AES_GCM_PASSPHRASE, RSA_HYBRID])
def test_new_envelopes_are_v4_with_a_32_byte_commitment(algorithm, rsa_pair) -> None:
    private_key, public_key = rsa_pair
    if algorithm == AES_GCM_PASSPHRASE:
        sealed = encrypt_image_bytes(IMAGE, algorithm, passphrase=PASSPHRASE, context=CONTEXT)
        secrets = {"passphrase": PASSPHRASE}
    else:
        sealed = encrypt_image_bytes(IMAGE, algorithm, public_key_pem=public_key, context=CONTEXT)
        secrets = {"private_key_pem": private_key, "private_key_passphrase": ACCOUNT_PASSWORD}

    metadata = sealed.metadata
    assert metadata["version"] == crypto.ENVELOPE_V4 == crypto.CURRENT_ENVELOPE_VERSION == 4
    assert set(metadata) <= crypto.V4_ENVELOPE_KEYS
    assert len(b64decode(metadata["key_commitment"])) == crypto.KEY_COMMITMENT_BYTES == 32
    assert is_key_committing(metadata)
    assert decrypt_image_bytes(sealed.ciphertext, metadata, **secrets) == IMAGE


def test_commitment_and_image_key_follow_the_spec_construction() -> None:
    sealed = _passphrase_envelope()
    metadata = sealed.metadata
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=PASSPHRASE)
    nonce = b64decode(metadata["image_nonce"])
    aad = b"IES-CONTEXT-V4\x00" + crypto.canonical_json(metadata["context"])
    assert context_aad(metadata["context"], version=4) == aad

    def hkdf(info: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"IES-V4", info=info).derive(
            data_key
        )

    image_key = hkdf(b"IES-V4\x00image-key")
    commitment = hkdf(b"IES-V4\x00key-commitment\x00" + nonce + hashlib.sha256(aad).digest())

    assert b64decode(metadata["key_commitment"]) == commitment
    assert derive_v4_keys(data_key, nonce, aad) == (image_key, commitment)
    assert AESGCM(image_key).decrypt(nonce, sealed.ciphertext, aad) == IMAGE
    with pytest.raises(InvalidTag):
        AESGCM(data_key).decrypt(nonce, sealed.ciphertext, aad)


def test_a_key_that_fails_the_commitment_is_refused_before_gcm(monkeypatch) -> None:
    sealed = _passphrase_envelope()
    metadata = copy.deepcopy(sealed.metadata)
    metadata["key_wrap"] = wrap_data_key_passphrase(os.urandom(32), PASSPHRASE)

    real_aesgcm = crypto.AESGCM

    class ImageGcmMustNotRun:
        """Lets key unwrapping use AES-GCM but fails if the image itself is opened."""

        def __init__(self, key: bytes) -> None:
            self._inner = real_aesgcm(key)

        def encrypt(self, nonce, data, associated_data):
            return self._inner.encrypt(nonce, data, associated_data)

        def decrypt(self, nonce, data, associated_data):
            if associated_data and associated_data.startswith(b"IES-CONTEXT-V4"):
                raise AssertionError("AES-GCM ran on the image before the commitment check")
            return self._inner.decrypt(nonce, data, associated_data)

    monkeypatch.setattr(crypto, "AESGCM", ImageGcmMustNotRun)
    with pytest.raises(CryptoError, match="key commitment"):
        decrypt_image_bytes(sealed.ciphertext, metadata, passphrase=PASSPHRASE)


def test_an_edited_commitment_is_refused() -> None:
    sealed = _passphrase_envelope()
    metadata = copy.deepcopy(sealed.metadata)
    commitment = bytearray(b64decode(metadata["key_commitment"]))
    commitment[0] ^= 0x01
    metadata["key_commitment"] = b64encode(bytes(commitment)).decode()
    with pytest.raises(CryptoError, match="key commitment"):
        decrypt_image_bytes(sealed.ciphertext, metadata, passphrase=PASSPHRASE)


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m.pop("key_commitment"),
        lambda m: m.__setitem__("key_commitment", b64encode(bytes(31)).decode()),
        lambda m: m.__setitem__("key_commitment", m["key_commitment"].rstrip("=")),
        lambda m: m.__setitem__("key_commitment", 12345),
        lambda m: m.__setitem__("unexpected", 1),
    ],
    ids=["missing", "short", "non-canonical", "not-a-string", "extra-field"],
)
def test_v4_envelopes_are_closed(change) -> None:
    metadata = copy.deepcopy(_passphrase_envelope().metadata)
    change(metadata)
    with pytest.raises(CryptoError):
        validate_envelope(metadata)


def test_version_3_can_still_be_written_and_read() -> None:
    sealed = _passphrase_envelope(version=3)
    metadata = sealed.metadata
    assert metadata["version"] == 3
    assert "key_commitment" not in metadata
    assert not is_key_committing(metadata)

    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=PASSPHRASE)
    nonce = b64decode(metadata["image_nonce"])
    aad = context_aad(metadata["context"])
    assert aad.startswith(b"IES-CONTEXT-V3\x00")
    assert AESGCM(data_key).decrypt(nonce, sealed.ciphertext, aad) == IMAGE
    assert decrypt_image_bytes(sealed.ciphertext, metadata, passphrase=PASSPHRASE) == IMAGE


def test_relabelling_a_v4_envelope_as_v3_fails() -> None:
    sealed = _passphrase_envelope()
    metadata = copy.deepcopy(sealed.metadata)
    metadata["version"] = 3
    del metadata["key_commitment"]
    with pytest.raises(CryptoError):
        decrypt_image_bytes(sealed.ciphertext, metadata, passphrase=PASSPHRASE)


@pytest.mark.parametrize("version", [1, 2, 5])
def test_only_versions_3_and_4_can_be_written(version) -> None:
    with pytest.raises(CryptoError):
        _passphrase_envelope(version=version)
