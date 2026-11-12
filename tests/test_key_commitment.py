"""The attack version 4 exists to stop, carried out for real.

With plain AES-GCM (version 3), one stored ciphertext can carry a valid tag
under two different data keys. An owner who wraps one key for Alice and the
other for Bob shows them two different images, though the vault stores one.
Version 4 refuses every key but the one its commitment names.
"""

from __future__ import annotations

import copy
from base64 import b64decode, b64encode

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    CryptoError,
    context_aad,
    decrypt_image_bytes,
    derive_v4_keys,
    encrypt_image_bytes,
    wrap_data_key_passphrase,
)
from image_encryption_system.lab.gcm import forge_two_key_ciphertext

KEY_ALICE = bytes(range(32))
KEY_BOB = bytes(range(100, 132))
PLAINTEXT_ALICE = b"A" * 256
PLAINTEXT_BOB = b"B" * 256


def _template(version: int) -> dict:
    """A real envelope of the given version, whose nonce and context we reuse."""
    return encrypt_image_bytes(
        b"placeholder",
        AES_GCM_PASSPHRASE,
        passphrase="template",
        context={"filename": "x.png"},
        version=version,
    ).metadata


def _with_wrap(metadata: dict, key: bytes, passphrase: str) -> dict:
    changed = copy.deepcopy(metadata)
    changed["key_wrap"] = wrap_data_key_passphrase(key, passphrase)
    return changed


def test_v3_opens_under_two_keys_but_v4_refuses_the_second() -> None:
    # Version 3: the forgery works. Two wraps, one ciphertext, two images.
    v3 = _template(3)
    nonce = b64decode(v3["image_nonce"])
    aad3 = context_aad(v3["context"])
    forged = forge_two_key_ciphertext(
        KEY_ALICE, KEY_BOB, nonce, aad3, PLAINTEXT_ALICE, PLAINTEXT_BOB
    )

    alice_sees = decrypt_image_bytes(
        forged, _with_wrap(v3, KEY_ALICE, "alice pass"), passphrase="alice pass"
    )
    bob_sees = decrypt_image_bytes(
        forged, _with_wrap(v3, KEY_BOB, "bob pass"), passphrase="bob pass"
    )
    assert alice_sees != bob_sees
    assert alice_sees[:112] == PLAINTEXT_ALICE[:112]
    assert bob_sees[128:] == PLAINTEXT_BOB[128:]

    # Version 4: the same forgery against the derived GCM keys still satisfies
    # AES-GCM, but the commitment names only Alice's data key.
    v4 = _template(4)
    nonce = b64decode(v4["image_nonce"])
    aad4 = context_aad(v4["context"], version=4)
    alice_image_key, alice_commitment = derive_v4_keys(KEY_ALICE, nonce, aad4)
    bob_image_key, _bob_commitment = derive_v4_keys(KEY_BOB, nonce, aad4)
    forged = forge_two_key_ciphertext(
        alice_image_key, bob_image_key, nonce, aad4, PLAINTEXT_ALICE, PLAINTEXT_BOB
    )
    v4["key_commitment"] = b64encode(alice_commitment).decode()

    AESGCM(bob_image_key).decrypt(nonce, forged, aad4)  # GCM alone would accept Bob
    opened = decrypt_image_bytes(
        forged, _with_wrap(v4, KEY_ALICE, "alice pass"), passphrase="alice pass"
    )
    assert opened[:112] == PLAINTEXT_ALICE[:112]
    with pytest.raises(CryptoError, match="key commitment"):
        decrypt_image_bytes(forged, _with_wrap(v4, KEY_BOB, "bob pass"), passphrase="bob pass")
