from io import BytesIO

import pytest
from PIL import Image

from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
    generate_rsa_key_pair,
    pack_ies,
    reencrypt_private_key_pem,
    unpack_ies,
    unwrap_data_key,
    wrap_data_key_passphrase,
    wrap_data_key_rsa,
)


def sample_png() -> bytes:
    image = Image.new("RGB", (64, 40), "#0f766e")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_aes_gcm_round_trip() -> None:
    plaintext = sample_png()
    aad = b"user=1|filename=sample.png|mime=image/png"

    encrypted = encrypt_image_bytes(
        plaintext,
        AES_GCM_PASSPHRASE,
        passphrase="a very strong passphrase",
        aad=aad,
    )
    decrypted = decrypt_image_bytes(
        encrypted.ciphertext,
        encrypted.metadata,
        passphrase="a very strong passphrase",
        aad=aad,
    )

    assert decrypted == plaintext
    assert encrypted.ciphertext != plaintext


def test_aes_gcm_rejects_wrong_passphrase() -> None:
    encrypted = encrypt_image_bytes(
        sample_png(),
        AES_GCM_PASSPHRASE,
        passphrase="correct passphrase",
    )

    with pytest.raises(CryptoError):
        decrypt_image_bytes(
            encrypted.ciphertext,
            encrypted.metadata,
            passphrase="wrong passphrase",
        )


def test_rsa_hybrid_round_trip() -> None:
    plaintext = sample_png()
    private_key, public_key = generate_rsa_key_pair("account password")

    encrypted = encrypt_image_bytes(
        plaintext,
        RSA_HYBRID,
        public_key_pem=public_key,
    )
    decrypted = decrypt_image_bytes(
        encrypted.ciphertext,
        encrypted.metadata,
        private_key_pem=private_key,
        private_key_passphrase="account password",
    )

    assert decrypted == plaintext
    assert encrypted.metadata["key_wrap"]["type"] == "rsa-oaep-sha256"


def test_rewrap_data_key_lets_recipient_decrypt() -> None:
    plaintext = sample_png()
    encrypted = encrypt_image_bytes(
        plaintext,
        AES_GCM_PASSPHRASE,
        passphrase="image secret phrase",
    )
    data_key = unwrap_data_key(encrypted.metadata["key_wrap"], passphrase="image secret phrase")
    bob_private, bob_public = generate_rsa_key_pair("bob account password")
    shared_meta = {**encrypted.metadata, "key_wrap": wrap_data_key_rsa(data_key, bob_public)}

    decrypted = decrypt_image_bytes(
        encrypted.ciphertext,
        shared_meta,
        private_key_pem=bob_private,
        private_key_passphrase="bob account password",
    )
    assert decrypted == plaintext

    eve_private, _eve_public = generate_rsa_key_pair("eve account password")
    with pytest.raises(CryptoError):
        decrypt_image_bytes(
            encrypted.ciphertext,
            shared_meta,
            private_key_pem=eve_private,
            private_key_passphrase="eve account password",
        )


def test_ies_container_round_trip() -> None:
    encrypted = encrypt_image_bytes(sample_png(), AES_GCM_PASSPHRASE, passphrase="pack passphrase")
    blob = pack_ies(encrypted.ciphertext, encrypted.metadata)
    ciphertext, metadata = unpack_ies(blob)
    assert ciphertext == encrypted.ciphertext
    assert metadata["algorithm"] == AES_GCM_PASSPHRASE


def test_unpack_ies_rejects_garbage() -> None:
    with pytest.raises(CryptoError):
        unpack_ies(b"not-an-ies-file")


def test_reencrypt_private_key_pem_uses_new_password() -> None:
    plaintext = sample_png()
    private_pem, public_pem = generate_rsa_key_pair("old password 1")
    encrypted = encrypt_image_bytes(plaintext, RSA_HYBRID, public_key_pem=public_pem)
    rotated = reencrypt_private_key_pem(private_pem, "old password 1", "new password 2")

    with pytest.raises(CryptoError):
        decrypt_image_bytes(
            encrypted.ciphertext,
            encrypted.metadata,
            private_key_pem=rotated,
            private_key_passphrase="old password 1",
        )

    assert (
        decrypt_image_bytes(
            encrypted.ciphertext,
            encrypted.metadata,
            private_key_pem=rotated,
            private_key_passphrase="new password 2",
        )
        == plaintext
    )


def test_passphrase_wrap_rotation_round_trip() -> None:
    plaintext = sample_png()
    encrypted = encrypt_image_bytes(
        plaintext,
        AES_GCM_PASSPHRASE,
        passphrase="old image passphrase",
    )
    data_key = unwrap_data_key(
        encrypted.metadata["key_wrap"],
        passphrase="old image passphrase",
    )
    rotated_meta = {
        **encrypted.metadata,
        "key_wrap": wrap_data_key_passphrase(data_key, "new image passphrase"),
    }

    assert (
        decrypt_image_bytes(
            encrypted.ciphertext,
            rotated_meta,
            passphrase="new image passphrase",
        )
        == plaintext
    )
    with pytest.raises(CryptoError):
        decrypt_image_bytes(
            encrypted.ciphertext,
            rotated_meta,
            passphrase="old image passphrase",
        )
