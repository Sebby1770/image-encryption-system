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
    reencrypt_private_key,
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


def test_reencrypt_private_key_keeps_rsa_hybrid_working() -> None:
    plaintext = sample_png()
    private_key, public_key = generate_rsa_key_pair("old-password-ok")
    encrypted = encrypt_image_bytes(plaintext, RSA_HYBRID, public_key_pem=public_key)

    rewritten = reencrypt_private_key(private_key, "old-password-ok", "new-password-ok")
    decrypted = decrypt_image_bytes(
        encrypted.ciphertext,
        encrypted.metadata,
        private_key_pem=rewritten,
        private_key_passphrase="new-password-ok",
    )
    assert decrypted == plaintext

    with pytest.raises(CryptoError):
        decrypt_image_bytes(
            encrypted.ciphertext,
            encrypted.metadata,
            private_key_pem=rewritten,
            private_key_passphrase="old-password-ok",
        )

