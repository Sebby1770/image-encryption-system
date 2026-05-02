from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


AES_GCM_PASSPHRASE = "AES-GCM"
RSA_HYBRID = "RSA-HYBRID"
SUPPORTED_ALGORITHMS = (AES_GCM_PASSPHRASE, RSA_HYBRID)

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


class CryptoError(Exception):
    """Raised when encryption or decryption cannot be completed safely."""


@dataclass(frozen=True)
class EncryptionResult:
    ciphertext: bytes
    metadata: dict[str, Any]


def generate_rsa_key_pair(passphrase: str) -> tuple[bytes, bytes]:
    if not passphrase:
        raise CryptoError("A passphrase is required to protect the private key.")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def encrypt_image_bytes(
    image_bytes: bytes,
    algorithm: str,
    *,
    passphrase: str | None = None,
    public_key_pem: bytes | None = None,
    aad: bytes = b"",
) -> EncryptionResult:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise CryptoError(f"Unsupported algorithm: {algorithm}")
    if not image_bytes:
        raise CryptoError("Image bytes cannot be empty.")

    data_key = os.urandom(AES_KEY_BYTES)
    image_nonce = os.urandom(GCM_NONCE_BYTES)
    ciphertext = AESGCM(data_key).encrypt(image_nonce, image_bytes, aad)

    metadata: dict[str, Any] = {
        "version": 1,
        "algorithm": algorithm,
        "image_nonce": _b64encode(image_nonce),
    }

    if algorithm == AES_GCM_PASSPHRASE:
        metadata["key_wrap"] = _wrap_key_with_passphrase(data_key, passphrase)
    elif algorithm == RSA_HYBRID:
        metadata["key_wrap"] = _wrap_key_with_rsa(data_key, public_key_pem)

    return EncryptionResult(ciphertext=ciphertext, metadata=metadata)


def decrypt_image_bytes(
    ciphertext: bytes,
    metadata: dict[str, Any],
    *,
    passphrase: str | None = None,
    private_key_pem: bytes | None = None,
    private_key_passphrase: str | None = None,
    aad: bytes = b"",
) -> bytes:
    try:
        algorithm = metadata["algorithm"]
        image_nonce = _b64decode(metadata["image_nonce"])
        key_wrap = metadata["key_wrap"]
    except KeyError as exc:
        raise CryptoError("Encrypted image metadata is incomplete.") from exc

    if algorithm == AES_GCM_PASSPHRASE:
        data_key = _unwrap_key_with_passphrase(key_wrap, passphrase)
    elif algorithm == RSA_HYBRID:
        data_key = _unwrap_key_with_rsa(key_wrap, private_key_pem, private_key_passphrase)
    else:
        raise CryptoError(f"Unsupported algorithm: {algorithm}")

    try:
        return AESGCM(data_key).decrypt(image_nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("Decryption failed. The key, passphrase, or ciphertext is invalid.") from exc


def _wrap_key_with_passphrase(data_key: bytes, passphrase: str | None) -> dict[str, str | int]:
    if not passphrase:
        raise CryptoError("AES-GCM mode requires a passphrase.")

    salt = os.urandom(16)
    wrapping_key = _derive_passphrase_key(passphrase, salt)
    wrapping_nonce = os.urandom(GCM_NONCE_BYTES)
    wrapped_key = AESGCM(wrapping_key).encrypt(wrapping_nonce, data_key, b"image-data-key")

    return {
        "type": "scrypt-aes-gcm",
        "salt": _b64encode(salt),
        "nonce": _b64encode(wrapping_nonce),
        "wrapped_key": _b64encode(wrapped_key),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }


def _unwrap_key_with_passphrase(key_wrap: dict[str, Any], passphrase: str | None) -> bytes:
    if not passphrase:
        raise CryptoError("A passphrase is required for AES-GCM decryption.")
    if key_wrap.get("type") != "scrypt-aes-gcm":
        raise CryptoError("Unsupported AES key wrapping metadata.")

    try:
        salt = _b64decode(key_wrap["salt"])
        nonce = _b64decode(key_wrap["nonce"])
        wrapped_key = _b64decode(key_wrap["wrapped_key"])
    except KeyError as exc:
        raise CryptoError("AES key wrapping metadata is incomplete.") from exc

    wrapping_key = _derive_passphrase_key(
        passphrase,
        salt,
        n=int(key_wrap.get("n", SCRYPT_N)),
        r=int(key_wrap.get("r", SCRYPT_R)),
        p=int(key_wrap.get("p", SCRYPT_P)),
    )
    try:
        return AESGCM(wrapping_key).decrypt(nonce, wrapped_key, b"image-data-key")
    except InvalidTag as exc:
        raise CryptoError("Passphrase did not unlock this image.") from exc


def _wrap_key_with_rsa(data_key: bytes, public_key_pem: bytes | None) -> dict[str, str]:
    if not public_key_pem:
        raise CryptoError("RSA hybrid mode requires a public key.")

    public_key = serialization.load_pem_public_key(public_key_pem)
    wrapped_key = public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "type": "rsa-oaep-sha256",
        "wrapped_key": _b64encode(wrapped_key),
    }


def _unwrap_key_with_rsa(
    key_wrap: dict[str, Any],
    private_key_pem: bytes | None,
    private_key_passphrase: str | None,
) -> bytes:
    if not private_key_pem:
        raise CryptoError("RSA hybrid decryption requires a private key.")
    if not private_key_passphrase:
        raise CryptoError("RSA hybrid decryption requires the private key passphrase.")
    if key_wrap.get("type") != "rsa-oaep-sha256":
        raise CryptoError("Unsupported RSA key wrapping metadata.")

    try:
        wrapped_key = _b64decode(key_wrap["wrapped_key"])
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=private_key_passphrase.encode("utf-8"),
        )
        return private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except (ValueError, TypeError) as exc:
        raise CryptoError("Private key passphrase is invalid.") from exc


def _derive_passphrase_key(
    passphrase: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    kdf = Scrypt(salt=salt, length=AES_KEY_BYTES, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def _b64encode(value: bytes) -> str:
    return b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return b64decode(value.encode("ascii"))

