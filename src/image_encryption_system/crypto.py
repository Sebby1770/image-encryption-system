from __future__ import annotations

import os
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

AES_GCM_PASSPHRASE = "AES-GCM"
RSA_HYBRID = "RSA-HYBRID"
SUPPORTED_ALGORITHMS = (AES_GCM_PASSPHRASE, RSA_HYBRID)

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
SCRYPT_SALT_BYTES = 16
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
MAX_PASSPHRASE_BYTES = 1024
MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024
MAX_SCRYPT_WORK_FACTOR = 2**22
SUPPORTED_METADATA_VERSIONS = frozenset({1, 2})


class CryptoError(Exception):
    """Raised when encryption or decryption cannot be completed safely."""


@dataclass(frozen=True)
class EncryptionResult:
    ciphertext: bytes
    metadata: dict[str, Any]


def rewrap_private_key(private_pem: bytes, old_passphrase: str, new_passphrase: str) -> bytes:
    old_password = _passphrase_bytes(old_passphrase, label="Current passphrase")
    new_password = _passphrase_bytes(new_passphrase, label="New passphrase")
    if len(new_passphrase) < 10:
        raise CryptoError("New passphrase must be at least 10 characters.")

    try:
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=old_password,
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise CryptoError("Current private-key passphrase is invalid.") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("The stored private key is not an RSA private key.")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(new_password),
    )


def generate_rsa_key_pair(passphrase: str) -> tuple[bytes, bytes]:
    password = _passphrase_bytes(passphrase, label="Passphrase")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
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
        "version": 2,
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
    if not isinstance(metadata, dict):
        raise CryptoError("Encrypted image metadata must be an object.")
    if not isinstance(ciphertext, bytes) or len(ciphertext) < GCM_TAG_BYTES:
        raise CryptoError("Encrypted image ciphertext is invalid.")
    try:
        version = int(metadata.get("version", 1))
        algorithm = metadata["algorithm"]
        image_nonce = _b64decode(metadata["image_nonce"], label="image nonce")
        key_wrap = metadata["key_wrap"]
    except (KeyError, TypeError, ValueError) as exc:
        raise CryptoError("Encrypted image metadata is incomplete.") from exc
    if version not in SUPPORTED_METADATA_VERSIONS:
        raise CryptoError(f"Unsupported encrypted image metadata version: {version}")
    if len(image_nonce) != GCM_NONCE_BYTES:
        raise CryptoError("Encrypted image nonce has an invalid length.")
    if not isinstance(key_wrap, dict):
        raise CryptoError("Encrypted image key wrapping metadata must be an object.")

    if algorithm == AES_GCM_PASSPHRASE:
        data_key = _unwrap_key_with_passphrase(key_wrap, passphrase)
    elif algorithm == RSA_HYBRID:
        data_key = _unwrap_key_with_rsa(key_wrap, private_key_pem, private_key_passphrase)
    else:
        raise CryptoError(f"Unsupported algorithm: {algorithm}")

    try:
        return AESGCM(data_key).decrypt(image_nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError(
            "Decryption failed. The key, passphrase, or ciphertext is invalid."
        ) from exc


def _wrap_key_with_passphrase(data_key: bytes, passphrase: str | None) -> dict[str, str | int]:
    _passphrase_bytes(passphrase, label="AES-GCM passphrase")

    salt = os.urandom(SCRYPT_SALT_BYTES)
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
    _passphrase_bytes(passphrase, label="AES-GCM passphrase")
    if key_wrap.get("type") != "scrypt-aes-gcm":
        raise CryptoError("Unsupported AES key wrapping metadata.")

    try:
        salt = _b64decode(key_wrap["salt"], label="Scrypt salt")
        nonce = _b64decode(key_wrap["nonce"], label="wrapping nonce")
        wrapped_key = _b64decode(key_wrap["wrapped_key"], label="wrapped data key")
        n = int(key_wrap.get("n", SCRYPT_N))
        r = int(key_wrap.get("r", SCRYPT_R))
        p = int(key_wrap.get("p", SCRYPT_P))
    except (KeyError, TypeError, ValueError) as exc:
        raise CryptoError("AES key wrapping metadata is incomplete.") from exc
    if len(salt) != SCRYPT_SALT_BYTES:
        raise CryptoError("Scrypt salt has an invalid length.")
    if len(nonce) != GCM_NONCE_BYTES:
        raise CryptoError("Wrapping nonce has an invalid length.")
    if len(wrapped_key) != AES_KEY_BYTES + GCM_TAG_BYTES:
        raise CryptoError("Wrapped data key has an invalid length.")
    _validate_scrypt_parameters(n=n, r=r, p=p)

    wrapping_key = _derive_passphrase_key(
        passphrase,
        salt,
        n=n,
        r=r,
        p=p,
    )
    try:
        return AESGCM(wrapping_key).decrypt(nonce, wrapped_key, b"image-data-key")
    except InvalidTag as exc:
        raise CryptoError("Passphrase did not unlock this image.") from exc


def _wrap_key_with_rsa(data_key: bytes, public_key_pem: bytes | None) -> dict[str, str]:
    if not public_key_pem:
        raise CryptoError("RSA hybrid mode requires a public key.")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise CryptoError("RSA public key is invalid.") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptoError("RSA hybrid mode requires an RSA public key.")
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
        wrapped_key = _b64decode(key_wrap["wrapped_key"], label="RSA-wrapped data key")
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=_passphrase_bytes(
                private_key_passphrase,
                label="Private-key passphrase",
            ),
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoError("RSA hybrid mode requires an RSA private key.")
        expected_wrapped_bytes = (private_key.key_size + 7) // 8
        if len(wrapped_key) != expected_wrapped_bytes:
            raise CryptoError("RSA-wrapped data key has an invalid length.")
        return private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except CryptoError:
        raise
    except (KeyError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CryptoError("Private key passphrase is invalid.") from exc


def _derive_passphrase_key(
    passphrase: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    _validate_scrypt_parameters(n=n, r=r, p=p)
    kdf = Scrypt(salt=salt, length=AES_KEY_BYTES, n=n, r=r, p=p)
    return kdf.derive(_passphrase_bytes(passphrase, label="AES-GCM passphrase"))


def _validate_scrypt_parameters(*, n: int, r: int, p: int) -> None:
    if n < SCRYPT_N or n > MAX_SCRYPT_WORK_FACTOR or n & (n - 1):
        raise CryptoError("Scrypt work factor is outside the supported range.")
    if not 1 <= r <= 32 or not 1 <= p <= 16:
        raise CryptoError("Scrypt parameters are outside the supported range.")
    if 128 * n * r > MAX_SCRYPT_MEMORY_BYTES:
        raise CryptoError("Scrypt parameters require too much memory.")
    if n * r * p > MAX_SCRYPT_WORK_FACTOR * SCRYPT_R:
        raise CryptoError("Scrypt parameters require too much work.")


def _passphrase_bytes(passphrase: str | None, *, label: str) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise CryptoError(f"{label} is required.")
    encoded = passphrase.encode("utf-8")
    if len(encoded) > MAX_PASSPHRASE_BYTES:
        raise CryptoError(f"{label} is too long.")
    return encoded


def _b64encode(value: bytes) -> str:
    return b64encode(value).decode("ascii")


def _b64decode(value: str, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise CryptoError(f"Encoded {label} must be text.")
    try:
        return b64decode(value.encode("ascii"), validate=True)
    except (BinasciiError, UnicodeEncodeError, ValueError) as exc:
        raise CryptoError(f"Encoded {label} is invalid.") from exc
