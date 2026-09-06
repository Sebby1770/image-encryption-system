from __future__ import annotations

import json
import os
import struct
from base64 import b64decode, b64encode
from dataclasses import dataclass
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
GCM_TAG_BYTES = 16
SCRYPT_SALT_BYTES = 16
# Cost this build writes into new wrappings. Raising it strengthens every key
# minted from here on; existing files keep decrypting because the floor below is
# a separate constant.
#
# 2**16 is four times the previous cost. It measures ~308 ms and 67 MB per
# derivation, against ~611 ms and 134 MB at 2**17. The KDF runs on every decrypt
# rather than only at login, so the higher setting would let a handful of
# concurrent decrypts exhaust memory on a small host; the decrypt throttle bounds
# that, but not enough to justify doubling the per-request cost.
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1
# Weakest cost we are still willing to spend on an existing file.
#
# This used to be SCRYPT_N itself, which quietly made the default un-raisable:
# bumping the cost would have rejected every vault file and .ies blob already
# written at the old parameters. Keeping the floor separate lets the default
# move forward while old wrappings stay readable, and `ies rewrap` upgrades
# them in place.
MIN_SCRYPT_N = 2**14
# Wrap metadata travels with the ciphertext, so every parameter below is
# attacker-controlled on any .ies file or restored backup. These ceilings keep a
# hostile blob from steering Scrypt into a memory-exhaustion DoS.
MAX_PASSPHRASE_BYTES = 1024
MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024
MAX_SCRYPT_WORK_FACTOR = 2**22
SUPPORTED_METADATA_VERSIONS = frozenset({1, 2})
IES_MAGIC = b"IES1"
WRAP_SCRYPT = "scrypt-aes-gcm"
WRAP_RSA = "rsa-oaep-sha256"


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
    _validate_metadata_version(metadata)
    try:
        image_nonce = _b64decode(metadata["image_nonce"])
        key_wrap = metadata["key_wrap"]
    except KeyError as exc:
        raise CryptoError("Encrypted image metadata is incomplete.") from exc

    data_key = unwrap_data_key(
        key_wrap,
        passphrase=passphrase,
        private_key_pem=private_key_pem,
        private_key_passphrase=private_key_passphrase,
    )

    try:
        return AESGCM(data_key).decrypt(image_nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError(
            "Decryption failed. The key, passphrase, or ciphertext is invalid."
        ) from exc


def _validate_metadata_version(metadata: dict[str, Any]) -> None:
    """Reject envelope metadata this build does not know how to read.

    ``SUPPORTED_METADATA_VERSIONS`` was declared from the beginning but never
    consulted, so a blob claiming any version at all was decoded on the
    assumption that its fields meant what this build expects. Checking it turns
    a future format change into a clear refusal instead of a misparse.
    """
    raw = metadata.get("version", 1)
    try:
        version = int(raw)
    except (TypeError, ValueError) as exc:
        raise CryptoError("Encrypted image metadata has an invalid version.") from exc
    if version not in SUPPORTED_METADATA_VERSIONS:
        raise CryptoError(f"Unsupported encrypted image metadata version: {version}")


def unwrap_data_key(
    key_wrap: dict[str, Any],
    *,
    passphrase: str | None = None,
    private_key_pem: bytes | None = None,
    private_key_passphrase: str | None = None,
) -> bytes:
    """Recover the AES data key from passphrase or RSA wrapping metadata."""
    wrap_type = key_wrap.get("type")
    if wrap_type == WRAP_SCRYPT:
        return _unwrap_key_with_passphrase(key_wrap, passphrase)
    if wrap_type == WRAP_RSA:
        return _unwrap_key_with_rsa(key_wrap, private_key_pem, private_key_passphrase)
    raise CryptoError("Unsupported key wrapping metadata.")


def wrap_data_key_rsa(data_key: bytes, public_key_pem: bytes) -> dict[str, str]:
    """Re-wrap an existing AES data key with a recipient's RSA public key."""
    if len(data_key) != AES_KEY_BYTES:
        raise CryptoError("Refusing to wrap a data key of unexpected length.")
    return _wrap_key_with_rsa(data_key, public_key_pem)


def wrap_data_key_passphrase(data_key: bytes, passphrase: str) -> dict[str, str | int]:
    """Re-wrap an existing AES data key with a new Scrypt+AES passphrase."""
    if len(data_key) != AES_KEY_BYTES:
        raise CryptoError("Refusing to wrap a data key of unexpected length.")
    return _wrap_key_with_passphrase(data_key, passphrase)


def reencrypt_private_key_pem(
    private_pem: bytes,
    old_passphrase: str,
    new_passphrase: str,
) -> bytes:
    """Load a password-wrapped RSA PEM and wrap it again with a new password."""
    if not new_passphrase:
        raise CryptoError("A passphrase is required to protect the private key.")
    try:
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=old_passphrase.encode("utf-8") if old_passphrase else None,
        )
    except (ValueError, TypeError) as exc:
        raise CryptoError("Current password is invalid.") from exc
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(new_passphrase.encode("utf-8")),
    )


def pack_ies(ciphertext: bytes, metadata: dict[str, Any]) -> bytes:
    """Pack ciphertext and wrap metadata into a portable .ies vault file."""
    raw_meta = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return IES_MAGIC + struct.pack(">I", len(raw_meta)) + raw_meta + ciphertext


def unpack_ies(blob: bytes) -> tuple[bytes, dict[str, Any]]:
    """Split a portable .ies vault file into ciphertext and metadata."""
    if len(blob) < 8 or blob[:4] != IES_MAGIC:
        raise CryptoError("Not a valid IES vault file.")
    meta_len = struct.unpack(">I", blob[4:8])[0]
    start = 8
    end = start + meta_len
    if meta_len < 2 or end > len(blob):
        raise CryptoError("IES vault file metadata is truncated.")
    try:
        metadata = json.loads(blob[start:end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError("IES vault file metadata is invalid.") from exc
    if not isinstance(metadata, dict):
        raise CryptoError("IES vault file metadata is invalid.")
    return blob[end:], metadata


def cli_aad(filename: str) -> bytes:
    return f"cli|filename={filename}".encode()


def _wrap_key_with_passphrase(
    data_key: bytes,
    passphrase: str | None,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> dict[str, str | int]:
    if not passphrase:
        raise CryptoError("AES-GCM mode requires a passphrase.")

    salt = os.urandom(SCRYPT_SALT_BYTES)
    # Derive with the same parameters that get written into the metadata. They
    # used to be supplied twice — once implicitly through this function's default
    # arguments and once as literals in the dict below — which meant the recorded
    # cost could drift from the cost actually spent without anything failing
    # until a decrypt.
    wrapping_key = _derive_passphrase_key(passphrase, salt, n=n, r=r, p=p)
    wrapping_nonce = os.urandom(GCM_NONCE_BYTES)
    wrapped_key = AESGCM(wrapping_key).encrypt(wrapping_nonce, data_key, b"image-data-key")

    return {
        "type": WRAP_SCRYPT,
        "salt": _b64encode(salt),
        "nonce": _b64encode(wrapping_nonce),
        "wrapped_key": _b64encode(wrapped_key),
        "n": n,
        "r": r,
        "p": p,
    }


def _unwrap_key_with_passphrase(key_wrap: dict[str, Any], passphrase: str | None) -> bytes:
    if not passphrase:
        raise CryptoError("A passphrase is required for AES-GCM decryption.")
    if key_wrap.get("type") != WRAP_SCRYPT:
        raise CryptoError("Unsupported AES key wrapping metadata.")

    try:
        salt = _b64decode(key_wrap["salt"])
        nonce = _b64decode(key_wrap["nonce"])
        wrapped_key = _b64decode(key_wrap["wrapped_key"])
    except KeyError as exc:
        raise CryptoError("AES key wrapping metadata is incomplete.") from exc

    try:
        n = int(key_wrap.get("n", SCRYPT_N))
        r = int(key_wrap.get("r", SCRYPT_R))
        p = int(key_wrap.get("p", SCRYPT_P))
    except (TypeError, ValueError) as exc:
        raise CryptoError("AES key wrapping metadata is incomplete.") from exc

    if len(salt) != SCRYPT_SALT_BYTES:
        raise CryptoError("Scrypt salt has an invalid length.")
    if len(nonce) != GCM_NONCE_BYTES:
        raise CryptoError("Wrapping nonce has an invalid length.")
    if len(wrapped_key) != AES_KEY_BYTES + GCM_TAG_BYTES:
        raise CryptoError("Wrapped data key has an invalid length.")

    wrapping_key = _derive_passphrase_key(passphrase, salt, n=n, r=r, p=p)
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
        "type": WRAP_RSA,
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
    if key_wrap.get("type") != WRAP_RSA:
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
    _validate_scrypt_parameters(n=n, r=r, p=p)
    kdf = Scrypt(salt=salt, length=AES_KEY_BYTES, n=n, r=r, p=p)
    return kdf.derive(_passphrase_bytes(passphrase, label="AES-GCM passphrase"))


def _validate_scrypt_parameters(*, n: int, r: int, p: int) -> None:
    """Reject Scrypt costs outside the range this vault is willing to spend.

    ``n`` must stay a power of two at or above ``MIN_SCRYPT_N``, so a hostile
    blob can neither weaken the KDF below the supported baseline nor push it into
    an allocation large enough to take the process down. The floor is
    deliberately below the cost we write ourselves so the default can be raised
    without stranding files wrapped by an earlier release.
    """
    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_WORK_FACTOR or n & (n - 1):
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


def _b64decode(value: str) -> bytes:
    return b64decode(value.encode("ascii"))
