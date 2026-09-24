from __future__ import annotations

import binascii
import json
import os
import re
import struct
from base64 import b64decode, b64encode
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

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
# Wrap metadata travels with the ciphertext, so every parameter below is
# attacker-controlled on any .ies file or restored backup. These ceilings keep a
# hostile blob from steering Scrypt into a memory-exhaustion DoS.
MAX_PASSPHRASE_BYTES = 1024
MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024
MAX_SCRYPT_WORK_FACTOR = 2**22
IES_MAGIC = b"IES1"
WRAP_SCRYPT = "scrypt-aes-gcm"
WRAP_RSA = "rsa-oaep-sha256"
WRAP_TYPES = (WRAP_SCRYPT, WRAP_RSA)

# Envelope versions this code can open. Version 1 is the original format whose
# AAD is rebuilt from the legacy ``aad`` dict. Version 3 seals a structured
# ``context``. Version 2 is deliberately skipped: the discarded v1.0 lineage of
# this project wrote ``"version": 2`` with an incompatible layout.
ENVELOPE_V1 = 1
ENVELOPE_V3 = 3
CURRENT_ENVELOPE_VERSION = ENVELOPE_V3
SUPPORTED_ENVELOPE_VERSIONS = frozenset({ENVELOPE_V1, ENVELOPE_V3})
CONTEXT_AAD_PREFIX = b"IES-CONTEXT-V3\x00"
MAX_METADATA_BYTES = 64 * 1024
MAX_CONTEXT_BYTES = 4096
CONTEXT_SOURCES = frozenset({"web", "cli", "browser"})
_ASSET_ID = re.compile(r"[0-9a-f]{32}")


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


def new_asset_id() -> str:
    """Random identifier sealed into every version 3 envelope."""
    return uuid4().hex


def encrypt_image_bytes(
    image_bytes: bytes,
    algorithm: str,
    *,
    passphrase: str | None = None,
    public_key_pem: bytes | None = None,
    context: Mapping[str, Any] | None = None,
) -> EncryptionResult:
    """Encrypt into a version 3 envelope whose AAD is the sealed ``context``.

    ``context`` may carry ``asset``, ``owner``, ``filename``, ``mime``,
    ``format``, ``width``, ``height`` and ``source``. ``algorithm`` and ``wrap``
    are always filled in here, and ``asset`` defaults to a fresh random id.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise CryptoError(f"Unsupported algorithm: {algorithm}")
    if not image_bytes:
        raise CryptoError("Image bytes cannot be empty.")

    sealed = dict(context or {})
    sealed.setdefault("asset", new_asset_id())
    sealed["algorithm"] = algorithm
    sealed["wrap"] = WRAP_SCRYPT if algorithm == AES_GCM_PASSPHRASE else WRAP_RSA
    _validate_context(sealed, algorithm=algorithm)

    data_key = os.urandom(AES_KEY_BYTES)
    image_nonce = os.urandom(GCM_NONCE_BYTES)
    key_wrap: dict[str, Any]
    if algorithm == AES_GCM_PASSPHRASE:
        key_wrap = _wrap_key_with_passphrase(data_key, passphrase)
    else:
        key_wrap = _wrap_key_with_rsa(data_key, public_key_pem)
    ciphertext = AESGCM(data_key).encrypt(image_nonce, image_bytes, context_aad(sealed))

    metadata: dict[str, Any] = {
        "version": CURRENT_ENVELOPE_VERSION,
        "algorithm": algorithm,
        "image_nonce": _b64encode(image_nonce),
        "key_wrap": key_wrap,
        "context": sealed,
    }
    return EncryptionResult(ciphertext=ciphertext, metadata=metadata)


def decrypt_image_bytes(
    ciphertext: bytes,
    metadata: dict[str, Any],
    *,
    passphrase: str | None = None,
    private_key_pem: bytes | None = None,
    private_key_passphrase: str | None = None,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt an envelope of any supported version.

    The AAD is rebuilt from the envelope itself. ``aad`` is only for version 1
    callers that know the context out of band; for version 3 the sealed context
    is authoritative and a conflicting ``aad`` is refused.
    """
    version = validate_envelope(metadata)
    derived = aad_from_metadata(metadata)
    if aad is None or aad == derived:
        effective_aad = derived
    elif version == ENVELOPE_V1:
        effective_aad = aad
    else:
        raise CryptoError("Supplied AAD conflicts with the sealed envelope context.")
    if not isinstance(ciphertext, bytes) or len(ciphertext) < GCM_TAG_BYTES:
        raise CryptoError("Encrypted image ciphertext is truncated.")

    data_key = unwrap_data_key(
        metadata["key_wrap"],
        passphrase=passphrase,
        private_key_pem=private_key_pem,
        private_key_passphrase=private_key_passphrase,
    )

    try:
        return AESGCM(data_key).decrypt(
            _b64decode(metadata["image_nonce"]), ciphertext, effective_aad
        )
    except InvalidTag as exc:
        raise CryptoError(
            "Decryption failed. The key, passphrase, or ciphertext is invalid."
        ) from exc


def validate_envelope(metadata: Any) -> int:
    """Check every envelope field's type and size before anything uses it.

    Returns the envelope version. Raises ``CryptoError`` for anything malformed,
    so hostile ``.ies`` files and backups fail cleanly instead of crashing.
    """
    if not isinstance(metadata, dict):
        raise CryptoError("Encrypted image metadata must be an object.")
    version = metadata.get("version", ENVELOPE_V1)
    if isinstance(version, bool) or not isinstance(version, int):
        raise CryptoError("Encrypted image metadata version is invalid.")
    if version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise CryptoError(f"Unsupported encrypted image envelope version: {version}")
    algorithm = metadata.get("algorithm")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise CryptoError("Encrypted image algorithm is not supported.")
    if len(_b64decode(metadata.get("image_nonce"))) != GCM_NONCE_BYTES:
        raise CryptoError("Encrypted image nonce has an invalid length.")
    key_wrap = metadata.get("key_wrap")
    if not isinstance(key_wrap, dict) or key_wrap.get("type") not in WRAP_TYPES:
        raise CryptoError("Encrypted image key wrapping metadata is invalid.")
    if version == ENVELOPE_V3:
        _validate_context(metadata.get("context"), algorithm=algorithm)
    else:
        legacy = metadata.get("aad")
        if legacy is not None and not isinstance(legacy, dict):
            raise CryptoError("Encrypted image context is invalid.")
    return int(version)


def context_aad(context: Mapping[str, Any]) -> bytes:
    """Canonical AAD bytes for a version 3 context.

    Sorted keys, no whitespace, UTF-8 (not ASCII-escaped), so a browser's
    ``JSON.stringify`` over the same sorted object produces identical bytes.
    """
    body = json.dumps(dict(context), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return CONTEXT_AAD_PREFIX + body.encode("utf-8")


def _validate_context(context: Any, *, algorithm: str) -> None:
    if not isinstance(context, dict):
        raise CryptoError("Encrypted image context is missing.")
    allowed = {
        "asset",
        "algorithm",
        "wrap",
        "owner",
        "filename",
        "mime",
        "format",
        "width",
        "height",
        "source",
    }
    if not set(context) <= allowed:
        raise CryptoError("Encrypted image context has unexpected fields.")
    if not isinstance(context.get("asset"), str) or not _ASSET_ID.fullmatch(context["asset"]):
        raise CryptoError("Encrypted image context has an invalid asset id.")
    if context.get("algorithm") != algorithm:
        raise CryptoError("Encrypted image context does not match its algorithm.")
    if context.get("wrap") not in WRAP_TYPES:
        raise CryptoError("Encrypted image context has an invalid wrap type.")
    for key in ("owner", "width", "height"):
        if key in context:
            value = context[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value < 2**31:
                raise CryptoError(f"Encrypted image context has an invalid {key}.")
    for key, limit in (("filename", 255), ("mime", 100), ("format", 16)):
        if key in context and (not isinstance(context[key], str) or len(context[key]) > limit):
            raise CryptoError(f"Encrypted image context has an invalid {key}.")
    if "source" in context and context["source"] not in CONTEXT_SOURCES:
        raise CryptoError("Encrypted image context has an invalid source.")
    if len(context_aad(context)) > MAX_CONTEXT_BYTES:
        raise CryptoError("Encrypted image context is too large.")


def unwrap_data_key(
    key_wrap: dict[str, Any],
    *,
    passphrase: str | None = None,
    private_key_pem: bytes | None = None,
    private_key_passphrase: str | None = None,
) -> bytes:
    """Recover the AES data key from passphrase or RSA wrapping metadata."""
    if not isinstance(key_wrap, dict):
        raise CryptoError("Unsupported key wrapping metadata.")
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
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CryptoError("Current password is invalid.") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("The stored private key is not an RSA private key.")
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
    if meta_len > MAX_METADATA_BYTES:
        raise CryptoError("IES vault file metadata is too large.")
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


def web_aad(user_id: int, original_filename: str, mime_type: str) -> bytes:
    return f"user={user_id}|filename={original_filename}|mime={mime_type}".encode()


def aad_from_metadata(metadata: dict[str, Any]) -> bytes:
    """Rebuild the AAD an envelope was sealed with from the envelope itself.

    Version 3 seals the canonical ``context``. Version 1 web uploads recorded
    ``user_id``/``original_filename``/``mime_type`` under ``aad``; version 1 CLI
    encryptions recorded ``source="cli"`` and ``filename``. Any other version 1
    envelope was sealed without associated data.
    """
    if validate_envelope(metadata) == ENVELOPE_V3:
        return context_aad(metadata["context"])
    context = metadata.get("aad")
    if not isinstance(context, dict):
        return b""
    if context.get("source") == "cli":
        return cli_aad(str(context.get("filename", "")))
    if "user_id" in context:
        try:
            user_id = int(context["user_id"])
        except (TypeError, ValueError) as exc:
            raise CryptoError("Encrypted image context is invalid.") from exc
        return web_aad(
            user_id,
            str(context.get("original_filename", "")),
            str(context.get("mime_type", "")),
        )
    return b""


def _wrap_key_with_passphrase(data_key: bytes, passphrase: str | None) -> dict[str, str | int]:
    if not passphrase:
        raise CryptoError("AES-GCM mode requires a passphrase.")

    salt = os.urandom(SCRYPT_SALT_BYTES)
    wrapping_key = _derive_passphrase_key(passphrase, salt)
    wrapping_nonce = os.urandom(GCM_NONCE_BYTES)
    wrapped_key = AESGCM(wrapping_key).encrypt(wrapping_nonce, data_key, b"image-data-key")

    return {
        "type": WRAP_SCRYPT,
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

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CryptoError("RSA public key could not be parsed.") from exc
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
    except KeyError as exc:
        raise CryptoError("RSA key wrapping metadata is incomplete.") from exc
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CryptoError("Private key passphrase is invalid.") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("RSA hybrid decryption requires an RSA private key.")
    try:
        return private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise CryptoError("RSA key unwrap failed.") from exc


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

    ``n`` must stay a power of two at or above the value we write ourselves, so
    a hostile blob can neither weaken the KDF below our own baseline nor push it
    into an allocation large enough to take the process down.
    """
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


def _b64decode(value: Any) -> bytes:
    if not isinstance(value, str):
        raise CryptoError("Encrypted image metadata field must be base64 text.")
    try:
        return b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CryptoError("Encrypted image metadata field is not valid base64.") from exc
