from __future__ import annotations

import json
import math
from hashlib import sha256
from io import BytesIO
from typing import Any

from PIL import Image
from werkzeug.utils import secure_filename

from .crypto import AES_GCM_PASSPHRASE, RSA_HYBRID, CryptoError, encrypt_image_bytes


def image_entropy(image_bytes: bytes) -> float:
    if not image_bytes:
        return 0.0
    counts = [0] * 256
    for byte in image_bytes:
        counts[byte] += 1
    length = len(image_bytes)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


AAD_VERSION = 2
SUPPORTED_IMAGE_FORMATS = frozenset({"PNG", "JPEG", "WEBP", "GIF", "BMP", "TIFF"})


def normalize_filename(filename: str) -> str:
    return secure_filename(filename.strip()) or "image"


def asset_aad(
    user_id: int,
    original_filename: str,
    mime_type: str,
    *,
    version: int = AAD_VERSION,
    algorithm: str | None = None,
    image_format: str | None = None,
    width: int | None = None,
    height: int | None = None,
    unlock_after: str | None = None,
) -> bytes:
    if version == 1:
        return f"user={user_id}|filename={original_filename}|mime={mime_type}".encode()
    if version != AAD_VERSION:
        raise CryptoError(f"Unsupported asset context version: {version}")

    context = {
        "algorithm": algorithm or "",
        "height": int(height or 0),
        "image_format": image_format or "",
        "mime_type": mime_type,
        "original_filename": original_filename,
        "schema": "image-encryption-system.asset-context.v2",
        "unlock_after": unlock_after or "",
        "user_id": int(user_id),
        "width": int(width or 0),
    }
    return json.dumps(
        context,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def inspect_image(image_bytes: bytes) -> dict[str, int | str]:
    with Image.open(BytesIO(image_bytes)) as image:
        image.verify()

    with Image.open(BytesIO(image_bytes)) as image:
        image_format = image.format or "UNKNOWN"
        if image_format not in SUPPORTED_IMAGE_FORMATS:
            raise ValueError(f"Unsupported image format: {image_format}")
        mime_type = Image.MIME.get(image_format, "application/octet-stream")
        width, height = image.size
        image.load()
        return {
            "format": image_format,
            "mime_type": mime_type,
            "width": width,
            "height": height,
        }


def encrypt_upload(
    *,
    user_id: int,
    filename: str,
    image_bytes: bytes,
    algorithm: str,
    passphrase: str | None,
    public_key_pem: bytes | None,
    unlock_after: str | None = None,
) -> tuple[bytes, dict[str, Any], dict[str, int | str]]:
    if not image_bytes:
        raise ValueError("Image bytes cannot be empty.")

    safe_filename = normalize_filename(filename)
    image_info = inspect_image(image_bytes)
    aad_context: dict[str, Any] = {
        "version": AAD_VERSION,
        "user_id": user_id,
        "original_filename": safe_filename,
        "mime_type": str(image_info["mime_type"]),
        "algorithm": algorithm,
        "image_format": str(image_info["format"]),
        "width": int(image_info["width"]),
        "height": int(image_info["height"]),
        "unlock_after": unlock_after or "",
    }
    aad = asset_aad(**aad_context)
    result = encrypt_image_bytes(
        image_bytes,
        algorithm,
        passphrase=passphrase if algorithm == AES_GCM_PASSPHRASE else None,
        public_key_pem=public_key_pem if algorithm == RSA_HYBRID else None,
        aad=aad,
    )
    metadata = {
        **result.metadata,
        "content_hash": sha256(image_bytes).hexdigest(),
        "entropy_bits": image_entropy(image_bytes),
        "aad": aad_context,
    }
    if unlock_after:
        metadata["unlock_after"] = unlock_after
    return result.ciphertext, metadata, image_info
