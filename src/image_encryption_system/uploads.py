from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import math
from typing import Any

from PIL import Image, UnidentifiedImageError

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


def asset_aad(user_id: int, original_filename: str, mime_type: str) -> bytes:
    return f"user={user_id}|filename={original_filename}|mime={mime_type}".encode("utf-8")


def inspect_image(image_bytes: bytes) -> dict[str, int | str]:
    with Image.open(BytesIO(image_bytes)) as image:
        image.verify()

    with Image.open(BytesIO(image_bytes)) as image:
        image_format = image.format or "UNKNOWN"
        mime_type = Image.MIME.get(image_format, "application/octet-stream")
        width, height = image.size
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
) -> tuple[bytes, dict[str, Any], dict[str, int | str]]:
    if not image_bytes:
        raise ValueError("Image bytes cannot be empty.")

    image_info = inspect_image(image_bytes)
    aad = asset_aad(user_id, filename, str(image_info["mime_type"]))
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
        "aad": {
            "user_id": user_id,
            "original_filename": filename,
            "mime_type": image_info["mime_type"],
        },
    }
    return result.ciphertext, metadata, image_info
