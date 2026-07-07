from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from .crypto import AES_GCM_PASSPHRASE, RSA_HYBRID, CryptoError, decrypt_image_bytes, encrypt_image_bytes
from .uploads import asset_aad, inspect_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ies",
        description="Encrypt or decrypt image files offline using the Image Encryption System format.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt = subparsers.add_parser("encrypt", help="Encrypt an image file to a .ies bundle.")
    encrypt.add_argument("input", type=Path)
    encrypt.add_argument("-o", "--output", type=Path)
    encrypt.add_argument(
        "--algorithm",
        choices=[AES_GCM_PASSPHRASE, RSA_HYBRID],
        default=AES_GCM_PASSPHRASE,
    )
    encrypt.add_argument("--passphrase", help="Required for AES-GCM mode.")
    encrypt.add_argument("--public-key", type=Path, help="PEM public key for RSA hybrid mode.")

    decrypt = subparsers.add_parser("decrypt", help="Decrypt a .ies bundle back to an image.")
    decrypt.add_argument("input", type=Path)
    decrypt.add_argument("-o", "--output", type=Path)
    decrypt.add_argument("--passphrase", help="Required for AES-GCM mode.")
    decrypt.add_argument("--private-key", type=Path, help="PEM private key for RSA hybrid mode.")
    decrypt.add_argument("--private-key-passphrase", help="Password for the encrypted private key.")

    return parser


def default_output_path(input_path: Path, suffix: str) -> Path:
    return input_path.with_suffix(input_path.suffix + suffix)


def write_bundle(path: Path, *, metadata: dict, ciphertext: bytes) -> None:
    payload = {
        "format": "image-encryption-system-bundle",
        "version": 1,
        "metadata": metadata,
        "ciphertext_b64": __import__("base64").b64encode(ciphertext).decode("ascii"),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_bundle(path: Path) -> tuple[dict, bytes]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    metadata = payload["metadata"]
    ciphertext = __import__("base64").b64decode(payload["ciphertext_b64"].encode("ascii"))
    return metadata, ciphertext


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "encrypt":
            image_bytes = args.input.read_bytes()
            image_info = inspect_image(image_bytes)
            output = args.output or default_output_path(args.input, ".ies")
            public_key = args.public_key.read_bytes() if args.public_key else None
            aad = asset_aad(0, args.input.name, str(image_info["mime_type"]))
            result = encrypt_image_bytes(
                image_bytes,
                args.algorithm,
                passphrase=args.passphrase,
                public_key_pem=public_key,
                aad=aad,
            )
            metadata = {
                **result.metadata,
                "aad": {
                    "user_id": 0,
                    "original_filename": args.input.name,
                    "mime_type": image_info["mime_type"],
                },
                "image_format": image_info["format"],
                "width": image_info["width"],
                "height": image_info["height"],
            }
            write_bundle(output, metadata=metadata, ciphertext=result.ciphertext)
            print(f"Encrypted {args.input} -> {output}")
            return 0

        metadata, ciphertext = read_bundle(args.input)
        aad_meta = metadata.get("aad", {})
        aad = asset_aad(
            int(aad_meta.get("user_id", 0)),
            str(aad_meta.get("original_filename", args.input.stem)),
            str(aad_meta.get("mime_type", "application/octet-stream")),
        )
        private_key = args.private_key.read_bytes() if args.private_key else None
        plaintext = decrypt_image_bytes(
            ciphertext,
            metadata,
            passphrase=args.passphrase,
            private_key_pem=private_key,
            private_key_passphrase=args.private_key_passphrase,
            aad=aad,
        )
        output = args.output or Path(str(aad_meta.get("original_filename", args.input.with_suffix("").name)))
        output.write_bytes(plaintext)
        print(f"Decrypted {args.input} -> {output}")
        return 0
    except (CryptoError, ValueError, KeyError, UnidentifiedImageError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
