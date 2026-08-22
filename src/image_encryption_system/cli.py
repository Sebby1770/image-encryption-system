from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from contextlib import suppress
from pathlib import Path

from PIL import UnidentifiedImageError
from werkzeug.utils import secure_filename

from .crypto import AES_GCM_PASSPHRASE, RSA_HYBRID, CryptoError, decrypt_image_bytes
from .uploads import asset_aad, encrypt_upload, inspect_image

BUNDLE_FORMAT = "image-encryption-system-bundle"
BUNDLE_VERSION = 2
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
OWNER_ONLY_FILE_MODE = 0o600


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ies",
        description=(
            "Encrypt or decrypt image files offline using the Image Encryption System format."
        ),
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
    encrypt.add_argument(
        "--passphrase-file",
        type=Path,
        help="Read the AES passphrase from a file instead of process arguments.",
    )
    encrypt.add_argument("--public-key", type=Path, help="PEM public key for RSA hybrid mode.")
    encrypt.add_argument("--force", action="store_true", help="Replace an existing output file.")

    decrypt = subparsers.add_parser("decrypt", help="Decrypt a .ies bundle back to an image.")
    decrypt.add_argument("input", type=Path)
    decrypt.add_argument("-o", "--output", type=Path)
    decrypt.add_argument("--passphrase", help="Required for AES-GCM mode.")
    decrypt.add_argument(
        "--passphrase-file", type=Path, help="Read the AES passphrase from a file."
    )
    decrypt.add_argument("--private-key", type=Path, help="PEM private key for RSA hybrid mode.")
    decrypt.add_argument("--private-key-passphrase", help="Password for the encrypted private key.")
    decrypt.add_argument(
        "--private-key-passphrase-file",
        type=Path,
        help="Read the private-key password from a file.",
    )
    decrypt.add_argument("--force", action="store_true", help="Replace an existing output file.")

    return parser


def default_output_path(input_path: Path, suffix: str) -> Path:
    return input_path.with_suffix(input_path.suffix + suffix)


def write_bundle(
    path: Path,
    *,
    metadata: dict,
    ciphertext: bytes,
    force: bool = False,
) -> None:
    payload = {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "metadata": metadata,
        "ciphertext_b64": b64encode(ciphertext).decode("ascii"),
    }
    _write_private_file(
        path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        force=force,
    )


def read_bundle(path: Path) -> tuple[dict, bytes]:
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("Bundle exceeds the 128 MiB safety limit.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Bundle root must be a JSON object.")
    if payload.get("format") != BUNDLE_FORMAT:
        raise ValueError("File is not an Image Encryption System bundle.")
    if int(payload.get("version", 0)) not in {1, BUNDLE_VERSION}:
        raise ValueError("Bundle version is not supported.")
    metadata = payload.get("metadata")
    ciphertext_b64 = payload.get("ciphertext_b64")
    if not isinstance(metadata, dict) or not isinstance(ciphertext_b64, str):
        raise ValueError("Bundle metadata or ciphertext is invalid.")
    try:
        ciphertext = b64decode(ciphertext_b64.encode("ascii"), validate=True)
    except (BinasciiError, UnicodeEncodeError) as exc:
        raise ValueError("Bundle ciphertext is not valid base64.") from exc
    if len(ciphertext) < 16:
        raise ValueError("Bundle ciphertext is too short.")
    return metadata, ciphertext


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "encrypt":
            image_bytes = args.input.read_bytes()
            output = args.output or default_output_path(args.input, ".ies")
            public_key = args.public_key.read_bytes() if args.public_key else None
            passphrase = _secret_value(
                direct=args.passphrase,
                file_path=args.passphrase_file,
                prompt="AES passphrase: ",
                required=args.algorithm == AES_GCM_PASSPHRASE,
            )
            ciphertext, metadata, image_info = encrypt_upload(
                user_id=0,
                filename=args.input.name,
                image_bytes=image_bytes,
                algorithm=args.algorithm,
                passphrase=passphrase,
                public_key_pem=public_key,
            )
            metadata.update(
                {
                    "image_format": image_info["format"],
                    "width": image_info["width"],
                    "height": image_info["height"],
                }
            )
            write_bundle(
                output,
                metadata=metadata,
                ciphertext=ciphertext,
                force=args.force,
            )
            print(f"Encrypted {args.input} -> {output}")
            return 0

        metadata, ciphertext = read_bundle(args.input)
        aad_meta = metadata.get("aad", {})
        if not isinstance(aad_meta, dict):
            raise ValueError("Bundle asset context is invalid.")
        aad = asset_aad(
            int(aad_meta.get("user_id", 0)),
            str(aad_meta.get("original_filename", args.input.stem)),
            str(aad_meta.get("mime_type", "application/octet-stream")),
            version=int(aad_meta.get("version", 1)),
            algorithm=str(aad_meta.get("algorithm", "")) or None,
            image_format=str(aad_meta.get("image_format", "")) or None,
            width=int(aad_meta.get("width", 0)),
            height=int(aad_meta.get("height", 0)),
            unlock_after=str(aad_meta.get("unlock_after", "")) or None,
        )
        private_key = args.private_key.read_bytes() if args.private_key else None
        passphrase = _secret_value(
            direct=args.passphrase,
            file_path=args.passphrase_file,
            prompt="AES passphrase: ",
            required=metadata.get("algorithm") == AES_GCM_PASSPHRASE,
        )
        private_key_passphrase = _secret_value(
            direct=args.private_key_passphrase,
            file_path=args.private_key_passphrase_file,
            prompt="Private-key passphrase: ",
            required=metadata.get("algorithm") == RSA_HYBRID,
        )
        plaintext = decrypt_image_bytes(
            ciphertext,
            metadata,
            passphrase=passphrase,
            private_key_pem=private_key,
            private_key_passphrase=private_key_passphrase,
            aad=aad,
        )
        inspect_image(plaintext)
        output = args.output or _safe_embedded_output(
            aad_meta.get("original_filename"),
            fallback=args.input.with_suffix("").name,
        )
        _write_private_file(output, plaintext, force=args.force)
        print(f"Decrypted {args.input} -> {output}")
        return 0
    except (
        BinasciiError,
        CryptoError,
        json.JSONDecodeError,
        OSError,
        TypeError,
        ValueError,
        KeyError,
        UnidentifiedImageError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _secret_value(
    *,
    direct: str | None,
    file_path: Path | None,
    prompt: str,
    required: bool,
) -> str | None:
    if direct is not None and file_path is not None:
        raise ValueError("Use either a passphrase argument or a passphrase file, not both.")
    if file_path is not None:
        return file_path.read_text(encoding="utf-8").rstrip("\r\n")
    if direct is not None:
        return direct
    if required and sys.stdin.isatty():
        return getpass.getpass(prompt)
    return None


def _safe_embedded_output(value: object, *, fallback: str) -> Path:
    candidate = Path(str(value or fallback)).name
    safe_name = secure_filename(candidate) or secure_filename(fallback) or "decrypted-image"
    return Path.cwd() / safe_name


def _write_private_file(path: Path, content: bytes, *, force: bool) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(
            f"Refusing to replace existing file: {path}. Use --force to overwrite."
        )
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        if os.name != "nt":
            os.chmod(temporary, OWNER_ONLY_FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not force:
            raise FileExistsError(
                f"Refusing to replace existing file: {path}. Use --force to overwrite."
            )
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, OWNER_ONLY_FILE_MODE)
    except Exception:
        with suppress(OSError):
            os.close(fd)
        temporary.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
