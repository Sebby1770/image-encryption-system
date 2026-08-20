from __future__ import annotations

import argparse
from getpass import getpass
import json
from pathlib import Path
import sys

from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="image-vault",
        description="Encrypt and decrypt images with the same AES-GCM / RSA hybrid scheme as the vault.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = sub.add_parser("encrypt", help="Encrypt an image file")
    encrypt_parser.add_argument("image", type=Path)
    encrypt_parser.add_argument("-o", "--out", type=Path, help="Ciphertext output path")
    encrypt_parser.add_argument("--meta", type=Path, help="Metadata JSON output path")
    encrypt_parser.add_argument(
        "--algorithm",
        choices=[AES_GCM_PASSPHRASE, RSA_HYBRID],
        default=AES_GCM_PASSPHRASE,
    )
    encrypt_parser.add_argument("--passphrase")
    encrypt_parser.add_argument("--public-key", type=Path, help="PEM public key for RSA-HYBRID")

    decrypt_parser = sub.add_parser("decrypt", help="Decrypt a ciphertext + metadata pair")
    decrypt_parser.add_argument("ciphertext", type=Path)
    decrypt_parser.add_argument("--meta", type=Path, required=True, help="Metadata JSON from encrypt")
    decrypt_parser.add_argument("-o", "--out", type=Path, required=True, help="Plaintext output path")
    decrypt_parser.add_argument("--passphrase")
    decrypt_parser.add_argument("--private-key", type=Path, help="Encrypted PEM private key")
    decrypt_parser.add_argument("--private-key-passphrase")

    args = parser.parse_args(argv)
    try:
        if args.command == "encrypt":
            return _encrypt(args)
        return _decrypt(args)
    except (CryptoError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _encrypt(args: argparse.Namespace) -> int:
    image_bytes = args.image.read_bytes()
    passphrase = args.passphrase
    public_key = args.public_key.read_bytes() if args.public_key else None
    if args.algorithm == AES_GCM_PASSPHRASE and not passphrase:
        passphrase = getpass("AES passphrase: ")
    if args.algorithm == RSA_HYBRID and not public_key:
        raise ValueError("RSA-HYBRID requires --public-key")

    result = encrypt_image_bytes(
        image_bytes,
        args.algorithm,
        passphrase=passphrase,
        public_key_pem=public_key,
        aad=_cli_aad(args.image.name),
    )
    out_path = args.out or args.image.with_suffix(args.image.suffix + ".enc")
    meta_path = args.meta or out_path.with_suffix(".json")
    out_path.write_bytes(result.ciphertext)
    metadata = {
        **result.metadata,
        "aad": {"original_filename": args.image.name, "source": "cli"},
    }
    meta_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out_path}")
    print(f"wrote {meta_path}")
    return 0


def _decrypt(args: argparse.Namespace) -> int:
    ciphertext = args.ciphertext.read_bytes()
    metadata = json.loads(args.meta.read_text(encoding="utf-8"))
    aad_info = metadata.get("aad", {})
    aad = _cli_aad(str(aad_info.get("original_filename", args.ciphertext.name)))
    if aad_info.get("source") != "cli":
        # Vault-encrypted images bind AAD to user/filename/mime; CLI cannot reconstruct
        # that without the original metadata fields.
        user_id = aad_info.get("user_id")
        filename = aad_info.get("original_filename")
        mime = aad_info.get("mime_type")
        if user_id is not None and filename and mime:
            aad = f"user={user_id}|filename={filename}|mime={mime}".encode("utf-8")

    passphrase = args.passphrase
    private_key = args.private_key.read_bytes() if args.private_key else None
    private_pass = args.private_key_passphrase
    if metadata.get("algorithm") == AES_GCM_PASSPHRASE and not passphrase:
        passphrase = getpass("AES passphrase: ")
    if metadata.get("algorithm") == RSA_HYBRID and not private_pass:
        private_pass = getpass("Private key password: ")

    plaintext = decrypt_image_bytes(
        ciphertext,
        metadata,
        passphrase=passphrase,
        private_key_pem=private_key,
        private_key_passphrase=private_pass,
        aad=aad,
    )
    args.out.write_bytes(plaintext)
    print(f"wrote {args.out}")
    return 0


def _cli_aad(filename: str) -> bytes:
    return f"cli|filename={filename}".encode("utf-8")
