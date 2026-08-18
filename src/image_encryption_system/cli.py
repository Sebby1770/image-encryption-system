from __future__ import annotations

import argparse
from getpass import getpass
from pathlib import Path
import sys
from typing import Sequence

from hashlib import sha256

from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    cli_aad,
    decrypt_image_bytes,
    encrypt_image_bytes,
    generate_rsa_key_pair,
    pack_ies,
    unpack_ies,
    unwrap_data_key,
    wrap_data_key_passphrase,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ies",
        description="Encrypt and decrypt images with AES-256-GCM (optional RSA wrap).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file into an .ies vault blob.")
    encrypt_parser.add_argument("input", type=Path, help="Input file (for example IN.png)")
    encrypt_parser.add_argument("--out", "-o", type=Path, required=True, help="Output vault file")
    encrypt_parser.add_argument("--passphrase", "-p", help="AES passphrase (prompted if omitted)")
    encrypt_parser.add_argument("--public-key", type=Path, help="Recipient RSA public key (PEM)")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt an .ies vault blob.")
    decrypt_parser.add_argument("input", type=Path, help="Input vault file")
    decrypt_parser.add_argument("--out", "-o", type=Path, required=True, help="Output plaintext file")
    decrypt_parser.add_argument("--passphrase", "-p", help="AES or private-key passphrase")
    decrypt_parser.add_argument("--private-key", type=Path, help="RSA private key (PEM)")

    keygen_parser = subparsers.add_parser("keygen", help="Generate an RSA-3072 key pair.")
    keygen_parser.add_argument("--passphrase", "-p", help="Private key passphrase (prompted if omitted)")
    keygen_parser.add_argument("--out-private", type=Path, default=Path("ies-private.pem"))
    keygen_parser.add_argument("--out-public", type=Path, default=Path("ies-public.pem"))

    inspect_parser = subparsers.add_parser("inspect", help="Print public .ies metadata (no secrets).")
    inspect_parser.add_argument("input", type=Path, help="Input vault file")

    verify_parser = subparsers.add_parser("verify", help="Unwrap the data key only; exit 0 on success.")
    verify_parser.add_argument("input", type=Path, help="Input vault file")
    verify_parser.add_argument("--passphrase", "-p", help="AES or private-key passphrase")
    verify_parser.add_argument("--private-key", type=Path, help="RSA private key (PEM)")

    rewrap_parser = subparsers.add_parser(
        "rewrap", help="Rotate the passphrase wrap on an .ies file (ciphertext unchanged)."
    )
    rewrap_parser.add_argument("input", type=Path, help="Input vault file")
    rewrap_parser.add_argument("--out", "-o", type=Path, required=True, help="Output vault file")
    rewrap_parser.add_argument("--old-passphrase", help="Current AES passphrase")
    rewrap_parser.add_argument("--new-passphrase", help="Replacement AES passphrase")

    hash_parser = subparsers.add_parser("hash", help="Print SHA-256 of the ciphertext payload.")
    hash_parser.add_argument("input", type=Path, help="Input vault file")

    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "encrypt":
            return _encrypt(args)
        if args.command == "decrypt":
            return _decrypt(args)
        if args.command == "keygen":
            return _keygen(args)
        if args.command == "inspect":
            return _inspect(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "rewrap":
            return _rewrap(args)
        if args.command == "hash":
            return _hash(args)
    except (CryptoError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.error(f"unknown command {args.command}")
    return 2


def _encrypt(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    plaintext = source.read_bytes()
    if not plaintext:
        raise ValueError("refusing to encrypt an empty file")

    aad = cli_aad(source.name)
    if args.public_key is not None:
        public_key = Path(args.public_key).read_bytes()
        result = encrypt_image_bytes(
            plaintext,
            RSA_HYBRID,
            public_key_pem=public_key,
            aad=aad,
        )
    else:
        passphrase = args.passphrase or getpass("AES passphrase: ")
        result = encrypt_image_bytes(
            plaintext,
            AES_GCM_PASSPHRASE,
            passphrase=passphrase,
            aad=aad,
        )

    metadata = {
        **result.metadata,
        "aad": {"source": "cli", "filename": source.name},
        "original_filename": source.name,
        "ciphertext_sha256": sha256(result.ciphertext).hexdigest(),
    }
    args.out.write_bytes(pack_ies(result.ciphertext, metadata))
    return 0


def _decrypt(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    ciphertext, metadata = unpack_ies(source.read_bytes())
    aad_info = metadata.get("aad") or {}
    if aad_info.get("source") == "cli":
        aad = cli_aad(str(aad_info.get("filename", "")))
    else:
        aad = b""

    passphrase = args.passphrase
    private_key = Path(args.private_key).read_bytes() if args.private_key else None
    if private_key is not None and not passphrase:
        passphrase = getpass("Private key passphrase: ")
    elif private_key is None and not passphrase:
        passphrase = getpass("AES passphrase: ")

    plaintext = decrypt_image_bytes(
        ciphertext,
        metadata,
        passphrase=None if private_key is not None else passphrase,
        private_key_pem=private_key,
        private_key_passphrase=passphrase if private_key is not None else None,
        aad=aad,
    )
    args.out.write_bytes(plaintext)
    return 0


def _keygen(args: argparse.Namespace) -> int:
    passphrase = args.passphrase or getpass("Private key passphrase: ")
    private_pem, public_pem = generate_rsa_key_pair(passphrase)
    args.out_private.write_bytes(private_pem)
    args.out_public.write_bytes(public_pem)
    return 0


def _inspect(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    ciphertext, metadata = unpack_ies(source.read_bytes())
    wrap = metadata.get("key_wrap")
    wrap_type = wrap.get("type") if isinstance(wrap, dict) else None
    original = metadata.get("original_filename")
    digest = sha256(ciphertext).hexdigest()
    print(f"version: {metadata.get('version', '')}")
    print(f"algorithm: {metadata.get('algorithm', '')}")
    if wrap_type:
        print(f"wrap: {wrap_type}")
    if original:
        print(f"original_filename: {original}")
    print(f"ciphertext_sha256: {digest}")
    stored = metadata.get("ciphertext_sha256")
    if stored:
        print(f"stored_sha256: {stored}")
        print("integrity: ok" if stored == digest else "integrity: mismatch")
    return 0


def _verify(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    _ciphertext, metadata = unpack_ies(source.read_bytes())
    key_wrap = metadata.get("key_wrap")
    if not isinstance(key_wrap, dict):
        raise CryptoError("Encrypted image metadata is incomplete.")

    passphrase = args.passphrase
    private_key = Path(args.private_key).read_bytes() if args.private_key else None
    if private_key is not None and not passphrase:
        passphrase = getpass("Private key passphrase: ")
    elif private_key is None and not passphrase:
        passphrase = getpass("AES passphrase: ")

    unwrap_data_key(
        key_wrap,
        passphrase=None if private_key is not None else passphrase,
        private_key_pem=private_key,
        private_key_passphrase=passphrase if private_key is not None else None,
    )
    print("ok")
    return 0


def _rewrap(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    ciphertext, metadata = unpack_ies(source.read_bytes())
    key_wrap = metadata.get("key_wrap")
    if not isinstance(key_wrap, dict):
        raise CryptoError("Encrypted image metadata is incomplete.")
    old_passphrase = args.old_passphrase or getpass("Current AES passphrase: ")
    new_passphrase = args.new_passphrase or getpass("New AES passphrase: ")
    data_key = unwrap_data_key(key_wrap, passphrase=old_passphrase)
    metadata["key_wrap"] = wrap_data_key_passphrase(data_key, new_passphrase)
    metadata["ciphertext_sha256"] = sha256(ciphertext).hexdigest()
    args.out.write_bytes(pack_ies(ciphertext, metadata))
    return 0


def _hash(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    ciphertext, _metadata = unpack_ies(source.read_bytes())
    print(sha256(ciphertext).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
