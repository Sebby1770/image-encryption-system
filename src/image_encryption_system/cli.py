from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from getpass import getpass
from hashlib import sha256
from pathlib import Path

from .cloak import BITS, CloakError, cloak, is_png, load_cover, uncloak
from .covers import PALETTES
from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
    generate_rsa_key_pair,
    is_key_committing,
    pack_ies,
    unpack_ies,
    unwrap_data_key,
    validate_envelope,
    wrap_data_key_passphrase,
)
from .lab import LAB_SIZES, SAMPLES, prepare, run_lab, sample
from .lab.ciphers import CIPHER_INFO, CIPHER_NAMES
from .lab.report import render_standalone_html


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ies",
        description="Encrypt and decrypt images with AES-256-GCM (optional RSA wrap).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file into an .ies vault blob."
    )
    encrypt_parser.add_argument("input", type=Path, help="Input file (for example IN.png)")
    encrypt_parser.add_argument("--out", "-o", type=Path, required=True, help="Output vault file")
    encrypt_parser.add_argument("--passphrase", "-p", help="AES passphrase (prompted if omitted)")
    encrypt_parser.add_argument("--public-key", type=Path, help="Recipient RSA public key (PEM)")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt an .ies vault blob.")
    decrypt_parser.add_argument("input", type=Path, help="Input vault file")
    decrypt_parser.add_argument(
        "--out", "-o", type=Path, required=True, help="Output plaintext file"
    )
    decrypt_parser.add_argument("--passphrase", "-p", help="AES or private-key passphrase")
    decrypt_parser.add_argument(
        "--private-key", type=Path, help="RSA private key (.key from keygen, or PEM)"
    )

    keygen_parser = subparsers.add_parser("keygen", help="Generate an RSA-3072 key pair.")
    keygen_parser.add_argument(
        "--passphrase", "-p", help="Private key passphrase (prompted if omitted)"
    )
    keygen_parser.add_argument("--out-private", type=Path, default=Path("ies-private.key"))
    keygen_parser.add_argument("--out-public", type=Path, default=Path("ies-public.pem"))
    keygen_parser.add_argument(
        "--pem",
        action="store_true",
        help=(
            "Write OpenSSL-compatible encrypted PKCS#8 instead of the Scrypt-sealed "
            "format. Its PBKDF2 (2,048 rounds) is far cheaper to brute-force."
        ),
    )

    inspect_parser = subparsers.add_parser(
        "inspect", help="Print public .ies metadata (no secrets)."
    )
    inspect_parser.add_argument("input", type=Path, help="Input vault file")

    verify_parser = subparsers.add_parser(
        "verify", help="Unwrap the data key only; exit 0 on success."
    )
    verify_parser.add_argument("input", type=Path, help="Input vault file")
    verify_parser.add_argument("--passphrase", "-p", help="AES or private-key passphrase")
    verify_parser.add_argument(
        "--private-key", type=Path, help="RSA private key (.key from keygen, or PEM)"
    )

    rewrap_parser = subparsers.add_parser(
        "rewrap", help="Rotate the passphrase wrap on an .ies file (ciphertext unchanged)."
    )
    rewrap_parser.add_argument("input", type=Path, help="Input vault file")
    rewrap_parser.add_argument("--out", "-o", type=Path, required=True, help="Output vault file")
    rewrap_parser.add_argument("--old-passphrase", help="Current AES passphrase")
    rewrap_parser.add_argument("--new-passphrase", help="Replacement AES passphrase")

    hash_parser = subparsers.add_parser("hash", help="Print SHA-256 of the ciphertext payload.")
    hash_parser.add_argument("input", type=Path, help="Input vault file")

    cloak_parser = subparsers.add_parser(
        "cloak", help="Hide an .ies vault file inside an ordinary-looking PNG."
    )
    cloak_parser.add_argument("input", type=Path, help="Input vault file")
    cloak_parser.add_argument("--out", "-o", type=Path, required=True, help="Output PNG")
    cloak_parser.add_argument(
        "--cover", type=Path, help="Your own cover picture (default: a generated landscape)"
    )
    cloak_parser.add_argument(
        "--bits",
        choices=["auto", *(str(k) for k in BITS)],
        default="auto",
        help="Low bits used per wavelet coefficient (auto: as few as fit)",
    )
    cloak_parser.add_argument(
        "--palette", choices=PALETTES, default="dusk", help="Generated landscape style"
    )
    cloak_parser.add_argument(
        "--seed", help="Seed for the generated landscape (default: a new one each time)"
    )

    uncloak_parser = subparsers.add_parser(
        "uncloak", help="Recover the .ies vault file hidden in a cloaked PNG."
    )
    uncloak_parser.add_argument("input", type=Path, help="Cloaked PNG")
    uncloak_parser.add_argument("--out", "-o", type=Path, required=True, help="Output vault file")

    lab_parser = subparsers.add_parser(
        "lab", help="Cipher Lab: score and attack eleven image ciphers."
    )
    lab_commands = lab_parser.add_subparsers(dest="lab_command", required=True)
    lab_commands.add_parser("list", help="List the lab's ciphers.")
    run_parser = lab_commands.add_parser("run", help="Run the lab on an image.")
    source = run_parser.add_mutually_exclusive_group()
    source.add_argument("--image", type=Path, help="Your own image")
    source.add_argument("--sample", choices=SAMPLES, help="A built-in image (default test-card)")
    run_parser.add_argument(
        "--size", type=int, choices=LAB_SIZES, default=256, help="Square size in pixels"
    )
    run_parser.add_argument(
        "--cipher",
        action="append",
        choices=CIPHER_NAMES,
        dest="ciphers",
        help="Run only this cipher (repeatable; default all)",
    )
    run_parser.add_argument("--seed", help="Derive the lab key from this text, for repeatable runs")
    run_parser.add_argument("--json", type=Path, help="Write the full report as JSON")
    run_parser.add_argument("--html", type=Path, help="Write a self-contained HTML report")

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
        if args.command == "cloak":
            return _cloak(args)
        if args.command == "uncloak":
            return _uncloak(args)
        if args.command == "lab":
            return _lab(args)
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

    context = {"filename": source.name[:255], "source": "cli"}
    if args.public_key is not None:
        public_key = Path(args.public_key).read_bytes()
        result = encrypt_image_bytes(
            plaintext,
            RSA_HYBRID,
            public_key_pem=public_key,
            context=context,
        )
    else:
        passphrase = args.passphrase or getpass("AES passphrase: ")
        result = encrypt_image_bytes(
            plaintext,
            AES_GCM_PASSPHRASE,
            passphrase=passphrase,
            context=context,
        )

    metadata = {
        **result.metadata,
        "ciphertext_sha256": sha256(result.ciphertext).hexdigest(),
    }
    args.out.write_bytes(pack_ies(result.ciphertext, metadata))
    return 0


def _decrypt(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    ciphertext, metadata = unpack_ies(_read_vault_file(source))
    validate_envelope(metadata)

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
    )
    args.out.write_bytes(plaintext)
    return 0


def _keygen(args: argparse.Namespace) -> int:
    passphrase = args.passphrase or getpass("Private key passphrase: ")
    private_key, public_pem = generate_rsa_key_pair(passphrase, pem=args.pem)
    args.out_private.write_bytes(private_key)
    args.out_public.write_bytes(public_pem)
    return 0


def _inspect(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    ciphertext, metadata = unpack_ies(_read_vault_file(source))
    wrap = metadata.get("key_wrap")
    wrap_type = wrap.get("type") if isinstance(wrap, dict) else None
    context = metadata.get("context")
    original = metadata.get("original_filename") or (
        context.get("filename") if isinstance(context, dict) else None
    )
    digest = sha256(ciphertext).hexdigest()
    print(f"version: {metadata.get('version', '')}")
    # Only version 4 commits to its key: an older envelope can be built to open
    # as two different images under two keys. `inspect` prints what it is given
    # without validating it, so an envelope that does not validate says so here
    # rather than failing the whole command.
    try:
        committing = (
            "yes" if is_key_committing(metadata) else f"no (version {metadata.get('version', 1)})"
        )
    except CryptoError:
        committing = "unknown (the envelope does not validate)"
    print(f"key commitment: {committing}")
    print(f"algorithm: {metadata.get('algorithm', '')}")
    if wrap_type:
        print(f"wrap: {wrap_type}")
    if original:
        print(f"original_filename: {original}")
    if isinstance(context, dict):
        for key in sorted(context):
            print(f"context.{key}: {context[key]}")
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
    _ciphertext, metadata = unpack_ies(_read_vault_file(source))
    validate_envelope(metadata)
    key_wrap = metadata["key_wrap"]

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
    ciphertext, metadata = unpack_ies(_read_vault_file(source))
    validate_envelope(metadata)
    key_wrap = metadata["key_wrap"]
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
    ciphertext, _metadata = unpack_ies(_read_vault_file(source))
    print(sha256(ciphertext).hexdigest())
    return 0


# Leading bytes of the other image formats the vault accepts. A vault file
# handed over as one of these is almost always a cloaked PNG that something
# recompressed, which destroys what it carried.
_OTHER_IMAGE_SIGNATURES = (
    b"\xff\xd8\xff",  # JPEG
    b"GIF87a",
    b"GIF89a",
    b"BM",
    b"II*\x00",  # TIFF, little-endian
    b"MM\x00*",  # TIFF, big-endian
)


def _read_vault_file(source: Path) -> bytes:
    """An .ies file's bytes, uncloaking a cloaked PNG on the way."""
    data = source.read_bytes()
    if is_png(data):
        return uncloak(data)
    if data.startswith(_OTHER_IMAGE_SIGNATURES) or (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
        raise CloakError(
            "This image does not carry a vault file, or it was recompressed or edited "
            "(a cloaked file must stay a PNG)."
        )
    return data


def _cloak(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    payload = _read_vault_file(source)
    _ciphertext, metadata = unpack_ies(payload)
    validate_envelope(metadata)
    cover = None
    if args.cover is not None:
        if not args.cover.is_file():
            raise ValueError(f"cover file not found: {args.cover}")
        cover = load_cover(args.cover.read_bytes())
    seed = args.seed.encode("utf-8") if args.seed else os.urandom(16)
    bits = None if args.bits == "auto" else int(args.bits)
    png, report = cloak(payload, cover=cover, bits=bits, seed=seed, palette=args.palette)
    args.out.write_bytes(png)
    origin = f"your picture {args.cover.name}" if args.cover else f"generated, {args.palette}"
    print(f"cloaked: {args.out}")
    print(f"cover: {report.width}x{report.height} ({origin})")
    print(f"bits per coefficient: {report.bits}")
    print(f"payload: {report.payload_bytes:,} of {report.capacity_bytes:,} bytes")
    print(f"PSNR: {report.psnr:.1f} dB  SSIM: {report.ssim:.4f}")
    return 0


def _uncloak(args: argparse.Namespace) -> int:
    source: Path = args.input
    if not source.is_file():
        raise ValueError(f"input file not found: {source}")
    data = source.read_bytes()
    if not is_png(data):
        raise CloakError(
            "This image does not carry a vault file, or it was recompressed or edited."
        )
    payload = uncloak(data)
    _ciphertext, metadata = unpack_ies(payload)
    validate_envelope(metadata)
    args.out.write_bytes(payload)
    return 0


def _lab(args: argparse.Namespace) -> int:
    if args.lab_command == "list":
        for name, title, family in CIPHER_INFO:
            print(f"{name:18} {family:22} {title}")
        return 0

    if args.image is not None:
        image, label = prepare(args.image.read_bytes(), args.size), args.image.name
    else:
        label = args.sample or "test-card"
        image = sample(label, args.size)
    key = sha256(args.seed.encode("utf-8")).digest() if args.seed else None
    report = run_lab(image, ciphers=args.ciphers, key=key, source=label)

    print(f"Cipher Lab: {label}, {args.size}x{args.size}")
    for row in report.to_dict()["results"]:
        statistics = row["statistics"]
        print(
            f"{row['name']:18} {row['verdict']:28} "
            f"stats {statistics['passed']}/{statistics['judged']}  {row['headline']}"
        )
    if args.json is not None:
        args.json.write_text(json.dumps(report.to_dict(), indent=2, allow_nan=False))
        print(f"wrote {args.json}")
    if args.html is not None:
        args.html.write_text(render_standalone_html(report), encoding="utf-8")
        print(f"wrote {args.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
