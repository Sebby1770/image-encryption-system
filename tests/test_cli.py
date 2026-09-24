from io import BytesIO
from pathlib import Path

from PIL import Image

from image_encryption_system.cli import main


def _png(path, color: str = "#0f766e") -> None:
    image = Image.new("RGB", (32, 20), color)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    path.write_bytes(buffer.getvalue())


def test_cli_encrypt_decrypt_with_passphrase(tmp_path) -> None:
    source = tmp_path / "IN.png"
    vault = tmp_path / "out.bin"
    restored = tmp_path / "restored.png"
    _png(source)

    encrypt_args = ["encrypt", str(source), "--passphrase", "cli-secret-pass", "--out", str(vault)]
    assert main(encrypt_args) == 0
    assert vault.is_file()
    assert vault.read_bytes().startswith(b"IES1")
    assert vault.read_bytes() != source.read_bytes()

    decrypt_args = [
        "decrypt",
        str(vault),
        "--passphrase",
        "cli-secret-pass",
        "--out",
        str(restored),
    ]
    assert main(decrypt_args) == 0
    assert restored.read_bytes() == source.read_bytes()


def test_cli_keygen_rsa_round_trip(tmp_path) -> None:
    source = tmp_path / "photo.png"
    vault = tmp_path / "photo.ies"
    restored = tmp_path / "photo-out.png"
    private_key = tmp_path / "ies-private.pem"
    public_key = tmp_path / "ies-public.pem"
    _png(source, "#b7791f")

    assert (
        main(
            [
                "keygen",
                "--passphrase",
                "key passphrase",
                "--out-private",
                str(private_key),
                "--out-public",
                str(public_key),
            ]
        )
        == 0
    )
    assert b"BEGIN" in private_key.read_bytes()
    assert b"BEGIN PUBLIC KEY" in public_key.read_bytes()

    assert main(["encrypt", str(source), "--public-key", str(public_key), "--out", str(vault)]) == 0
    assert (
        main(
            [
                "decrypt",
                str(vault),
                "--private-key",
                str(private_key),
                "--passphrase",
                "key passphrase",
                "--out",
                str(restored),
            ]
        )
        == 0
    )
    assert restored.read_bytes() == source.read_bytes()


def test_cli_decrypt_rejects_wrong_passphrase(tmp_path) -> None:
    source = tmp_path / "IN.png"
    vault = tmp_path / "out.bin"
    restored = tmp_path / "nope.png"
    _png(source)
    assert main(["encrypt", str(source), "--passphrase", "right-secret", "--out", str(vault)]) == 0
    wrong_args = ["decrypt", str(vault), "--passphrase", "wrong-secret", "--out", str(restored)]
    assert main(wrong_args) == 1
    assert not restored.exists()


def test_cli_missing_input_fails(tmp_path) -> None:
    missing = tmp_path / "missing.png"
    missing_args = [
        "encrypt",
        str(missing),
        "--passphrase",
        "x" * 12,
        "--out",
        str(tmp_path / "out.bin"),
    ]
    assert main(missing_args) == 1


def test_cli_rejects_non_rsa_public_key_cleanly(tmp_path, capsys) -> None:
    """A non-RSA PEM used to crash with AttributeError instead of a clean error."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    source = tmp_path / "photo.png"
    _png(source)
    ec_public = tmp_path / "ec-public.pem"
    ec_public.write_bytes(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    code = main(
        ["encrypt", str(source), "--public-key", str(ec_public), "--out", str(tmp_path / "x")]
    )

    assert code == 1
    assert "RSA" in capsys.readouterr().err


def test_cli_decrypts_a_web_download(tmp_path) -> None:
    """A .ies file downloaded from the web vault must open with `ies decrypt`."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from helpers import encrypt_png, make_app, register, sample_png

    app = make_app(tmp_path / "instance")
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client, filename="holiday.png", passphrase="web passphrase 1")
    response = client.get("/images/1/download")
    assert response.status_code == 200

    vault = tmp_path / "holiday.png.ies"
    vault.write_bytes(response.data)
    restored = tmp_path / "restored.png"
    code = main(["decrypt", str(vault), "--passphrase", "web passphrase 1", "--out", str(restored)])

    assert code == 0
    assert restored.read_bytes() == sample_png()
