from PIL import Image
from io import BytesIO

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

    assert main(["encrypt", str(source), "--passphrase", "cli-secret-pass", "--out", str(vault)]) == 0
    assert vault.is_file()
    assert vault.read_bytes().startswith(b"IES1")
    assert vault.read_bytes() != source.read_bytes()

    assert main(["decrypt", str(vault), "--passphrase", "cli-secret-pass", "--out", str(restored)]) == 0
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
    assert main(["decrypt", str(vault), "--passphrase", "wrong-secret", "--out", str(restored)]) == 1
    assert not restored.exists()


def test_cli_missing_input_fails(tmp_path) -> None:
    missing = tmp_path / "missing.png"
    assert main(["encrypt", str(missing), "--passphrase", "x" * 12, "--out", str(tmp_path / "out.bin")]) == 1
