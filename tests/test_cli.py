from pathlib import Path

from PIL import Image

from image_encryption_system.cli import main
from image_encryption_system.crypto import generate_rsa_key_pair


def _sample(path: Path) -> Path:
    Image.new("RGB", (24, 16), "#0f766e").save(path)
    return path


def test_cli_aes_round_trip(tmp_path) -> None:
    image = _sample(tmp_path / "photo.png")
    ciphertext = tmp_path / "photo.png.enc"
    meta = tmp_path / "photo.json"
    out = tmp_path / "out.png"

    assert (
        main(
            [
                "encrypt",
                str(image),
                "--out",
                str(ciphertext),
                "--meta",
                str(meta),
                "--passphrase",
                "cli-passphrase",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "decrypt",
                str(ciphertext),
                "--meta",
                str(meta),
                "--out",
                str(out),
                "--passphrase",
                "cli-passphrase",
            ]
        )
        == 0
    )
    assert out.read_bytes() == image.read_bytes()
    assert ciphertext.read_bytes() != image.read_bytes()


def test_cli_rsa_round_trip(tmp_path) -> None:
    private_pem, public_pem = generate_rsa_key_pair("cli-account-password")
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    image = _sample(tmp_path / "rsa.png")
    ciphertext = tmp_path / "rsa.png.enc"
    meta = tmp_path / "rsa.json"
    out = tmp_path / "rsa-out.png"

    assert (
        main(
            [
                "encrypt",
                str(image),
                "--algorithm",
                "RSA-HYBRID",
                "--public-key",
                str(public_path),
                "--out",
                str(ciphertext),
                "--meta",
                str(meta),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "decrypt",
                str(ciphertext),
                "--meta",
                str(meta),
                "--out",
                str(out),
                "--private-key",
                str(private_path),
                "--private-key-passphrase",
                "cli-account-password",
            ]
        )
        == 0
    )
    assert out.read_bytes() == image.read_bytes()
