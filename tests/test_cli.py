import os
import stat
from io import BytesIO

from PIL import Image

from image_encryption_system.cli import main, write_bundle
from image_encryption_system.crypto import AES_GCM_PASSPHRASE, encrypt_image_bytes
from image_encryption_system.uploads import asset_aad


def sample_png() -> bytes:
    image = Image.new("RGB", (24, 16), "#08776b")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def malicious_filename_bundle(path, filename: str) -> None:
    context = {
        "version": 2,
        "user_id": 0,
        "original_filename": filename,
        "mime_type": "image/png",
        "algorithm": AES_GCM_PASSPHRASE,
        "image_format": "PNG",
        "width": 24,
        "height": 16,
        "unlock_after": "",
    }
    encrypted = encrypt_image_bytes(
        sample_png(),
        AES_GCM_PASSPHRASE,
        passphrase="correct passphrase",
        aad=asset_aad(**context),
    )
    metadata = {**encrypted.metadata, "aad": context}
    write_bundle(path, metadata=metadata, ciphertext=encrypted.ciphertext)


def test_cli_sanitizes_embedded_output_path_and_writes_owner_only(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    bundle = workspace / "malicious.ies"
    malicious_filename_bundle(bundle, "../../escaped.png")
    monkeypatch.chdir(workspace)

    result = main(["decrypt", str(bundle), "--passphrase", "correct passphrase"])

    assert result == 0
    output = workspace / "escaped.png"
    assert output.read_bytes() == sample_png()
    assert not (tmp_path / "escaped.png").exists()
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_cli_refuses_to_replace_existing_output_without_force(tmp_path, monkeypatch) -> None:
    bundle = tmp_path / "image.ies"
    malicious_filename_bundle(bundle, "image.png")
    output = tmp_path / "image.png"
    output.write_bytes(b"keep me")
    monkeypatch.chdir(tmp_path)

    result = main(["decrypt", str(bundle), "--passphrase", "correct passphrase"])

    assert result == 1
    assert output.read_bytes() == b"keep me"


def test_cli_force_allows_explicit_replacement(tmp_path, monkeypatch) -> None:
    bundle = tmp_path / "image.ies"
    malicious_filename_bundle(bundle, "image.png")
    output = tmp_path / "image.png"
    output.write_bytes(b"replace me")
    monkeypatch.chdir(tmp_path)

    result = main(["decrypt", str(bundle), "--passphrase", "correct passphrase", "--force"])

    assert result == 0
    assert output.read_bytes() == sample_png()
