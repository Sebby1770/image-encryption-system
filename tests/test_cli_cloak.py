"""`ies cloak` / `ies uncloak`, and cloaked PNGs accepted wherever an .ies is."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import numpy as np
import pytest
from helpers import sample_png
from PIL import Image

from image_encryption_system.cli import main
from image_encryption_system.crypto import unpack_ies

PASS = "a cli passphrase for cloaking"


def _encrypted(tmp_path: Path) -> Path:
    source = tmp_path / "photo.png"
    source.write_bytes(sample_png())
    out = tmp_path / "photo.ies"
    assert main(["encrypt", str(source), "--passphrase", PASS, "--out", str(out)]) == 0
    return out


def _cloaked(tmp_path: Path, *extra: str) -> tuple[Path, Path]:
    ies = _encrypted(tmp_path)
    png = tmp_path / "photo.cloaked.png"
    assert main(["cloak", str(ies), "-o", str(png), "--seed", "cli", *extra]) == 0
    return ies, png


def test_cloak_then_uncloak_round_trips(tmp_path, capsys) -> None:
    ies, png = _cloaked(tmp_path)
    report = capsys.readouterr().out
    assert "PSNR" in report and "bits per coefficient: 2" in report
    assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    back = tmp_path / "back.ies"
    assert main(["uncloak", str(png), "-o", str(back)]) == 0
    assert back.read_bytes() == ies.read_bytes()


def test_decrypt_accepts_a_cloaked_png(tmp_path) -> None:
    _ies, png = _cloaked(tmp_path)
    out = tmp_path / "opened.png"
    assert main(["decrypt", str(png), "--passphrase", PASS, "-o", str(out)]) == 0
    assert out.read_bytes() == sample_png()


def test_cloak_with_a_custom_cover_and_one_bit(tmp_path, capsys) -> None:
    cover = tmp_path / "cover.png"
    pixels = np.random.default_rng(1).integers(0, 256, (300, 400, 3), dtype=np.uint8)
    Image.fromarray(pixels).save(cover)
    _ies, png = _cloaked(tmp_path, "--cover", str(cover), "--bits", "1")
    assert "bits per coefficient: 1" in capsys.readouterr().out
    with Image.open(png) as image:
        assert image.size == (400, 300)


def test_inspect_verify_hash_and_rewrap_accept_cloaked_files(tmp_path, capsys) -> None:
    ies, png = _cloaked(tmp_path)
    capsys.readouterr()

    assert main(["hash", str(png)]) == 0
    from_png = capsys.readouterr().out
    assert main(["hash", str(ies)]) == 0
    assert capsys.readouterr().out == from_png

    assert main(["inspect", str(png)]) == 0
    assert "key commitment: yes" in capsys.readouterr().out
    assert main(["verify", str(png), "--passphrase", PASS]) == 0
    assert capsys.readouterr().out.strip() == "ok"

    rewrapped = tmp_path / "rewrapped.ies"
    assert (
        main(
            [
                "rewrap",
                str(png),
                "-o",
                str(rewrapped),
                "--old-passphrase",
                PASS,
                "--new-passphrase",
                "a brand new passphrase",
            ]
        )
        == 0
    )
    ciphertext, _metadata = unpack_ies(rewrapped.read_bytes())
    assert ciphertext == unpack_ies(ies.read_bytes())[0]


def _ordinary_photos(tmp_path: Path) -> list[Path]:
    png = tmp_path / "holiday.png"
    png.write_bytes(sample_png())
    jpeg = tmp_path / "holiday.jpg"
    buffer = BytesIO()
    Image.new("RGB", (32, 24), "#336699").save(buffer, format="JPEG")
    jpeg.write_bytes(buffer.getvalue())
    return [png, jpeg]


@pytest.mark.parametrize("command", ["decrypt", "uncloak"])
def test_an_ordinary_photo_is_not_mistaken_for_a_vault_file(tmp_path, capsys, command) -> None:
    for photo in _ordinary_photos(tmp_path):
        extra = ["--passphrase", PASS] if command == "decrypt" else []
        code = main([command, str(photo), "-o", str(tmp_path / "out.bin"), *extra])
        captured = capsys.readouterr()
        assert code == 1
        assert "does not carry a vault file" in captured.err
        assert "Traceback" not in captured.err
        assert not (tmp_path / "out.bin").exists()


def test_cloak_refuses_a_file_that_is_not_a_vault_file(tmp_path, capsys) -> None:
    junk = tmp_path / "notes.txt"
    junk.write_text("not a vault file")
    assert main(["cloak", str(junk), "-o", str(tmp_path / "x.png")]) == 1
    assert "error:" in capsys.readouterr().err
    assert not (tmp_path / "x.png").exists()


def test_cloak_options_are_validated(tmp_path) -> None:
    ies = _encrypted(tmp_path)
    with pytest.raises(SystemExit) as exit_info:
        main(["cloak", str(ies), "-o", str(tmp_path / "x.png"), "--bits", "4"])
    assert exit_info.value.code == 2
