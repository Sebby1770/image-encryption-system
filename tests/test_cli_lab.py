"""`ies lab`: the Cipher Lab from the command line."""

from __future__ import annotations

import json

import pytest
from helpers import sample_png

from image_encryption_system.cli import main
from image_encryption_system.lab import CIPHER_NAMES


def test_lab_list_names_every_cipher(capsys) -> None:
    assert main(["lab", "list"]) == 0
    out = capsys.readouterr().out
    for name in CIPHER_NAMES:
        assert name in out
    assert "Double random phase encoding" in out


def test_lab_run_writes_json_and_html(tmp_path, capsys) -> None:
    report_json, report_html = tmp_path / "lab.json", tmp_path / "lab.html"
    code = main(
        [
            "lab", "run", "--sample", "test-card", "--size", "64", "--seed", "demo",
            "--json", str(report_json), "--html", str(report_html),
        ]
    )  # fmt: skip
    assert code == 0
    out = capsys.readouterr().out
    assert "arnold" in out and "Broken" in out and "Strong + committing" in out
    data = json.loads(report_json.read_text())
    assert [r["name"] for r in data["results"]] == list(CIPHER_NAMES)
    assert report_html.read_text().startswith("<!doctype html>")


def test_lab_run_on_an_image_file_with_a_subset(tmp_path, capsys) -> None:
    picture = tmp_path / "mine.png"
    picture.write_bytes(sample_png())
    report_json = tmp_path / "lab.json"
    code = main(
        [
            "lab", "run", "--image", str(picture), "--size", "32",
            "--cipher", "arnold", "--cipher", "aes-gcm", "--json", str(report_json),
        ]
    )  # fmt: skip
    assert code == 0
    data = json.loads(report_json.read_text())
    assert [r["name"] for r in data["results"]] == ["arnold", "aes-gcm"]
    assert data["source"] == "mine.png" and data["size"] == 32


def test_the_seed_makes_runs_repeatable(tmp_path) -> None:
    def arnold_ciphertext(seed: str) -> str:
        path = tmp_path / f"{seed}.json"
        args = ["lab", "run", "--size", "32", "--cipher", "arnold", "--seed", seed]
        assert main([*args, "--json", str(path)]) == 0
        return json.loads(path.read_text())["results"][0]["images"]["cipher"]

    assert arnold_ciphertext("one") == arnold_ciphertext("one")
    assert arnold_ciphertext("one") != arnold_ciphertext("two")


def test_lab_run_with_a_non_image_exits_1(tmp_path, capsys) -> None:
    junk = tmp_path / "notes.png"
    junk.write_text("not an image")
    assert main(["lab", "run", "--image", str(junk), "--size", "32"]) == 1
    err = capsys.readouterr().err
    assert "error:" in err and "Traceback" not in err


@pytest.mark.parametrize(
    "args",
    [
        ["lab", "run", "--size", "100"],
        ["lab", "run", "--cipher", "rot13"],
        ["lab", "run", "--sample", "mona-lisa"],
        ["lab", "run", "--sample", "test-card", "--image", "x.png"],
        ["lab"],
    ],
    ids=["size", "cipher", "sample", "both-sources", "no-subcommand"],
)
def test_bad_lab_arguments_exit_2(args) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    assert exit_info.value.code == 2
