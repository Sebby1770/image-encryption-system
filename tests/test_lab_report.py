"""Running the whole lab, its verdicts, and the self-contained report."""

from __future__ import annotations

import json
import re
import time

import numpy as np
import pytest

from image_encryption_system.lab import CIPHER_NAMES, LabReport, imaging, run_lab
from image_encryption_system.lab.report import render_standalone_html

KEY = bytes(range(32))
EXPECTED = {
    "arnold": "Broken",
    "logistic-xor": "Broken",
    "hyperchaos": "Leaks",
    "wavelet": "Broken",
    "wht": "Broken",
    "drpe": "Broken",
    "neural": "Leaks",
    "aes-ecb": "Leaks",
    "aes-ctr-fixed-iv": "Broken",
    "aes-gcm": "Strong, not key-committing",
    "aes-gcm-v4": "Strong + committing",
}


@pytest.fixture(scope="module")
def report() -> LabReport:
    return run_lab(imaging.sample("test-card", 64), key=KEY, source="test-card")


def test_verdicts_on_the_test_card(report) -> None:
    assert [r.name for r in report.results] == list(CIPHER_NAMES)
    assert {r.name: r.verdict for r in report.results} == EXPECTED


def test_each_result_carries_its_evidence(report) -> None:
    by_name = {r.name: r for r in report.results}
    assert set(by_name["arnold"].images) >= {"cipher", "tampered"}
    assert "pattern" in by_name["aes-ecb"].images
    assert {"salamander-1", "salamander-2"} <= set(by_name["aes-gcm"].images)
    assert "salamander-2" not in by_name["aes-gcm-v4"].images
    assert "tampered" not in by_name["aes-gcm"].images  # it refused
    for result in report.results:
        assert len(result.histogram) == 64 and max(result.histogram) == pytest.approx(1.0)
        assert result.seconds > 0


def test_report_is_json_safe(report) -> None:
    data = json.loads(json.dumps(report.to_dict(), allow_nan=False))
    assert data["size"] == 64 and data["source"] == "test-card"
    assert data["plaintext"].startswith("data:image/png;base64,")
    first = data["results"][0]
    assert first["verdict"] == "Broken" and first["verdict_slug"] == "broken"
    assert first["headline"].startswith("Broken with 1 chosen image")
    assert first["images"]["cipher"].startswith("data:image/jpeg;base64,")
    assert {m["key"] for m in first["metrics"]} >= {"entropy", "npcr_uaci", "round_trip"}
    assert all("display" in m and "mark" in m for m in first["metrics"])
    assert all("outcome" in a for a in first["attacks"])


def test_standalone_html_is_self_contained(report) -> None:
    html = render_standalone_html(report)
    assert html.startswith("<!doctype html>")
    assert "<style>" in html and "--accent" in html
    assert "data:image/png;base64," in html and "data:image/jpeg;base64," in html
    assert not re.search(r"""(src|href)=["']?(https?:)?//""", html)
    assert "url(http" not in html
    for title in ("Arnold cat map", "Double random phase encoding", "AES-256-GCM (vault v3)"):
        assert title in html
    assert "Rhouma" in html  # the lesson: statistics are not security
    assert "<script" not in html


def test_run_lab_validates_its_inputs() -> None:
    image = imaging.sample("gradient", 32)
    with pytest.raises(ValueError):
        run_lab(image, ciphers=["rot13"], key=KEY)
    with pytest.raises(ValueError):
        run_lab(image, ciphers=[], key=KEY)
    with pytest.raises(ValueError):
        run_lab(np.zeros((48, 48, 3), np.uint8), key=KEY)
    only = run_lab(image, ciphers=["arnold"], key=KEY)
    assert [r.name for r in only.results] == ["arnold"]


def test_a_random_key_is_used_when_none_is_given() -> None:
    image = imaging.sample("gradient", 32)
    first = run_lab(image, ciphers=["logistic-xor"])
    second = run_lab(image, ciphers=["logistic-xor"])
    assert first.results[0].images["cipher"] != second.results[0].images["cipher"]


@pytest.mark.slow
def test_full_run_at_256() -> None:
    started = time.perf_counter()
    report = run_lab(imaging.sample("landscape", 256), key=KEY, source="landscape")
    elapsed = time.perf_counter() - started
    assert elapsed < 20, elapsed
    gcm = next(r for r in report.results if r.name == "aes-gcm-v4")
    local = next(m for m in gcm.metrics if m.key == "local_entropy")
    assert local.value is not None and local.passed is not None
    assert len(render_standalone_html(report)) < 3_000_000
