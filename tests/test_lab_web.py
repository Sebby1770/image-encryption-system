"""The Cipher Lab page: run every cipher on a sample or an upload, in memory."""

from __future__ import annotations

import struct
import zlib
from io import BytesIO

import pytest
from helpers import csrf_token, make_app, raw_db, register, sample_png

from image_encryption_system.lab import CIPHER_NAMES, SAMPLES


@pytest.fixture()
def lab(tmp_path):
    app = make_app(tmp_path, CSRF_ENABLED=True, LAB_IMAGE_SIZE=64)
    client = app.test_client()
    register(client, "alice")
    return app, client


def _run(client, *, csrf=True, ciphers=CIPHER_NAMES, **fields):
    data = {"source": "sample", "sample": "test-card", **fields}
    data["cipher"] = list(ciphers)
    if csrf:
        data["csrf_token"] = csrf_token(client)
    return client.post("/lab", data=data, content_type="multipart/form-data")


def _huge_png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", 100_000, 100_000, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00" * 8))
        + chunk(b"IEND", b"")
    )


def test_lab_requires_login(tmp_path) -> None:
    client = make_app(tmp_path).test_client()
    assert client.get("/lab").status_code == 302
    assert client.post("/lab").status_code in {302, 400}


def test_lab_form_lists_samples_and_ciphers(lab) -> None:
    _app, client = lab
    page = client.get("/lab").get_data(as_text=True)
    for name in SAMPLES:
        assert f'value="{name}"' in page
    for name in CIPHER_NAMES:
        assert f'name="cipher" value="{name}"' in page
    assert "css/lab.css" in page
    assert "never stored" in page


def test_running_a_sample_renders_the_scorecard(lab) -> None:
    _app, client = lab
    response = _run(client)
    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]
    page = response.get_data(as_text=True)
    for title in (
        "Arnold cat map",
        "Logistic-map XOR",
        "Keyed neural network",
        "AES-256-GCM (vault v3)",
    ):
        assert title in page
    assert "Broken" in page and "Strong + committing" in page
    assert "data:image/png;base64," in page and "data:image/jpeg;base64," in page
    assert "Rhouma" in page


def test_a_subset_of_ciphers_runs_alone(lab) -> None:
    _app, client = lab
    page = _run(client, ciphers=["wht", "aes-gcm-v4"]).get_data(as_text=True)
    assert "Walsh-Hadamard mask" in page and "Arnold cat map" not in page


def test_an_uploaded_image_is_used_and_never_stored(lab, tmp_path) -> None:
    app, client = lab
    store = app.extensions["vault_store"]
    vault_files = sorted(p.name for p in store.vault_dir.iterdir())
    with raw_db(tmp_path) as db:
        events_before = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    response = _run(client, source="upload", image=(BytesIO(sample_png()), "mine.png"))

    assert response.status_code == 200
    assert "your upload" in response.get_data(as_text=True)
    assert sorted(p.name for p in store.vault_dir.iterdir()) == vault_files
    assert store.list_assets(1) == []
    with raw_db(tmp_path) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == events_before


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"ciphers": []}, "at least one cipher"),
        ({"ciphers": ["rot13"]}, "Unknown"),
        ({"sample": "mona-lisa"}, "built-in"),
        ({"source": "upload"}, "Choose an image"),
        ({"source": "upload", "image": (BytesIO(b"plain text"), "notes.png")}, "not accepted"),
        ({"source": "upload", "image": (BytesIO(_huge_png()), "huge.png")}, "too large"),
        ({"source": "sideways"}, "built-in image or upload"),
    ],
    ids=[
        "no-ciphers",
        "unknown-cipher",
        "unknown-sample",
        "no-file",
        "not-an-image",
        "bomb",
        "bad-source",
    ],
)
def test_bad_lab_requests_get_clean_errors(lab, fields, message) -> None:
    _app, client = lab
    ciphers = fields.pop("ciphers", CIPHER_NAMES)
    response = _run(client, ciphers=ciphers, **fields)
    assert response.status_code == 400
    page = response.get_data(as_text=True)
    assert message.lower() in page.lower()
    assert 'name="cipher"' in page  # the form is shown again


def test_lab_requires_csrf_and_is_throttled(tmp_path) -> None:
    app = make_app(tmp_path, CSRF_ENABLED=True, LAB_IMAGE_SIZE=32, LAB_RATE_LIMIT=1)
    client = app.test_client()
    register(client, "alice")
    assert _run(client, csrf=False, ciphers=["arnold"]).status_code == 400
    assert _run(client, ciphers=["arnold"]).status_code == 200
    limited = _run(client, ciphers=["arnold"])
    assert limited.status_code == 429
    assert "Too many" in limited.get_data(as_text=True)


def test_nav_links_to_the_lab(lab) -> None:
    _app, client = lab
    assert 'href="/lab"' in client.get("/dashboard").get_data(as_text=True)
