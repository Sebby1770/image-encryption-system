"""Behaviour of the version 3 envelope and the hardening that came with it."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO

import pytest
from helpers import PASSWORD, bearer_headers, encrypt_png, login, make_app, register, with_csrf

from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    CONTEXT_AAD_PREFIX,
    CryptoError,
    context_aad,
    decrypt_image_bytes,
    encrypt_image_bytes,
    unpack_ies,
)


def _store(app):
    return app.extensions["vault_store"]


def _restore(client, archive: bytes):
    return client.post(
        "/restore",
        data=with_csrf(client, {"backup": (BytesIO(archive), "backup.zip")}),
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def test_web_upload_seals_owner_asset_type_and_dimensions(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client, filename="holiday.png")
    asset = _store(app).list_assets(1)[0]

    context = asset.metadata["context"]

    assert asset.metadata["version"] == 3
    assert context == {
        "asset": asset.stored_filename.removesuffix(".enc"),
        "algorithm": "AES-GCM",
        "wrap": "scrypt-aes-gcm",
        "owner": 1,
        "filename": "holiday.png",
        "mime": "image/png",
        "format": "PNG",
        "width": 80,
        "height": 48,
        "source": "web",
    }


def test_context_aad_is_canonical_sorted_compact_utf8() -> None:
    aad = context_aad({"b": 1, "a": "café"})
    assert aad == CONTEXT_AAD_PREFIX + '{"a":"café","b":1}'.encode()


def test_v3_rejects_an_out_of_band_aad_that_conflicts_with_the_context() -> None:
    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase="a passphrase!")
    with pytest.raises(CryptoError, match="conflicts"):
        decrypt_image_bytes(
            result.ciphertext, result.metadata, passphrase="a passphrase!", aad=b"other"
        )


def test_editing_the_sealed_context_breaks_decryption() -> None:
    result = encrypt_image_bytes(
        b"pixels", AES_GCM_PASSPHRASE, passphrase="a passphrase!", context={"owner": 1}
    )
    metadata = json.loads(json.dumps(result.metadata))
    metadata["context"]["owner"] = 2
    with pytest.raises(CryptoError):
        decrypt_image_bytes(result.ciphertext, metadata, passphrase="a passphrase!")


def test_restoring_the_same_backup_twice_does_not_duplicate(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    exported = client.get("/backup").data

    first = _restore(client, exported)
    assert b"Restored 0 encrypted image" in first.data
    assert len(_store(app).list_assets(1)) == 1


def test_restore_after_deleting_brings_the_asset_back_and_it_decrypts(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    exported = client.get("/backup").data
    client.post("/images/1/delete", data=with_csrf(client))

    assert b"Restored 1 encrypted image" in _restore(client, exported).data
    asset = _store(app).list_assets(1)[0]
    decrypted = client.post(
        f"/images/{asset.id}/decrypt", data=with_csrf(client, {"passphrase": "image passphrase"})
    )
    assert decrypted.status_code == 200


def test_v3_backup_cannot_be_restored_into_a_different_account(tmp_path) -> None:
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register(alice, "alice")
    register(bob, "bob")
    encrypt_png(alice)
    exported = alice.get("/backup").data

    response = _restore(bob, exported)

    assert b"different account" in response.data
    assert _store(app).list_assets(2) == []


def test_backup_manifest_carries_the_v3_envelope(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    with zipfile.ZipFile(BytesIO(client.get("/backup").data)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["assets"][0]["metadata"]["version"] == 3


def test_cli_writes_v3_with_a_cli_context(tmp_path) -> None:
    from image_encryption_system.cli import main

    source = tmp_path / "note.png"
    source.write_bytes(b"\x89PNG not really")
    out = tmp_path / "note.ies"
    assert main(["encrypt", str(source), "--passphrase", "cli passphrase", "--out", str(out)]) == 0

    _ciphertext, metadata = unpack_ies(out.read_bytes())

    assert metadata["version"] == 3
    assert metadata["context"]["source"] == "cli"
    assert metadata["context"]["filename"] == "note.png"


def test_audit_chain_is_reported_on_the_page_and_api(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)

    page = client.get("/audit")
    api = client.get("/api/audit", headers=bearer_headers(client, "alice")).get_json()

    assert b"Audit chain verified" in page.data
    assert api["chain"]["ok"] is True
    assert api["chain"]["events"] >= 2


def test_legacy_audit_rows_are_sealed_on_upgrade(tmp_path) -> None:
    import sqlite3

    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    with sqlite3.connect(tmp_path / "vault.sqlite3") as db:
        db.execute("UPDATE audit_events SET prev_hash = NULL, chain_hash = NULL")

    upgraded = make_app(tmp_path)

    assert _store(upgraded).verify_audit_chain(1).ok


def test_html_pages_carry_a_strict_csp(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")

    headers = client.get("/dashboard").headers

    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_templates_contain_no_inline_script_or_handlers() -> None:
    import re
    from pathlib import Path

    import image_encryption_system

    templates = Path(image_encryption_system.__file__).parent / "templates"
    for template in templates.glob("*.html"):
        text = template.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), template.name
        assert not re.search(r"\son[a-z]+=", text), template.name


def test_password_change_ends_other_browser_sessions(tmp_path) -> None:
    app = make_app(tmp_path)
    laptop, phone = app.test_client(), app.test_client()
    register(laptop, "alice")
    login(phone, "alice")
    assert phone.get("/dashboard").status_code == 200

    laptop.post(
        "/account/password",
        data=with_csrf(
            laptop,
            {
                "old_password": PASSWORD,
                "new_password": "another long password",
                "confirm_password": "another long password",
            },
        ),
    )

    assert laptop.get("/dashboard").status_code == 200
    assert phone.get("/dashboard").status_code == 302


def test_generated_secret_is_persisted_across_restarts(tmp_path, monkeypatch) -> None:
    from image_encryption_system.web import create_app

    monkeypatch.delenv("SECRET_KEY", raising=False)
    config = {
        "TESTING": True,
        "INSTANCE_DIR": tmp_path,
        "DATABASE_PATH": tmp_path / "vault.sqlite3",
        "VAULT_DIR": tmp_path / "vault",
        "KEY_DIR": tmp_path / "keys",
    }
    first = create_app(dict(config))
    second = create_app(dict(config))

    assert first.config["SECRET_KEY"] == second.config["SECRET_KEY"]
    assert len(first.config["SECRET_KEY"]) >= 48
    assert first.config["JWT_SECRET"] != first.config["SECRET_KEY"]
    assert (tmp_path / "keys" / "flask-secret.key").stat().st_mode & 0o077 == 0
