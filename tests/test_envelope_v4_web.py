"""Version 4 on the server and in the CLI.

Everything the server and CLI seal is version 4 (key-committing). Version 1
and 3 images already stored still open and still restore, but the browser can
no longer add new version 3 images: an upload or re-key must be version 4, so
re-keying is also how an older image is upgraded.
"""

from __future__ import annotations

import json
from base64 import b64decode
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import pytest
from helpers import (
    BROWSER_PASS,
    browser_envelope,
    csrf_token,
    encrypt_png,
    make_app,
    post_sealed,
    register,
    sample_png,
    with_csrf,
)

from image_encryption_system.cli import main as cli_main
from image_encryption_system.crypto import (
    decrypt_image_bytes,
    encrypt_image_bytes,
    unpack_ies,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def vault(tmp_path):
    app = make_app(tmp_path, CSRF_ENABLED=True)
    alice = app.test_client()
    register(alice, "alice")
    return app, alice


def _store_v3_browser_image(app, owner: int = 1):
    """An end-to-end image as a release before version 4 would have stored it."""
    metadata, ciphertext = browser_envelope(owner, version=3)
    context = metadata["context"]
    asset = app.extensions["vault_store"].save_asset(
        user_id=owner,
        original_filename=context["filename"],
        algorithm=metadata["algorithm"],
        mime_type=context["mime"],
        image_format=context["format"],
        width=context["width"],
        height=context["height"],
        metadata=metadata,
        ciphertext=ciphertext,
        asset_uuid=context["asset"],
    )
    return asset, metadata, ciphertext


def _reencrypted(metadata, **options):
    """A fresh envelope sealing the same context: what the browser sends to re-key."""
    result = encrypt_image_bytes(
        sample_png(),
        metadata["algorithm"],
        passphrase=BROWSER_PASS,
        context=metadata["context"],
        **options,
    )
    digest = sha256(result.ciphertext).hexdigest()
    return {**result.metadata, "ciphertext_sha256": digest}, result.ciphertext


def _post_rekey(client, asset_id, metadata, ciphertext):
    data = {
        "envelope": json.dumps(metadata),
        "ciphertext": (BytesIO(ciphertext), "blob"),
        "shares": "[]",
        "csrf_token": csrf_token(client),
    }
    return client.post(f"/images/{asset_id}/rekey", data=data, content_type="multipart/form-data")


def test_server_mode_uploads_are_v4(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    asset = app.extensions["vault_store"].list_assets(1)[0]

    assert asset.metadata["version"] == 4
    assert len(b64decode(asset.metadata["key_commitment"])) == 32
    opened = client.post(f"/images/{asset.id}/decrypt", data={"passphrase": "image passphrase"})
    assert opened.status_code == 200
    assert opened.data == sample_png()


def test_a_stale_page_sending_v3_is_told_to_reload(vault) -> None:
    app, alice = vault
    response = post_sealed(alice, *browser_envelope(1, version=3))

    assert response.status_code == 400
    assert "version 4" in response.get_json()["error"]
    assert "Reload the page" in response.get_json()["error"]
    assert app.extensions["vault_store"].list_assets(1) == []


def test_a_v3_image_already_stored_still_opens(vault) -> None:
    app, alice = vault
    asset, _metadata, ciphertext = _store_v3_browser_image(app)

    sealed = alice.get(f"/images/{asset.id}/sealed")
    assert sealed.status_code == 200
    blob_ciphertext, blob_metadata = unpack_ies(sealed.data)
    assert blob_metadata["version"] == 3
    assert blob_ciphertext == ciphertext
    opened = decrypt_image_bytes(blob_ciphertext, blob_metadata, passphrase=BROWSER_PASS)
    assert opened == sample_png()


def test_rekey_upgrades_a_v3_image_to_v4(vault) -> None:
    app, alice = vault
    store = app.extensions["vault_store"]
    asset, metadata, _ciphertext = _store_v3_browser_image(app)
    new_metadata, new_ciphertext = _reencrypted(metadata)

    response = _post_rekey(alice, asset.id, new_metadata, new_ciphertext)

    assert response.status_code == 200, response.get_json()
    stored = store.get_asset(asset.id)
    assert stored.metadata["version"] == 4
    assert stored.metadata["key_commitment"] == new_metadata["key_commitment"]
    assert stored.metadata["context"] == metadata["context"]
    assert store.read_ciphertext(stored) == new_ciphertext


def test_rekey_with_a_v3_envelope_is_refused(vault) -> None:
    app, alice = vault
    store = app.extensions["vault_store"]
    metadata, ciphertext = browser_envelope(1)
    asset_id = post_sealed(alice, metadata, ciphertext).get_json()["asset_id"]
    old_metadata, old_ciphertext = _reencrypted(metadata, version=3)

    response = _post_rekey(alice, asset_id, old_metadata, old_ciphertext)

    assert response.status_code == 400
    assert "Reload the page" in response.get_json()["error"]
    assert store.read_ciphertext(store.get_asset(asset_id)) == ciphertext


def test_restore_accepts_v3_and_v4_images(vault) -> None:
    app, alice = vault
    store = app.extensions["vault_store"]
    v3_asset, _v3_metadata, v3_ciphertext = _store_v3_browser_image(app)
    v4_metadata, v4_ciphertext = browser_envelope(1)
    v4_id = post_sealed(alice, v4_metadata, v4_ciphertext).get_json()["asset_id"]
    archive = alice.get("/backup").data
    store.delete_asset(v3_asset.id, 1)
    store.delete_asset(v4_id, 1)

    restored = alice.post(
        "/restore",
        data=with_csrf(alice, {"backup": (BytesIO(archive), "backup.zip")}),
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert b"Restored 2 encrypted image" in restored.data
    by_version = {asset.metadata["version"]: asset for asset in store.list_assets(1)}
    assert set(by_version) == {3, 4}
    assert store.read_ciphertext(by_version[3]) == v3_ciphertext
    assert store.read_ciphertext(by_version[4]) == v4_ciphertext
    for asset in by_version.values():
        assert asset.end_to_end
        opened = decrypt_image_bytes(
            store.read_ciphertext(asset), asset.metadata, passphrase=BROWSER_PASS
        )
        assert opened == sample_png()


def test_restoring_a_v4_backup_twice_does_not_duplicate(vault) -> None:
    app, alice = vault
    store = app.extensions["vault_store"]
    post_sealed(alice, *browser_envelope(1))
    archive = alice.get("/backup").data

    alice.post(
        "/restore",
        data=with_csrf(alice, {"backup": (BytesIO(archive), "backup.zip")}),
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert len(store.list_assets(1)) == 1


def test_cli_inspect_reports_key_commitment(tmp_path, capsys) -> None:
    source = tmp_path / "note.png"
    source.write_bytes(sample_png())
    out = tmp_path / "note.ies"
    assert (
        cli_main(["encrypt", str(source), "--passphrase", "cli passphrase", "--out", str(out)]) == 0
    )
    capsys.readouterr()

    assert cli_main(["inspect", str(out)]) == 0
    assert "key commitment: yes" in capsys.readouterr().out

    assert cli_main(["inspect", str(FIXTURES / "legacy-v1-cli.ies")]) == 0
    assert "key commitment: no (version 1)" in capsys.readouterr().out
