from io import BytesIO
import json
import zipfile

from helpers import (
    bearer_headers,
    encrypt_png,
    logout,
    make_app,
    register,
    sample_png,
)


def test_backup_and_restore_round_trip(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png()

    register(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    original = store.list_assets(alice.id)[0]

    backup = client.get("/backup")
    assert backup.status_code == 200
    assert backup.mimetype == "application/zip"
    assert backup.data[:2] == b"PK"

    with zipfile.ZipFile(BytesIO(backup.data)) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        assert any(name.startswith("assets/") and name.endswith(".enc") for name in names)
        assert not any(name.endswith(".pem") or "private" in name.lower() for name in names)
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["username"] == "alice"
        assert manifest["assets"][0]["original_filename"] == "secret.png"
        assert "password_hash" not in json.dumps(manifest)

    client.post(f"/images/{original.id}/delete", follow_redirects=True)
    assert store.list_assets(alice.id) == []

    restored = client.post(
        "/restore",
        data={"backup": (BytesIO(backup.data), "alice-backup.zip")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert restored.status_code == 200
    assets = store.list_assets(alice.id)
    assert len(assets) == 1
    assert assets[0].original_filename == "secret.png"
    assert assets[0].id != original.id

    decrypted = client.post(
        f"/images/{assets[0].id}/decrypt",
        data={"passphrase": "image passphrase"},
    )
    assert decrypted.data == plaintext


def test_download_ciphertext_ies_and_delete(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    asset = store.list_assets(store.get_user_by_username("alice").id)[0]

    download = client.get(f"/images/{asset.id}/download")
    assert download.status_code == 200
    assert download.data.startswith(b"IES1")
    assert "secret.png.ies" in download.headers.get("Content-Disposition", "")

    from image_encryption_system.crypto import decrypt_image_bytes, unpack_ies

    ciphertext, metadata = unpack_ies(download.data)
    aad = f"user={asset.user_id}|filename=secret.png|mime={asset.mime_type}".encode()
    assert decrypt_image_bytes(ciphertext, metadata, passphrase="image passphrase", aad=aad) == sample_png()

    deleted = client.post(f"/images/{asset.id}/delete", follow_redirects=True)
    assert deleted.status_code == 200
    assert store.list_assets(store.get_user_by_username("alice").id) == []


def test_backup_requires_owner_and_logs_event(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    client.get("/backup")

    headers = bearer_headers(client, "alice")
    audit = client.get("/api/audit", headers=headers)
    actions = [event["action"] for event in audit.get_json()["events"]]
    assert "backup" in actions
    assert "upload" in actions

    logout(client)
    denied = client.get("/backup", follow_redirects=True)
    assert b"Sign in to continue" in denied.data
