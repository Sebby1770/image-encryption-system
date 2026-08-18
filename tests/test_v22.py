from datetime import datetime, timedelta, timezone
from io import BytesIO

import jwt
import pytest
from PIL import Image

from image_encryption_system.cli import main
from image_encryption_system.crypto import AES_GCM_PASSPHRASE

from helpers import (
    PASSWORD,
    encrypt_png,
    login,
    logout,
    make_app,
    register,
    sample_png,
    with_csrf,
)


NEW_PASSWORD = "brand new vault password"


def jpeg_with_fake_exif() -> bytes:
    image = Image.new("RGB", (40, 24), "#115e59")
    buffer = BytesIO()
    image.save(buffer, format="JPEG", quality=90)
    jpeg = buffer.getvalue()
    payload = b"Exif\x00\x00" + b"FAKE-GPS-99.9" + b"\x00" * 16
    app1 = b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
    return jpeg[:2] + app1 + jpeg[2:]


def test_password_change_invalidates_old_session_and_jwt(tmp_path) -> None:
    app = make_app(tmp_path)
    alice = app.test_client()
    other = app.test_client()

    register(alice, "alice")
    login(other, "alice")

    token_response = alice.post("/api/token", json={"username": "alice", "password": PASSWORD})
    assert token_response.status_code == 200
    token = token_response.get_json()["token"]
    payload = jwt.decode(
        token,
        app.config["JWT_SECRET"],
        algorithms=["HS256"],
        issuer=app.config["JWT_ISSUER"],
    )
    assert payload["ver"] == 1
    assert alice.get("/api/images", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert b"Encrypted image vault" in other.get("/dashboard").data

    changed = alice.post(
        "/account/password",
        data=with_csrf(
            alice,
            {
                "old_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "confirm_password": NEW_PASSWORD,
            },
        ),
        follow_redirects=True,
    )
    assert changed.status_code == 200
    assert b"Password updated" in changed.data
    assert b"Encrypted image vault" in changed.data

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    assert user is not None
    assert user.token_version == 2

    stale = alice.get("/api/images", headers={"Authorization": f"Bearer {token}"})
    assert stale.status_code == 401
    assert stale.get_json()["error"] == "invalid bearer token"

    other_dash = other.get("/dashboard", follow_redirects=True)
    assert b"Sign in to continue" in other_dash.data
    assert b"Encrypted image vault" not in other_dash.data

    fresh = alice.post("/api/token", json={"username": "alice", "password": NEW_PASSWORD})
    assert fresh.status_code == 200
    new_token = fresh.get_json()["token"]
    new_payload = jwt.decode(
        new_token,
        app.config["JWT_SECRET"],
        algorithms=["HS256"],
        issuer=app.config["JWT_ISSUER"],
    )
    assert new_payload["ver"] == 2
    listed = alice.get("/api/images", headers={"Authorization": f"Bearer {new_token}"})
    assert listed.status_code == 200


def test_share_expiry_blocks_recipient_decrypt(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png()

    register(client, "alice")
    encrypt_png(client)
    logout(client)
    register(client, "bob")
    logout(client)

    login(client, "alice")
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    bob = store.get_user_by_username("bob")
    asset = store.list_assets(alice.id)[0]

    shared = client.post(
        f"/images/{asset.id}/share",
        data={"username": "bob", "passphrase": "image passphrase", "expires_hours": "24"},
        follow_redirects=True,
    )
    assert shared.status_code == 200
    assert b"Expires" in shared.data
    assert b"expires" in shared.data

    share = store.get_share(asset.id, bob.id)
    assert share is not None
    assert share.expires_at is not None
    expires = datetime.fromisoformat(share.expires_at)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    delta = expires - datetime.now(timezone.utc)
    assert timedelta(hours=23) < delta < timedelta(hours=25)

    logout(client)
    login(client, "bob")
    inbox = client.get("/dashboard")
    assert b"expires" in inbox.data
    before = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
    )
    assert before.status_code == 200
    assert before.data == plaintext

    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
    with store._connect() as db:
        db.execute("UPDATE shares SET expires_at = ? WHERE id = ?", (past, share.id))

    denied = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
        headers={"Accept": "application/json"},
    )
    assert denied.status_code in {403, 404}
    assert denied.data != plaintext


def test_delete_account_removes_user_assets_and_keys(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png()

    register(client, "alice")
    encrypt_png(client)
    logout(client)
    register(client, "bob")
    logout(client)

    login(client, "alice")
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    bob = store.get_user_by_username("bob")
    asset = store.list_assets(alice.id)[0]
    stored = asset.stored_filename
    alice_id = alice.id

    client.post(
        f"/images/{asset.id}/share",
        data={"username": "bob", "passphrase": "image passphrase"},
        follow_redirects=True,
    )
    assert store.get_share(asset.id, bob.id) is not None

    refused = client.post(
        "/account/delete",
        data=with_csrf(client, {"password": "not-the-password"}),
        follow_redirects=True,
    )
    assert refused.status_code == 200
    assert store.get_user_by_username("alice") is not None

    deleted = client.post(
        "/account/delete",
        data=with_csrf(client, {"password": PASSWORD}),
        follow_redirects=True,
    )
    assert deleted.status_code == 200
    assert b"Account deleted" in deleted.data
    assert store.get_user_by_username("alice") is None
    with pytest.raises(LookupError):
        store.get_user(alice_id)
    assert store.list_assets(alice_id) == []
    assert not store.private_key_path(alice_id).exists()
    assert not store.public_key_path(alice_id).exists()
    assert not (store.vault_dir / stored).exists()

    login_again = login(client, "alice", follow_redirects=True)
    assert b"Signed in" not in login_again.data

    login(client, "bob")
    denied = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
        headers={"Accept": "application/json"},
    )
    assert denied.status_code in {403, 404}
    assert denied.data != plaintext


def test_upload_strips_jpeg_exif(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    raw = jpeg_with_fake_exif()
    assert b"Exif" in raw
    assert b"FAKE-GPS-99.9" in raw

    register(client, "alice")
    uploaded = client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(raw), "geo.jpg"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert uploaded.status_code == 200

    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]
    decrypted = client.post(
        f"/images/{asset.id}/decrypt",
        data={"passphrase": "image passphrase"},
    )
    assert decrypted.status_code == 200
    assert b"Exif" not in decrypted.data
    assert b"FAKE-GPS-99.9" not in decrypted.data
    with Image.open(BytesIO(decrypted.data)) as image:
        assert image.size == (40, 24)
        assert dict(image.getexif()) == {}


def test_cli_inspect_and_verify(tmp_path, capsys) -> None:
    source = tmp_path / "IN.png"
    vault = tmp_path / "photo.ies"
    Image.new("RGB", (16, 12), "#0f766e").save(source, format="PNG")

    assert main(["encrypt", str(source), "--passphrase", "cli-secret-pass", "--out", str(vault)]) == 0
    assert main(["inspect", str(vault)]) == 0
    printed = capsys.readouterr().out
    assert "AES-GCM" in printed
    assert "version:" in printed
    assert "wrapped_key" not in printed
    assert "salt" not in printed
    assert "nonce" not in printed

    assert main(["verify", str(vault), "--passphrase", "cli-secret-pass"]) == 0
    assert "ok" in capsys.readouterr().out
    assert main(["verify", str(vault), "--passphrase", "wrong-secret"]) == 1
    assert not (tmp_path / "restored.png").exists()
