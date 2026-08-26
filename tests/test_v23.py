import time

from helpers import (
    bearer_headers,
    encrypt_png,
    login,
    make_app,
    register,
    sample_png,
    with_csrf,
)
from PIL import Image

from image_encryption_system.cli import main
from image_encryption_system.crypto import cli_aad, decrypt_image_bytes, unpack_ies


def test_capability_link_decrypt_and_max_downloads(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png()

    register(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]

    created = client.post(
        f"/images/{asset.id}/link",
        data=with_csrf(
            client,
            {
                "passphrase": "image passphrase",
                "max_downloads": "1",
                "expires_hours": "24",
                "label": "reviewer",
            },
        ),
        follow_redirects=True,
    )
    assert created.status_code == 200
    assert b"Capability link created" in created.data
    assert b"/l/" in created.data

    links = store.list_link_shares_for_owner(alice.id)[asset.id]
    assert len(links) == 1
    assert links[0].max_downloads == 1
    assert links[0].label == "reviewer"

    headers = bearer_headers(client, "alice")
    api = client.post(
        f"/api/images/{asset.id}/link",
        json={"passphrase": "image passphrase", "max_downloads": 1},
        headers=headers,
    )
    assert api.status_code == 200
    token = api.get_json()["token"]
    url = api.get_json()["url"]
    assert token in url

    guest = app.test_client()
    page = guest.get(f"/l/{token}")
    assert page.status_code == 200
    assert b"secret.png" in page.data

    first = guest.post(f"/l/{token}/decrypt")
    assert first.status_code == 200
    assert first.data == plaintext

    second = guest.post(f"/l/{token}/decrypt")
    assert second.status_code == 403


def test_rename_notes_favorite_and_audit_csv(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]

    updated = client.post(
        f"/images/{asset.id}/meta",
        data=with_csrf(
            client,
            {"filename": "passport.png", "notes": "keep offline", "favorite": "1"},
        ),
        follow_redirects=True,
    )
    assert updated.status_code == 200
    refreshed = store.get_asset(asset.id)
    assert refreshed.original_filename == "passport.png"
    assert refreshed.notes == "keep offline"
    assert refreshed.favorite is True

    favorites = client.get("/dashboard?favorites=1")
    assert favorites.status_code == 200
    assert b"passport.png" in favorites.data

    csv_resp = client.get("/audit.csv")
    assert csv_resp.status_code == 200
    assert csv_resp.mimetype == "text/csv"
    body = csv_resp.get_data(as_text=True)
    assert "action" in body
    assert "meta" in body

    pem = client.get("/account/public-key")
    assert pem.status_code == 200
    assert b"BEGIN PUBLIC KEY" in pem.data


def test_session_idle_timeout_signs_out(tmp_path) -> None:
    app = make_app(tmp_path, SESSION_IDLE_SECONDS=30)
    client = app.test_client()
    register(client, "alice")
    login(client, "alice")
    assert b"Encrypted image vault" in client.get("/dashboard").data

    with client.session_transaction() as sess:
        sess["last_seen"] = time.time() - 120

    bounced = client.get("/dashboard", follow_redirects=True)
    assert b"Sign in to continue" in bounced.data
    assert b"Encrypted image vault" not in bounced.data


def test_integrity_hash_and_cli_rewrap(tmp_path, capsys) -> None:
    source = tmp_path / "IN.png"
    vault = tmp_path / "photo.ies"
    rotated = tmp_path / "rotated.ies"
    Image.new("RGB", (16, 12), "#0f766e").save(source, format="PNG")

    encrypt_args = ["encrypt", str(source), "--passphrase", "old-secret-pass", "--out", str(vault)]
    assert main(encrypt_args) == 0
    assert main(["hash", str(vault)]) == 0
    digest = capsys.readouterr().out.strip()
    assert len(digest) == 64

    assert (
        main(
            [
                "rewrap",
                str(vault),
                "--old-passphrase",
                "old-secret-pass",
                "--new-passphrase",
                "new-secret-pass",
                "--out",
                str(rotated),
            ]
        )
        == 0
    )
    ciphertext, metadata = unpack_ies(rotated.read_bytes())
    assert metadata["key_wrap"]["type"] == "scrypt-aes-gcm"
    restored = decrypt_image_bytes(
        ciphertext,
        metadata,
        passphrase="new-secret-pass",
        aad=cli_aad("IN.png"),
    )
    assert restored.startswith(b"\x89PNG")

    app = make_app(tmp_path / "web")
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]
    assert store.ciphertext_sha256(asset)
    path = store.vault_dir / asset.stored_filename
    path.write_bytes(b"tampered-ciphertext-not-gcm")
    try:
        store.ciphertext_sha256(asset)
        raise AssertionError("expected integrity failure")
    except ValueError as exc:
        assert "integrity" in str(exc).lower()


def test_sweep_expired_user_shares(tmp_path) -> None:
    from datetime import datetime, timedelta, timezone

    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    from helpers import logout

    logout(client)
    register(client, "bob")
    logout(client)
    login(client, "alice")

    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    bob = store.get_user_by_username("bob")
    asset = store.list_assets(alice.id)[0]
    client.post(
        f"/images/{asset.id}/share",
        data={"username": "bob", "passphrase": "image passphrase", "expires_hours": "1"},
        follow_redirects=True,
    )
    share = store.get_share(asset.id, bob.id)
    assert share is not None
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
    with store._connect() as db:
        db.execute("UPDATE shares SET expires_at = ? WHERE id = ?", (past, share.id))
    assert store.sweep_expired_shares() >= 1
    assert store.get_share(asset.id, bob.id) is None
