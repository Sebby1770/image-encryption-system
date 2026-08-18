from io import BytesIO

from image_encryption_system.crypto import AES_GCM_PASSPHRASE, RSA_HYBRID
from image_encryption_system.security import LoginGuard
from image_encryption_system.storage import VaultStore

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


def test_revoke_share_blocks_recipient_decrypt(tmp_path) -> None:
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
        data={"username": "bob", "passphrase": "image passphrase"},
        follow_redirects=True,
    )
    assert shared.status_code == 200
    assert b"Revoke" in shared.data

    share = store.get_share(asset.id, bob.id)
    assert share is not None

    logout(client)
    login(client, "bob")
    before = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
    )
    assert before.status_code == 200
    assert before.data == plaintext

    logout(client)
    login(client, "alice")
    revoked = client.post(f"/share/{share.id}/revoke", follow_redirects=True)
    assert revoked.status_code == 200
    assert store.get_share(asset.id, bob.id) is None
    assert b"Revoke" not in revoked.data

    logout(client)
    login(client, "bob")
    dashboard = client.get("/dashboard")
    assert b"secret.png" not in dashboard.data

    denied = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
        headers={"Accept": "application/json"},
    )
    assert denied.status_code in {403, 404}
    assert denied.data != plaintext


def test_change_password_rewrapping_rsa(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png("#115e59")

    register(client, "alice")
    uploaded = client.post(
        "/images",
        data={
            "algorithm": RSA_HYBRID,
            "image": (BytesIO(plaintext), "rsa-secret.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert uploaded.status_code == 200

    form = client.get("/account/password")
    assert form.status_code == 200
    assert b"Current password" in form.data

    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]
    assert asset.algorithm == RSA_HYBRID

    original = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
    )
    assert original.data == plaintext

    changed = client.post(
        "/account/password",
        data={
            "old_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
        follow_redirects=True,
    )
    assert changed.status_code == 200
    assert b"Password updated" in changed.data

    still_old = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
        follow_redirects=True,
    )
    assert still_old.data != plaintext

    with_new = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": NEW_PASSWORD},
    )
    assert with_new.status_code == 200
    assert with_new.data == plaintext

    logout(client)
    old_login = login(client, "alice", password=PASSWORD, follow_redirects=True)
    assert b"Signed in" not in old_login.data
    new_login = login(client, "alice", password=NEW_PASSWORD, follow_redirects=True)
    assert b"Signed in" in new_login.data


def test_post_without_csrf_token_is_400(tmp_path) -> None:
    app = make_app(tmp_path, CSRF_ENABLED=True)
    client = app.test_client()
    client.get("/")

    missing = client.post(
        "/register",
        data={"username": "alice", "password": PASSWORD},
    )
    assert missing.status_code == 400
    assert b"CSRF" in missing.data

    register(client, "alice")
    login_page = client.get("/")
    assert login_page.status_code in {200, 302}

    logout(client)
    bad_login = client.post(
        "/login",
        data={"username": "alice", "password": PASSWORD},
    )
    assert bad_login.status_code == 400

    login(client, "alice")
    bad_upload = client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(sample_png()), "secret.png"),
        },
        content_type="multipart/form-data",
    )
    assert bad_upload.status_code == 400

    good_upload = encrypt_png(client)
    assert good_upload.status_code == 200


def test_lockout_persists_across_app_restart(tmp_path) -> None:
    app = make_app(
        tmp_path,
        LOGIN_RATE_LIMIT=20,
        LOGIN_LOCKOUT_THRESHOLD=8,
        LOGIN_LOCKOUT_SECONDS=900,
    )
    client = app.test_client()
    register(client, "alice")
    logout(client)

    for _ in range(8):
        response = login(client, "alice", password="wrong-password-1")
        assert response.status_code in {200, 302, 403}

    locked = login(client, "alice", password=PASSWORD)
    assert locked.status_code == 403

    restarted = make_app(
        tmp_path,
        LOGIN_RATE_LIMIT=20,
        LOGIN_LOCKOUT_THRESHOLD=8,
        LOGIN_LOCKOUT_SECONDS=900,
    )
    client2 = restarted.test_client()
    still_locked = login(client2, "alice", password=PASSWORD)
    assert still_locked.status_code == 403

    api_locked = client2.post(
        "/api/token",
        json={"username": "alice", "password": PASSWORD},
    )
    assert api_locked.status_code == 403
    assert api_locked.get_json()["error"] == "account locked"


def test_login_guard_table_is_source_of_truth(tmp_path) -> None:
    store = VaultStore(tmp_path / "vault.sqlite3", tmp_path / "vault", tmp_path / "keys")
    store.init()
    guard = LoginGuard(
        store,
        max_attempts=20,
        window_seconds=600,
        lockout_threshold=8,
        lockout_seconds=900,
    )
    for _ in range(7):
        assert guard.record_failure("alice") is False
    assert guard.record_failure("alice") is True
    assert guard.is_locked("alice")

    other = LoginGuard(
        store,
        max_attempts=20,
        window_seconds=600,
        lockout_threshold=8,
        lockout_seconds=900,
    )
    assert other.is_locked("alice")
    assert other.precheck("127.0.0.1", "alice") == "locked"


def test_rotate_passphrase_wrap_round_trip(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png()

    register(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]
    ciphertext_before = store.read_ciphertext(asset)
    wrap_before = asset.metadata["key_wrap"]

    rotated = client.post(
        f"/images/{asset.id}/rotate-passphrase",
        data=with_csrf(
            client,
            {
                "old_passphrase": "image passphrase",
                "new_passphrase": "rotated passphrase",
            },
        ),
        follow_redirects=True,
    )
    assert rotated.status_code == 200
    assert b"Passphrase wrap rotated" in rotated.data

    updated = store.get_asset(asset.id)
    assert store.read_ciphertext(updated) == ciphertext_before
    assert updated.metadata["key_wrap"] != wrap_before

    stale = client.post(
        f"/images/{asset.id}/decrypt",
        data={"passphrase": "image passphrase"},
        follow_redirects=True,
    )
    assert stale.data != plaintext

    fresh = client.post(
        f"/images/{asset.id}/decrypt",
        data={"passphrase": "rotated passphrase"},
    )
    assert fresh.status_code == 200
    assert fresh.data == plaintext
