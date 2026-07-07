from io import BytesIO
import os
import re
import stat

import pytest
from PIL import Image

from image_encryption_system.crypto import AES_GCM_PASSPHRASE
from image_encryption_system.web import create_app


def sample_png(color: str = "#b7791f") -> bytes:
    image = Image.new("RGB", (80, 48), color)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def make_app(tmp_path, **overrides):
    config = {
        "TESTING": True,
        "SECRET_KEY": "test-secret-test-secret-test-secret",
        "JWT_SECRET": "jwt-secret-jwt-secret-jwt-secret",
        "INSTANCE_DIR": tmp_path,
        "DATABASE_PATH": tmp_path / "vault.sqlite3",
        "VAULT_DIR": tmp_path / "vault",
        "KEY_DIR": tmp_path / "keys",
    }
    config.update(overrides)
    return create_app(config)


def csrf_from(response) -> str:
    match = re.search(rb'name="_csrf_token" value="([^"]+)"', response.data)
    assert match is not None
    return match.group(1).decode("utf-8")


def csrf_token(client, path: str = "/") -> str:
    return csrf_from(client.get(path))


def test_register_encrypt_decrypt_and_jwt(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200

    plaintext = sample_png()
    token = csrf_token(client, "/dashboard")
    response = client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(plaintext), "secret.png"),
            "_csrf_token": token,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    assets = store.list_assets(user.id)
    assert len(assets) == 1
    assert store.read_ciphertext(assets[0]) != plaintext

    token = csrf_token(client, "/dashboard")
    response = client.post(
        f"/images/{assets[0].id}/decrypt",
        data={"passphrase": "image passphrase", "_csrf_token": token},
    )
    assert response.status_code == 200
    assert response.data == plaintext
    assert response.mimetype == "image/png"

    response = client.post(
        "/api/token",
        json={"username": "alice", "password": "correct horse battery"},
    )
    assert response.status_code == 200
    token = response.get_json()["token"]

    response = client.get("/api/images", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json()["images"][0]["filename"] == "secret.png"


def test_generated_files_are_owner_only(tmp_path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX file modes are not portable to Windows")

    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")

    assert stat.S_IMODE(store.key_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.private_key_path(user.id).stat().st_mode) == 0o600
    assert stat.S_IMODE(store.public_key_path(user.id).stat().st_mode) == 0o600

    token = csrf_token(client, "/dashboard")
    response = client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(sample_png()), "secret.png"),
            "_csrf_token": token,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200

    asset = store.list_assets(user.id)[0]
    encrypted_path = store.vault_dir / asset.stored_filename
    assert stat.S_IMODE(store.vault_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(encrypted_path.stat().st_mode) == 0o600


def test_login_throttles_repeated_bad_passwords(tmp_path) -> None:
    app = make_app(
        tmp_path,
        AUTH_RATE_LIMIT_ATTEMPTS=2,
        AUTH_RATE_LIMIT_WINDOW_SECONDS=300,
        AUTH_RATE_LIMIT_LOCKOUT_SECONDS=300,
    )
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
    )
    token = csrf_token(client, "/dashboard")
    client.post("/logout", data={"_csrf_token": token})

    token = csrf_token(client, "/")
    for _ in range(2):
        response = client.post(
            "/login",
            data={"username": "alice", "password": "wrong password", "_csrf_token": token},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Invalid username or password" in response.data

    response = client.post(
        "/login",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Too many failed sign-in attempts" in response.data


def test_api_token_throttles_repeated_bad_passwords(tmp_path) -> None:
    app = make_app(
        tmp_path,
        AUTH_RATE_LIMIT_ATTEMPTS=1,
        AUTH_RATE_LIMIT_WINDOW_SECONDS=300,
        AUTH_RATE_LIMIT_LOCKOUT_SECONDS=300,
    )
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
    )

    response = client.post(
        "/api/token",
        json={"username": "alice", "password": "wrong password"},
    )
    assert response.status_code == 401

    response = client.post(
        "/api/token",
        json={"username": "alice", "password": "correct horse battery"},
    )
    assert response.status_code == 429
    payload = response.get_json()
    assert payload["error"] == "too many failed attempts"
    assert payload["retry_after_seconds"] > 0
    assert response.headers["Retry-After"] == str(payload["retry_after_seconds"])


def test_form_posts_require_csrf_token(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    response = client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Your form session expired" in response.data


def test_delete_asset_and_audit_log(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
    )

    token = csrf_token(client, "/dashboard")
    client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(sample_png()), "secret.png"),
            "_csrf_token": token,
        },
        content_type="multipart/form-data",
    )

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    asset = store.list_assets(user.id)[0]

    token = csrf_token(client, "/dashboard")
    response = client.post(
        f"/images/{asset.id}/delete",
        data={"_csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert store.list_assets(user.id) == []

    events = store.list_audit_events(user.id)
    assert any(event.action == "delete" for event in events)


def test_api_upload_and_delete(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
    )

    response = client.post(
        "/api/token",
        json={"username": "alice", "password": "correct horse battery"},
    )
    jwt_token = response.get_json()["token"]
    headers = {"Authorization": f"Bearer {jwt_token}"}

    response = client.post(
        "/api/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(sample_png()), "secret.png"),
        },
        headers=headers,
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    asset_id = response.get_json()["image"]["id"]

    response = client.delete(f"/api/images/{asset_id}", headers=headers)
    assert response.status_code == 200
    assert response.get_json()["deleted"] is True


def test_vault_search_sort_and_bulk_delete(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
    )

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")

    for name, color in (
        ("alpha.png", "#b7791f"),
        ("beta.png", "#2d6a4f"),
        ("gamma.png", "#4a4e69"),
    ):
        token = csrf_token(client, "/dashboard")
        client.post(
            "/images",
            data={
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": "image passphrase",
                "image": (BytesIO(sample_png(color)), name),
                "_csrf_token": token,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assets = store.list_assets(user.id, query="beta")
    assert len(assets) == 1
    assert assets[0].original_filename == "beta.png"

    all_assets = store.list_assets(user.id, sort="name")
    assert [asset.original_filename for asset in all_assets] == ["alpha.png", "beta.png", "gamma.png"]

    token = csrf_token(client, "/dashboard")
    ids = [asset.id for asset in store.list_assets(user.id)[:2]]
    response = client.post(
        "/images/bulk-delete",
        data={"asset_ids": ids, "_csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert len(store.list_assets(user.id)) == 1


def test_tags_search_and_vault_export(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
    )

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")

    for name, tags in (("holiday.png", "vacation, family"), ("work.png", "work")):
        token = csrf_token(client, "/dashboard")
        client.post(
            "/images",
            data={
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": "image passphrase",
                "tags": tags,
                "image": (BytesIO(sample_png()), name),
                "_csrf_token": token,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    tagged = store.list_assets(user.id, tag="vacation")
    assert len(tagged) == 1
    assert tagged[0].tags == "vacation,family"

    token = csrf_token(client, "/dashboard")
    client.post("/logout", data={"_csrf_token": token})
    token = csrf_token(client, "/")
    client.post(
        "/login",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
        follow_redirects=True,
    )
    response = client.get("/vault/export")
    assert response.status_code == 200
    assert response.mimetype == "application/zip"


def test_update_tags_rename_and_api_stats(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
    )

    token = csrf_token(client, "/dashboard")
    client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "tags": "draft",
            "image": (BytesIO(sample_png()), "photo.png"),
            "_csrf_token": token,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    asset = store.list_assets(user.id)[0]

    token = csrf_token(client, "/dashboard")
    client.post(
        f"/images/{asset.id}/tags",
        data={"tags": "final,archive", "_csrf_token": token},
        follow_redirects=True,
    )
    updated = store.get_asset(asset.id)
    assert updated.tags == "final,archive"

    token = csrf_token(client, "/dashboard")
    client.post(
        f"/images/{asset.id}/rename",
        data={"filename": "renamed.png", "_csrf_token": token},
        follow_redirects=True,
    )
    renamed = store.get_asset(asset.id)
    assert renamed.original_filename == "renamed.png"

    response = client.post(
        "/api/token",
        json={"username": "alice", "password": "correct horse battery"},
    )
    headers = {"Authorization": f"Bearer {response.get_json()['token']}"}
    stats = client.get("/api/stats", headers=headers).get_json()
    assert stats["assets"] == 1
    assert "final" in stats["tags"]


def test_v050_notes_bulk_tags_password_docs_and_duplicate(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
        follow_redirects=True,
    )

    plaintext = sample_png()
    token = csrf_token(client, "/dashboard")
    client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "tags": "draft",
            "notes": "first upload",
            "image": (BytesIO(plaintext), "secret.png"),
            "_csrf_token": token,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    asset = store.list_assets(user.id)[0]
    assert asset.notes == "first upload"
    assert asset.metadata.get("content_hash")

    token = csrf_token(client, "/dashboard")
    duplicate = client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(plaintext), "duplicate.png"),
            "_csrf_token": token,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"Duplicate image detected" in duplicate.data
    assert len(store.list_assets(user.id)) == 1

    token = csrf_token(client, "/dashboard")
    client.post(
        "/images/bulk-tags",
        data={"asset_ids": [str(asset.id)], "tags": "archive,final", "_csrf_token": token},
        follow_redirects=True,
    )
    assert store.get_asset(asset.id).tags == "archive,final"

    token = csrf_token(client, "/dashboard")
    client.post(
        "/account/password",
        data={
            "current_password": "correct horse battery",
            "new_password": "new horse battery",
            "confirm_password": "new horse battery",
            "_csrf_token": token,
        },
        follow_redirects=True,
    )
    assert store.authenticate_user("alice", "new horse battery")

    docs = client.get("/api/docs").get_json()
    assert docs["version"] == "0.6.0"
    assert any(item["path"] == "/api/stats" for item in docs["endpoints"])


def test_v060_audit_chain_entropy_and_timelock(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    token = csrf_token(client, "/register")
    client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery", "_csrf_token": token},
        follow_redirects=True,
    )

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    future = "2099-12-31T23:59"
    token = csrf_token(client, "/dashboard")
    client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "unlock_after": future,
            "image": (BytesIO(sample_png()), "locked.png"),
            "_csrf_token": token,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    asset = store.list_assets(user.id)[0]
    assert asset.metadata.get("entropy_bits", 0) > 0
    assert asset.metadata.get("unlock_after") == future

    token = csrf_token(client, "/dashboard")
    locked = client.post(
        f"/images/{asset.id}/preview",
        data={"passphrase": "image passphrase", "_csrf_token": token},
    )
    assert locked.status_code == 400
    assert b"Time-locked" in locked.data

    chain = store.verify_audit_chain(user.id)
    assert chain["valid"] is True
    assert chain["checked"] >= 2

    token = csrf_token(client, "/dashboard")
    client.post("/audit/verify", data={"_csrf_token": token}, follow_redirects=True)

    response = client.post(
        "/api/token",
        json={"username": "alice", "password": "correct horse battery"},
    )
    headers = {"Authorization": f"Bearer {response.get_json()['token']}"}
    verify = client.get("/api/audit/verify", headers=headers).get_json()
    assert verify["valid"] is True


def test_production_requires_strong_secrets(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        make_app(
            tmp_path,
            REQUIRE_STRONG_SECRETS=True,
            SECRET_KEY="dev-secret-change-me-dev-secret-change-me",
            JWT_SECRET="jwt-secret-jwt-secret-jwt-secret",
        )
