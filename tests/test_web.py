from io import BytesIO
import os
import re
import stat

import pytest
from PIL import Image

from image_encryption_system.crypto import AES_GCM_PASSPHRASE
from image_encryption_system.web import create_app


def sample_png() -> bytes:
    image = Image.new("RGB", (80, 48), "#b7791f")
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


def test_production_requires_strong_secrets(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        make_app(
            tmp_path,
            REQUIRE_STRONG_SECRETS=True,
            SECRET_KEY="dev-secret-change-me-dev-secret-change-me",
            JWT_SECRET="jwt-secret-jwt-secret-jwt-secret",
        )
