from io import BytesIO

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
        "AUTH_MAX_FAILURES": 5,
        "AUTH_WINDOW_SECONDS": 300,
        "AUTH_LOCKOUT_SECONDS": 900,
    }
    config.update(overrides)
    return create_app(config)


def register_alice(client) -> None:
    response = client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery"},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_register_encrypt_decrypt_and_jwt(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register_alice(client)

    plaintext = sample_png()
    response = client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(plaintext), "secret.png"),
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

    response = client.post(
        f"/images/{assets[0].id}/decrypt",
        data={"passphrase": "image passphrase"},
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


def test_debug_is_not_hardcoded_on() -> None:
    source = (__import__("pathlib").Path(__file__).resolve().parents[1] / "run.py").read_text(
        encoding="utf-8"
    )
    assert "app.run(debug=True)" not in source
    assert "IES_DEBUG" in source


def test_private_key_permissions(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register_alice(client)

    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    private_mode = store.private_key_path(user.id).stat().st_mode & 0o777
    public_mode = store.public_key_path(user.id).stat().st_mode & 0o777
    key_dir_mode = store.key_dir.stat().st_mode & 0o777
    assert private_mode == 0o600
    assert public_mode == 0o600
    assert key_dir_mode == 0o700


def test_login_and_token_throttling(tmp_path) -> None:
    app = make_app(tmp_path, AUTH_MAX_FAILURES=3, AUTH_WINDOW_SECONDS=600)
    client = app.test_client()
    register_alice(client)
    client.post("/logout")

    for _ in range(3):
        response = client.post(
            "/login",
            data={"username": "alice", "password": "definitely-wrong"},
            follow_redirects=False,
        )
        assert response.status_code in {302, 429}

    response = client.post(
        "/login",
        data={"username": "alice", "password": "definitely-wrong"},
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"]

    response = client.post(
        "/api/token",
        json={"username": "alice", "password": "definitely-wrong"},
    )
    assert response.status_code == 429
    assert response.get_json()["error"] == "too many authentication attempts"


def test_csrf_required_when_forced(tmp_path) -> None:
    app = make_app(tmp_path, FORCE_CSRF=True)
    client = app.test_client()
    response = client.post(
        "/register",
        data={"username": "bob", "password": "correct horse battery"},
    )
    assert response.status_code == 400

    landing = client.get("/register")
    html = landing.get_data(as_text=True)
    token_marker = 'name="csrf_token" value="'
    assert token_marker in html
    token = html.split(token_marker, 1)[1].split('"', 1)[0]
    response = client.post(
        "/register",
        data={"username": "bob", "password": "correct horse battery", "csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_delete_and_audit_and_password_change(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register_alice(client)

    plaintext = sample_png()
    client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "image passphrase",
            "image": (BytesIO(plaintext), "secret.png"),
        },
        content_type="multipart/form-data",
    )
    store = app.extensions["vault_store"]
    user = store.get_user_by_username("alice")
    asset = store.list_assets(user.id)[0]

    download = client.get(f"/images/{asset.id}/ciphertext")
    assert download.status_code == 200
    assert download.data == store.read_ciphertext(asset)

    deleted = client.post(f"/images/{asset.id}/delete", follow_redirects=True)
    assert deleted.status_code == 200
    assert store.list_assets(user.id) == []

    changed = client.post(
        "/settings/password",
        data={
            "current_password": "correct horse battery",
            "new_password": "new horse battery",
            "confirm_password": "new horse battery",
        },
        follow_redirects=True,
    )
    assert changed.status_code == 200
    client.post("/logout")
    relogin = client.post(
        "/login",
        data={"username": "alice", "password": "new horse battery"},
        follow_redirects=True,
    )
    assert relogin.status_code == 200
    events = store.list_audit_for_user(user.id)
    assert any(event.event_type == "account.password_changed" for event in events)
    assert any(event.event_type == "image.deleted" for event in events)


def test_health_endpoint(tmp_path) -> None:
    app = make_app(tmp_path)
    response = app.test_client().get("/health")
    assert response.status_code == 200
    assert response.get_json()["ok"] is True
