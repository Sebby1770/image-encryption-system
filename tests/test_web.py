from io import BytesIO

from PIL import Image

from image_encryption_system.crypto import AES_GCM_PASSPHRASE
from image_encryption_system.web import create_app


def sample_png() -> bytes:
    image = Image.new("RGB", (80, 48), "#b7791f")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def make_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-test-secret-test-secret",
            "JWT_SECRET": "jwt-secret-jwt-secret-jwt-secret",
            "INSTANCE_DIR": tmp_path,
            "DATABASE_PATH": tmp_path / "vault.sqlite3",
            "VAULT_DIR": tmp_path / "vault",
            "KEY_DIR": tmp_path / "keys",
        }
    )


def test_register_encrypt_decrypt_and_jwt(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    response = client.post(
        "/register",
        data={"username": "alice", "password": "correct horse battery"},
        follow_redirects=True,
    )
    assert response.status_code == 200

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
