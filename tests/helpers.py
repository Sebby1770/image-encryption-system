from io import BytesIO

from PIL import Image

from image_encryption_system.crypto import AES_GCM_PASSPHRASE
from image_encryption_system.web import create_app

PASSWORD = "correct horse battery"


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


def register(client, username: str, password: str = PASSWORD):
    return client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def login(client, username: str, password: str = PASSWORD, **kwargs):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        **kwargs,
    )


def logout(client):
    return client.post("/logout", follow_redirects=True)


def encrypt_png(client, filename: str = "secret.png", passphrase: str = "image passphrase"):
    return client.post(
        "/images",
        data={
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": passphrase,
            "image": (BytesIO(sample_png()), filename),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def bearer_headers(client, username: str, password: str = PASSWORD) -> dict[str, str]:
    response = client.post("/api/token", json={"username": username, "password": password})
    token = response.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}
