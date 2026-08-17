from image_encryption_system.crypto import AES_GCM_PASSPHRASE, RSA_HYBRID

from helpers import (
    PASSWORD,
    encrypt_png,
    login,
    logout,
    make_app,
    register,
    sample_png,
)


def test_alice_shares_to_bob_and_eve_cannot(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png()

    register(client, "alice")
    response = encrypt_png(client)
    assert response.status_code == 200

    logout(client)
    register(client, "bob")
    logout(client)
    register(client, "eve")
    logout(client)

    login(client, "alice")
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]

    response = client.post(
        f"/images/{asset.id}/share",
        data={"username": "bob", "passphrase": "image passphrase"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Shared with bob" in response.data

    logout(client)
    login(client, "bob")
    dashboard = client.get("/dashboard")
    assert b"Shared with me" in dashboard.data
    assert b"secret.png" in dashboard.data
    assert b"From alice" in dashboard.data

    decrypted = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
    )
    assert decrypted.status_code == 200
    assert decrypted.data == plaintext

    logout(client)
    login(client, "eve")
    eve_dashboard = client.get("/dashboard")
    assert b"secret.png" not in eve_dashboard.data

    denied = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
        follow_redirects=True,
    )
    assert denied.status_code == 200
    assert denied.data != plaintext
    assert b"do not have access" in denied.data

    eve = store.get_user_by_username("eve")
    assert store.get_share(asset.id, eve.id) is None
    assert store.list_shared_with_user(eve.id) == []


def test_share_rsa_hybrid_image(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    plaintext = sample_png("#115e59")

    register(client, "alice")
    from io import BytesIO

    client.post(
        "/images",
        data={
            "algorithm": RSA_HYBRID,
            "image": (BytesIO(plaintext), "rsa-secret.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    logout(client)
    register(client, "bob")
    logout(client)

    login(client, "alice")
    store = app.extensions["vault_store"]
    alice = store.get_user_by_username("alice")
    asset = store.list_assets(alice.id)[0]
    assert asset.algorithm == RSA_HYBRID

    response = client.post(
        f"/images/{asset.id}/share",
        data={"username": "bob", "private_key_passphrase": PASSWORD},
        follow_redirects=True,
    )
    assert response.status_code == 200

    logout(client)
    login(client, "bob")
    decrypted = client.post(
        f"/images/{asset.id}/decrypt",
        data={"private_key_passphrase": PASSWORD},
    )
    assert decrypted.data == plaintext


def test_cannot_share_to_unknown_user(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    asset = store.list_assets(store.get_user_by_username("alice").id)[0]
    response = client.post(
        f"/images/{asset.id}/share",
        data={"username": "nobody", "passphrase": "image passphrase"},
        follow_redirects=True,
    )
    assert b"No account exists" in response.data


def test_dashboard_search_filters_by_name_and_algorithm(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client, filename="vacation.png")
    encrypt_png(client, filename="passport.png")

    found = client.get("/dashboard?q=pass")
    assert b"passport.png" in found.data
    assert b"vacation.png" not in found.data

    hidden = client.get(f"/dashboard?q=pass&algorithm={AES_GCM_PASSPHRASE}")
    assert b"passport.png" in hidden.data

    empty = client.get("/dashboard?algorithm=RSA-HYBRID")
    assert b"passport.png" not in empty.data
    assert b"vacation.png" not in empty.data
