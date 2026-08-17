from helpers import (
    PASSWORD,
    bearer_headers,
    encrypt_png,
    login,
    logout,
    make_app,
    register,
)


def test_audit_page_and_api_are_owner_only(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    register(client, "alice")
    logout(client)
    login(client, "alice")
    encrypt_png(client)
    store = app.extensions["vault_store"]
    asset = store.list_assets(store.get_user_by_username("alice").id)[0]
    client.post(f"/images/{asset.id}/decrypt", data={"passphrase": "image passphrase"})

    page = client.get("/audit")
    assert page.status_code == 200
    assert b'<span class="pill">login</span>' in page.data
    assert b'<span class="pill">upload</span>' in page.data
    assert b'<span class="pill">decrypt</span>' in page.data

    headers = bearer_headers(client, "alice")
    api = client.get("/api/audit", headers=headers)
    assert api.status_code == 200
    actions = {event["action"] for event in api.get_json()["events"]}
    assert {"login", "upload", "decrypt"} <= actions
    for event in api.get_json()["events"]:
        assert "password" not in event

    logout(client)
    register(client, "bob")
    bob_page = client.get("/audit")
    assert b'<span class="pill">upload</span>' not in bob_page.data
    assert b'<span class="pill">decrypt</span>' not in bob_page.data

    bob_headers = bearer_headers(client, "bob", PASSWORD)
    bob_api = client.get("/api/audit", headers=bob_headers)
    bob_actions = {event["action"] for event in bob_api.get_json()["events"]}
    assert "upload" not in bob_actions
    assert "decrypt" not in bob_actions
