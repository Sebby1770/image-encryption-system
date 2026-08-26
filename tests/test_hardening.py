from helpers import PASSWORD, login, make_app, register

from image_encryption_system.config import Config


def test_default_upload_limit_is_8mb() -> None:
    assert Config.MAX_CONTENT_LENGTH == 8 * 1024 * 1024


def test_login_rate_limit_is_five_per_window(tmp_path) -> None:
    app = make_app(tmp_path, LOGIN_RATE_LIMIT=5, LOGIN_LOCKOUT_THRESHOLD=99)
    client = app.test_client()
    register(client, "alice")
    client.post("/logout")

    for _ in range(5):
        response = login(client, "alice", password="definitely-wrong")
        assert response.status_code in {200, 302}

    limited = login(client, "alice", password="definitely-wrong")
    assert limited.status_code == 429

    api_limited = client.post(
        "/api/token",
        json={"username": "alice", "password": "definitely-wrong"},
    )
    assert api_limited.status_code == 429


def test_lockout_after_eight_failed_logins(tmp_path) -> None:
    app = make_app(
        tmp_path,
        LOGIN_RATE_LIMIT=20,
        LOGIN_LOCKOUT_THRESHOLD=8,
        LOGIN_LOCKOUT_SECONDS=900,
    )
    client = app.test_client()
    register(client, "alice")
    client.post("/logout")

    for _ in range(8):
        response = login(client, "alice", password="wrong-password-1")
        assert response.status_code in {200, 302, 403}

    locked = login(client, "alice", password=PASSWORD)
    assert locked.status_code == 403

    api_locked = client.post(
        "/api/token",
        json={"username": "alice", "password": PASSWORD},
    )
    assert api_locked.status_code == 403
    assert api_locked.get_json()["error"] == "account locked"


def test_successful_login_resets_failure_count(tmp_path) -> None:
    app = make_app(tmp_path, LOGIN_RATE_LIMIT=20, LOGIN_LOCKOUT_THRESHOLD=8)
    client = app.test_client()
    register(client, "alice")
    client.post("/logout")

    for _ in range(4):
        login(client, "alice", password="wrong-password-1")

    ok = login(client, "alice", password=PASSWORD, follow_redirects=True)
    assert ok.status_code == 200
    assert b"Signed in" in ok.data
