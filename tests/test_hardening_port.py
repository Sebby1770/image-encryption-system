"""Hardening carried over from the parallel v3.0 line (#6, #10).

Each test pins a control that line added and this one lacked: throttles outside
the login form, a password policy rotation cannot bypass, a KDF cost that can
rise without stranding old files, an audience-bound API token, and the rest of
the browser-side headers.
"""

import os

import jwt
import pytest
from helpers import PASSWORD, encrypt_png, make_app, register, with_csrf

from image_encryption_system import crypto
from image_encryption_system.crypto import (
    LEGACY_SCRYPT_N,
    MIN_SCRYPT_N,
    CryptoError,
    _unwrap_key_with_passphrase,
    _wrap_key_with_passphrase,
)
from image_encryption_system.security import PasswordPolicyError, validate_password

DATA_KEY = bytes(range(32))

# --------------------------------------------------------------------------- #
# Scrypt cost
# --------------------------------------------------------------------------- #


@pytest.mark.production_kdf
def test_new_wrappings_use_the_production_cost() -> None:
    wrap = _wrap_key_with_passphrase(DATA_KEY, "pass-phrase-1")
    assert wrap["n"] == 2**16
    assert _unwrap_key_with_passphrase(wrap, "pass-phrase-1") == DATA_KEY


def test_the_accepted_floor_is_separate_from_the_default() -> None:
    # The whole point of the split: the default rose without moving the floor.
    assert MIN_SCRYPT_N < 2**16
    assert MIN_SCRYPT_N == LEGACY_SCRYPT_N == 2**14


@pytest.mark.production_kdf
def test_a_file_wrapped_at_the_old_cost_still_opens(monkeypatch) -> None:
    """Before the split, raising SCRYPT_N would have rejected every old file."""
    monkeypatch.setattr(crypto, "SCRYPT_N", LEGACY_SCRYPT_N)
    legacy = _wrap_key_with_passphrase(DATA_KEY, "pass-phrase-1")
    monkeypatch.setattr(crypto, "SCRYPT_N", 2**16)

    assert legacy["n"] == 2**14
    assert _unwrap_key_with_passphrase(legacy, "pass-phrase-1") == DATA_KEY


@pytest.mark.production_kdf
def test_a_wrap_without_n_falls_back_to_the_legacy_cost(monkeypatch) -> None:
    """A wrap that omits ``n`` predates explicit parameters, so it was made at
    2^14. Falling back to the *current* default would derive the wrong key."""
    monkeypatch.setattr(crypto, "SCRYPT_N", LEGACY_SCRYPT_N)
    wrap = _wrap_key_with_passphrase(DATA_KEY, "pass-phrase-1")
    monkeypatch.setattr(crypto, "SCRYPT_N", 2**16)
    del wrap["n"]

    assert _unwrap_key_with_passphrase(wrap, "pass-phrase-1") == DATA_KEY


def test_a_cost_below_the_floor_is_refused() -> None:
    wrap = _wrap_key_with_passphrase(DATA_KEY, "pass-phrase-1")
    wrap["n"] = MIN_SCRYPT_N // 2
    with pytest.raises(CryptoError, match="Scrypt"):
        _unwrap_key_with_passphrase(wrap, "pass-phrase-1")


def test_recorded_cost_matches_the_cost_spent(monkeypatch) -> None:
    """The wrap used to derive with import-time default arguments while writing
    the cost separately; changing the module value at runtime exposed the gap."""
    monkeypatch.setattr(crypto, "SCRYPT_N", 2**15)
    wrap = _wrap_key_with_passphrase(DATA_KEY, "pass-phrase-1")
    assert wrap["n"] == 2**15
    assert _unwrap_key_with_passphrase(wrap, "pass-phrase-1") == DATA_KEY


# --------------------------------------------------------------------------- #
# Password policy
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "password, reason",
    [
        ("short", "at least"),
        ("aaaaaaaaaaaa", "five different"),
        ("password123", "too common"),
        ("", "required"),
        ("x" * 1025, "too long"),
    ],
)
def test_policy_rejects_weak_passwords(password: str, reason: str) -> None:
    with pytest.raises(PasswordPolicyError, match=reason):
        validate_password(password)


def test_policy_rejects_a_password_containing_the_username() -> None:
    with pytest.raises(PasswordPolicyError, match="username"):
        validate_password("Mallory-is-great-99", username="mallory")


def test_policy_accepts_a_reasonable_passphrase() -> None:
    validate_password(PASSWORD, username="rider")


def test_registration_rejects_a_weak_password(tmp_path) -> None:
    app = make_app(tmp_path)
    response = register(app.test_client(), "weakling", password="aaaaaaaaaaaa")
    assert b"five different" in response.data
    assert app.extensions["vault_store"].count_users() == 0


def test_password_rotation_cannot_bypass_the_policy(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "rotator")

    response = client.post(
        "/account/password",
        data=with_csrf(
            client,
            {
                "old_password": PASSWORD,
                "new_password": "aaaaaaaaaaaa",
                "confirm_password": "aaaaaaaaaaaa",
            },
        ),
        follow_redirects=True,
    )
    assert b"five different" in response.data
    store = app.extensions["vault_store"]
    assert store.authenticate_user("rotator", PASSWORD) is not None


def test_storage_enforces_the_policy_for_every_caller(tmp_path) -> None:
    store = make_app(tmp_path).extensions["vault_store"]
    with pytest.raises(PasswordPolicyError):
        store.create_user("cli-user", "password123")


# --------------------------------------------------------------------------- #
# Throttles beyond the login form
# --------------------------------------------------------------------------- #


def test_registration_is_throttled_per_address(tmp_path) -> None:
    """Each registration mints an RSA-3072 key pair: a CPU amplifier anyone can
    call without an account."""
    app = make_app(tmp_path, REGISTER_RATE_LIMIT=2, REGISTER_RATE_WINDOW_SECONDS=600)
    client = app.test_client()

    for name in ("first", "second"):
        assert register(client, name).status_code in (200, 302)
        client.post("/logout", data=with_csrf(client))

    assert register(client, "third").status_code == 429
    assert app.extensions["vault_store"].count_users() == 2


def test_decrypt_attempts_are_throttled_per_account(tmp_path) -> None:
    app = make_app(tmp_path, DECRYPT_RATE_LIMIT=3, DECRYPT_RATE_WINDOW_SECONDS=600)
    client = app.test_client()
    register(client, "guessed")
    encrypt_png(client, passphrase="vault-passphrase")
    asset = app.extensions["vault_store"].list_assets(1)[0]

    statuses = [
        client.post(
            f"/images/{asset.id}/decrypt", data=with_csrf(client, {"passphrase": "wrong-guess"})
        ).status_code
        for _ in range(4)
    ]
    assert statuses[-1] == 429
    assert 429 not in statuses[:-1]


def test_capability_links_are_throttled_per_address(tmp_path) -> None:
    app = make_app(tmp_path, LINK_RATE_LIMIT=2, LINK_RATE_WINDOW_SECONDS=600)
    client = app.test_client()
    statuses = [client.get(f"/l/guess{i}").status_code for i in range(3)]
    assert statuses == [404, 404, 429]


def test_a_zero_limit_disables_a_throttle(tmp_path) -> None:
    app = make_app(tmp_path, LINK_RATE_LIMIT=0)
    client = app.test_client()
    assert {client.get(f"/l/guess{i}").status_code for i in range(25)} == {404}


# --------------------------------------------------------------------------- #
# API token audience
# --------------------------------------------------------------------------- #


def _api_user(app):
    client = app.test_client()
    register(client, "apiuser")
    user = app.extensions["vault_store"].get_user_by_username("apiuser")
    return client, user


def test_issued_tokens_carry_and_honour_the_audience(tmp_path) -> None:
    app = make_app(tmp_path)
    client, _ = _api_user(app)
    token = client.post(
        "/api/token", json={"username": "apiuser", "password": PASSWORD}
    ).get_json()["token"]

    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == app.config["JWT_AUDIENCE"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/images", headers=headers).status_code == 200


@pytest.mark.parametrize("audience", [None, "some-other-service"])
def test_tokens_without_this_audience_are_refused(tmp_path, audience) -> None:
    """The README promised audience validation; tokens carried no aud and none
    was checked, so a token minted for another service sharing the key passed."""
    from datetime import datetime, timedelta, timezone

    app = make_app(tmp_path)
    client, user = _api_user(app)
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user.id),
        "iss": app.config["JWT_ISSUER"],
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "ver": user.token_version,
    }
    if audience:
        claims["aud"] = audience
    token = jwt.encode(claims, app.config["JWT_SECRET"], algorithm="HS256")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/images", headers=headers).status_code == 401


# --------------------------------------------------------------------------- #
# Response headers and health check
# --------------------------------------------------------------------------- #


def test_browser_isolation_headers_are_sent(tmp_path) -> None:
    response = make_app(tmp_path).test_client().get("/")
    assert "camera=()" in response.headers["Permissions-Policy"]
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_hsts_is_sent_only_over_https(tmp_path) -> None:
    client = make_app(tmp_path).test_client()
    assert "Strict-Transport-Security" not in client.get("/", base_url="http://localhost").headers
    secure = client.get("/", base_url="https://localhost")
    assert "max-age=" in secure.headers["Strict-Transport-Security"]


def test_healthz_reports_ok_without_detail(tmp_path) -> None:
    response = make_app(tmp_path).test_client().get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_healthz_reports_unavailable_when_the_database_is_gone(tmp_path) -> None:
    app = make_app(tmp_path)
    os.remove(app.config["DATABASE_PATH"])
    app.config["DATABASE_PATH"].mkdir()  # a directory cannot be opened as a database
    store = app.extensions["vault_store"]
    store.database_path = app.config["DATABASE_PATH"]

    response = app.test_client().get("/healthz")
    assert response.status_code == 503
    assert response.get_json() == {"status": "unavailable"}
