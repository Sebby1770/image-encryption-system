"""Coverage for the v3.1 authentication hardening.

Each test pins a gap found by measuring or probing 3.0.0: unknown usernames
answered ~25x faster than known ones, API tokens accepted with claims missing,
sessions and API tokens were signed with the same key, and a session kept warm
by activity never expired.
"""

import time
from datetime import datetime, timedelta, timezone
from statistics import median

import jwt
from helpers import PASSWORD, make_app, register, with_csrf

from image_encryption_system.config import derive_jwt_secret

# --------------------------------------------------------------------------
# Username enumeration by timing
# --------------------------------------------------------------------------


def test_unknown_username_costs_the_same_hash_work_as_a_known_one(tmp_path) -> None:
    app = make_app(tmp_path, LOGIN_RATE_LIMIT=10_000, LOGIN_LOCKOUT_THRESHOLD=10_000)
    store = app.extensions["vault_store"]
    store.create_user("realclerk", PASSWORD)

    def timed(username: str) -> float:
        start = time.perf_counter()
        assert store.authenticate_user(username, "wrong-password-x") is None
        return time.perf_counter() - start

    timed("warmup")  # the dummy hash is built lazily on first use
    known = median(timed("realclerk") for _ in range(9))
    unknown = median(timed(f"ghost{i}") for i in range(9))

    # Before the fix the unknown path skipped hashing entirely and ran ~25x
    # faster. Equal work should land well inside a factor of two.
    assert unknown > known * 0.5, f"unknown {unknown * 1000:.1f}ms vs known {known * 1000:.1f}ms"


def test_valid_credentials_still_authenticate(tmp_path) -> None:
    app = make_app(tmp_path)
    store = app.extensions["vault_store"]
    store.create_user("owner", PASSWORD)
    assert store.authenticate_user("owner", PASSWORD) is not None
    assert store.authenticate_user("OWNER ", PASSWORD) is not None
    assert store.authenticate_user("owner", "nope-nope-nope") is None


# --------------------------------------------------------------------------
# API token claims
# --------------------------------------------------------------------------


def _token(app, **claims) -> str:
    return jwt.encode(claims, app.config["JWT_SECRET"], algorithm="HS256")


def _full_claims(app, user) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "sub": str(user.id),
        "iss": app.config["JWT_ISSUER"],
        "aud": app.config["JWT_AUDIENCE"],
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "ver": user.token_version,
    }


def test_issued_tokens_carry_an_audience_and_are_accepted(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "apiuser")
    client.post("/logout", data=with_csrf(client))

    issued = client.post("/api/token", json={"username": "apiuser", "password": PASSWORD})
    token = issued.get_json()["token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == app.config["JWT_AUDIENCE"]

    response = client.get("/api/images", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_each_required_claim_is_enforced(tmp_path) -> None:
    """A signed token missing any claim the API depends on must be refused.

    PyJWT validates exp and aud only when present, so without `require` a token
    lacking them never expires and is accepted by any audience; one lacking
    `ver` defaulted to version 1 and outlived a password change.
    """
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "claimer")
    user = app.extensions["vault_store"].get_user_by_username("claimer")

    ok = _token(app, **_full_claims(app, user))
    assert client.get("/api/images", headers={"Authorization": f"Bearer {ok}"}).status_code == 200

    for claim in ("exp", "iat", "iss", "aud", "sub", "ver"):
        claims = _full_claims(app, user)
        del claims[claim]
        bad = _token(app, **claims)
        status = client.get("/api/images", headers={"Authorization": f"Bearer {bad}"}).status_code
        assert status == 401, f"token without {claim} was accepted"


def test_token_for_another_audience_is_refused(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "aud-user")
    user = app.extensions["vault_store"].get_user_by_username("aud-user")

    claims = _full_claims(app, user)
    claims["aud"] = "some-other-service"
    token = _token(app, **claims)
    assert (
        client.get("/api/images", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    )


def test_api_tokens_are_not_signed_with_the_session_key(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("JWT_SECRET", raising=False)
    secret = "a-session-secret-that-is-long-enough-for-the-check"
    derived = derive_jwt_secret(secret)

    assert derived != secret
    assert derived == derive_jwt_secret(secret), "derivation must be stable across restarts"
    assert derive_jwt_secret(secret + "x") != derived


# --------------------------------------------------------------------------
# Absolute session lifetime
# --------------------------------------------------------------------------


def test_active_session_still_expires_at_the_absolute_limit(tmp_path) -> None:
    app = make_app(tmp_path, SESSION_ABSOLUTE_SECONDS=3600, SESSION_IDLE_SECONDS=1800)
    client = app.test_client()
    register(client, "marathon")

    assert client.get("/dashboard").status_code == 200

    # Kept warm by activity (last_seen is fresh), but issued long ago.
    with client.session_transaction() as sess:
        sess["issued_at"] = time.time() - 3601
        sess["last_seen"] = time.time()

    response = client.get("/dashboard")
    assert response.status_code == 302
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_session_without_an_issue_time_is_not_granted_forever(tmp_path) -> None:
    app = make_app(tmp_path, SESSION_ABSOLUTE_SECONDS=3600)
    client = app.test_client()
    register(client, "legacy")

    with client.session_transaction() as sess:
        sess.pop("issued_at", None)

    assert client.get("/dashboard").status_code == 302


def test_fresh_session_is_unaffected(tmp_path) -> None:
    app = make_app(tmp_path, SESSION_ABSOLUTE_SECONDS=3600)
    client = app.test_client()
    register(client, "fresh")
    assert client.get("/dashboard").status_code == 200
