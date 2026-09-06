"""Coverage for the v3.0.0 defence-in-depth work.

Each test here pins a gap that existed in 2.3.0: the browser-side controls were
absent entirely, the signing secret had a published fallback, the metadata
version constant was declared but never consulted, the Scrypt floor was welded
to the current default, and throttling stopped at the login form.
"""

import pytest
from helpers import PASSWORD, encrypt_png, make_app, register, with_csrf

from image_encryption_system.config import KNOWN_INSECURE_SECRETS
from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    MIN_SCRYPT_N,
    SCRYPT_N,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
)
from image_encryption_system.security import (
    PasswordPolicyError,
    RequestThrottle,
    validate_password,
)
from image_encryption_system.storage import VaultStore

# --------------------------------------------------------------------------
# Security response headers
# --------------------------------------------------------------------------


def test_every_response_carries_the_browser_side_controls(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    response = client.get("/")

    csp = response.headers["Content-Security-Policy"]
    # No inline allowance: the dashboard and auth scripts are same-origin files
    # precisely so this can stay strict.
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "camera=()" in response.headers["Permissions-Policy"]
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_hsts_is_asserted_only_over_https(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()

    plain = client.get("/", base_url="http://localhost")
    assert "Strict-Transport-Security" not in plain.headers

    secure = client.get("/", base_url="https://localhost")
    assert "max-age=" in secure.headers["Strict-Transport-Security"]


def test_decrypted_image_is_never_cacheable(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "cacher")

    assert encrypt_png(client, passphrase="vault-passphrase").status_code == 200

    response = client.post(
        "/images/1/decrypt",
        data=with_csrf(client, {"passphrase": "vault-passphrase"}),
    )
    assert response.status_code == 200
    # send_file otherwise labels this like a static asset, which would let a
    # proxy or the browser's disk cache retain decrypted plaintext.
    assert "no-store" in response.headers["Cache-Control"]
    assert response.headers["Pragma"] == "no-cache"


def test_backup_and_public_key_downloads_are_not_cacheable(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "archivist")

    for path in ("/backup", "/account/public-key"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "no-store" in response.headers["Cache-Control"], path


def test_ordinary_pages_stay_cacheable(tmp_path) -> None:
    app = make_app(tmp_path)
    response = app.test_client().get("/")
    assert "no-store" not in response.headers.get("Cache-Control", "")


# --------------------------------------------------------------------------
# Session cookie
# --------------------------------------------------------------------------


def test_session_cookie_is_hardened(tmp_path) -> None:
    app = make_app(tmp_path)
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    client = app.test_client()
    register(client, "cookieuser")
    client.post("/logout", data=with_csrf(client))

    response = client.post(
        "/login",
        data=with_csrf(client, {"username": "cookieuser", "password": PASSWORD}),
    )
    header = response.headers.get("Set-Cookie", "")

    assert "ies_session=" in header
    assert "HttpOnly" in header
    assert "SameSite=Lax" in header


def test_secure_cookie_defaults_on_outside_testing(tmp_path) -> None:
    # TESTING forces the flag off so the test client (plain HTTP) keeps working;
    # the production default is what matters.
    from image_encryption_system.config import Config

    assert Config.SESSION_COOKIE_SECURE is True
    assert make_app(tmp_path).config["SESSION_COOKIE_SECURE"] is False


# --------------------------------------------------------------------------
# Signing secret
# --------------------------------------------------------------------------


def test_app_refuses_to_boot_on_a_published_secret(tmp_path) -> None:
    for secret in list(KNOWN_INSECURE_SECRETS)[:3]:
        with pytest.raises(RuntimeError, match="publicly known"):
            make_app(tmp_path, TESTING=False, SECRET_KEY=secret)


def test_app_refuses_a_short_secret(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="at least 32"):
        make_app(tmp_path, TESTING=False, SECRET_KEY="too-short")


def test_generated_secret_is_random_and_persisted(tmp_path, monkeypatch) -> None:
    from image_encryption_system.config import load_or_create_secret_key

    monkeypatch.delenv("SECRET_KEY", raising=False)
    first = load_or_create_secret_key(tmp_path)
    second = load_or_create_secret_key(tmp_path)

    assert len(first) >= 32
    assert first not in KNOWN_INSECURE_SECRETS
    # Stable across calls, or every restart would log everyone out.
    assert first == second
    assert (tmp_path / "secret.key").read_text().strip() == first

    other = load_or_create_secret_key(tmp_path / "elsewhere")
    assert other != first


# --------------------------------------------------------------------------
# Envelope metadata version
# --------------------------------------------------------------------------


def test_unsupported_metadata_version_is_refused() -> None:
    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase="pass-phrase-1")

    hostile = dict(result.metadata)
    hostile["version"] = 99

    with pytest.raises(CryptoError, match="Unsupported encrypted image metadata version"):
        decrypt_image_bytes(result.ciphertext, hostile, passphrase="pass-phrase-1")


def test_non_numeric_metadata_version_is_refused() -> None:
    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase="pass-phrase-1")
    hostile = dict(result.metadata)
    hostile["version"] = {"nested": "object"}

    with pytest.raises(CryptoError, match="invalid version"):
        decrypt_image_bytes(result.ciphertext, hostile, passphrase="pass-phrase-1")


def test_supported_versions_still_decrypt() -> None:
    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase="pass-phrase-1")
    for version in (1, 2):
        metadata = dict(result.metadata)
        metadata["version"] = version
        plaintext = decrypt_image_bytes(result.ciphertext, metadata, passphrase="pass-phrase-1")
        assert plaintext == b"pixels"


# --------------------------------------------------------------------------
# Scrypt cost ladder
# --------------------------------------------------------------------------


def test_default_cost_is_above_the_acceptance_floor() -> None:
    # The whole point of separating them: the default can be raised without
    # rejecting anything already written.
    assert SCRYPT_N > MIN_SCRYPT_N


def test_files_wrapped_at_the_old_default_still_decrypt() -> None:
    """A vault written before the cost was raised must keep opening.

    Before this release the validator rejected anything below the *current*
    default, so raising the default would have bricked every existing file.
    """
    from image_encryption_system.crypto import _wrap_key_with_passphrase, unwrap_data_key

    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase="pass-phrase-1")
    legacy = dict(result.metadata)

    # Re-wrap the same data key at the historical cost, the way an older release
    # would have written it.
    data_key = unwrap_data_key(result.metadata["key_wrap"], passphrase="pass-phrase-1")
    legacy_wrap = _wrap_key_with_passphrase(data_key, "pass-phrase-1", n=MIN_SCRYPT_N)

    assert legacy_wrap["n"] == MIN_SCRYPT_N
    legacy["key_wrap"] = legacy_wrap
    assert decrypt_image_bytes(result.ciphertext, legacy, passphrase="pass-phrase-1") == b"pixels"


def test_cost_below_the_floor_is_still_rejected() -> None:
    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase="pass-phrase-1")
    weakened = dict(result.metadata)
    weakened["key_wrap"] = {**result.metadata["key_wrap"], "n": 1024}

    with pytest.raises(CryptoError, match="outside the supported range"):
        decrypt_image_bytes(result.ciphertext, weakened, passphrase="pass-phrase-1")


# --------------------------------------------------------------------------
# Password policy
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password, reason",
    [
        ("short", "at least"),
        ("aaaaaaaaaaaa", "five different"),
        ("password123", "too common"),
        ("", "required"),
    ],
)
def test_policy_rejects_weak_passwords(password: str, reason: str) -> None:
    with pytest.raises(PasswordPolicyError, match=reason):
        validate_password(password)


def test_policy_rejects_a_password_containing_the_username() -> None:
    with pytest.raises(PasswordPolicyError, match="username"):
        validate_password("SebastianForbes99", username="sebastianforbes")


def test_policy_accepts_a_reasonable_passphrase() -> None:
    validate_password("correct horse battery", username="rider")


def test_registration_rejects_a_weak_password(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    response = register(client, "weakling", password="aaaaaaaaaaaa")

    assert b"five different" in response.data
    store: VaultStore = app.extensions["vault_store"]
    assert store.count_users() == 0


def test_password_rotation_cannot_bypass_the_policy(tmp_path) -> None:
    """Rotation is the obvious way around a registration-only policy."""
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

    # The old password must still work, i.e. nothing was changed.
    client.post("/logout", data=with_csrf(client))
    login = client.post(
        "/login",
        data=with_csrf(client, {"username": "rotator", "password": PASSWORD}),
        follow_redirects=True,
    )
    assert login.status_code == 200


# --------------------------------------------------------------------------
# Throttling beyond the login form
# --------------------------------------------------------------------------


def test_request_throttle_bounds_a_window_and_survives_a_new_instance(tmp_path) -> None:
    store = VaultStore(tmp_path / "db.sqlite3", tmp_path / "vault", tmp_path / "keys")
    store.init()

    throttle = RequestThrottle(store, "throttle:test", limit=3, window_seconds=600)
    assert [throttle.allow("1.2.3.4") for _ in range(4)] == [True, True, True, False]

    # A different key has its own budget.
    assert throttle.allow("5.6.7.8") is True

    # Counters live in the database, so a restart does not reset them.
    revived = RequestThrottle(store, "throttle:test", limit=3, window_seconds=600)
    assert revived.allow("1.2.3.4") is False


def test_registration_is_throttled(tmp_path) -> None:
    """Registration mints an RSA-3072 key pair, so it is a CPU amplifier."""
    app = make_app(tmp_path, REGISTER_RATE_LIMIT=2, REGISTER_RATE_WINDOW_SECONDS=600)
    client = app.test_client()

    assert register(client, "first").status_code in (200, 302)
    client.post("/logout", data=with_csrf(client))
    assert register(client, "second").status_code in (200, 302)
    client.post("/logout", data=with_csrf(client))

    blocked = register(client, "third")
    assert blocked.status_code == 429

    store: VaultStore = app.extensions["vault_store"]
    assert store.count_users() == 2


def test_decrypt_attempts_are_throttled(tmp_path) -> None:
    app = make_app(tmp_path, DECRYPT_RATE_LIMIT=3, DECRYPT_RATE_WINDOW_SECONDS=600)
    client = app.test_client()
    register(client, "guessed")

    encrypt_png(client, passphrase="vault-passphrase")

    statuses = [
        client.post(
            "/images/1/decrypt",
            data=with_csrf(client, {"passphrase": "wrong-guess"}),
        ).status_code
        for _ in range(4)
    ]
    assert statuses[-1] == 429


def test_capability_links_are_throttled(tmp_path) -> None:
    app = make_app(tmp_path, LINK_RATE_LIMIT=2, LINK_RATE_WINDOW_SECONDS=600)
    client = app.test_client()

    # Unauthenticated token guessing must be bounded even though these routes
    # deliberately skip CSRF.
    statuses = [client.get(f"/l/guess{i}").status_code for i in range(3)]
    assert statuses[-1] == 429


# --------------------------------------------------------------------------
# Health check
# --------------------------------------------------------------------------


def test_healthz_reports_ok_without_leaking_detail(tmp_path) -> None:
    app = make_app(tmp_path)
    response = app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
