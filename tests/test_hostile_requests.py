"""Hostile or stale requests get clean answers, never HTTP 500 or a fake success.

Found in the inline review of the end-to-end code:

- Python's JSON decoder recurses once per nesting level, so ``"[" * 50000``
  raised RecursionError, which no route caught. ``/api/token`` needs no account.
- Routes that read a JSON body called ``.get()`` on whatever arrived, so a JSON
  list crashed them.
- An expired session made every end-to-end fetch() follow the login redirect to
  an HTML page with status 200, which the page then treated as success.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from helpers import (
    bearer_headers,
    browser_envelope,
    csrf_token,
    make_app,
    post_sealed,
    register,
)

from image_encryption_system.crypto import CryptoError, unpack_ies

DEEP = "[" * 50_000 + "]" * 50_000


@pytest.fixture()
def vault(tmp_path):
    # Exceptions become real 500 responses, as in production, instead of
    # propagating into the test.
    app = make_app(tmp_path, CSRF_ENABLED=True, PROPAGATE_EXCEPTIONS=False)
    alice = app.test_client()
    register(alice, "alice")
    metadata, ciphertext = browser_envelope(1)
    asset_id = post_sealed(alice, metadata, ciphertext).get_json()["asset_id"]
    return app, alice, asset_id


def _json_post(client, url, body, **headers):
    return client.post(url, data=body, content_type="application/json", headers=headers)


@pytest.mark.parametrize(
    "body", [DEEP, "[1]", '"text"', "7", "null"], ids=["deep", "list", "string", "number", "null"]
)
def test_api_token_answers_hostile_json_cleanly(vault, body) -> None:
    app, _alice, _asset = vault
    response = _json_post(app.test_client(), "/api/token", body)
    assert response.status_code in (400, 401)


@pytest.mark.parametrize("body", [DEEP, '["x"]'], ids=["deep", "list"])
def test_json_routes_answer_hostile_bodies_cleanly(vault, body) -> None:
    app, alice, asset_id = vault
    token = {"X-CSRF-Token": csrf_token(alice)}
    for url in (
        f"/images/{asset_id}/shares/sealed",
        f"/images/{asset_id}/links/sealed",
        f"/images/{asset_id}/rewrap",
    ):
        assert _json_post(alice, url, body, **token).status_code == 400, url
    bearer = bearer_headers(alice, "alice")
    for url in (f"/api/images/{asset_id}/share", f"/api/images/{asset_id}/link"):
        assert _json_post(alice, url, body, **bearer).status_code == 400, url


def test_a_deeply_nested_envelope_is_refused_cleanly(vault) -> None:
    _app, alice, _asset = vault
    data = {
        "csrf_token": csrf_token(alice),
        "envelope": DEEP[:60_000],
        "ciphertext": (io.BytesIO(b"x" * 64), "blob"),
    }
    response = alice.post("/images/sealed", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert "nested" in response.get_json()["error"]


def test_deeply_nested_kept_shares_are_refused_cleanly(vault) -> None:
    app, alice, asset_id = vault
    store = app.extensions["vault_store"]
    old = store.get_asset(asset_id)
    fresh, fresh_ciphertext = browser_envelope(1, asset=old.metadata["context"]["asset"])
    data = {
        "csrf_token": csrf_token(alice),
        "envelope": json.dumps(fresh),
        "shares": DEEP,
        "ciphertext": (io.BytesIO(fresh_ciphertext), "blob"),
    }
    response = alice.post(
        f"/images/{asset_id}/rekey", data=data, content_type="multipart/form-data"
    )
    assert response.status_code == 400
    assert store.read_ciphertext(store.get_asset(asset_id)) == store.read_ciphertext(old)


def test_a_backup_with_a_nested_manifest_is_refused_cleanly(vault) -> None:
    _app, alice, _asset = vault
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("manifest.json", DEEP)
    response = alice.post(
        "/restore",
        data={"csrf_token": csrf_token(alice), "backup": (io.BytesIO(archive.getvalue()), "b.zip")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"not valid JSON" in response.data


def test_an_ies_file_with_nested_metadata_raises_crypto_error() -> None:
    header = DEEP[:60_000].encode()
    blob = b"IES1" + len(header).to_bytes(4, "big") + header
    with pytest.raises(CryptoError):
        unpack_ies(blob)


# ---------------------------------------------------------------------------
# Expired sessions


def _expire(app) -> None:
    """What the idle timeout, a logout elsewhere, or a password change does."""
    app.extensions["vault_store"].delete_user_sessions(1)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/images/{id}/sealed"),
        ("get", "/images/{id}/envelope"),
        ("get", "/users/alice/public-key"),
        ("post", "/images/sealed"),
        ("post", "/images/{id}/rekey"),
        ("post", "/images/{id}/shares/sealed"),
        ("post", "/images/{id}/links/sealed"),
        ("post", "/images/{id}/rewrap"),
        ("post", "/account/private-key"),
    ],
)
def test_fetch_requests_after_the_session_ends_get_401_json_not_a_redirect(
    vault, method, path
) -> None:
    app, alice, asset_id = vault
    token = csrf_token(alice)
    _expire(app)
    url = path.format(id=asset_id)
    headers = {"Accept": "application/json", "X-CSRF-Token": token}
    response = getattr(alice, method)(url, headers=headers, data={"csrf_token": token})
    assert response.status_code == 401
    assert response.is_json
    assert "session" in response.get_json()["error"].lower()


def test_page_navigation_after_the_session_ends_still_redirects_to_sign_in(vault) -> None:
    app, alice, _asset = vault
    _expire(app)
    response = alice.get("/dashboard")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
