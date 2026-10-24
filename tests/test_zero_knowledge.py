"""End-to-end mode on the server side.

The browser seals images itself (``static/js/ies-crypto.js``); these tests send
the server envelopes of exactly that shape, built with crypto.py, and check
what it accepts, what it refuses, and that it never offers to unwrap a key it
was never given.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256
from io import BytesIO

import pytest
from cryptography.hazmat.primitives import serialization
from helpers import (
    PASSWORD,
    csrf_token,
    encrypt_png,
    make_app,
    raw_db,
    register,
    sample_png,
    with_csrf,
)

from image_encryption_system import crypto
from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    MIN_SCRYPT_N,
    RSA_HYBRID,
    decrypt_image_bytes,
    encrypt_image_bytes,
    load_private_key,
    unpack_ies,
    unwrap_data_key,
    wrap_data_key_passphrase,
    wrap_data_key_rsa,
)

IMAGE_PASS = "a browser-side passphrase"
NEW_PASS = "a rotated browser-side passphrase"


def browser_envelope(owner: int, *, algorithm=AES_GCM_PASSPHRASE, public_key=None, **context):
    """An envelope shaped exactly like ies-crypto.encryptImage's output."""
    sealed_context = {
        "owner": owner,
        "filename": "holiday.png",
        "mime": "image/png",
        "format": "PNG",
        "width": 80,
        "height": 48,
        "source": "browser",
        **context,
    }
    result = encrypt_image_bytes(
        sample_png(),
        algorithm,
        passphrase=IMAGE_PASS if algorithm == AES_GCM_PASSPHRASE else None,
        public_key_pem=public_key,
        context=sealed_context,
    )
    metadata = {**result.metadata, "ciphertext_sha256": sha256(result.ciphertext).hexdigest()}
    return metadata, result.ciphertext


def post_sealed(client, metadata, ciphertext, *, csrf: bool = True):
    data = {
        "envelope": json.dumps(metadata),
        "ciphertext": (BytesIO(ciphertext), "blob"),
    }
    if csrf:
        data["csrf_token"] = csrf_token(client)
    return client.post("/images/sealed", data=data, content_type="multipart/form-data")


def post_json(client, url, payload=None, *, csrf: bool = True):
    headers = {"X-CSRF-Token": csrf_token(client)} if csrf else {}
    return client.post(url, json=payload or {}, headers=headers)


@pytest.fixture()
def vault(tmp_path):
    app = make_app(tmp_path, CSRF_ENABLED=True)
    alice = app.test_client()
    bob = app.test_client()
    register(alice, "alice")
    register(bob, "bob")
    return app, alice, bob


def upload(client, owner=1, **kwargs):
    metadata, ciphertext = browser_envelope(owner, **kwargs)
    response = post_sealed(client, metadata, ciphertext)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["asset_id"], metadata, ciphertext


def test_a_browser_sealed_upload_is_stored_as_ciphertext_only(vault) -> None:
    app, alice, _bob = vault
    asset_id, metadata, ciphertext = upload(alice)
    store = app.extensions["vault_store"]
    asset = store.get_asset(asset_id)
    assert asset.end_to_end
    assert store.read_ciphertext(asset) == ciphertext
    assert asset.metadata["context"] == metadata["context"]
    assert (asset.image_format, asset.width, asset.height) == ("PNG", 80, 48)

    page = alice.get("/dashboard").get_data(as_text=True)
    assert "End-to-end" in page
    assert f'data-e2e-asset="{asset_id}"' in page
    listing = alice.get("/api/images", headers=_bearer(alice, "alice")).get_json()
    assert listing["images"][0]["end_to_end"] is True


def _bearer(client, username):
    token = client.post("/api/token", json={"username": username, "password": PASSWORD})
    return {"Authorization": f"Bearer {token.get_json()['token']}"}


def _mutate(path, value):
    def apply(metadata, ciphertext):
        target = metadata
        for key in path[:-1]:
            target = target[key]
        if value is _DELETE:
            del target[path[-1]]
        else:
            target[path[-1]] = value
        return metadata, ciphertext

    return apply


_DELETE = object()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_mutate(["context", "owner"], 2), "different account"),
        (_mutate(["context", "source"], "web"), "complete browser context"),
        (_mutate(["context", "width"], _DELETE), "complete browser context"),
        (_mutate(["context", "wrap"], "rsa-oaep-sha256"), "does not match the sealed algorithm"),
        (_mutate(["ciphertext_sha256"], "0" * 64), "integrity"),
        (_mutate(["ciphertext_sha256"], _DELETE), "integrity"),
        (_mutate(["key_wrap", "salt"], "AAAA"), "salt"),
        (_mutate(["key_wrap", "n"], 2**30), "Scrypt"),
        (_mutate(["unexpected"], 1), "unexpected fields"),
        (_mutate(["version"], 1), "version 3"),
        (lambda m, c: (m, c[:8]), "integrity|truncated"),
    ],
    ids=[
        "other-owner",
        "server-source",
        "partial-context",
        "wrap-mismatch",
        "bad-digest",
        "no-digest",
        "bad-salt",
        "hostile-kdf",
        "open-envelope",
        "legacy-version",
        "truncated",
    ],
)
def test_malformed_sealed_uploads_are_refused(vault, change, message) -> None:
    app, alice, _bob = vault
    metadata, ciphertext = change(*browser_envelope(1))
    if "ciphertext_sha256" in metadata and metadata["ciphertext_sha256"] != "0" * 64:
        metadata["ciphertext_sha256"] = sha256(ciphertext).hexdigest()
    response = post_sealed(alice, metadata, ciphertext)
    assert response.status_code == 400
    assert re.search(message, response.get_json()["error"])
    assert app.extensions["vault_store"].list_assets(1) == []


@pytest.mark.parametrize(
    ("context", "message"),
    [
        ({"format": "TIFF", "mime": "image/tiff"}, "not accepted"),
        ({"format": "SVG", "mime": "image/svg+xml"}, "not accepted"),
        ({"format": "PNG", "mime": "text/html"}, "not accepted"),
        ({"width": 100_000, "height": 100_000}, "too large"),
    ],
)
def test_only_displayable_allow_listed_images_are_accepted(vault, context, message) -> None:
    _app, alice, _bob = vault
    metadata, ciphertext = browser_envelope(1, **context)
    response = post_sealed(alice, metadata, ciphertext)
    assert response.status_code == 400
    assert message in response.get_json()["error"]


def test_sealed_upload_needs_a_csrf_token(vault) -> None:
    _app, alice, _bob = vault
    metadata, ciphertext = browser_envelope(1)
    assert post_sealed(alice, metadata, ciphertext, csrf=False).status_code == 400


@pytest.mark.production_kdf
def test_a_new_passphrase_wrap_cannot_be_cheaper_than_the_servers(vault) -> None:
    _app, alice, _bob = vault
    metadata, ciphertext = browser_envelope(1)
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=IMAGE_PASS)
    assert metadata["key_wrap"]["n"] == crypto.SCRYPT_N == 2**16
    with pytest.MonkeyPatch.context() as cheap:
        cheap.setattr(crypto, "SCRYPT_N", MIN_SCRYPT_N)
        metadata["key_wrap"] = wrap_data_key_passphrase(data_key, IMAGE_PASS)
    response = post_sealed(alice, metadata, ciphertext)
    assert response.status_code == 400
    assert "below this vault's cost" in response.get_json()["error"]


def test_a_reused_asset_id_never_overwrites_someone_elses_ciphertext(vault) -> None:
    app, alice, bob = vault
    asset_id, metadata, ciphertext = upload(alice)
    store = app.extensions["vault_store"]
    asset = store.get_asset(asset_id)

    # Bob seals his own image under Alice's asset id.
    forged, forged_ciphertext = browser_envelope(2, asset=metadata["context"]["asset"])
    response = post_sealed(bob, forged, forged_ciphertext)
    assert response.status_code == 400
    assert store.read_ciphertext(asset) == ciphertext

    # The store itself refuses even when the route's own check is bypassed.
    with pytest.raises(ValueError, match="already exists"):
        store.save_asset(
            user_id=2,
            original_filename="x.png",
            algorithm=AES_GCM_PASSPHRASE,
            mime_type="image/png",
            image_format="PNG",
            width=80,
            height=48,
            metadata=forged,
            ciphertext=forged_ciphertext,
            asset_uuid=metadata["context"]["asset"],
        )
    assert store.read_ciphertext(asset) == ciphertext


def test_server_side_routes_refuse_end_to_end_images_even_with_the_right_secret(vault) -> None:
    app, alice, _bob = vault
    asset_id, _metadata, _ciphertext = upload(alice)
    attempts = [
        (f"/images/{asset_id}/decrypt", {"passphrase": IMAGE_PASS}),
        (f"/images/{asset_id}/share", {"username": "bob", "passphrase": IMAGE_PASS}),
        (f"/images/{asset_id}/link", {"passphrase": IMAGE_PASS}),
        (
            f"/images/{asset_id}/rotate-passphrase",
            {"old_passphrase": IMAGE_PASS, "new_passphrase": NEW_PASS},
        ),
    ]
    for url, form in attempts:
        response = alice.post(url, data=with_csrf(alice, form), follow_redirects=True)
        assert b"end-to-end encrypted" in response.data, url

    headers = _bearer(alice, "alice")
    for url, body in [
        (f"/api/images/{asset_id}/share", {"username": "bob", "passphrase": IMAGE_PASS}),
        (f"/api/images/{asset_id}/link", {"passphrase": IMAGE_PASS}),
    ]:
        response = alice.post(url, json=body, headers=headers)
        assert response.status_code == 400
        assert "end-to-end encrypted" in response.get_json()["error"]

    store = app.extensions["vault_store"]
    assert store.list_recipients_for_owner(1) == {}
    assert store.list_link_shares_for_owner(1) == {}
    actions = {event.action for event in store.list_audit_events(1)}
    assert not actions & {"decrypt", "share", "link", "rotate"}


def test_sealed_ciphertext_is_served_only_with_the_callers_own_wrap(vault) -> None:
    app, alice, bob = vault
    asset_id, metadata, ciphertext = upload(alice)

    owner_copy = alice.get(f"/images/{asset_id}/sealed")
    assert owner_copy.status_code == 200
    assert owner_copy.headers["Cache-Control"] == "no-store"
    blob_ciphertext, blob_metadata = unpack_ies(owner_copy.data)
    assert blob_ciphertext == ciphertext
    assert decrypt_image_bytes(blob_ciphertext, blob_metadata, passphrase=IMAGE_PASS) == (
        sample_png()
    )

    assert bob.get(f"/images/{asset_id}/sealed").status_code == 403
    assert alice.get("/images/999/sealed").status_code == 404
    events = [event.action for event in app.extensions["vault_store"].list_audit_events(1)]
    assert "fetch" in events


def _bob_wrap(app, metadata):
    store = app.extensions["vault_store"]
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=IMAGE_PASS)
    return wrap_data_key_rsa(data_key, store.read_public_key(2))


def test_a_browser_made_share_opens_for_the_recipient_only(vault) -> None:
    app, alice, bob = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _ciphertext = upload(alice)

    lookup = alice.get("/users/BOB/public-key")
    assert lookup.status_code == 200
    assert lookup.get_json()["public_key"] == store.read_public_key(2).decode()
    assert alice.get("/users/nobody/public-key").status_code == 404

    response = post_json(
        alice,
        f"/images/{asset_id}/shares/sealed",
        {"username": "bob", "key_wrap": _bob_wrap(app, metadata), "expires_hours": 2},
    )
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["username"] == "bob"
    assert response.get_json()["expires_at"]

    shared = bob.get(f"/images/{asset_id}/sealed")
    assert shared.status_code == 200
    blob_ciphertext, blob_metadata = unpack_ies(shared.data)
    assert blob_metadata["key_wrap"]["type"] == "rsa-oaep-sha256"
    private_key = store.read_private_key(2)
    assert load_private_key(private_key, PASSWORD, owner=2)
    assert (
        decrypt_image_bytes(
            blob_ciphertext,
            blob_metadata,
            private_key_pem=private_key,
            private_key_passphrase=PASSWORD,
        )
        == sample_png()
    )

    # Once the share has expired, the recipient gets nothing.
    with raw_db(app.config["INSTANCE_DIR"]) as db:
        db.execute("UPDATE shares SET expires_at = '2000-01-01T00:00:00+00:00'")
    assert bob.get(f"/images/{asset_id}/sealed").status_code == 403


@pytest.mark.parametrize(
    ("payload", "status", "message"),
    [
        ({"username": "bob", "key_wrap": "bob-wrap-scrypt"}, 400, "recipient's public key"),
        (
            {"username": "bob", "key_wrap": {"type": "rsa-oaep-sha256", "wrapped_key": "AAAA"}},
            400,
            "length",
        ),
        ({"username": "alice", "key_wrap": "bob-wrap"}, 400, "already own"),
        ({"username": "carol", "key_wrap": "bob-wrap"}, 404, "No account"),
        (
            {"username": "bob", "key_wrap": "bob-wrap", "expires_hours": -1},
            400,
            "greater than zero",
        ),
    ],
    ids=["wrong-wrap-type", "short-wrap", "self", "unknown", "bad-expiry"],
)
def test_browser_made_shares_are_validated(vault, payload, status, message) -> None:
    app, alice, _bob = vault
    asset_id, metadata, _ciphertext = upload(alice)
    if payload["key_wrap"] == "bob-wrap":
        payload["key_wrap"] = _bob_wrap(app, metadata)
    elif payload["key_wrap"] == "bob-wrap-scrypt":
        payload["key_wrap"] = metadata["key_wrap"]
    response = post_json(alice, f"/images/{asset_id}/shares/sealed", payload)
    assert response.status_code == status
    assert message in response.get_json()["error"]


def test_only_the_owner_of_an_end_to_end_image_can_share_link_or_rotate_it(vault) -> None:
    app, alice, bob = vault
    asset_id, metadata, _ciphertext = upload(alice)
    wrap = _bob_wrap(app, metadata)
    for url, payload in [
        (f"/images/{asset_id}/shares/sealed", {"username": "alice", "key_wrap": wrap}),
        (f"/images/{asset_id}/links/sealed", {"key_wrap": metadata["key_wrap"]}),
        (f"/images/{asset_id}/rewrap", {"key_wrap": metadata["key_wrap"]}),
    ]:
        assert post_json(bob, url, payload).status_code == 403, url
        assert post_json(alice, url, payload, csrf=False).status_code == 400, url


def test_server_mode_images_are_not_shared_through_the_sealed_routes(vault) -> None:
    app, alice, _bob = vault
    encrypt_png(alice, passphrase=IMAGE_PASS)
    asset = app.extensions["vault_store"].list_assets(1)[0]
    assert not asset.end_to_end
    data_key = unwrap_data_key(asset.metadata["key_wrap"], passphrase=IMAGE_PASS)
    wrap = wrap_data_key_rsa(data_key, app.extensions["vault_store"].read_public_key(2))
    response = post_json(
        alice, f"/images/{asset.id}/shares/sealed", {"username": "bob", "key_wrap": wrap}
    )
    assert response.status_code == 400
    assert "encrypted on the server" in response.get_json()["error"]


def _link_wrap(metadata, secret: str):
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=IMAGE_PASS)
    return wrap_data_key_passphrase(data_key, secret)


def test_an_end_to_end_link_keeps_its_key_in_the_fragment(vault) -> None:
    app, alice, _bob = vault
    asset_id, metadata, ciphertext = upload(alice)
    secret = "fragment-secret-" + "k" * 27
    response = post_json(
        alice,
        f"/images/{asset_id}/links/sealed",
        {"key_wrap": _link_wrap(metadata, secret), "max_downloads": 1, "label": "printer"},
    )
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert "#" not in body["url"]
    path = body["url"].split("://", 1)[1].split("/", 1)[1]

    stranger = app.test_client()
    page = stranger.get(f"/{path}").get_data(as_text=True)
    assert "data-e2e-link" in page
    assert "Decrypt and download" not in page  # no server-side decrypt form

    # The server-side decrypt path is refused and does not spend the download.
    refused = stranger.post(f"/{path}/decrypt")
    assert refused.status_code == 400
    assert "end-to-end encrypted" in refused.get_json()["error"]

    blob = stranger.get(f"/{path}/blob")
    assert blob.status_code == 200
    blob_ciphertext, blob_metadata = unpack_ies(blob.data)
    assert blob_ciphertext == ciphertext
    assert decrypt_image_bytes(blob_ciphertext, blob_metadata, passphrase=secret) == sample_png()
    assert stranger.get(f"/{path}/blob").status_code == 403  # download cap of one


@pytest.mark.production_kdf
def test_link_wraps_may_use_the_kdf_floor_because_their_secret_is_random(vault) -> None:
    app, alice, _bob = vault
    metadata, ciphertext = browser_envelope(1)
    asset_id = post_sealed(alice, metadata, ciphertext).get_json()["asset_id"]
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=IMAGE_PASS)
    with pytest.MonkeyPatch.context() as cheap:
        cheap.setattr(crypto, "SCRYPT_N", MIN_SCRYPT_N)
        wrap = wrap_data_key_passphrase(data_key, "random link secret value")
    response = post_json(alice, f"/images/{asset_id}/links/sealed", {"key_wrap": wrap})
    assert response.status_code == 200
    rsa_wrap = _bob_wrap(app, metadata)
    response = post_json(alice, f"/images/{asset_id}/links/sealed", {"key_wrap": rsa_wrap})
    assert response.status_code == 400


def test_rewrap_replaces_the_passphrase_wrap(vault) -> None:
    app, alice, _bob = vault
    asset_id, metadata, _ciphertext = upload(alice)
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=IMAGE_PASS)
    response = post_json(
        alice,
        f"/images/{asset_id}/rewrap",
        {"key_wrap": wrap_data_key_passphrase(data_key, NEW_PASS)},
    )
    assert response.status_code == 200
    stored = app.extensions["vault_store"].get_asset(asset_id).metadata
    assert unwrap_data_key(stored["key_wrap"], passphrase=NEW_PASS) == data_key
    with pytest.raises(crypto.CryptoError):
        unwrap_data_key(stored["key_wrap"], passphrase=IMAGE_PASS)

    rsa_id, rsa_metadata, _ = upload(
        alice,
        algorithm=RSA_HYBRID,
        public_key=app.extensions["vault_store"].read_public_key(1),
    )
    response = post_json(alice, f"/images/{rsa_id}/rewrap", {"key_wrap": stored["key_wrap"]})
    assert response.status_code == 400


def test_the_sealed_private_key_is_handed_out_only_to_its_owner(vault) -> None:
    app, alice, _bob = vault
    store = app.extensions["vault_store"]
    response = post_json(alice, "/account/private-key")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.get_json()
    assert body["owner"] == 1
    assert body["private_key"]["format"] == "ies-private-key"
    assert crypto.canonical_json(body["private_key"]) == store.read_private_key(1)
    assert post_json(alice, "/account/private-key", csrf=False).status_code == 400
    assert app.test_client().post("/account/private-key").status_code in (302, 400)

    # A key still in the legacy format must be upgraded at sign-in first.
    key = load_private_key(store.read_private_key(1), PASSWORD)
    store.private_key_path(1).unlink()
    store.legacy_private_key_path(1).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSWORD.encode()),
        )
    )
    response = post_json(alice, "/account/private-key")
    assert response.status_code == 409
    assert "Sign out and back in" in response.get_json()["error"]


def test_private_key_requests_are_throttled(tmp_path) -> None:
    app = make_app(tmp_path, DECRYPT_RATE_LIMIT=2)
    alice = app.test_client()
    register(alice, "alice")
    assert [post_json(alice, "/account/private-key").status_code for _ in range(3)] == [
        200,
        200,
        429,
    ]


def test_end_to_end_images_survive_backup_and_restore(vault) -> None:
    app, alice, _bob = vault
    asset_id, _metadata, ciphertext = upload(alice)
    archive = alice.get("/backup").data
    store = app.extensions["vault_store"]
    store.delete_asset(asset_id, 1)
    restored = alice.post(
        "/restore",
        data=with_csrf(alice, {"backup": (BytesIO(archive), "backup.zip")}),
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"Restored 1 encrypted image" in restored.data
    asset = store.list_assets(1)[0]
    assert asset.end_to_end
    assert store.read_ciphertext(asset) == ciphertext


def test_account_page_shows_the_key_fingerprint(vault) -> None:
    app, alice, _bob = vault
    page = alice.get("/account/password").get_data(as_text=True)
    fingerprint = crypto.public_key_fingerprint(app.extensions["vault_store"].read_public_key(1))
    assert fingerprint in page


def test_a_plain_upload_that_claims_end_to_end_mode_stores_nothing(vault) -> None:
    app, alice, _bob = vault
    response = alice.post(
        "/images",
        data=with_csrf(
            alice,
            {
                "mode": "browser",
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": IMAGE_PASS,
                "image": (BytesIO(sample_png()), "secret.png"),
            },
        ),
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"End-to-end encryption did not run" in response.data
    assert app.extensions["vault_store"].list_assets(1) == []
