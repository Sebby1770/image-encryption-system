"""Re-keying end-to-end images, so that revoking a share really cuts it off.

Revoking deletes a recipient's wrap, but a recipient who kept the data key
could still decrypt the stored ciphertext if they ever got it again (a later
link, a leaked backup, a breached server). Re-keying re-encrypts the image in
the owner's browser under a fresh key, keeps only the shares the owner chooses
(with new wraps), and invalidates every link.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from hashlib import sha256
from io import BytesIO

import pytest
from helpers import (
    BROWSER_PASS,
    PASSWORD,
    browser_envelope,
    csrf_token,
    encrypt_png,
    make_app,
    post_json,
    post_sealed,
    raw_db,
    register,
    sample_png,
)

from image_encryption_system import storage
from image_encryption_system.crypto import (
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
    unpack_ies,
    unwrap_data_key,
    wrap_data_key_passphrase,
    wrap_data_key_rsa,
)


@pytest.fixture()
def vault(tmp_path):
    app = make_app(tmp_path, CSRF_ENABLED=True)
    clients = {}
    for name in ("alice", "bob", "carol"):
        clients[name] = app.test_client()
        register(clients[name], name)
    return app, clients


def _share(app, client, asset_id, metadata, recipient_id, username):
    store = app.extensions["vault_store"]
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=BROWSER_PASS)
    wrap = wrap_data_key_rsa(data_key, store.read_public_key(recipient_id))
    response = post_json(
        client, f"/images/{asset_id}/shares/sealed", {"username": username, "key_wrap": wrap}
    )
    assert response.status_code == 200, response.get_json()


def _shared_vault(vault):
    """Alice's image, shared with Bob and Carol and published as a link."""
    app, clients = vault
    metadata, ciphertext = browser_envelope(1)
    response = post_sealed(clients["alice"], metadata, ciphertext)
    asset_id = response.get_json()["asset_id"]
    _share(app, clients["alice"], asset_id, metadata, 2, "bob")
    _share(app, clients["alice"], asset_id, metadata, 3, "carol")
    data_key = unwrap_data_key(metadata["key_wrap"], passphrase=BROWSER_PASS)
    link = post_json(
        clients["alice"],
        f"/images/{asset_id}/links/sealed",
        {"key_wrap": wrap_data_key_passphrase(data_key, "link secret value 1234567890")},
    ).get_json()
    return asset_id, metadata, data_key, link


def _rekeyed(metadata, **context_changes):
    """A fresh envelope for the same image and sealed context: new key, new nonce."""
    context = {**metadata["context"], **context_changes}
    result = encrypt_image_bytes(
        sample_png(), metadata["algorithm"], passphrase=BROWSER_PASS, context=context
    )
    new_metadata = {**result.metadata, "ciphertext_sha256": sha256(result.ciphertext).hexdigest()}
    data_key = unwrap_data_key(new_metadata["key_wrap"], passphrase=BROWSER_PASS)
    return new_metadata, result.ciphertext, data_key


def post_rekey(client, asset_id, metadata, ciphertext, shares=(), *, csrf=True):
    data = {
        "envelope": json.dumps(metadata),
        "ciphertext": (BytesIO(ciphertext), "blob"),
        "shares": json.dumps(list(shares)),
    }
    if csrf:
        data["csrf_token"] = csrf_token(client)
    return client.post(f"/images/{asset_id}/rekey", data=data, content_type="multipart/form-data")


def test_rekey_cuts_off_dropped_recipients_and_links(vault) -> None:
    app, clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, old_key, link = _shared_vault(vault)
    new_metadata, new_ciphertext, new_key = _rekeyed(metadata)
    bob_wrap = wrap_data_key_rsa(new_key, store.read_public_key(2))

    response = post_rekey(
        clients["alice"],
        asset_id,
        new_metadata,
        new_ciphertext,
        [{"username": "bob", "key_wrap": bob_wrap}],
    )
    assert response.status_code == 200, response.get_json()
    assert response.get_json() == {"ok": True, "kept": ["bob"], "links_revoked": 1}

    asset = store.get_asset(asset_id)
    assert store.read_ciphertext(asset) == new_ciphertext
    assert asset.metadata["key_wrap"] == new_metadata["key_wrap"]
    assert asset.end_to_end

    # Whoever kept the old data key can no longer open what is stored.
    with pytest.raises(CryptoError):
        decrypt_image_bytes(
            store.read_ciphertext(asset),
            {**asset.metadata, "key_wrap": metadata["key_wrap"]},
            passphrase=BROWSER_PASS,
        )
    assert old_key != new_key

    # Bob was kept and opens the new ciphertext with his own key...
    sealed = clients["bob"].get(f"/images/{asset_id}/sealed")
    assert sealed.status_code == 200
    blob_ciphertext, blob_metadata = unpack_ies(sealed.data)
    assert (
        decrypt_image_bytes(
            blob_ciphertext,
            blob_metadata,
            private_key_pem=store.read_private_key(2),
            private_key_passphrase=PASSWORD,
        )
        == sample_png()
    )
    # ...Carol was dropped, and the link is gone.
    assert clients["carol"].get(f"/images/{asset_id}/sealed").status_code == 403
    path = link["url"].split("://", 1)[1].split("/", 1)[1]
    assert app.test_client().get(f"/{path}/blob").status_code == 404
    assert "rekey" in [event.action for event in store.list_audit_events(1)]


def test_rekey_keeps_a_kept_shares_expiry(vault) -> None:
    app, clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    with raw_db(app.config["INSTANCE_DIR"]) as db:
        db.execute(
            "UPDATE shares SET expires_at = '2999-01-01T00:00:00+00:00' WHERE recipient_user_id = 2"
        )
    new_metadata, new_ciphertext, new_key = _rekeyed(metadata)
    wrap = wrap_data_key_rsa(new_key, store.read_public_key(2))
    response = post_rekey(
        clients["alice"],
        asset_id,
        new_metadata,
        new_ciphertext,
        [{"username": "bob", "key_wrap": wrap}],
    )
    assert response.status_code == 200
    share = store.get_share(asset_id, 2)
    assert share is not None
    assert share.expires_at == "2999-01-01T00:00:00+00:00"
    assert share.key_wrap == wrap


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda m, c: ({**m, "context": {**m["context"], "asset": "f" * 32}}, c),
            "same sealed context",
        ),
        (lambda m, c: ({**m, "context": {**m["context"], "width": 81}}, c), "same sealed context"),
        (
            lambda m, c: ({**m, "context": {**m["context"], "filename": "other.png"}}, c),
            "same sealed context",
        ),
        (lambda m, c: ({**m, "ciphertext_sha256": "0" * 64}, c), "integrity"),
    ],
    ids=["other-asset", "other-size", "other-filename", "bad-digest"],
)
def test_a_rekey_must_describe_the_same_image(vault, change, message) -> None:
    app, clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    before = store.read_ciphertext(store.get_asset(asset_id))
    new_metadata, new_ciphertext, _new_key = _rekeyed(metadata)
    new_metadata, new_ciphertext = change(new_metadata, new_ciphertext)
    response = post_rekey(clients["alice"], asset_id, new_metadata, new_ciphertext)
    assert response.status_code == 400
    assert message in response.get_json()["error"]
    assert store.read_ciphertext(store.get_asset(asset_id)) == before
    assert len(store.list_recipients_for_owner(1)[asset_id]) == 2


def test_a_rekey_that_reuses_the_old_ciphertext_is_refused(vault) -> None:
    app, clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    old = store.get_asset(asset_id)
    response = post_rekey(clients["alice"], asset_id, old.metadata, store.read_ciphertext(old))
    assert response.status_code == 400
    assert "new key" in response.get_json()["error"]


@pytest.mark.parametrize(
    ("shares", "message"),
    [
        ([{"username": "dave", "key_wrap": "new-bob-wrap"}], "not currently shared"),
        ([{"username": "alice", "key_wrap": "new-bob-wrap"}], "not currently shared"),
        ([{"username": "bob", "key_wrap": "scrypt"}], "recipient's public key"),
        ([{"username": "bob", "key_wrap": "new-bob-wrap"}] * 2, "more than once"),
        ("not a list", "list"),
    ],
    ids=["stranger", "owner", "wrong-wrap", "duplicate", "malformed"],
)
def test_kept_shares_are_validated(vault, shares, message) -> None:
    app, clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    new_metadata, new_ciphertext, new_key = _rekeyed(metadata)
    replacements = {
        "new-bob-wrap": wrap_data_key_rsa(new_key, store.read_public_key(2)),
        "scrypt": new_metadata["key_wrap"],
    }
    if isinstance(shares, list):
        shares = [{**item, "key_wrap": replacements[item["key_wrap"]]} for item in shares]
    data = {
        "csrf_token": csrf_token(clients["alice"]),
        "envelope": json.dumps(new_metadata),
        "ciphertext": (BytesIO(new_ciphertext), "blob"),
        "shares": json.dumps(shares),
    }
    response = clients["alice"].post(
        f"/images/{asset_id}/rekey", data=data, content_type="multipart/form-data"
    )
    assert response.status_code == 400
    assert message in response.get_json()["error"]
    assert len(store.list_recipients_for_owner(1)[asset_id]) == 2


def test_an_expired_share_cannot_be_kept(vault) -> None:
    app, clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    with raw_db(app.config["INSTANCE_DIR"]) as db:
        db.execute(
            "UPDATE shares SET expires_at = '2000-01-01T00:00:00+00:00' WHERE recipient_user_id = 2"
        )
    new_metadata, new_ciphertext, new_key = _rekeyed(metadata)
    wrap = wrap_data_key_rsa(new_key, store.read_public_key(2))
    response = post_rekey(
        clients["alice"],
        asset_id,
        new_metadata,
        new_ciphertext,
        [{"username": "bob", "key_wrap": wrap}],
    )
    assert response.status_code == 400
    assert "not currently shared" in response.get_json()["error"]


def test_only_the_owner_can_rekey_and_only_end_to_end_images(vault) -> None:
    app, clients = vault
    asset_id, metadata, _old, _link = _shared_vault(vault)
    new_metadata, new_ciphertext, _new_key = _rekeyed(metadata)
    assert post_rekey(clients["bob"], asset_id, new_metadata, new_ciphertext).status_code == 403
    assert (
        post_rekey(clients["alice"], asset_id, new_metadata, new_ciphertext, csrf=False).status_code
        == 400
    )

    encrypt_png(clients["alice"], passphrase=BROWSER_PASS)
    server_asset = app.extensions["vault_store"].list_assets(1)[0]
    assert not server_asset.end_to_end
    response = post_rekey(clients["alice"], server_asset.id, new_metadata, new_ciphertext)
    assert response.status_code == 400
    assert "encrypted on the server" in response.get_json()["error"]


def test_a_failed_swap_leaves_the_old_image_and_shares_intact(vault, monkeypatch) -> None:
    app, clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    asset = store.get_asset(asset_id)
    before = store.read_ciphertext(asset)
    new_metadata, new_ciphertext, _new_key = _rekeyed(metadata)

    real_replace = os.replace

    def failing_replace(src, dst):
        if str(src).endswith(".rekey"):
            raise OSError("disk full")
        return real_replace(src, dst)

    monkeypatch.setattr(storage.os, "replace", failing_replace)
    with pytest.raises(OSError):
        store.rekey_asset(asset_id, 1, metadata=new_metadata, ciphertext=new_ciphertext, shares={})
    monkeypatch.undo()

    after = store.get_asset(asset_id)
    assert store.read_ciphertext(after) == before
    assert after.metadata == asset.metadata
    assert len(store.list_recipients_for_owner(1)[asset_id]) == 2
    assert store.list_link_shares_for_owner(1)[asset_id]
    leftovers = [p.name for p in store.vault_dir.iterdir() if not p.name.endswith(".enc")]
    assert leftovers == []


def test_the_envelope_endpoint_returns_the_callers_wrap_without_ciphertext(vault) -> None:
    app, clients = vault
    asset_id, metadata, _old, _link = _shared_vault(vault)
    owner = clients["alice"].get(f"/images/{asset_id}/envelope")
    assert owner.status_code == 200
    assert owner.headers["Cache-Control"] == "no-store"
    assert owner.get_json()["metadata"]["key_wrap"] == metadata["key_wrap"]
    recipient = clients["bob"].get(f"/images/{asset_id}/envelope").get_json()["metadata"]
    assert recipient["key_wrap"]["type"] == "rsa-oaep-sha256"
    assert recipient["context"] == metadata["context"]

    stranger = app.test_client()
    register(stranger, "dave")
    assert stranger.get(f"/images/{asset_id}/envelope").status_code == 403
    assert clients["alice"].get("/images/999/envelope").status_code == 404


def test_overlapping_rekeys_never_pair_one_envelope_with_anothers_ciphertext(
    vault, monkeypatch
) -> None:
    """Two re-keys of one image at once (two tabs, say) must not cross wires.

    Forces the worst interleaving: the first re-key stages its ciphertext, the
    second stages its own, the first commits, then the second runs. With a
    shared staging path the first would swap in the second's bytes under its own
    envelope, leaving an image that can never be decrypted.
    """
    app, _clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    envelopes = {"first": _rekeyed(metadata), "second": _rekeyed(metadata)}
    first_staged, second_staged, first_done = (threading.Event() for _ in range(3))
    real_transaction = storage.VaultStore._transaction

    @contextmanager
    def interleaved(self):
        name = threading.current_thread().name
        if name == "first":
            first_staged.set()
            second_staged.wait(5)
        elif name == "second":
            second_staged.set()
            first_done.wait(5)
        with real_transaction(self) as db:
            yield db
        if name == "first":
            first_done.set()

    monkeypatch.setattr(storage.VaultStore, "_transaction", interleaved)
    errors: dict[str, BaseException] = {}

    def rekey(name: str) -> None:
        if name == "second":
            first_staged.wait(5)  # stage only after the first has staged
        new_metadata, new_ciphertext, _key = envelopes[name]
        try:
            store.rekey_asset(
                asset_id, 1, metadata=new_metadata, ciphertext=new_ciphertext, shares={}
            )
        except Exception as exc:  # recorded; the outcome is checked below
            errors[name] = exc

    threads = [threading.Thread(target=rekey, args=(name,), name=name) for name in envelopes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    monkeypatch.undo()

    asset = store.get_asset(asset_id)
    assert (
        decrypt_image_bytes(store.read_ciphertext(asset), asset.metadata, passphrase=BROWSER_PASS)
        == sample_png()
    ), errors
    leftovers = [p.name for p in store.vault_dir.iterdir() if not p.name.endswith(".enc")]
    assert leftovers == []


def test_a_commit_that_fails_after_the_swap_restores_the_old_file(vault, monkeypatch) -> None:
    app, _clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    asset = store.get_asset(asset_id)
    before = store.read_ciphertext(asset)
    new_metadata, new_ciphertext, _key = _rekeyed(metadata)
    real_transaction = storage.VaultStore._transaction

    @contextmanager
    def commit_fails(self):
        with real_transaction(self) as db:
            yield db
            # The new file is already in place; the commit itself now fails.
            raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(storage.VaultStore, "_transaction", commit_fails)
    with pytest.raises(sqlite3.OperationalError):
        store.rekey_asset(asset_id, 1, metadata=new_metadata, ciphertext=new_ciphertext, shares={})
    monkeypatch.undo()

    after = store.get_asset(asset_id)
    assert store.read_ciphertext(after) == before
    assert after.metadata == asset.metadata
    assert decrypt_image_bytes(before, after.metadata, passphrase=BROWSER_PASS) == sample_png()
    leftovers = [p.name for p in store.vault_dir.iterdir() if not p.name.endswith(".enc")]
    assert leftovers == []


def test_a_rekey_of_an_image_deleted_meanwhile_is_a_clean_not_found(vault, monkeypatch) -> None:
    """The owner deletes the image in another tab while a re-key is in flight."""
    app, _clients = vault
    store = app.extensions["vault_store"]
    asset_id, metadata, _old, _link = _shared_vault(vault)
    new_metadata, new_ciphertext, _key = _rekeyed(metadata)
    real_transaction = storage.VaultStore._transaction

    @contextmanager
    def deleted_first(self):
        store.delete_asset(asset_id, 1)
        with real_transaction(self) as db:
            yield db

    monkeypatch.setattr(storage.VaultStore, "_transaction", deleted_first)
    with pytest.raises(LookupError):
        store.rekey_asset(asset_id, 1, metadata=new_metadata, ciphertext=new_ciphertext, shares={})
    monkeypatch.undo()
    assert list(store.vault_dir.iterdir()) == []  # nothing staged or copied left behind
