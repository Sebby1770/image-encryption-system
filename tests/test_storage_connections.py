"""VaultStore must close every SQLite connection it opens.

``with sqlite3.connect(...) as db:`` only commits or rolls back on exit; it
never closes the connection. Left open, each one holds a file descriptor (and
can delay releasing SQLite locks) until garbage collection gets to it.
"""

import gc
import sqlite3
import sys
import time
import warnings
from hashlib import sha256

import pytest
from helpers import PASSWORD

from image_encryption_system.crypto import AES_GCM_PASSPHRASE
from image_encryption_system.storage import VaultStore

NEW_PASSWORD = "a different horse battery"
GUARD_INSERT = (
    "INSERT INTO login_guard (kind, username, ip, created_at) VALUES ('failure', 'alice', '', 1.0)"
)


def _make_store(tmp_path) -> VaultStore:
    store = VaultStore(tmp_path / "vault.sqlite3", tmp_path / "vault", tmp_path / "keys")
    store.init()
    return store


def _exercise_store(tmp_path) -> None:
    """Touch every VaultStore method that opens a connection, plus failure paths."""
    store = _make_store(tmp_path)
    store.init()  # re-running init on an existing database

    alice = store.create_user("alice", PASSWORD)
    bob = store.create_user("bob", PASSWORD)
    with pytest.raises(sqlite3.IntegrityError):
        store.create_user("alice", PASSWORD)  # fails inside the block
    assert store.authenticate_user("alice", PASSWORD) is not None
    assert store.authenticate_user("nobody", PASSWORD) is None
    assert store.count_users() == 2

    asset = store.save_asset(
        user_id=alice.id,
        original_filename="cat.png",
        algorithm=AES_GCM_PASSPHRASE,
        mime_type="image/png",
        image_format="PNG",
        width=1,
        height=1,
        metadata={"version": 3},
        ciphertext=bytes(32),
    )
    assert store.list_assets(alice.id, query="cat", algorithm=AES_GCM_PASSPHRASE)
    store.update_asset_details(asset.id, alice.id, notes="note", favorite=True)
    store.update_asset_metadata(asset.id, alice.id, asset.metadata)
    assert store.find_asset_by_uuid(asset.stored_filename.removesuffix(".enc")) is not None

    share = store.create_share(asset_id=asset.id, recipient_user_id=bob.id, key_wrap={})
    assert store.list_shared_with_user(bob.id, query="cat")
    assert store.list_recipients_for_owner(alice.id)
    with pytest.raises(PermissionError):
        store.delete_share(share.id, bob.id)  # raises inside the block
    store.delete_share(share.id, alice.id)

    token_hash = sha256(b"link").hexdigest()
    link = store.create_link_share(
        asset_id=asset.id, token_hash=token_hash, key_wrap={}, max_downloads=1
    )
    assert store.get_link_share_by_token_hash(token_hash) is not None
    assert store.reserve_link_download(link.id)
    assert not store.reserve_link_download(link.id)
    store.release_link_download(link.id)
    store.increment_link_download(link.id)
    assert store.list_link_shares_for_owner(alice.id)
    store.sweep_expired_shares()
    store.delete_link_share(link.id, alice.id)

    now = time.time()
    store.login_guard_add("failure", "alice", ip="127.0.0.1", created_at=now)
    assert store.login_guard_stamps("failure", "alice", ip="127.0.0.1", since=0)
    store.login_guard_prune("failure", "alice", ip="127.0.0.1", before=0)
    store.login_guard_set_lockout("alice", now + 60)
    assert store.login_guard_locked_until("alice") is not None
    store.login_guard_clear_failures("alice")

    sid = store.create_session(alice.id)
    assert store.session_is_active(sid, alice.id, max_age_seconds=60)
    store.delete_user_sessions(alice.id, keep_sid=sid)
    store.prune_sessions(max_age_seconds=60)
    store.delete_session(sid)

    store.add_audit_event(alice.id, "upload", asset_id=asset.id, ip="127.0.0.1")
    assert store.verify_audit_chain(alice.id).ok
    assert store.list_audit_events(alice.id)

    store.export_backup(alice.id)
    store.change_password(alice.id, PASSWORD, NEW_PASSWORD)
    store.delete_asset(asset.id, alice.id)
    store.delete_account(bob.id, PASSWORD)


def _is_open(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return False
    return True


def test_every_store_operation_closes_its_connection(tmp_path, monkeypatch) -> None:
    # Works on every Python version: keep a handle on each connection the store
    # opens and check afterwards that it was closed, not merely committed.
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def tracking_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", tracking_connect)

    _exercise_store(tmp_path)

    assert opened
    left_open = [connection for connection in opened if _is_open(connection)]
    assert not left_open, f"{len(left_open)} of {len(opened)} connections were left open"


@pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="sqlite3 warns about unclosed connections from Python 3.13",
)
def test_store_operations_emit_no_unclosed_database_warning(tmp_path) -> None:
    gc.collect()  # anything an earlier test leaked is not this test's problem
    # A warning raised from a destructor cannot propagate, so "error" would turn
    # it into an unraisable-exception report; recording it is deterministic.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        _exercise_store(tmp_path)
        gc.collect()

    leaks = [
        str(warning.message)
        for warning in caught
        if issubclass(warning.category, ResourceWarning)
        and "sqlite3.Connection" in str(warning.message)
    ]
    assert leaks == []


@pytest.mark.parametrize("opener", ["_connect", "_transaction"])
def test_connection_commits_on_success_and_then_closes(tmp_path, opener) -> None:
    store = _make_store(tmp_path)

    with getattr(store, opener)() as db:
        db.execute(GUARD_INSERT)

    assert store.login_guard_stamps("failure", "alice", since=0) == [1.0]
    assert not _is_open(db)


@pytest.mark.parametrize("opener", ["_connect", "_transaction"])
def test_connection_rolls_back_on_error_and_then_closes(tmp_path, opener) -> None:
    store = _make_store(tmp_path)

    with pytest.raises(RuntimeError, match="boom"), getattr(store, opener)() as db:
        db.execute(GUARD_INSERT)
        raise RuntimeError("boom")

    assert store.login_guard_stamps("failure", "alice", since=0) == []
    assert not _is_open(db)
