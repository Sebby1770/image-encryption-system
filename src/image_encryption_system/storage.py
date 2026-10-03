from __future__ import annotations

import hmac
import json
import os
import secrets
import sqlite3
import time
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .config import IMAGE_MIME_TYPES
from .crypto import (
    ENVELOPE_V3,
    GCM_TAG_BYTES,
    SUPPORTED_ALGORITHMS,
    CryptoError,
    generate_rsa_key_pair,
    new_asset_id,
    reencrypt_private_key_pem,
    validate_envelope,
)
from .security import validate_password

MAX_BACKUP_UNCOMPRESSED = 64 * 1024 * 1024
MAX_BACKUP_ASSETS = 1000
MAX_IMAGE_DIMENSION = 1_000_000
AUDIT_GENESIS = "GENESIS"
AUDIT_KEY_FILENAME = "audit-hmac.key"


@dataclass(frozen=True)
class User:
    id: int
    username: str
    password_hash: str
    created_at: str
    token_version: int = 1


@dataclass(frozen=True)
class EncryptedAsset:
    id: int
    user_id: int
    original_filename: str
    stored_filename: str
    algorithm: str
    mime_type: str
    image_format: str
    width: int
    height: int
    metadata: dict[str, Any]
    created_at: str
    notes: str = ""
    favorite: bool = False


@dataclass(frozen=True)
class AssetShare:
    id: int
    asset_id: int
    recipient_user_id: int
    key_wrap: dict[str, Any]
    created_at: str
    expires_at: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        return _deadline_passed(self.expires_at, now)


@dataclass(frozen=True)
class SharedInboxItem:
    share: AssetShare
    asset: EncryptedAsset
    owner_username: str


@dataclass(frozen=True)
class ShareRecipient:
    share_id: int
    username: str
    expires_at: str | None = None


@dataclass(frozen=True)
class LinkShare:
    id: int
    asset_id: int
    token_hash: str
    key_wrap: dict[str, Any]
    created_at: str
    expires_at: str | None = None
    max_downloads: int | None = None
    download_count: int = 0
    label: str = ""

    def is_expired(self, now: datetime | None = None) -> bool:
        return _deadline_passed(self.expires_at, now)

    def remaining_downloads(self) -> int | None:
        if self.max_downloads is None:
            return None
        return max(0, int(self.max_downloads) - int(self.download_count))

    def is_exhausted(self) -> bool:
        remaining = self.remaining_downloads()
        return remaining is not None and remaining <= 0


@dataclass(frozen=True)
class AuditEvent:
    id: int
    user_id: int | None
    action: str
    asset_id: int | None
    ip: str | None
    created_at: str


@dataclass(frozen=True)
class AuditChainReport:
    ok: bool
    events: int
    first_bad_id: int | None = None


class VaultStore:
    def __init__(
        self,
        database_path: Path,
        vault_dir: Path,
        key_dir: Path,
        *,
        audit_key: bytes | None = None,
    ):
        self.database_path = Path(database_path)
        self.vault_dir = Path(vault_dir)
        self.key_dir = Path(key_dir)
        self._audit_key_override = audit_key
        self._audit_key: bytes | None = None

    @property
    def audit_key(self) -> bytes:
        if self._audit_key is None:
            raw = self._audit_key_override or load_or_create_secret(
                self.key_dir / AUDIT_KEY_FILENAME
            ).encode("utf-8")
            # Domain-separate so the same operator secret is never used raw.
            self._audit_key = hmac.new(raw, b"ies/audit-chain/v1", sha256).digest()
        return self._audit_key

    def init(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    token_version INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS encrypted_assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL UNIQUE,
                    algorithm TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    image_format TEXT NOT NULL,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );

                CREATE TABLE IF NOT EXISTS shares (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    recipient_user_id INTEGER NOT NULL,
                    key_wrap_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    FOREIGN KEY (asset_id) REFERENCES encrypted_assets (id) ON DELETE CASCADE,
                    FOREIGN KEY (recipient_user_id) REFERENCES users (id),
                    UNIQUE (asset_id, recipient_user_id)
                );

                CREATE TABLE IF NOT EXISTS link_shares (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    key_wrap_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    max_downloads INTEGER,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    label TEXT,
                    FOREIGN KEY (asset_id) REFERENCES encrypted_assets (id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    asset_id INTEGER,
                    ip TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS login_guard (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    username TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    locked_until REAL
                );

                CREATE INDEX IF NOT EXISTS idx_assets_user ON encrypted_assets (user_id);
                CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares (recipient_user_id);
                CREATE INDEX IF NOT EXISTS idx_link_shares_asset ON link_shares (asset_id);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events (user_id, id DESC);
                CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
                CREATE INDEX IF NOT EXISTS idx_login_guard_lookup
                    ON login_guard (kind, username, ip, created_at);
                """
            )
            _ensure_column(
                db,
                "users",
                "token_version",
                "token_version INTEGER NOT NULL DEFAULT 1",
            )
            _ensure_column(db, "shares", "expires_at", "expires_at TEXT")
            _ensure_column(db, "encrypted_assets", "notes", "notes TEXT NOT NULL DEFAULT ''")
            _ensure_column(
                db,
                "encrypted_assets",
                "favorite",
                "favorite INTEGER NOT NULL DEFAULT 0",
            )
            _ensure_column(db, "audit_events", "prev_hash", "prev_hash TEXT")
            _ensure_column(db, "audit_events", "chain_hash", "chain_hash TEXT")
        self._seal_unchained_audit_events()

    def count_users(self) -> int:
        """Cheap query the health check uses to prove the database answers."""
        with self._connect() as db:
            row = db.execute("SELECT COUNT(*) AS total FROM users").fetchone()
        return int(row["total"]) if row else 0

    def create_user(self, username: str, password: str) -> User:
        username = username.strip().lower()
        if not username:
            raise ValueError("Username is required.")
        # Enforced here rather than in the view so every path that creates an
        # account — routes, CLI, future callers — clears the same bar.
        validate_password(password, username=username)

        now = _utc_now()
        password_hash = generate_password_hash(password)

        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO users (username, password_hash, created_at, token_version)
                VALUES (?, ?, ?, 1)
                """,
                (username, password_hash, now),
            )
            user_id = _last_row_id(cursor)

        private_pem, public_pem = generate_rsa_key_pair(password)
        self.private_key_path(user_id).write_bytes(private_pem)
        self.public_key_path(user_id).write_bytes(public_pem)
        return self.get_user(user_id)

    def authenticate_user(self, username: str, password: str) -> User | None:
        user = self.get_user_by_username(username)
        if user is None:
            # Spend the same hashing work as a real check, so response timing
            # does not reveal whether the username exists.
            check_password_hash(_dummy_password_hash(), password)
            return None
        if check_password_hash(user.password_hash, password):
            return user
        return None

    def get_user(self, user_id: int) -> User:
        with self._connect() as db:
            row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise LookupError("User not found.")
        return _user_from_row(row)

    def get_user_by_username(self, username: str) -> User | None:
        username = username.strip().lower()
        with self._connect() as db:
            row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return _user_from_row(row) if row else None

    def read_public_key(self, user_id: int) -> bytes:
        return self.public_key_path(user_id).read_bytes()

    def read_private_key(self, user_id: int) -> bytes:
        return self.private_key_path(user_id).read_bytes()

    def change_password(self, user_id: int, old_password: str, new_password: str) -> None:
        user = self.get_user(user_id)
        if not check_password_hash(user.password_hash, old_password):
            raise ValueError("Current password is incorrect.")
        # Rotation must clear the same bar as registration, or the policy is one
        # password change away from being bypassed.
        validate_password(new_password, username=user.username)

        new_pem = reencrypt_private_key_pem(
            self.read_private_key(user_id),
            old_password,
            new_password,
        )
        new_hash = generate_password_hash(new_password)
        pem_path = self.private_key_path(user_id)
        tmp_path = pem_path.with_name(pem_path.name + ".tmp")
        tmp_path.write_bytes(new_pem)
        try:
            with self._connect() as db:
                db.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, token_version = token_version + 1
                    WHERE id = ?
                    """,
                    (new_hash, user_id),
                )
            tmp_path.replace(pem_path)
        except Exception:
            with self._connect() as db:
                db.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, token_version = ?
                    WHERE id = ?
                    """,
                    (user.password_hash, user.token_version, user_id),
                )
            raise
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def private_key_path(self, user_id: int) -> Path:
        return self.key_dir / f"user-{user_id}-private.pem"

    def public_key_path(self, user_id: int) -> Path:
        return self.key_dir / f"user-{user_id}-public.pem"

    def delete_account(self, user_id: int, password: str) -> User:
        user = self.get_user(user_id)
        if not check_password_hash(user.password_hash, password):
            raise ValueError("Current password is incorrect.")

        assets = self.list_assets(user_id)
        ciphertext_paths = [self.vault_dir / asset.stored_filename for asset in assets]
        key_paths = [self.private_key_path(user_id), self.public_key_path(user_id)]

        with self._connect() as db:
            db.execute("DELETE FROM shares WHERE recipient_user_id = ?", (user_id,))
            db.execute(
                """
                DELETE FROM shares
                WHERE asset_id IN (SELECT id FROM encrypted_assets WHERE user_id = ?)
                """,
                (user_id,),
            )
            db.execute(
                """
                DELETE FROM link_shares
                WHERE asset_id IN (SELECT id FROM encrypted_assets WHERE user_id = ?)
                """,
                (user_id,),
            )
            db.execute("DELETE FROM encrypted_assets WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM audit_events WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM login_guard WHERE username = ?", (user.username,))
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))

        for path in ciphertext_paths + key_paths:
            if path.exists():
                path.unlink()
        return user

    def save_asset(
        self,
        *,
        user_id: int,
        original_filename: str,
        algorithm: str,
        mime_type: str,
        image_format: str,
        width: int,
        height: int,
        metadata: dict[str, Any],
        ciphertext: bytes,
        notes: str = "",
        favorite: bool = False,
        asset_uuid: str | None = None,
    ) -> EncryptedAsset:
        safe_name = secure_filename(original_filename) or "image"
        stored_filename = f"{asset_uuid or new_asset_id()}.enc"
        (self.vault_dir / stored_filename).write_bytes(ciphertext)
        now = _utc_now()
        stored_meta = dict(metadata)
        stored_meta.setdefault("ciphertext_sha256", sha256(ciphertext).hexdigest())

        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO encrypted_assets (
                    user_id, original_filename, stored_filename, algorithm, mime_type,
                    image_format, width, height, metadata_json, created_at, notes, favorite
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    safe_name,
                    stored_filename,
                    algorithm,
                    mime_type,
                    image_format,
                    width,
                    height,
                    json.dumps(stored_meta, sort_keys=True),
                    now,
                    notes or "",
                    1 if favorite else 0,
                ),
            )
            asset_id = _last_row_id(cursor)
        return self.get_asset(asset_id)

    def get_asset(self, asset_id: int) -> EncryptedAsset:
        with self._connect() as db:
            row = db.execute("SELECT * FROM encrypted_assets WHERE id = ?", (asset_id,)).fetchone()
        if row is None:
            raise LookupError("Encrypted image not found.")
        return _asset_from_row(row)

    def list_assets(
        self,
        user_id: int,
        *,
        query: str | None = None,
        algorithm: str | None = None,
        favorites_only: bool = False,
    ) -> list[EncryptedAsset]:
        sql = "SELECT * FROM encrypted_assets WHERE user_id = ?"
        params: list[Any] = [user_id]
        if query:
            sql += " AND (LOWER(original_filename) LIKE ? OR LOWER(COALESCE(notes, '')) LIKE ?)"
            needle = f"%{query.strip().lower()}%"
            params.extend([needle, needle])
        if algorithm:
            sql += " AND algorithm = ?"
            params.append(algorithm)
        if favorites_only:
            sql += " AND favorite = 1"
        sql += " ORDER BY favorite DESC, id DESC"
        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        return [_asset_from_row(row) for row in rows]

    def delete_asset(self, asset_id: int, user_id: int) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")
        path = self.vault_dir / asset.stored_filename
        with self._connect() as db:
            db.execute("DELETE FROM shares WHERE asset_id = ?", (asset_id,))
            db.execute("DELETE FROM link_shares WHERE asset_id = ?", (asset_id,))
            db.execute(
                "DELETE FROM encrypted_assets WHERE id = ? AND user_id = ?",
                (asset_id, user_id),
            )
        if path.exists():
            path.unlink()
        return asset

    def find_asset_by_uuid(self, asset_uuid: str) -> EncryptedAsset | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM encrypted_assets WHERE stored_filename = ?",
                (f"{asset_uuid}.enc",),
            ).fetchone()
        return _asset_from_row(row) if row else None

    def read_ciphertext(self, asset: EncryptedAsset) -> bytes:
        return (self.vault_dir / asset.stored_filename).read_bytes()

    def update_asset_details(
        self,
        asset_id: int,
        user_id: int,
        *,
        original_filename: str | None = None,
        notes: str | None = None,
        favorite: bool | None = None,
    ) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")
        next_name = (
            secure_filename(original_filename) or asset.original_filename
            if original_filename is not None
            else asset.original_filename
        )
        if original_filename is not None and not next_name:
            raise ValueError("Filename is required.")
        next_notes = asset.notes if notes is None else notes
        next_favorite = asset.favorite if favorite is None else bool(favorite)
        with self._connect() as db:
            db.execute(
                """
                UPDATE encrypted_assets
                SET original_filename = ?, notes = ?, favorite = ?
                WHERE id = ? AND user_id = ?
                """,
                (next_name, next_notes, 1 if next_favorite else 0, asset_id, user_id),
            )
        return self.get_asset(asset_id)

    def ciphertext_sha256(self, asset: EncryptedAsset) -> str:
        digest = sha256(self.read_ciphertext(asset)).hexdigest()
        stored = str((asset.metadata or {}).get("ciphertext_sha256") or "")
        if stored and stored != digest:
            raise ValueError("Ciphertext integrity check failed.")
        return digest

    def update_asset_metadata(
        self,
        asset_id: int,
        user_id: int,
        metadata: dict[str, Any],
    ) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")
        with self._connect() as db:
            db.execute(
                """
                UPDATE encrypted_assets
                SET metadata_json = ?
                WHERE id = ? AND user_id = ?
                """,
                (json.dumps(metadata, sort_keys=True), asset_id, user_id),
            )
        return self.get_asset(asset_id)

    def create_share(
        self,
        *,
        asset_id: int,
        recipient_user_id: int,
        key_wrap: dict[str, Any],
        expires_at: str | None = None,
    ) -> AssetShare:
        now = _utc_now()
        payload = json.dumps(key_wrap, sort_keys=True)
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO shares (
                    asset_id, recipient_user_id, key_wrap_json, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(asset_id, recipient_user_id) DO UPDATE SET
                    key_wrap_json = excluded.key_wrap_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (asset_id, recipient_user_id, payload, now, expires_at),
            )
        share = self.get_share(asset_id, recipient_user_id)
        if share is None:
            raise RuntimeError("Share was not persisted.")
        return share

    def get_share(self, asset_id: int, recipient_user_id: int) -> AssetShare | None:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT * FROM shares
                WHERE asset_id = ? AND recipient_user_id = ?
                """,
                (asset_id, recipient_user_id),
            ).fetchone()
        return _share_from_row(row) if row else None

    def delete_share(self, share_id: int, owner_user_id: int) -> AssetShare:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT s.*, ea.user_id AS owner_user_id
                FROM shares AS s
                JOIN encrypted_assets AS ea ON ea.id = s.asset_id
                WHERE s.id = ?
                """,
                (share_id,),
            ).fetchone()
            if row is None:
                raise LookupError("Share not found.")
            if int(row["owner_user_id"]) != owner_user_id:
                raise PermissionError("You can only revoke shares you created.")
            share = _share_from_row(row)
            db.execute("DELETE FROM shares WHERE id = ?", (share_id,))
        return share

    def list_shared_with_user(
        self,
        recipient_user_id: int,
        *,
        query: str | None = None,
        algorithm: str | None = None,
    ) -> list[SharedInboxItem]:
        sql = """
            SELECT ea.*,
                   s.id AS share_id,
                   s.recipient_user_id AS share_recipient_user_id,
                   s.key_wrap_json AS share_key_wrap_json,
                   s.created_at AS shared_at,
                   s.expires_at AS share_expires_at,
                   u.username AS owner_username
            FROM shares AS s
            JOIN encrypted_assets AS ea ON ea.id = s.asset_id
            JOIN users AS u ON u.id = ea.user_id
            WHERE s.recipient_user_id = ?
        """
        params: list[Any] = [recipient_user_id]
        if query:
            sql += " AND LOWER(ea.original_filename) LIKE ?"
            params.append(f"%{query.strip().lower()}%")
        if algorithm:
            sql += " AND ea.algorithm = ?"
            params.append(algorithm)
        sql += " ORDER BY s.id DESC"
        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        items: list[SharedInboxItem] = []
        for row in rows:
            items.append(
                SharedInboxItem(
                    share=AssetShare(
                        id=int(row["share_id"]),
                        asset_id=int(row["id"]),
                        recipient_user_id=int(row["share_recipient_user_id"]),
                        key_wrap=json.loads(str(row["share_key_wrap_json"])),
                        created_at=str(row["shared_at"]),
                        expires_at=_optional_text(row["share_expires_at"]),
                    ),
                    asset=_asset_from_row(row),
                    owner_username=str(row["owner_username"]),
                )
            )
        return items

    def list_recipients_for_owner(self, owner_user_id: int) -> dict[int, list[ShareRecipient]]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT s.id AS share_id, s.asset_id, s.expires_at, u.username
                FROM shares AS s
                JOIN encrypted_assets AS ea ON ea.id = s.asset_id
                JOIN users AS u ON u.id = s.recipient_user_id
                WHERE ea.user_id = ?
                ORDER BY u.username
                """,
                (owner_user_id,),
            ).fetchall()
        mapping: dict[int, list[ShareRecipient]] = {}
        for row in rows:
            mapping.setdefault(int(row["asset_id"]), []).append(
                ShareRecipient(
                    share_id=int(row["share_id"]),
                    username=str(row["username"]),
                    expires_at=_optional_text(row["expires_at"]),
                )
            )
        return mapping

    def create_link_share(
        self,
        *,
        asset_id: int,
        token_hash: str,
        key_wrap: dict[str, Any],
        expires_at: str | None = None,
        max_downloads: int | None = None,
        label: str = "",
    ) -> LinkShare:
        now = _utc_now()
        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO link_shares (
                    asset_id, token_hash, key_wrap_json, created_at,
                    expires_at, max_downloads, download_count, label
                )
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    asset_id,
                    token_hash,
                    json.dumps(key_wrap, sort_keys=True),
                    now,
                    expires_at,
                    max_downloads,
                    label or "",
                ),
            )
            link_id = _last_row_id(cursor)
        link = self.get_link_share(link_id)
        if link is None:
            raise RuntimeError("Link share was not persisted.")
        return link

    def get_link_share(self, link_id: int) -> LinkShare | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM link_shares WHERE id = ?",
                (link_id,),
            ).fetchone()
        return _link_from_row(row) if row else None

    def get_link_share_by_token_hash(self, token_hash: str) -> LinkShare | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM link_shares WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        return _link_from_row(row) if row else None

    def increment_link_download(self, link_id: int) -> LinkShare:
        with self._connect() as db:
            db.execute(
                """
                UPDATE link_shares
                SET download_count = download_count + 1
                WHERE id = ?
                """,
                (link_id,),
            )
        link = self.get_link_share(link_id)
        if link is None:
            raise LookupError("Link share not found.")
        return link

    def reserve_link_download(self, link_id: int) -> bool:
        """Atomically claim one download. False if the cap is already used up.

        The check and the increment are one UPDATE, so concurrent requests can
        never both slip under ``max_downloads``.
        """
        with self._connect() as db:
            cursor = db.execute(
                """
                UPDATE link_shares
                SET download_count = download_count + 1
                WHERE id = ?
                  AND (max_downloads IS NULL OR download_count < max_downloads)
                """,
                (link_id,),
            )
            return cursor.rowcount == 1

    def release_link_download(self, link_id: int) -> None:
        """Give back a reserved download whose decryption did not complete."""
        with self._connect() as db:
            db.execute(
                """
                UPDATE link_shares
                SET download_count = download_count - 1
                WHERE id = ? AND download_count > 0
                """,
                (link_id,),
            )

    def delete_link_share(self, link_id: int, owner_user_id: int) -> LinkShare:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT ls.*, ea.user_id AS owner_user_id
                FROM link_shares AS ls
                JOIN encrypted_assets AS ea ON ea.id = ls.asset_id
                WHERE ls.id = ?
                """,
                (link_id,),
            ).fetchone()
            if row is None:
                raise LookupError("Link share not found.")
            if int(row["owner_user_id"]) != owner_user_id:
                raise PermissionError("You can only revoke links you created.")
            link = _link_from_row(row)
            db.execute("DELETE FROM link_shares WHERE id = ?", (link_id,))
        return link

    def list_link_shares_for_owner(self, owner_user_id: int) -> dict[int, list[LinkShare]]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT ls.*
                FROM link_shares AS ls
                JOIN encrypted_assets AS ea ON ea.id = ls.asset_id
                WHERE ea.user_id = ?
                ORDER BY ls.id DESC
                """,
                (owner_user_id,),
            ).fetchall()
        mapping: dict[int, list[LinkShare]] = {}
        for row in rows:
            link = _link_from_row(row)
            mapping.setdefault(link.asset_id, []).append(link)
        return mapping

    def sweep_expired_shares(self, now: datetime | None = None) -> int:
        stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
        with self._connect() as db:
            shares = db.execute(
                """
                DELETE FROM shares
                WHERE expires_at IS NOT NULL AND expires_at <= ?
                """,
                (stamp,),
            )
            links = db.execute(
                """
                DELETE FROM link_shares
                WHERE expires_at IS NOT NULL AND expires_at <= ?
                """,
                (stamp,),
            )
            return int(shares.rowcount or 0) + int(links.rowcount or 0)

    def login_guard_locked_until(self, username: str) -> float | None:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT locked_until FROM login_guard
                WHERE kind = 'lockout' AND username = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (username,),
            ).fetchone()
        if row is None or row["locked_until"] is None:
            return None
        return float(row["locked_until"])

    def login_guard_set_lockout(self, username: str, locked_until: float) -> None:
        with self._connect() as db:
            db.execute(
                "DELETE FROM login_guard WHERE kind = 'lockout' AND username = ?",
                (username,),
            )
            db.execute(
                """
                INSERT INTO login_guard (kind, username, ip, created_at, locked_until)
                VALUES ('lockout', ?, '', ?, ?)
                """,
                (username, time.time(), locked_until),
            )

    def login_guard_clear_failures(self, username: str) -> None:
        with self._connect() as db:
            db.execute(
                "DELETE FROM login_guard WHERE username = ? AND kind IN ('failure', 'lockout')",
                (username,),
            )

    def login_guard_stamps(
        self,
        kind: str,
        username: str,
        *,
        ip: str | None = None,
        since: float,
    ) -> list[float]:
        sql = """
            SELECT created_at FROM login_guard
            WHERE kind = ? AND username = ? AND created_at > ?
        """
        params: list[Any] = [kind, username, since]
        if ip is not None:
            sql += " AND ip = ?"
            params.append(ip)
        sql += " ORDER BY created_at"
        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        return [float(row["created_at"]) for row in rows]

    def login_guard_add(
        self,
        kind: str,
        username: str,
        *,
        ip: str = "",
        created_at: float,
        locked_until: float | None = None,
    ) -> None:
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO login_guard (kind, username, ip, created_at, locked_until)
                VALUES (?, ?, ?, ?, ?)
                """,
                (kind, username, ip, created_at, locked_until),
            )

    def login_guard_prune(
        self,
        kind: str,
        username: str,
        *,
        ip: str | None = None,
        before: float,
    ) -> None:
        sql = "DELETE FROM login_guard WHERE kind = ? AND username = ? AND created_at <= ?"
        params: list[Any] = [kind, username, before]
        if ip is not None:
            sql += " AND ip = ?"
            params.append(ip)
        with self._connect() as db:
            db.execute(sql, params)

    def create_session(self, user_id: int) -> str:
        """Register a server-side session and return its secret id."""
        sid = secrets.token_urlsafe(32)
        with self._connect() as db:
            db.execute(
                "INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)",
                (_session_key(sid), user_id, _utc_now()),
            )
        return sid

    def session_is_active(self, sid: str, user_id: int, *, max_age_seconds: int) -> bool:
        with self._connect() as db:
            row = db.execute(
                "SELECT user_id, created_at FROM sessions WHERE id = ?",
                (_session_key(sid),),
            ).fetchone()
        if row is None or int(row["user_id"]) != user_id:
            return False
        if max_age_seconds > 0:
            created = datetime.fromisoformat(str(row["created_at"]))
            if datetime.now(timezone.utc) - created > timedelta(seconds=max_age_seconds):
                self.delete_session(sid)
                return False
        return True

    def delete_session(self, sid: str) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE id = ?", (_session_key(sid),))

    def delete_user_sessions(self, user_id: int, *, keep_sid: str | None = None) -> None:
        with self._connect() as db:
            if keep_sid:
                db.execute(
                    "DELETE FROM sessions WHERE user_id = ? AND id != ?",
                    (user_id, _session_key(keep_sid)),
                )
            else:
                db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def prune_sessions(self, *, max_age_seconds: int) -> None:
        if max_age_seconds <= 0:
            return
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        with self._connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE created_at < ?",
                (cutoff.isoformat(timespec="seconds"),),
            )

    def add_audit_event(
        self,
        user_id: int | None,
        action: str,
        *,
        asset_id: int | None = None,
        ip: str | None = None,
    ) -> AuditEvent:
        """Append an event to the user's HMAC chain.

        ``BEGIN IMMEDIATE`` takes the write lock before reading the chain head,
        so two concurrent events can never both link to the same predecessor.
        """
        now = _utc_now()
        with self._transaction() as db:
            prev_hash = self._audit_head(db, user_id)
            cursor = db.execute(
                """
                INSERT INTO audit_events (user_id, action, asset_id, ip, created_at, prev_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, action, asset_id, ip, now, prev_hash),
            )
            event_id = _last_row_id(cursor)
            row = db.execute("SELECT * FROM audit_events WHERE id = ?", (event_id,)).fetchone()
            db.execute(
                "UPDATE audit_events SET chain_hash = ? WHERE id = ?",
                (self._audit_digest(row, prev_hash), event_id),
            )
        return _audit_from_row(row)

    def verify_audit_chain(self, user_id: int) -> AuditChainReport:
        """Recompute the user's whole chain; report the first event that fails.

        Edits, insertions, reordering, and deletions anywhere except the very
        end are detected. Truncating the newest events is not, because nothing
        outside the database records the chain head.
        """
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events WHERE user_id IS ? ORDER BY id",
                (user_id,),
            ).fetchall()
        expected_prev = AUDIT_GENESIS
        for row in rows:
            stored_prev = row["prev_hash"]
            stored_hash = row["chain_hash"] or ""
            digest = self._audit_digest(row, expected_prev)
            if stored_prev != expected_prev or not hmac.compare_digest(stored_hash, digest):
                return AuditChainReport(ok=False, events=len(rows), first_bad_id=int(row["id"]))
            expected_prev = stored_hash
        return AuditChainReport(ok=True, events=len(rows))

    def _audit_head(self, db: sqlite3.Connection, user_id: int | None) -> str:
        row = db.execute(
            """
            SELECT chain_hash FROM audit_events
            WHERE user_id IS ? ORDER BY id DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        return str(row["chain_hash"]) if row and row["chain_hash"] else AUDIT_GENESIS

    def _audit_digest(self, row: sqlite3.Row, prev_hash: str) -> str:
        payload = json.dumps(
            [
                int(row["id"]),
                row["user_id"],
                str(row["action"]),
                row["asset_id"],
                row["ip"],
                str(row["created_at"]),
                prev_hash,
            ],
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self.audit_key, payload, sha256).hexdigest()

    def _seal_unchained_audit_events(self) -> None:
        """Chain events written before the audit chain existed (one-time upgrade).

        This vouches for history only from the moment of the upgrade: events
        that were edited before sealing cannot be detected retroactively.
        """
        with self._transaction() as db:
            pending = db.execute(
                "SELECT DISTINCT user_id FROM audit_events WHERE chain_hash IS NULL"
            ).fetchall()
            for (user_id,) in pending:
                prev_hash = AUDIT_GENESIS
                rows = db.execute(
                    "SELECT * FROM audit_events WHERE user_id IS ? ORDER BY id",
                    (user_id,),
                ).fetchall()
                for row in rows:
                    if row["chain_hash"]:
                        prev_hash = str(row["chain_hash"])
                        continue
                    digest = self._audit_digest(row, prev_hash)
                    db.execute(
                        "UPDATE audit_events SET prev_hash = ?, chain_hash = ? WHERE id = ?",
                        (prev_hash, digest, int(row["id"])),
                    )
                    prev_hash = digest

    def list_audit_events(self, user_id: int, *, limit: int = 200) -> list[AuditEvent]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM audit_events
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return [_audit_from_row(row) for row in rows]

    def export_backup(self, user_id: int) -> bytes:
        user = self.get_user(user_id)
        assets = self.list_assets(user_id)
        manifest_assets: list[dict[str, Any]] = []
        manifest = {
            "version": 2,
            "exported_at": _utc_now(),
            "username": user.username,
            "assets": manifest_assets,
        }
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for asset in assets:
                blob_name = f"assets/{asset.stored_filename}"
                archive.writestr(blob_name, self.read_ciphertext(asset))
                manifest_assets.append(
                    {
                        "original_filename": asset.original_filename,
                        "algorithm": asset.algorithm,
                        "mime_type": asset.mime_type,
                        "image_format": asset.image_format,
                        "width": asset.width,
                        "height": asset.height,
                        "metadata": asset.metadata,
                        "blob": blob_name,
                        "created_at": asset.created_at,
                        "notes": asset.notes,
                        "favorite": asset.favorite,
                    }
                )
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        return buffer.getvalue()

    def import_backup(self, user_id: int, archive_bytes: bytes) -> int:
        """Restore a backup zip into ``user_id``'s vault.

        Every entry is validated before anything is written, so a bad backup
        restores nothing. Entries must be allow-listed images with a well-formed
        envelope; each blob may be referenced once; version 3 envelopes must be
        sealed to this account. Re-restoring an asset already in this vault is
        skipped rather than duplicated.
        """
        buffer = BytesIO(archive_bytes)
        if not zipfile.is_zipfile(buffer):
            raise ValueError("Backup file is not a valid zip archive.")
        buffer.seek(0)
        pending: list[dict[str, Any]] = []
        with zipfile.ZipFile(buffer, "r") as archive:
            uncompressed = sum(info.file_size for info in archive.infolist())
            if uncompressed > MAX_BACKUP_UNCOMPRESSED:
                raise ValueError("Backup archive is too large.")
            names = set(archive.namelist())
            if "manifest.json" not in names:
                raise ValueError("Backup is missing manifest.json.")
            try:
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Backup manifest is not valid JSON.") from exc
            assets = manifest.get("assets") if isinstance(manifest, dict) else None
            if not isinstance(assets, list):
                raise ValueError("Backup manifest does not list assets.")
            if len(assets) > MAX_BACKUP_ASSETS:
                raise ValueError(f"Backup lists more than {MAX_BACKUP_ASSETS} assets.")
            seen_blobs: set[str] = set()
            for item in assets:
                if not isinstance(item, dict):
                    raise ValueError("Backup asset entry is invalid.")
                blob_name = _safe_zip_member(str(item.get("blob", "")))
                if blob_name in seen_blobs:
                    raise ValueError("Backup references the same ciphertext more than once.")
                seen_blobs.add(blob_name)
                if blob_name not in names:
                    raise ValueError(f"Backup is missing ciphertext {blob_name}.")
                entry = self._validated_backup_entry(user_id, item)
                entry["ciphertext"] = archive.read(blob_name)
                if len(entry["ciphertext"]) < GCM_TAG_BYTES:
                    raise ValueError("Backup ciphertext is truncated.")
                pending.append(entry)

        restored = 0
        for entry in pending:
            asset_uuid = entry.pop("asset_uuid")
            if asset_uuid is not None and self.find_asset_by_uuid(asset_uuid) is not None:
                continue
            self.save_asset(user_id=user_id, asset_uuid=asset_uuid, **entry)
            restored += 1
        return restored

    def _validated_backup_entry(self, user_id: int, item: dict[str, Any]) -> dict[str, Any]:
        metadata = item.get("metadata")
        try:
            version = validate_envelope(metadata)
        except CryptoError as exc:
            raise ValueError(f"Backup asset has an invalid envelope: {exc}") from exc
        assert isinstance(metadata, dict)
        algorithm = str(item.get("algorithm") or "")
        image_format = str(item.get("image_format") or "")
        mime_type = str(item.get("mime_type") or "")
        try:
            width = int(item.get("width") or 0)
            height = int(item.get("height") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Backup asset dimensions are invalid.") from exc
        if algorithm not in SUPPORTED_ALGORITHMS or algorithm != metadata["algorithm"]:
            raise ValueError("Backup asset algorithm is not supported.")
        if IMAGE_MIME_TYPES.get(image_format) != mime_type:
            raise ValueError("Backup asset is not an allow-listed image type.")
        if not (1 <= width <= MAX_IMAGE_DIMENSION and 1 <= height <= MAX_IMAGE_DIMENSION):
            raise ValueError("Backup asset dimensions are invalid.")

        asset_uuid: str | None = None
        if version == ENVELOPE_V3:
            context = metadata["context"]
            if context.get("owner") != user_id:
                raise ValueError(
                    "Backup contains images sealed to a different account; "
                    "restore it into the account that exported it."
                )
            sealed = (
                context.get("mime"),
                context.get("format"),
                context.get("width"),
                context.get("height"),
            )
            if sealed != (mime_type, image_format, width, height):
                raise ValueError("Backup asset does not match its sealed context.")
            asset_uuid = str(context["asset"])
            existing = self.find_asset_by_uuid(asset_uuid)
            if existing is not None and existing.user_id != user_id:
                raise ValueError("Backup asset id collides with another account's image.")
        return {
            "asset_uuid": asset_uuid,
            "original_filename": str(item.get("original_filename") or "image"),
            "algorithm": algorithm,
            "mime_type": mime_type,
            "image_format": image_format,
            "width": width,
            "height": height,
            "metadata": metadata,
            "notes": str(item.get("notes") or ""),
            "favorite": bool(item.get("favorite")),
        }

    def _open_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """A connection that commits on success, rolls back on error, then closes.

        A bare ``with sqlite3.connect(...)`` block only ends the transaction;
        it never closes the connection, which then holds a file descriptor
        until garbage collection.
        """
        connection = self._open_connection()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """A connection holding the database write lock until commit."""
        connection = self._open_connection()
        connection.isolation_level = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")
        finally:
            connection.close()


def load_or_create_secret(path: Path) -> str:
    """Read a persisted random secret, creating it (mode 0600) on first use."""
    path = Path(path)
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
    return value


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    return generate_password_hash(secrets.token_urlsafe(32))


def _session_key(sid: str) -> str:
    return sha256(sid.encode("utf-8")).hexdigest()


def _deadline_passed(expires_at: str | None, now: datetime | None = None) -> bool:
    if not expires_at:
        return False
    moment = now or datetime.now(timezone.utc)
    expires = datetime.fromisoformat(expires_at)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment >= expires


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_zip_member(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ValueError("Backup archive contains an unsafe path.")
    return name


def _user_from_row(row: sqlite3.Row) -> User:
    keys = set(row.keys())
    token_version = int(row["token_version"]) if "token_version" in keys else 1
    return User(
        id=int(row["id"]),
        username=str(row["username"]),
        password_hash=str(row["password_hash"]),
        created_at=str(row["created_at"]),
        token_version=token_version,
    )


def _asset_from_row(row: sqlite3.Row) -> EncryptedAsset:
    keys = set(row.keys())
    notes = str(row["notes"]) if "notes" in keys and row["notes"] is not None else ""
    has_favorite = "favorite" in keys and row["favorite"] is not None
    favorite = bool(int(row["favorite"])) if has_favorite else False
    return EncryptedAsset(
        id=int(row["id"]),
        user_id=int(row["user_id"]),
        original_filename=str(row["original_filename"]),
        stored_filename=str(row["stored_filename"]),
        algorithm=str(row["algorithm"]),
        mime_type=str(row["mime_type"]),
        image_format=str(row["image_format"]),
        width=int(row["width"]),
        height=int(row["height"]),
        metadata=json.loads(str(row["metadata_json"])),
        created_at=str(row["created_at"]),
        notes=notes,
        favorite=favorite,
    )


def _link_from_row(row: sqlite3.Row) -> LinkShare:
    keys = set(row.keys())
    max_downloads = row["max_downloads"] if "max_downloads" in keys else None
    download_count = row["download_count"] if "download_count" in keys else 0
    label = row["label"] if "label" in keys else ""
    return LinkShare(
        id=int(row["id"]),
        asset_id=int(row["asset_id"]),
        token_hash=str(row["token_hash"]),
        key_wrap=json.loads(str(row["key_wrap_json"])),
        created_at=str(row["created_at"]),
        expires_at=_optional_text(row["expires_at"]) if "expires_at" in keys else None,
        max_downloads=int(max_downloads) if max_downloads is not None else None,
        download_count=int(download_count or 0),
        label=str(label or ""),
    )


def _share_from_row(row: sqlite3.Row) -> AssetShare:
    keys = set(row.keys())
    expires_at = _optional_text(row["expires_at"]) if "expires_at" in keys else None
    return AssetShare(
        id=int(row["id"]),
        asset_id=int(row["asset_id"]),
        recipient_user_id=int(row["recipient_user_id"]),
        key_wrap=json.loads(str(row["key_wrap_json"])),
        created_at=str(row["created_at"]),
        expires_at=expires_at,
    )


def _last_row_id(cursor: sqlite3.Cursor) -> int:
    if cursor.lastrowid is None:
        raise RuntimeError("SQLite did not report the inserted row id.")
    return int(cursor.lastrowid)


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {str(row[1]) for row in db.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def _audit_from_row(row: sqlite3.Row) -> AuditEvent:
    asset_id = row["asset_id"]
    user_id = row["user_id"]
    ip = row["ip"]
    return AuditEvent(
        id=int(row["id"]),
        user_id=int(user_id) if user_id is not None else None,
        action=str(row["action"]),
        asset_id=int(asset_id) if asset_id is not None else None,
        ip=str(ip) if ip is not None else None,
        created_at=str(row["created_at"]),
    )
