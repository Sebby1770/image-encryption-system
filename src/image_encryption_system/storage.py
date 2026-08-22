from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .crypto import generate_rsa_key_pair

OWNER_ONLY_DIR_MODE = 0o700
OWNER_ONLY_FILE_MODE = 0o600
AUDIT_CHAIN_VERSION = 2
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 1024
MAX_FILENAME_LENGTH = 255
MAX_TAGS_LENGTH = 512
MAX_NOTES_LENGTH = 2_000
_STORED_FILENAME_RE = re.compile(r"^[0-9a-f]{32}\.enc$")
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


@dataclass(frozen=True)
class User:
    id: int
    username: str
    password_hash: str
    auth_version: int
    created_at: str


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
    tags: str
    notes: str
    created_at: str


@dataclass(frozen=True)
class AuditEvent:
    id: int
    user_id: int
    action: str
    detail: str
    created_at: str
    prev_hash: str
    chain_hash: str


@dataclass(frozen=True)
class VaultStats:
    asset_count: int
    ciphertext_bytes: int
    algorithms: dict[str, int]


class VaultStore:
    def __init__(
        self,
        database_path: Path,
        vault_dir: Path,
        key_dir: Path,
        *,
        audit_key: bytes,
    ):
        self.database_path = Path(database_path)
        self.vault_dir = Path(vault_dir)
        self.key_dir = Path(key_dir)
        if len(audit_key) < 32:
            raise ValueError("Audit key must be at least 32 bytes.")
        self.audit_key = hashlib.sha256(b"image-encryption-system.audit.v2\0" + audit_key).digest()

    def init(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        _restrict_owner_access(self.database_path.parent)
        _restrict_owner_access(self.vault_dir)
        _restrict_owner_access(self.key_dir)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    auth_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
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

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    prev_hash TEXT NOT NULL DEFAULT 'GENESIS',
                    chain_hash TEXT NOT NULL DEFAULT '',
                    chain_version INTEGER NOT NULL DEFAULT 2,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );

                CREATE INDEX IF NOT EXISTS idx_assets_user_created
                    ON encrypted_assets (user_id, id DESC);
                CREATE INDEX IF NOT EXISTS idx_assets_user_algorithm
                    ON encrypted_assets (user_id, algorithm);
                CREATE INDEX IF NOT EXISTS idx_audit_user_created
                    ON audit_events (user_id, id DESC);
                """
            )
            self._ensure_auth_version_column(db)
            self._ensure_tags_column(db)
            self._ensure_notes_column(db)
            self._ensure_audit_chain_columns(db)
            db.execute("PRAGMA optimize")
        if os.name != "nt":
            os.chmod(self.database_path, OWNER_ONLY_FILE_MODE)

    def _ensure_auth_version_column(self, db: sqlite3.Connection) -> None:
        columns = {str(row[1]) for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "auth_version" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1")

    def _ensure_audit_chain_columns(self, db: sqlite3.Connection) -> None:
        columns = {str(row[1]) for row in db.execute("PRAGMA table_info(audit_events)").fetchall()}
        if "prev_hash" not in columns:
            db.execute(
                "ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'GENESIS'"
            )
        if "chain_hash" not in columns:
            db.execute("ALTER TABLE audit_events ADD COLUMN chain_hash TEXT NOT NULL DEFAULT ''")
        if "chain_version" not in columns:
            db.execute(
                "ALTER TABLE audit_events ADD COLUMN chain_version INTEGER NOT NULL DEFAULT 1"
            )

        needs_migration = db.execute(
            """
            SELECT 1 FROM audit_events
            WHERE chain_hash = '' OR chain_version != ?
            LIMIT 1
            """,
            (AUDIT_CHAIN_VERSION,),
        ).fetchone()
        if not needs_migration:
            return

        user_rows = db.execute(
            "SELECT DISTINCT user_id FROM audit_events ORDER BY user_id"
        ).fetchall()
        for user_row in user_rows:
            user_id = int(user_row["user_id"])
            previous = "GENESIS"
            rows = db.execute(
                """
                SELECT id, user_id, action, detail, created_at
                FROM audit_events
                WHERE user_id = ?
                ORDER BY id ASC
                """,
                (user_id,),
            ).fetchall()
            for row in rows:
                chain_hash = self._audit_digest(
                    previous,
                    user_id,
                    str(row["action"]),
                    str(row["detail"]),
                    str(row["created_at"]),
                )
                db.execute(
                    """
                    UPDATE audit_events
                    SET prev_hash = ?, chain_hash = ?, chain_version = ?
                    WHERE id = ?
                    """,
                    (previous, chain_hash, AUDIT_CHAIN_VERSION, int(row["id"])),
                )
                previous = chain_hash

    def _ensure_notes_column(self, db: sqlite3.Connection) -> None:
        columns = {
            str(row[1]) for row in db.execute("PRAGMA table_info(encrypted_assets)").fetchall()
        }
        if "notes" not in columns:
            db.execute("ALTER TABLE encrypted_assets ADD COLUMN notes TEXT NOT NULL DEFAULT ''")

    def _ensure_tags_column(self, db: sqlite3.Connection) -> None:
        columns = {
            str(row[1]) for row in db.execute("PRAGMA table_info(encrypted_assets)").fetchall()
        }
        if "tags" not in columns:
            db.execute("ALTER TABLE encrypted_assets ADD COLUMN tags TEXT NOT NULL DEFAULT ''")

    def create_user(self, username: str, password: str) -> User:
        username = username.strip().lower()
        if not username:
            raise ValueError("Username is required.")
        if len(username) > MAX_USERNAME_LENGTH:
            raise ValueError(f"Username must be {MAX_USERNAME_LENGTH} characters or fewer.")
        if not _USERNAME_RE.fullmatch(username) or username[-1] in "_.-":
            raise ValueError(
                "Username may use lowercase letters, numbers, dots, underscores, and hyphens, "
                "and must start and end with a letter or number."
            )
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters.")
        if len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password must be {MAX_PASSWORD_LENGTH} characters or fewer.")

        now = _utc_now()
        password_hash = generate_password_hash(password)
        private_pem, public_pem = generate_rsa_key_pair(password)
        created_paths: list[Path] = []

        try:
            with self._connect() as db:
                cursor = db.execute(
                    """
                    INSERT INTO users (username, password_hash, auth_version, created_at)
                    VALUES (?, ?, 1, ?)
                    """,
                    (username, password_hash, now),
                )
                user_id = int(cursor.lastrowid)
                private_path = self.private_key_path(user_id)
                public_path = self.public_key_path(user_id)
                _atomic_write_owner_only_file(private_path, private_pem)
                created_paths.append(private_path)
                _atomic_write_owner_only_file(public_path, public_pem)
                created_paths.append(public_path)
        except Exception:
            for path in created_paths:
                path.unlink(missing_ok=True)
            raise
        return self.get_user(user_id)

    def authenticate_user(self, username: str, password: str) -> User | None:
        if len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH:
            return None
        user = self.get_user_by_username(username.strip().lower())
        if user and check_password_hash(user.password_hash, password):
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

    def private_key_path(self, user_id: int) -> Path:
        return self.key_dir / f"user-{user_id}-private.pem"

    def public_key_path(self, user_id: int) -> Path:
        return self.key_dir / f"user-{user_id}-public.pem"

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
        tags: str = "",
        notes: str = "",
    ) -> EncryptedAsset:
        safe_name = secure_filename(original_filename) or "image"
        if len(safe_name) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename must be {MAX_FILENAME_LENGTH} characters or fewer.")
        normalized_tags = _normalize_tags(tags)
        normalized_notes = _normalize_notes(notes)
        stored_filename = f"{uuid4().hex}.enc"
        ciphertext_path = self._vault_path(stored_filename)
        _atomic_write_owner_only_file(ciphertext_path, ciphertext)
        now = _utc_now()

        try:
            with self._connect() as db:
                cursor = db.execute(
                    """
                    INSERT INTO encrypted_assets (
                        user_id, original_filename, stored_filename, algorithm, mime_type,
                        image_format, width, height, metadata_json, tags, notes, created_at
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
                        json.dumps(metadata, sort_keys=True),
                        normalized_tags,
                        normalized_notes,
                        now,
                    ),
                )
                asset_id = int(cursor.lastrowid)
        except Exception:
            ciphertext_path.unlink(missing_ok=True)
            raise
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
        query: str = "",
        algorithm: str = "",
        tag: str = "",
        sort: str = "newest",
    ) -> list[EncryptedAsset]:
        sql = "SELECT * FROM encrypted_assets WHERE user_id = ?"
        params: list[object] = [user_id]

        if query.strip():
            sql += " AND (original_filename LIKE ? OR tags LIKE ? OR notes LIKE ?)"
            params.extend([f"%{query.strip()}%", f"%{query.strip()}%", f"%{query.strip()}%"])
        if algorithm.strip():
            sql += " AND algorithm = ?"
            params.append(algorithm.strip())
        if tag.strip():
            sql += " AND (',' || tags || ',') LIKE ?"
            params.append(f"%,{tag.strip().lower()},%")

        order_map = {
            "newest": "id DESC",
            "oldest": "id ASC",
            "name": "original_filename COLLATE NOCASE ASC",
            "largest": "width * height DESC",
        }
        sql += f" ORDER BY {order_map.get(sort, 'id DESC')}"

        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        return [_asset_from_row(row) for row in rows]

    def find_asset_by_content_hash(self, user_id: int, content_hash: str) -> EncryptedAsset | None:
        if not content_hash:
            return None
        for asset in self.list_assets(user_id):
            if asset.metadata.get("content_hash") == content_hash:
                return asset
        return None

    def change_user_password(self, user_id: int, old_password: str, new_password: str) -> User:
        user = self.get_user(user_id)
        if not check_password_hash(user.password_hash, old_password):
            raise ValueError("Current password is incorrect.")
        if len(new_password) < 10:
            raise ValueError("New password must be at least 10 characters.")
        if len(new_password.encode("utf-8")) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"New password must be {MAX_PASSWORD_LENGTH} characters or fewer.")
        if old_password == new_password:
            raise ValueError("New password must be different from the current password.")

        from .crypto import rewrap_private_key

        private_pem = self.read_private_key(user_id)
        new_private_pem = rewrap_private_key(private_pem, old_password, new_password)
        password_hash = generate_password_hash(new_password)
        private_path = self.private_key_path(user_id)
        _atomic_write_owner_only_file(private_path, new_private_pem)
        try:
            with self._connect() as db:
                db.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, auth_version = auth_version + 1
                    WHERE id = ?
                    """,
                    (password_hash, user_id),
                )
        except Exception:
            _atomic_write_owner_only_file(private_path, private_pem)
            raise
        return self.get_user(user_id)

    def bulk_update_tags(self, asset_ids: list[int], user_id: int, tags: str) -> int:
        updated = 0
        for asset_id in asset_ids:
            try:
                self.update_asset_tags(asset_id, user_id, tags)
                updated += 1
            except (LookupError, PermissionError):
                continue
        return updated

    def update_asset_notes(self, asset_id: int, user_id: int, notes: str) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")
        with self._connect() as db:
            db.execute(
                "UPDATE encrypted_assets SET notes = ? WHERE id = ?",
                (_normalize_notes(notes), asset_id),
            )
        return self.get_asset(asset_id)

    def update_asset_tags(self, asset_id: int, user_id: int, tags: str) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")
        normalized = _normalize_tags(tags)
        with self._connect() as db:
            db.execute(
                "UPDATE encrypted_assets SET tags = ? WHERE id = ?",
                (normalized, asset_id),
            )
        return self.get_asset(asset_id)

    def update_asset_filename(self, asset_id: int, user_id: int, filename: str) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")
        safe_name = secure_filename(filename.strip()) or asset.original_filename
        if len(safe_name) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename must be {MAX_FILENAME_LENGTH} characters or fewer.")
        with self._connect() as db:
            db.execute(
                "UPDATE encrypted_assets SET original_filename = ? WHERE id = ?",
                (safe_name, asset_id),
            )
        return self.get_asset(asset_id)

    def delete_assets(self, asset_ids: list[int], user_id: int) -> list[EncryptedAsset]:
        deleted: list[EncryptedAsset] = []
        for asset_id in asset_ids:
            deleted.append(self.delete_asset(asset_id, user_id))
        return deleted

    def read_ciphertext(self, asset: EncryptedAsset) -> bytes:
        return self._vault_path(asset.stored_filename).read_bytes()

    def delete_asset(self, asset_id: int, user_id: int) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")

        ciphertext_path = self._vault_path(asset.stored_filename)
        with self._connect() as db:
            db.execute("DELETE FROM encrypted_assets WHERE id = ?", (asset_id,))
        if ciphertext_path.exists():
            ciphertext_path.unlink()
        return asset

    def record_audit(self, user_id: int, action: str, detail: str) -> None:
        now = _utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prev = db.execute(
                """
                SELECT chain_hash FROM audit_events
                WHERE user_id = ? AND chain_hash != ''
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            prev_hash = str(prev[0]) if prev and prev[0] else "GENESIS"
            chain_hash = self._audit_digest(prev_hash, user_id, action, detail, now)
            db.execute(
                """
                INSERT INTO audit_events (
                    user_id, action, detail, created_at, prev_hash, chain_hash,
                    chain_version
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    action,
                    detail,
                    now,
                    prev_hash,
                    chain_hash,
                    AUDIT_CHAIN_VERSION,
                ),
            )

    def verify_audit_chain(self, user_id: int) -> dict[str, int | bool | str]:
        ordered = self.list_all_audit_events(user_id)
        previous = "GENESIS"
        for event in ordered:
            expected = self._audit_digest(
                previous,
                event.user_id,
                event.action,
                event.detail,
                event.created_at,
            )
            if event.prev_hash != previous or not hmac.compare_digest(
                event.chain_hash,
                expected,
            ):
                return {
                    "valid": False,
                    "checked": len(ordered),
                    "broken_at": event.id,
                    "tip": event.chain_hash,
                }
            previous = event.chain_hash
        return {
            "valid": True,
            "checked": len(ordered),
            "tip": previous,
        }

    def list_audit_events(self, user_id: int, *, limit: int = 25) -> list[AuditEvent]:
        limit = max(1, min(int(limit), 1_000))
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

    def list_all_audit_events(self, user_id: int) -> list[AuditEvent]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM audit_events
                WHERE user_id = ?
                ORDER BY id ASC
                """,
                (user_id,),
            ).fetchall()
        return [_audit_from_row(row) for row in rows]

    def list_tags(self, user_id: int) -> list[str]:
        tags: set[str] = set()
        for asset in self.list_assets(user_id):
            for tag in asset.tags.split(","):
                normalized = tag.strip()
                if normalized:
                    tags.add(normalized)
        return sorted(tags)

    def audit_summary(self, user_id: int) -> dict[str, int]:
        events = self.list_audit_events(user_id, limit=500)
        summary: dict[str, int] = {}
        for event in events:
            summary[event.action] = summary.get(event.action, 0) + 1
        return summary

    def vault_stats(self, user_id: int) -> VaultStats:
        assets = self.list_assets(user_id)
        algorithms: dict[str, int] = {}
        ciphertext_bytes = 0
        for asset in assets:
            algorithms[asset.algorithm] = algorithms.get(asset.algorithm, 0) + 1
            ciphertext_path = self._vault_path(asset.stored_filename)
            if ciphertext_path.exists():
                ciphertext_bytes += ciphertext_path.stat().st_size
        return VaultStats(
            asset_count=len(assets),
            ciphertext_bytes=ciphertext_bytes,
            algorithms=algorithms,
        )

    def _vault_path(self, stored_filename: str) -> Path:
        if not _STORED_FILENAME_RE.fullmatch(stored_filename):
            raise ValueError("Stored ciphertext filename is invalid.")
        return self.vault_dir / stored_filename

    def _audit_digest(
        self,
        previous: str,
        user_id: int,
        action: str,
        detail: str,
        created_at: str,
    ) -> str:
        payload = json.dumps(
            {
                "action": action,
                "created_at": created_at,
                "detail": detail,
                "previous": previous,
                "schema": "image-encryption-system.audit.v2",
                "user_id": user_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hmac.new(self.audit_key, payload, hashlib.sha256).hexdigest()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _restrict_owner_access(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, OWNER_ONLY_DIR_MODE)


def _atomic_write_owner_only_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        if os.name != "nt":
            os.chmod(temporary_path, OWNER_ONLY_FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        if os.name != "nt":
            os.chmod(path, OWNER_ONLY_FILE_MODE)
    except Exception:
        with suppress(OSError):
            os.close(fd)
        temporary_path.unlink(missing_ok=True)
        raise


def _user_from_row(row: sqlite3.Row) -> User:
    keys = row.keys()
    return User(
        id=int(row["id"]),
        username=str(row["username"]),
        password_hash=str(row["password_hash"]),
        auth_version=int(row["auth_version"]) if "auth_version" in keys else 1,
        created_at=str(row["created_at"]),
    )


def _asset_from_row(row: sqlite3.Row) -> EncryptedAsset:
    keys = row.keys()
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
        tags=str(row["tags"]) if "tags" in keys else "",
        notes=str(row["notes"]) if "notes" in keys else "",
        created_at=str(row["created_at"]),
    )


def _normalize_tags(tags: str) -> str:
    parts = [part.strip().lower() for part in tags.split(",") if part.strip()]
    normalized = ",".join(dict.fromkeys(parts))
    if len(normalized) > MAX_TAGS_LENGTH:
        raise ValueError(f"Tags must be {MAX_TAGS_LENGTH} characters or fewer.")
    return normalized


def _normalize_notes(notes: str) -> str:
    normalized = notes.strip()
    if len(normalized) > MAX_NOTES_LENGTH:
        raise ValueError(f"Notes must be {MAX_NOTES_LENGTH} characters or fewer.")
    return normalized


def _audit_from_row(row: sqlite3.Row) -> AuditEvent:
    keys = row.keys()
    return AuditEvent(
        id=int(row["id"]),
        user_id=int(row["user_id"]),
        action=str(row["action"]),
        detail=str(row["detail"]),
        created_at=str(row["created_at"]),
        prev_hash=str(row["prev_hash"]) if "prev_hash" in keys else "GENESIS",
        chain_hash=str(row["chain_hash"]) if "chain_hash" in keys else "",
    )
