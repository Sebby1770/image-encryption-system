from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .crypto import generate_rsa_key_pair

OWNER_ONLY_DIR_MODE = 0o700
OWNER_ONLY_FILE_MODE = 0o600


@dataclass(frozen=True)
class User:
    id: int
    username: str
    password_hash: str
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
    created_at: str


@dataclass(frozen=True)
class AuditEvent:
    id: int
    user_id: int
    action: str
    detail: str
    created_at: str


@dataclass(frozen=True)
class VaultStats:
    asset_count: int
    ciphertext_bytes: int
    algorithms: dict[str, int]


class VaultStore:
    def __init__(self, database_path: Path, vault_dir: Path, key_dir: Path):
        self.database_path = Path(database_path)
        self.vault_dir = Path(vault_dir)
        self.key_dir = Path(key_dir)

    def init(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        _restrict_owner_access(self.vault_dir)
        _restrict_owner_access(self.key_dir)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
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
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
                """
            )
            self._ensure_tags_column(db)

    def _ensure_tags_column(self, db: sqlite3.Connection) -> None:
        columns = {
            str(row[1])
            for row in db.execute("PRAGMA table_info(encrypted_assets)").fetchall()
        }
        if "tags" not in columns:
            db.execute(
                "ALTER TABLE encrypted_assets ADD COLUMN tags TEXT NOT NULL DEFAULT ''"
            )

    def create_user(self, username: str, password: str) -> User:
        username = username.strip().lower()
        if not username:
            raise ValueError("Username is required.")
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters.")

        now = _utc_now()
        password_hash = generate_password_hash(password)

        with self._connect() as db:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, now),
            )
            user_id = int(cursor.lastrowid)

        private_pem, public_pem = generate_rsa_key_pair(password)
        _write_owner_only_file(self.private_key_path(user_id), private_pem)
        _write_owner_only_file(self.public_key_path(user_id), public_pem)
        return self.get_user(user_id)

    def authenticate_user(self, username: str, password: str) -> User | None:
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
    ) -> EncryptedAsset:
        safe_name = secure_filename(original_filename) or "image"
        stored_filename = f"{uuid4().hex}.enc"
        _write_owner_only_file(self.vault_dir / stored_filename, ciphertext)
        now = _utc_now()

        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO encrypted_assets (
                    user_id, original_filename, stored_filename, algorithm, mime_type,
                    image_format, width, height, metadata_json, tags, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    _normalize_tags(tags),
                    now,
                ),
            )
            asset_id = int(cursor.lastrowid)
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
            sql += " AND (original_filename LIKE ? OR tags LIKE ?)"
            params.extend([f"%{query.strip()}%", f"%{query.strip()}%"])
        if algorithm.strip():
            sql += " AND algorithm = ?"
            params.append(algorithm.strip())
        if tag.strip():
            sql += " AND tags LIKE ?"
            params.append(f"%{tag.strip()}%")

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

    def delete_assets(self, asset_ids: list[int], user_id: int) -> list[EncryptedAsset]:
        deleted: list[EncryptedAsset] = []
        for asset_id in asset_ids:
            deleted.append(self.delete_asset(asset_id, user_id))
        return deleted

    def read_ciphertext(self, asset: EncryptedAsset) -> bytes:
        return (self.vault_dir / asset.stored_filename).read_bytes()

    def delete_asset(self, asset_id: int, user_id: int) -> EncryptedAsset:
        asset = self.get_asset(asset_id)
        if asset.user_id != user_id:
            raise PermissionError("You do not have access to this encrypted image.")

        ciphertext_path = self.vault_dir / asset.stored_filename
        with self._connect() as db:
            db.execute("DELETE FROM encrypted_assets WHERE id = ?", (asset_id,))
        if ciphertext_path.exists():
            ciphertext_path.unlink()
        return asset

    def record_audit(self, user_id: int, action: str, detail: str) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO audit_events (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
                (user_id, action, detail, _utc_now()),
            )

    def list_audit_events(self, user_id: int, *, limit: int = 25) -> list[AuditEvent]:
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
            ciphertext_path = self.vault_dir / asset.stored_filename
            if ciphertext_path.exists():
                ciphertext_bytes += ciphertext_path.stat().st_size
        return VaultStats(
            asset_count=len(assets),
            ciphertext_bytes=ciphertext_bytes,
            algorithms=algorithms,
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _restrict_owner_access(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, OWNER_ONLY_DIR_MODE)


def _write_owner_only_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        path.write_bytes(content)
        return

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, OWNER_ONLY_FILE_MODE)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
    os.chmod(path, OWNER_ONLY_FILE_MODE)


def _user_from_row(row: sqlite3.Row) -> User:
    return User(
        id=int(row["id"]),
        username=str(row["username"]),
        password_hash=str(row["password_hash"]),
        created_at=str(row["created_at"]),
    )


def _asset_from_row(row: sqlite3.Row) -> EncryptedAsset:
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
        tags=str(row["tags"]) if "tags" in row.keys() else "",
        created_at=str(row["created_at"]),
    )


def _normalize_tags(tags: str) -> str:
    parts = [part.strip().lower() for part in tags.split(",") if part.strip()]
    return ",".join(dict.fromkeys(parts))


def _audit_from_row(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        id=int(row["id"]),
        user_id=int(row["user_id"]),
        action=str(row["action"]),
        detail=str(row["detail"]),
        created_at=str(row["created_at"]),
    )
