from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .crypto import generate_rsa_key_pair, reencrypt_private_key


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


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
    byte_size: int
    metadata: dict[str, Any]
    created_at: str


@dataclass(frozen=True)
class AuditEvent:
    id: int
    user_id: int | None
    event_type: str
    detail: str
    ip_address: str
    created_at: str


class VaultStore:
    def __init__(self, database_path: Path, vault_dir: Path, key_dir: Path):
        self.database_path = Path(database_path)
        self.vault_dir = Path(vault_dir)
        self.key_dir = Path(key_dir)

    def init(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        _ensure_private_dir(self.vault_dir)
        _ensure_private_dir(self.key_dir)
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
                    byte_size INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    event_type TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    ip_address TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_lockouts (
                    username TEXT PRIMARY KEY,
                    failed_count INTEGER NOT NULL,
                    locked_until TEXT,
                    last_failed_at TEXT
                );
                """
            )
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(encrypted_assets)").fetchall()
            }
            if "byte_size" not in columns:
                db.execute(
                    "ALTER TABLE encrypted_assets ADD COLUMN byte_size INTEGER NOT NULL DEFAULT 0"
                )

    def create_user(self, username: str, password: str) -> User:
        username = username.strip().lower()
        if not username:
            raise ValueError("Username is required.")
        if len(username) > 64:
            raise ValueError("Username must be 64 characters or fewer.")
        if not username.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, hyphens, and underscores.")
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters.")

        now = _utc_now()
        password_hash = generate_password_hash(password, method="scrypt")

        with self._connect() as db:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, now),
            )
            user_id = int(cursor.lastrowid)

        try:
            private_pem, public_pem = generate_rsa_key_pair(password)
            _write_secret_file(self.private_key_path(user_id), private_pem)
            _write_secret_file(self.public_key_path(user_id), public_pem)
        except Exception:
            self.private_key_path(user_id).unlink(missing_ok=True)
            self.public_key_path(user_id).unlink(missing_ok=True)
            with self._connect() as db:
                db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            raise
        return self.get_user(user_id)

    def authenticate_user(self, username: str, password: str) -> User | None:
        user = self.get_user_by_username(username.strip().lower())
        if user and check_password_hash(user.password_hash, password):
            return user
        return None

    def change_password(self, user_id: int, old_password: str, new_password: str) -> None:
        user = self.get_user(user_id)
        if not check_password_hash(user.password_hash, old_password):
            raise ValueError("Current password is incorrect.")
        if len(new_password) < 10:
            raise ValueError("Password must be at least 10 characters.")
        if old_password == new_password:
            raise ValueError("New password must be different from the current password.")

        private_pem = self.read_private_key(user_id)
        rewrapped = reencrypt_private_key(private_pem, old_password, new_password)
        _write_secret_file(self.private_key_path(user_id), rewrapped)
        with self._connect() as db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password, method="scrypt"), user_id),
            )

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
    ) -> EncryptedAsset:
        safe_name = secure_filename(original_filename) or "image"
        stored_filename = f"{uuid4().hex}.enc"
        ciphertext_path = self.vault_dir / stored_filename
        _write_secret_file(ciphertext_path, ciphertext)
        now = _utc_now()

        try:
            with self._connect() as db:
                cursor = db.execute(
                    """
                    INSERT INTO encrypted_assets (
                        user_id, original_filename, stored_filename, algorithm, mime_type,
                        image_format, width, height, byte_size, metadata_json, created_at
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
                        len(ciphertext),
                        json.dumps(metadata, sort_keys=True),
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

    def list_assets(self, user_id: int) -> list[EncryptedAsset]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM encrypted_assets WHERE user_id = ? ORDER BY id DESC",
                (user_id,),
            ).fetchall()
        return [_asset_from_row(row) for row in rows]

    def delete_asset(self, asset: EncryptedAsset) -> None:
        ciphertext_path = self.vault_dir / asset.stored_filename
        with self._connect() as db:
            db.execute("DELETE FROM encrypted_assets WHERE id = ?", (asset.id,))
        ciphertext_path.unlink(missing_ok=True)

    def read_ciphertext(self, asset: EncryptedAsset) -> bytes:
        return (self.vault_dir / asset.stored_filename).read_bytes()

    def record_audit(
        self,
        *,
        event_type: str,
        user_id: int | None = None,
        detail: str = "",
        ip_address: str = "",
    ) -> None:
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO audit_events (user_id, event_type, detail, ip_address, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, event_type, detail, ip_address, _utc_now()),
            )

    def list_audit_for_user(self, user_id: int, limit: int = 50) -> list[AuditEvent]:
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

    def register_auth_failure(self, username: str, lockout_seconds: int, max_failures: int) -> None:
        username = username.strip().lower()
        if not username:
            return
        now = datetime.now(timezone.utc)
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM auth_lockouts WHERE username = ?",
                (username,),
            ).fetchone()
            failed_count = int(row["failed_count"]) + 1 if row else 1
            locked_until = None
            if failed_count >= max_failures:
                locked_until = (now + timedelta(seconds=lockout_seconds)).isoformat(timespec="seconds")
            db.execute(
                """
                INSERT INTO auth_lockouts (username, failed_count, locked_until, last_failed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    failed_count = excluded.failed_count,
                    locked_until = excluded.locked_until,
                    last_failed_at = excluded.last_failed_at
                """,
                (username, failed_count, locked_until, now.isoformat(timespec="seconds")),
            )

    def clear_auth_failures(self, username: str) -> None:
        username = username.strip().lower()
        with self._connect() as db:
            db.execute("DELETE FROM auth_lockouts WHERE username = ?", (username,))

    def lockout_retry_after(self, username: str) -> int:
        username = username.strip().lower()
        with self._connect() as db:
            row = db.execute(
                "SELECT locked_until FROM auth_lockouts WHERE username = ?",
                (username,),
            ).fetchone()
        if not row or not row["locked_until"]:
            return 0
        locked_until = datetime.fromisoformat(str(row["locked_until"]))
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds())
        if remaining <= 0:
            self.clear_auth_failures(username)
            return 0
        return remaining

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, PRIVATE_DIR_MODE)
    except OSError:
        pass


def _write_secret_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, PRIVATE_FILE_MODE)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)
    try:
        os.chmod(path, PRIVATE_FILE_MODE)
    except OSError:
        pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _user_from_row(row: sqlite3.Row) -> User:
    return User(
        id=int(row["id"]),
        username=str(row["username"]),
        password_hash=str(row["password_hash"]),
        created_at=str(row["created_at"]),
    )


def _asset_from_row(row: sqlite3.Row) -> EncryptedAsset:
    keys = row.keys()
    byte_size = int(row["byte_size"]) if "byte_size" in keys else 0
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
        byte_size=byte_size,
        metadata=json.loads(str(row["metadata_json"])),
        created_at=str(row["created_at"]),
    )


def _audit_from_row(row: sqlite3.Row) -> AuditEvent:
    user_id = row["user_id"]
    return AuditEvent(
        id=int(row["id"]),
        user_id=int(user_id) if user_id is not None else None,
        event_type=str(row["event_type"]),
        detail=str(row["detail"]),
        ip_address=str(row["ip_address"]),
        created_at=str(row["created_at"]),
    )
