from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import sqlite3
from typing import Any
from uuid import uuid4
import zipfile

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .crypto import generate_rsa_key_pair


MAX_BACKUP_UNCOMPRESSED = 64 * 1024 * 1024


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
    created_at: str


@dataclass(frozen=True)
class AssetShare:
    id: int
    asset_id: int
    recipient_user_id: int
    key_wrap: dict[str, Any]
    created_at: str


@dataclass(frozen=True)
class SharedInboxItem:
    share: AssetShare
    asset: EncryptedAsset
    owner_username: str


@dataclass(frozen=True)
class AuditEvent:
    id: int
    user_id: int | None
    action: str
    asset_id: int | None
    ip: str | None
    created_at: str


class VaultStore:
    def __init__(self, database_path: Path, vault_dir: Path, key_dir: Path):
        self.database_path = Path(database_path)
        self.vault_dir = Path(vault_dir)
        self.key_dir = Path(key_dir)

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

                CREATE TABLE IF NOT EXISTS shares (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    recipient_user_id INTEGER NOT NULL,
                    key_wrap_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES encrypted_assets (id) ON DELETE CASCADE,
                    FOREIGN KEY (recipient_user_id) REFERENCES users (id),
                    UNIQUE (asset_id, recipient_user_id)
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

                CREATE INDEX IF NOT EXISTS idx_assets_user ON encrypted_assets (user_id);
                CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares (recipient_user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events (user_id, id DESC);
                """
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
        self.private_key_path(user_id).write_bytes(private_pem)
        self.public_key_path(user_id).write_bytes(public_pem)
        return self.get_user(user_id)

    def authenticate_user(self, username: str, password: str) -> User | None:
        user = self.get_user_by_username(username)
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
    ) -> EncryptedAsset:
        safe_name = secure_filename(original_filename) or "image"
        stored_filename = f"{uuid4().hex}.enc"
        (self.vault_dir / stored_filename).write_bytes(ciphertext)
        now = _utc_now()

        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO encrypted_assets (
                    user_id, original_filename, stored_filename, algorithm, mime_type,
                    image_format, width, height, metadata_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        query: str | None = None,
        algorithm: str | None = None,
    ) -> list[EncryptedAsset]:
        sql = "SELECT * FROM encrypted_assets WHERE user_id = ?"
        params: list[Any] = [user_id]
        if query:
            sql += " AND LOWER(original_filename) LIKE ?"
            params.append(f"%{query.strip().lower()}%")
        if algorithm:
            sql += " AND algorithm = ?"
            params.append(algorithm)
        sql += " ORDER BY id DESC"
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
            db.execute(
                "DELETE FROM encrypted_assets WHERE id = ? AND user_id = ?",
                (asset_id, user_id),
            )
        if path.exists():
            path.unlink()
        return asset

    def read_ciphertext(self, asset: EncryptedAsset) -> bytes:
        return (self.vault_dir / asset.stored_filename).read_bytes()

    def create_share(
        self,
        *,
        asset_id: int,
        recipient_user_id: int,
        key_wrap: dict[str, Any],
    ) -> AssetShare:
        now = _utc_now()
        payload = json.dumps(key_wrap, sort_keys=True)
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO shares (asset_id, recipient_user_id, key_wrap_json, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(asset_id, recipient_user_id) DO UPDATE SET
                    key_wrap_json = excluded.key_wrap_json,
                    created_at = excluded.created_at
                """,
                (asset_id, recipient_user_id, payload, now),
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
                    ),
                    asset=_asset_from_row(row),
                    owner_username=str(row["owner_username"]),
                )
            )
        return items

    def list_recipients_for_owner(self, owner_user_id: int) -> dict[int, list[str]]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT s.asset_id, u.username
                FROM shares AS s
                JOIN encrypted_assets AS ea ON ea.id = s.asset_id
                JOIN users AS u ON u.id = s.recipient_user_id
                WHERE ea.user_id = ?
                ORDER BY u.username
                """,
                (owner_user_id,),
            ).fetchall()
        mapping: dict[int, list[str]] = {}
        for row in rows:
            mapping.setdefault(int(row["asset_id"]), []).append(str(row["username"]))
        return mapping

    def add_audit_event(
        self,
        user_id: int | None,
        action: str,
        *,
        asset_id: int | None = None,
        ip: str | None = None,
    ) -> AuditEvent:
        now = _utc_now()
        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO audit_events (user_id, action, asset_id, ip, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, action, asset_id, ip, now),
            )
            event_id = int(cursor.lastrowid)
            row = db.execute("SELECT * FROM audit_events WHERE id = ?", (event_id,)).fetchone()
        assert row is not None
        return _audit_from_row(row)

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
        manifest = {
            "version": 2,
            "exported_at": _utc_now(),
            "username": user.username,
            "assets": [],
        }
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for asset in assets:
                blob_name = f"assets/{asset.stored_filename}"
                archive.writestr(blob_name, self.read_ciphertext(asset))
                manifest["assets"].append(
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
                    }
                )
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        return buffer.getvalue()

    def import_backup(self, user_id: int, archive_bytes: bytes) -> int:
        buffer = BytesIO(archive_bytes)
        if not zipfile.is_zipfile(buffer):
            raise ValueError("Backup file is not a valid zip archive.")
        buffer.seek(0)
        restored = 0
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
            assets = manifest.get("assets")
            if not isinstance(assets, list):
                raise ValueError("Backup manifest does not list assets.")
            for item in assets:
                if not isinstance(item, dict):
                    raise ValueError("Backup asset entry is invalid.")
                blob_name = _safe_zip_member(str(item.get("blob", "")))
                if blob_name not in names:
                    raise ValueError(f"Backup is missing ciphertext {blob_name}.")
                ciphertext = archive.read(blob_name)
                metadata = item.get("metadata")
                if not isinstance(metadata, dict):
                    raise ValueError("Backup asset is missing encryption metadata.")
                self.save_asset(
                    user_id=user_id,
                    original_filename=str(item.get("original_filename") or "image"),
                    algorithm=str(item.get("algorithm") or ""),
                    mime_type=str(item.get("mime_type") or "application/octet-stream"),
                    image_format=str(item.get("image_format") or "UNKNOWN"),
                    width=int(item.get("width") or 0),
                    height=int(item.get("height") or 0),
                    metadata=metadata,
                    ciphertext=ciphertext,
                )
                restored += 1
        return restored

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_zip_member(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ValueError("Backup archive contains an unsafe path.")
    return name


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
        created_at=str(row["created_at"]),
    )


def _share_from_row(row: sqlite3.Row) -> AssetShare:
    return AssetShare(
        id=int(row["id"]),
        asset_id=int(row["asset_id"]),
        recipient_user_id=int(row["recipient_user_id"]),
        key_wrap=json.loads(str(row["key_wrap_json"])),
        created_at=str(row["created_at"]),
    )


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
