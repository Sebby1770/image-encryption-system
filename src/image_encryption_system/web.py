from __future__ import annotations

import hashlib
import hmac
import json as json_module
import secrets
import time
import zipfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from math import ceil
from pathlib import Path
from sqlite3 import IntegrityError
from threading import Lock
from typing import TypeVar

import jwt
from flask import (
    Flask,
    Response,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from PIL import Image, UnidentifiedImageError
from werkzeug.exceptions import RequestEntityTooLarge

from .config import APP_VERSION, Config
from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
)
from .storage import EncryptedAsset, User, VaultStore
from .uploads import AAD_VERSION, asset_aad, encrypt_upload, normalize_filename

F = TypeVar("F", bound=Callable)


class CredentialThrottle:
    def __init__(
        self,
        *,
        max_attempts: int,
        window_seconds: int,
        lockout_seconds: int,
        max_keys: int = 10_000,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.max_keys = max_keys
        self.failures: dict[str, list[float]] = {}
        self.locked_until: dict[str, float] = {}
        self._lock = Lock()

    def is_limited(self, key: str) -> bool:
        return self.retry_after(key) is not None

    def retry_after(self, key: str) -> int | None:
        with self._lock:
            now = time.monotonic()
            until = self.locked_until.get(key)
            if until is None:
                return None
            if until <= now:
                self.locked_until.pop(key, None)
                return None
            return max(1, ceil(until - now))

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._make_room(key, now)
            window_start = now - self.window_seconds
            attempts = [stamp for stamp in self.failures.get(key, []) if stamp >= window_start]
            attempts.append(now)
            if len(attempts) >= self.max_attempts:
                self.locked_until[key] = now + self.lockout_seconds
                self.failures[key] = []
            else:
                self.failures[key] = attempts

    def reset(self, key: str) -> None:
        with self._lock:
            self.failures.pop(key, None)
            self.locked_until.pop(key, None)

    def _make_room(self, incoming_key: str, now: float) -> None:
        known_keys = set(self.failures) | set(self.locked_until)
        if incoming_key in known_keys or len(known_keys) < self.max_keys:
            return
        window_start = now - self.window_seconds
        self.failures = {
            key: [stamp for stamp in attempts if stamp >= window_start]
            for key, attempts in self.failures.items()
            if any(stamp >= window_start for stamp in attempts)
        }
        self.locked_until = {key: until for key, until in self.locked_until.items() if until > now}
        while len(set(self.failures) | set(self.locked_until)) >= self.max_keys:
            if self.failures:
                self.failures.pop(next(iter(self.failures)))
            elif self.locked_until:
                self.locked_until.pop(next(iter(self.locked_until)))
            else:
                break


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.config["AUDIT_HMAC_KEY"] = app.config.get("AUDIT_HMAC_KEY") or app.config["SECRET_KEY"]
    _validate_runtime_secrets(app)
    Image.MAX_IMAGE_PIXELS = app.config["MAX_IMAGE_PIXELS"]

    app.config["INSTANCE_DIR"] = Path(app.config["INSTANCE_DIR"])
    app.config["DATABASE_PATH"] = Path(app.config["DATABASE_PATH"])
    app.config["VAULT_DIR"] = Path(app.config["VAULT_DIR"])
    app.config["KEY_DIR"] = Path(app.config["KEY_DIR"])
    app.permanent_session_lifetime = timedelta(
        seconds=int(app.config["PERMANENT_SESSION_LIFETIME_SECONDS"])
    )

    store = VaultStore(
        database_path=app.config["DATABASE_PATH"],
        vault_dir=app.config["VAULT_DIR"],
        key_dir=app.config["KEY_DIR"],
        audit_key=str(app.config["AUDIT_HMAC_KEY"]).encode("utf-8"),
    )
    store.init()
    app.extensions["vault_store"] = store
    app.extensions["credential_throttle"] = CredentialThrottle(
        max_attempts=app.config["AUTH_RATE_LIMIT_ATTEMPTS"],
        window_seconds=app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"],
        lockout_seconds=app.config["AUTH_RATE_LIMIT_LOCKOUT_SECONDS"],
    )
    app.extensions["decrypt_throttle"] = CredentialThrottle(
        max_attempts=app.config["DECRYPT_RATE_LIMIT_ATTEMPTS"],
        window_seconds=app.config["DECRYPT_RATE_LIMIT_WINDOW_SECONDS"],
        lockout_seconds=app.config["DECRYPT_RATE_LIMIT_LOCKOUT_SECONDS"],
    )
    app.extensions["register_throttle"] = CredentialThrottle(
        max_attempts=app.config["REGISTER_RATE_LIMIT_ATTEMPTS"],
        window_seconds=app.config["REGISTER_RATE_LIMIT_WINDOW_SECONDS"],
        lockout_seconds=app.config["REGISTER_RATE_LIMIT_LOCKOUT_SECONDS"],
    )

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; connect-src 'self'; "
            "font-src 'self'; form-action 'self'; frame-ancestors 'none'; "
            "img-src 'self' blob: data:; object-src 'none'; script-src 'self'; "
            "style-src 'self'"
        )
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge) -> Response:
        if request.path.startswith("/api/"):
            return jsonify({"error": "request exceeds the 16 MiB upload limit"}), 413
        flash("That upload exceeds the 16 MiB limit.", "error")
        return redirect(url_for("dashboard" if session.get("user_id") else "index"))

    @app.get("/health")
    def health() -> Response:
        return jsonify(
            {
                "status": "ok",
                "service": "image-encryption-system",
                "version": APP_VERSION,
            }
        )

    @app.context_processor
    def inject_globals() -> dict:
        return {
            "current_user": _current_user(store),
            "csrf_token": _csrf_token,
            "format_bytes": _format_bytes,
            "asset_unlock_after": _asset_unlock_after,
            "algorithms": [
                (AES_GCM_PASSPHRASE, "AES-GCM passphrase"),
                (RSA_HYBRID, "RSA hybrid"),
            ],
        }

    @app.before_request
    def protect_form_posts() -> Response | None:
        if request.method != "POST" or request.path.startswith("/api/"):
            return None
        if _valid_csrf_token(request.form.get("_csrf_token", "")):
            return None
        flash("Your form session expired. Please try again.", "error")
        return redirect(url_for("index"))

    @app.get("/")
    def index() -> str | Response:
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return render_template("auth.html", mode="login")

    @app.get("/register")
    def register_form() -> str:
        return render_template("auth.html", mode="register")

    @app.post("/register")
    def register() -> Response:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        throttle = app.extensions["register_throttle"]
        throttle_key = f"register:{_remote_address()}"
        retry_after = throttle.retry_after(throttle_key)
        if retry_after is not None:
            flash(
                f"Account creation is temporarily limited. Try again in {retry_after} seconds.",
                "error",
            )
            return redirect(url_for("register_form"))
        throttle.record_failure(throttle_key)
        try:
            user = store.create_user(username, password)
        except IntegrityError:
            flash("That username is already registered.", "error")
            return redirect(url_for("register_form"))
        except (CryptoError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("register_form"))

        session.clear()
        session.permanent = True
        session["user_id"] = user.id
        session["auth_version"] = user.auth_version
        store.record_audit(user.id, "register", f"Account created for {user.username}")
        flash("Account created. Your RSA keys were generated and stored locally.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/login")
    def login() -> Response:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        throttle = app.extensions["credential_throttle"]
        throttle_key = _credential_throttle_key(username)
        retry_after = throttle.retry_after(throttle_key)
        if retry_after is not None:
            flash(
                f"Too many failed sign-in attempts. Please wait {retry_after} seconds.",
                "error",
            )
            return redirect(url_for("index"))

        user = store.authenticate_user(username, password)
        if not user:
            throttle.record_failure(throttle_key)
            flash("Invalid username or password.", "error")
            return redirect(url_for("index"))

        throttle.reset(throttle_key)
        session.clear()
        session.permanent = True
        session["user_id"] = user.id
        session["auth_version"] = user.auth_version
        store.record_audit(user.id, "login", "Signed in via web session")
        flash("Signed in.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout() -> Response:
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("index"))

    @app.get("/dashboard")
    @login_required(store)
    def dashboard() -> str:
        user = _current_user(store)
        query = request.args.get("q", "")
        algorithm = request.args.get("algorithm", "")
        tag = request.args.get("tag", "")
        sort = request.args.get("sort", "newest")
        assets = store.list_assets(
            user.id,
            query=query,
            algorithm=algorithm,
            tag=tag,
            sort=sort,
        )
        stats = store.vault_stats(user.id)
        audit_events = store.list_audit_events(user.id)
        audit_summary = store.audit_summary(user.id)
        all_tags = store.list_tags(user.id)
        vault_health = _vault_health(store, user.id)
        return render_template(
            "dashboard.html",
            assets=assets,
            stats=stats,
            audit_events=audit_events,
            audit_summary=audit_summary,
            vault_health=vault_health,
            all_tags=all_tags,
            query=query,
            filter_algorithm=algorithm,
            filter_tag=tag,
            sort=sort,
        )

    @app.get("/vault/export")
    @login_required(store)
    def export_vault() -> Response:
        user = _current_user(store)
        assets = store.list_assets(user.id)
        archive = BytesIO()
        manifest: list[dict[str, object]] = []
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for asset in assets:
                ciphertext = store.read_ciphertext(asset)
                bundle.writestr(f"ciphertext/{asset.stored_filename}", ciphertext)
                manifest.append(
                    {
                        "id": asset.id,
                        "filename": asset.original_filename,
                        "algorithm": asset.algorithm,
                        "format": asset.image_format,
                        "size": {"width": asset.width, "height": asset.height},
                        "tags": asset.tags,
                        "created_at": asset.created_at,
                        "metadata": asset.metadata,
                    }
                )
            bundle.writestr("manifest.json", json_module.dumps(manifest, indent=2))
        archive.seek(0)
        store.record_audit(user.id, "export", f"Exported vault archive with {len(assets)} assets")
        return send_file(
            archive,
            mimetype="application/zip",
            download_name="encrypted-vault-export.zip",
            as_attachment=True,
        )

    @app.get("/api/docs")
    def api_docs() -> Response:
        return jsonify(
            {
                "service": "image-encryption-system",
                "version": APP_VERSION,
                "authentication": "Bearer JWT from POST /api/token",
                "endpoints": [
                    {"method": "GET", "path": "/health", "description": "Service health"},
                    {"method": "GET", "path": "/api/docs", "description": "This API catalog"},
                    {"method": "POST", "path": "/api/token", "description": "Issue JWT"},
                    {
                        "method": "GET",
                        "path": "/api/stats",
                        "description": "Vault stats and audit summary",
                    },
                    {
                        "method": "GET",
                        "path": "/api/images",
                        "description": "List encrypted assets",
                    },
                    {
                        "method": "POST",
                        "path": "/api/images",
                        "description": "Upload and encrypt image",
                    },
                    {
                        "method": "GET",
                        "path": "/api/images/<id>",
                        "description": "Fetch asset metadata",
                    },
                    {
                        "method": "POST",
                        "path": "/api/images/<id>/decrypt",
                        "description": "Decrypt asset",
                    },
                    {"method": "DELETE", "path": "/api/images/<id>", "description": "Delete asset"},
                    {"method": "GET", "path": "/api/audit", "description": "Recent audit events"},
                    {
                        "method": "GET",
                        "path": "/api/audit/verify",
                        "description": "Verify tamper-evident audit chain",
                    },
                    {
                        "method": "GET",
                        "path": "/api/audit/export",
                        "description": "Export full audit chain JSON",
                    },
                    {
                        "method": "GET",
                        "path": "/api/vault/health",
                        "description": "Composite vault health score",
                    },
                ],
            }
        )

    @app.post("/account/password")
    @login_required(store)
    def change_password() -> Response:
        user = _current_user(store)
        old_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            return redirect(url_for("dashboard"))
        try:
            updated_user = store.change_user_password(user.id, old_password, new_password)
            session["auth_version"] = updated_user.auth_version
            store.record_audit(user.id, "password", "Account password changed")
            flash("Password updated and RSA private key re-wrapped.", "success")
        except (CryptoError, ValueError) as exc:
            flash(str(exc), "error")
        except Exception:
            current_app.logger.exception(
                "Password change failed while updating account credentials"
            )
            flash("Password change failed safely; your existing password is still active.", "error")
        return redirect(url_for("dashboard"))

    @app.post("/images/bulk-tags")
    @login_required(store)
    def bulk_update_tags() -> Response:
        user = _current_user(store)
        raw_ids = request.form.getlist("asset_ids")
        asset_ids = [int(value) for value in raw_ids if value.isdigit()]
        tags = request.form.get("tags", "")
        if not asset_ids:
            flash("Select at least one asset to tag.", "error")
            return redirect(url_for("dashboard"))
        updated = store.bulk_update_tags(asset_ids, user.id, tags)
        store.record_audit(user.id, "update", f"Bulk tagged {updated} asset(s)")
        flash(f"Updated tags on {updated} asset(s).", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/notes")
    @login_required(store)
    def update_notes(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = store.update_asset_notes(asset_id, user.id, request.form.get("notes", ""))
            store.record_audit(user.id, "update", f"Updated notes for {asset.original_filename}")
            flash("Notes updated.", "success")
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/tags")
    @login_required(store)
    def update_tags(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = store.update_asset_tags(asset_id, user.id, request.form.get("tags", ""))
            store.record_audit(user.id, "update", f"Updated tags for {asset.original_filename}")
            flash("Tags updated.", "success")
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/rename")
    @login_required(store)
    def rename_asset(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = store.update_asset_filename(asset_id, user.id, request.form.get("filename", ""))
            store.record_audit(user.id, "update", f"Renamed asset to {asset.original_filename}")
            flash("Filename updated.", "success")
        except (LookupError, PermissionError, ValueError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    @app.post("/vault/import")
    @login_required(store)
    def import_vault_manifest() -> Response:
        user = _current_user(store)
        upload = request.files.get("archive")
        if upload is None or not upload.filename:
            flash("Choose a vault export ZIP to inspect.", "error")
            return redirect(url_for("dashboard"))
        try:
            manifest = _read_bounded_vault_manifest(
                upload.read(),
                max_manifest_bytes=app.config["MAX_VAULT_MANIFEST_BYTES"],
                max_members=app.config["MAX_VAULT_ARCHIVE_MEMBERS"],
            )
            imported = len(manifest)
            store.record_audit(
                user.id, "import", f"Validated vault manifest with {imported} assets"
            )
            flash(
                f"Manifest validated ({imported} assets). Ciphertext remains encrypted.", "success"
            )
        except (KeyError, ValueError, json_module.JSONDecodeError, zipfile.BadZipFile) as exc:
            flash(f"Invalid vault archive: {exc}", "error")
        return redirect(url_for("dashboard"))

    @app.get("/api/vault/health")
    @jwt_required(store)
    def api_vault_health() -> Response:
        user = g.api_user
        return jsonify(_vault_health(store, user.id))

    @app.get("/api/audit/export")
    @jwt_required(store)
    def api_audit_export() -> Response:
        user = g.api_user
        events = store.list_all_audit_events(user.id)
        return jsonify(
            {
                "chain": store.verify_audit_chain(user.id),
                "events": [
                    {
                        "id": event.id,
                        "action": event.action,
                        "detail": event.detail,
                        "created_at": event.created_at,
                        "prev_hash": event.prev_hash,
                        "chain_hash": event.chain_hash,
                    }
                    for event in events
                ],
            }
        )

    @app.get("/audit/export")
    @login_required(store)
    def export_audit_chain() -> Response:
        user = _current_user(store)
        events = store.list_all_audit_events(user.id)
        payload = {
            "chain": store.verify_audit_chain(user.id),
            "events": [
                {
                    "id": event.id,
                    "action": event.action,
                    "detail": event.detail,
                    "created_at": event.created_at,
                    "prev_hash": event.prev_hash,
                    "chain_hash": event.chain_hash,
                }
                for event in events
            ],
        }
        blob = BytesIO(json_module.dumps(payload, indent=2).encode("utf-8"))
        store.record_audit(user.id, "export", "Exported tamper-evident audit chain")
        return send_file(
            blob,
            mimetype="application/json",
            download_name="audit-chain-export.json",
            as_attachment=True,
        )

    @app.get("/api/audit/verify")
    @jwt_required(store)
    def api_verify_audit_chain() -> Response:
        user = g.api_user
        return jsonify(store.verify_audit_chain(user.id))

    @app.post("/audit/verify")
    @login_required(store)
    def verify_audit_chain() -> Response:
        user = _current_user(store)
        result = store.verify_audit_chain(user.id)
        if result["valid"]:
            flash(
                f"Audit chain valid ({result['checked']} events). Tip: {result['tip'][:12]}…",
                "success",
            )
        else:
            flash(f"Audit chain broken at event #{result.get('broken_at')}.", "error")
        return redirect(url_for("dashboard"))

    @app.get("/api/stats")
    @jwt_required(store)
    def api_stats() -> Response:
        user = g.api_user
        stats = store.vault_stats(user.id)
        return jsonify(
            {
                "assets": stats.asset_count,
                "ciphertext_bytes": stats.ciphertext_bytes,
                "algorithms": stats.algorithms,
                "tags": store.list_tags(user.id),
                "audit": store.audit_summary(user.id),
            }
        )

    @app.post("/images/bulk-delete")
    @login_required(store)
    def bulk_delete_images() -> Response:
        user = _current_user(store)
        raw_ids = request.form.getlist("asset_ids")
        asset_ids = [int(value) for value in raw_ids if value.isdigit()]
        if not asset_ids:
            flash("Select at least one encrypted image to delete.", "error")
            return redirect(url_for("dashboard"))

        deleted = 0
        for asset_id in asset_ids:
            try:
                asset = store.delete_asset(asset_id, user.id)
                store.record_audit(user.id, "delete", f"Bulk removed {asset.original_filename}")
                deleted += 1
            except (LookupError, PermissionError):
                continue

        flash(f"Deleted {deleted} encrypted image(s).", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images")
    @login_required(store)
    def upload_image() -> Response:
        user = _current_user(store)
        upload = request.files.get("image")
        algorithm = request.form.get("algorithm", AES_GCM_PASSPHRASE)
        passphrase = request.form.get("passphrase", "")
        tags = request.form.get("tags", "")

        if upload is None or not upload.filename:
            flash("Choose an image to encrypt.", "error")
            return redirect(url_for("dashboard"))

        if not _allowed_extension(upload.filename, app.config["ALLOWED_EXTENSIONS"]):
            flash("Unsupported file extension.", "error")
            return redirect(url_for("dashboard"))

        image_bytes = upload.read()
        try:
            safe_filename = normalize_filename(upload.filename)
            unlock_after = _normalize_unlock_after(request.form.get("unlock_after", ""))
            content_hash = hashlib.sha256(image_bytes).hexdigest()
            duplicate = store.find_asset_by_content_hash(user.id, content_hash)
            if duplicate:
                flash(
                    f"Duplicate image detected — already stored as {duplicate.original_filename}.",
                    "error",
                )
                return redirect(url_for("dashboard"))

            public_key = store.read_public_key(user.id) if algorithm == RSA_HYBRID else None
            ciphertext, metadata, image_info = encrypt_upload(
                user_id=user.id,
                filename=safe_filename,
                image_bytes=image_bytes,
                algorithm=algorithm,
                passphrase=passphrase if algorithm == AES_GCM_PASSPHRASE else None,
                public_key_pem=public_key,
                unlock_after=unlock_after,
            )
            asset = store.save_asset(
                user_id=user.id,
                original_filename=safe_filename,
                algorithm=algorithm,
                mime_type=str(image_info["mime_type"]),
                image_format=str(image_info["format"]),
                width=int(image_info["width"]),
                height=int(image_info["height"]),
                metadata=metadata,
                ciphertext=ciphertext,
                tags=tags,
                notes=request.form.get("notes", ""),
            )
            store.record_audit(
                user.id,
                "upload",
                f"Encrypted {asset.original_filename} with {algorithm}",
            )
        except (
            CryptoError,
            Image.DecompressionBombError,
            ValueError,
            UnidentifiedImageError,
        ) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        flash("Image encrypted and stored in the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/preview")
    @login_required(store)
    def preview_image(asset_id: int) -> Response:
        user = _current_user(store)
        throttle = app.extensions["decrypt_throttle"]
        throttle_key = _decrypt_throttle_key(user.id, asset_id)
        retry_after = throttle.retry_after(throttle_key)
        if retry_after is not None:
            response = jsonify(
                {
                    "error": "too many failed decryption attempts",
                    "retry_after_seconds": retry_after,
                }
            )
            response.headers["Retry-After"] = str(retry_after)
            return response, 429
        try:
            asset = _owned_asset(store, asset_id, user)
            _assert_unlocked(asset)
            ciphertext = store.read_ciphertext(asset)
            plaintext = decrypt_image_bytes(
                ciphertext,
                asset.metadata,
                passphrase=request.form.get("passphrase") or None,
                private_key_pem=store.read_private_key(user.id)
                if asset.algorithm == RSA_HYBRID
                else None,
                private_key_passphrase=request.form.get("private_key_passphrase") or None,
                aad=_aad_from_metadata(asset),
            )
            throttle.reset(throttle_key)
            store.record_audit(user.id, "decrypt", f"In-page preview for {asset.original_filename}")
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            if isinstance(exc, CryptoError):
                throttle.record_failure(throttle_key)
            if user:
                store.record_audit(
                    user.id, "decrypt_failed", f"Preview failed for asset {asset_id}: {exc}"
                )
            return jsonify({"error": str(exc)}), 400

        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=False,
        )

    @app.post("/images/<int:asset_id>/decrypt")
    @login_required(store)
    def decrypt_image(asset_id: int) -> Response:
        user = _current_user(store)
        throttle = app.extensions["decrypt_throttle"]
        throttle_key = _decrypt_throttle_key(user.id, asset_id)
        retry_after = throttle.retry_after(throttle_key)
        if retry_after is not None:
            flash(f"Too many failed decryptions. Try again in {retry_after} seconds.", "error")
            return redirect(url_for("dashboard"))
        try:
            asset = _owned_asset(store, asset_id, user)
            _assert_unlocked(asset)
            ciphertext = store.read_ciphertext(asset)
            plaintext = decrypt_image_bytes(
                ciphertext,
                asset.metadata,
                passphrase=request.form.get("passphrase") or None,
                private_key_pem=store.read_private_key(user.id)
                if asset.algorithm == RSA_HYBRID
                else None,
                private_key_passphrase=request.form.get("private_key_passphrase") or None,
                aad=_aad_from_metadata(asset),
            )
            throttle.reset(throttle_key)
            store.record_audit(
                user.id,
                "decrypt",
                f"Decrypted preview for {asset.original_filename}",
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            if isinstance(exc, CryptoError):
                throttle.record_failure(throttle_key)
            store.record_audit(
                user.id, "decrypt_failed", f"Decrypt failed for asset {asset_id}: {exc}"
            )
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=False,
        )

    @app.post("/images/<int:asset_id>/delete")
    @login_required(store)
    def delete_image(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = store.delete_asset(asset_id, user.id)
            store.record_audit(user.id, "delete", f"Removed {asset.original_filename} from vault")
            flash("Encrypted image deleted.", "success")
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    @app.post("/api/token")
    def api_token() -> Response:
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        throttle = app.extensions["credential_throttle"]
        throttle_key = _credential_throttle_key(username)
        retry_after = throttle.retry_after(throttle_key)
        if retry_after is not None:
            response = jsonify(
                {
                    "error": "too many failed attempts",
                    "retry_after_seconds": retry_after,
                }
            )
            response.headers["Retry-After"] = str(retry_after)
            return response, 429

        user = store.authenticate_user(username, password)
        if not user:
            throttle.record_failure(throttle_key)
            return jsonify({"error": "invalid credentials"}), 401

        throttle.reset(throttle_key)
        store.record_audit(user.id, "api_token", "Issued JWT access token")
        now = datetime.now(timezone.utc)
        lifetime_seconds = int(app.config["JWT_LIFETIME_SECONDS"])
        token = jwt.encode(
            {
                "sub": str(user.id),
                "iss": app.config["JWT_ISSUER"],
                "aud": app.config["JWT_AUDIENCE"],
                "ver": user.auth_version,
                "iat": now,
                "exp": now + timedelta(seconds=lifetime_seconds),
            },
            app.config["JWT_SECRET"],
            algorithm="HS256",
        )
        return jsonify(
            {
                "token": token,
                "token_type": "Bearer",
                "expires_in": lifetime_seconds,
            }
        )

    @app.get("/api/images")
    @jwt_required(store)
    def api_images() -> Response:
        user = g.api_user
        query = request.args.get("q", "")
        tag = request.args.get("tag", "")
        return jsonify(
            {
                "images": [
                    _asset_payload(asset)
                    for asset in store.list_assets(user.id, query=query, tag=tag)
                ]
            }
        )

    @app.post("/api/images")
    @jwt_required(store)
    def api_upload_image() -> Response:
        user = g.api_user
        upload = request.files.get("image")
        if upload is None or not upload.filename:
            return jsonify({"error": "image file is required"}), 400

        algorithm = request.form.get("algorithm", AES_GCM_PASSPHRASE)
        passphrase = request.form.get("passphrase")
        if not _allowed_extension(upload.filename, app.config["ALLOWED_EXTENSIONS"]):
            return jsonify({"error": "unsupported file extension"}), 400

        try:
            image_bytes = upload.read()
            safe_filename = normalize_filename(upload.filename)
            unlock_after = _normalize_unlock_after(request.form.get("unlock_after", ""))
            content_hash = hashlib.sha256(image_bytes).hexdigest()
            duplicate = store.find_asset_by_content_hash(user.id, content_hash)
            if duplicate:
                return jsonify(
                    {
                        "error": "duplicate image",
                        "existing_id": duplicate.id,
                        "filename": duplicate.original_filename,
                    }
                ), 409

            public_key = store.read_public_key(user.id) if algorithm == RSA_HYBRID else None
            ciphertext, metadata, image_info = encrypt_upload(
                user_id=user.id,
                filename=safe_filename,
                image_bytes=image_bytes,
                algorithm=algorithm,
                passphrase=passphrase,
                public_key_pem=public_key,
                unlock_after=unlock_after,
            )
            asset = store.save_asset(
                user_id=user.id,
                original_filename=safe_filename,
                algorithm=algorithm,
                mime_type=str(image_info["mime_type"]),
                image_format=str(image_info["format"]),
                width=int(image_info["width"]),
                height=int(image_info["height"]),
                metadata=metadata,
                ciphertext=ciphertext,
                tags=request.form.get("tags", ""),
                notes=request.form.get("notes", ""),
            )
            store.record_audit(user.id, "upload", f"API encrypted {asset.original_filename}")
            return jsonify({"image": _asset_payload(asset)}), 201
        except (
            CryptoError,
            Image.DecompressionBombError,
            ValueError,
            UnidentifiedImageError,
        ) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/images/<int:asset_id>")
    @jwt_required(store)
    def api_get_image(asset_id: int) -> Response:
        user = g.api_user
        try:
            asset = _owned_asset(store, asset_id, user)
        except (LookupError, PermissionError) as exc:
            status = 404 if isinstance(exc, LookupError) else 403
            return jsonify({"error": str(exc)}), status
        return jsonify({"image": _asset_payload(asset)})

    @app.post("/api/images/<int:asset_id>/decrypt")
    @jwt_required(store)
    def api_decrypt_image(asset_id: int) -> Response:
        user = g.api_user
        payload = request.get_json(silent=True) or {}
        throttle = app.extensions["decrypt_throttle"]
        throttle_key = _decrypt_throttle_key(user.id, asset_id)
        retry_after = throttle.retry_after(throttle_key)
        if retry_after is not None:
            response = jsonify(
                {
                    "error": "too many failed decryption attempts",
                    "retry_after_seconds": retry_after,
                }
            )
            response.headers["Retry-After"] = str(retry_after)
            return response, 429
        try:
            asset = _owned_asset(store, asset_id, user)
            _assert_unlocked(asset)
            ciphertext = store.read_ciphertext(asset)
            plaintext = decrypt_image_bytes(
                ciphertext,
                asset.metadata,
                passphrase=payload.get("passphrase"),
                private_key_pem=store.read_private_key(user.id)
                if asset.algorithm == RSA_HYBRID
                else None,
                private_key_passphrase=payload.get("private_key_passphrase"),
                aad=_aad_from_metadata(asset),
            )
            throttle.reset(throttle_key)
            store.record_audit(user.id, "decrypt", f"API decrypted {asset.original_filename}")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 423
        except (LookupError, PermissionError, CryptoError) as exc:
            if isinstance(exc, CryptoError):
                throttle.record_failure(throttle_key)
            store.record_audit(
                user.id, "decrypt_failed", f"API decrypt failed for asset {asset_id}: {exc}"
            )
            status = (
                404
                if isinstance(exc, LookupError)
                else 403
                if isinstance(exc, PermissionError)
                else 400
            )
            return jsonify({"error": str(exc)}), status

        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=True,
        )

    @app.delete("/api/images/<int:asset_id>")
    @jwt_required(store)
    def api_delete_image(asset_id: int) -> Response:
        user = g.api_user
        try:
            asset = store.delete_asset(asset_id, user.id)
            store.record_audit(user.id, "delete", f"API deleted {asset.original_filename}")
        except (LookupError, PermissionError) as exc:
            status = 404 if isinstance(exc, LookupError) else 403
            return jsonify({"error": str(exc)}), status
        return jsonify({"deleted": True, "id": asset.id})

    @app.get("/api/audit")
    @jwt_required(store)
    def api_audit_log() -> Response:
        user = g.api_user
        events = store.list_audit_events(user.id, limit=100)
        return jsonify(
            {
                "events": [
                    {
                        "id": event.id,
                        "action": event.action,
                        "detail": event.detail,
                        "created_at": event.created_at,
                    }
                    for event in events
                ]
            }
        )

    return app


def login_required(store: VaultStore) -> Callable[[F], F]:
    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not _current_user(store):
                flash("Sign in to continue.", "error")
                return redirect(url_for("index"))
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def jwt_required(store: VaultStore) -> Callable[[F], F]:
    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "missing bearer token"}), 401
            token = auth_header.removeprefix("Bearer ").strip()
            try:
                payload = jwt.decode(
                    token,
                    current_app.config["JWT_SECRET"],
                    algorithms=["HS256"],
                    issuer=current_app.config["JWT_ISSUER"],
                    audience=current_app.config["JWT_AUDIENCE"],
                    options={"require": ["aud", "exp", "iat", "iss", "sub", "ver"]},
                )
                user = store.get_user(int(payload["sub"]))
                if not hmac.compare_digest(
                    str(payload["ver"]),
                    str(user.auth_version),
                ):
                    raise jwt.InvalidTokenError("token has been revoked")
                g.api_user = user
            except (jwt.PyJWTError, LookupError, TypeError, ValueError):
                return jsonify({"error": "invalid bearer token"}), 401
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def _current_user(store: VaultStore) -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    try:
        user = store.get_user(int(user_id))
        session_version = session.get("auth_version")
        if session_version is None or not hmac.compare_digest(
            str(session_version),
            str(user.auth_version),
        ):
            session.clear()
            return None
        return user
    except (LookupError, TypeError, ValueError):
        session.clear()
        return None


def _csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return str(token)


def _valid_csrf_token(token: str) -> bool:
    expected = session.get("_csrf_token")
    return bool(expected and token and hmac.compare_digest(str(expected), str(token)))


def _validate_runtime_secrets(app: Flask) -> None:
    positive_integer_keys = (
        "AUTH_RATE_LIMIT_ATTEMPTS",
        "AUTH_RATE_LIMIT_WINDOW_SECONDS",
        "AUTH_RATE_LIMIT_LOCKOUT_SECONDS",
        "DECRYPT_RATE_LIMIT_ATTEMPTS",
        "DECRYPT_RATE_LIMIT_WINDOW_SECONDS",
        "DECRYPT_RATE_LIMIT_LOCKOUT_SECONDS",
        "JWT_LIFETIME_SECONDS",
        "MAX_IMAGE_PIXELS",
        "MAX_VAULT_ARCHIVE_MEMBERS",
        "MAX_VAULT_MANIFEST_BYTES",
        "PERMANENT_SESSION_LIFETIME_SECONDS",
        "REGISTER_RATE_LIMIT_ATTEMPTS",
        "REGISTER_RATE_LIMIT_WINDOW_SECONDS",
        "REGISTER_RATE_LIMIT_LOCKOUT_SECONDS",
    )
    for key in positive_integer_keys:
        if int(app.config[key]) <= 0:
            raise RuntimeError(f"{key} must be a positive integer.")

    if not app.config.get("REQUIRE_STRONG_SECRETS"):
        return

    weak_values = {
        "dev-secret-change-me-dev-secret-change-me",
        "change-me-before-deploying-use-at-least-32-bytes",
        "change-me-too-use-at-least-32-bytes",
    }
    for key in ("SECRET_KEY", "JWT_SECRET", "AUDIT_HMAC_KEY"):
        value = str(app.config.get(key, ""))
        if value in weak_values or len(value.encode("utf-8")) < 32:
            raise RuntimeError(f"{key} must be set to a strong value before deployment.")


def _owned_asset(store: VaultStore, asset_id: int, user: User) -> EncryptedAsset:
    asset = store.get_asset(asset_id)
    if asset.user_id != user.id:
        raise PermissionError("You do not have access to this encrypted image.")
    return asset


def _allowed_extension(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def _credential_throttle_key(username: str) -> str:
    normalized = username.strip().lower() or "anonymous"
    identity_digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]
    return f"{_remote_address()}:{identity_digest}"


def _remote_address() -> str:
    return request.remote_addr or "unknown"


def _decrypt_throttle_key(user_id: int, asset_id: int) -> str:
    return f"decrypt:{_remote_address()}:{user_id}:{asset_id}"


def _aad_from_metadata(asset: EncryptedAsset) -> bytes:
    aad = asset.metadata.get("aad", {})
    if not isinstance(aad, dict):
        raise CryptoError("Encrypted asset context is invalid.")
    try:
        version = int(aad.get("version", 1))
        context_user_id = int(aad.get("user_id", asset.user_id))
    except (TypeError, ValueError) as exc:
        raise CryptoError("Encrypted asset context is invalid.") from exc
    if context_user_id != asset.user_id:
        raise CryptoError("Encrypted asset ownership context does not match its vault record.")

    if version == 1:
        return asset_aad(
            context_user_id,
            str(aad.get("original_filename", asset.original_filename)),
            str(aad.get("mime_type", asset.mime_type)),
            version=1,
        )

    algorithm = str(aad.get("algorithm", ""))
    mime_type = str(aad.get("mime_type", ""))
    image_format = str(aad.get("image_format", ""))
    try:
        width = int(aad.get("width", 0))
        height = int(aad.get("height", 0))
    except (TypeError, ValueError) as exc:
        raise CryptoError("Encrypted asset dimensions are invalid.") from exc
    if (
        algorithm != asset.algorithm
        or mime_type != asset.mime_type
        or image_format != asset.image_format
        or width != asset.width
        or height != asset.height
    ):
        raise CryptoError("Encrypted asset context does not match its vault record.")
    return asset_aad(
        context_user_id,
        str(aad.get("original_filename", "")),
        mime_type,
        version=version,
        algorithm=algorithm,
        image_format=image_format,
        width=width,
        height=height,
        unlock_after=str(aad.get("unlock_after", "")) or None,
    )


def _vault_health(store: VaultStore, user_id: int) -> dict[str, int | float | bool | str]:
    stats = store.vault_stats(user_id)
    chain = store.verify_audit_chain(user_id)
    assets = store.list_assets(user_id)
    entropies: list[float] = []
    for asset in assets:
        try:
            entropy = float(asset.metadata.get("entropy_bits", 0) or 0)
        except (TypeError, ValueError):
            entropy = 0.0
        entropies.append(max(0.0, min(8.0, entropy)))
    average_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    locked_count = sum(1 for asset in assets if _asset_unlock_after(asset))
    score = int(
        min(
            100,
            (45 if chain["valid"] else 0)
            + min(25, stats.asset_count * 4)
            + min(20, average_entropy * 2.5)
            + min(10, len(store.list_tags(user_id)) * 2),
        )
    )
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D"
    return {
        "score": score,
        "grade": grade,
        "chain_valid": chain["valid"],
        "average_entropy": round(average_entropy, 3),
        "locked_assets": locked_count,
        "asset_count": stats.asset_count,
    }


def _assert_unlocked(asset: EncryptedAsset) -> None:
    unlock_after = _asset_unlock_after(asset)
    if not unlock_after:
        return
    try:
        unlock_at = datetime.fromisoformat(str(unlock_after))
        if unlock_at.tzinfo is None:
            unlock_at = unlock_at.replace(tzinfo=timezone.utc)
        unlock_at = unlock_at.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError("Time-lock metadata is invalid; decryption is blocked.") from exc
    if datetime.now(timezone.utc) < unlock_at:
        raise ValueError(f"Time-locked until {unlock_at.isoformat(timespec='seconds')}")


def _asset_unlock_after(asset: EncryptedAsset) -> str | None:
    aad = asset.metadata.get("aad")
    try:
        aad_version = int(aad.get("version", 1)) if isinstance(aad, dict) else 1
    except (TypeError, ValueError):
        return "invalid"
    if isinstance(aad, dict) and aad_version >= AAD_VERSION:
        authenticated_value = str(aad.get("unlock_after", "")).strip()
        compatibility_value = str(asset.metadata.get("unlock_after", "")).strip()
        if compatibility_value and compatibility_value != authenticated_value:
            return "invalid"
        return authenticated_value or None
    value = str(asset.metadata.get("unlock_after", "")).strip()
    return value or None


def _normalize_unlock_after(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    try:
        unlock_at = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Time-lock must be a valid ISO 8601 date and time.") from exc
    if unlock_at.tzinfo is None:
        unlock_at = unlock_at.replace(tzinfo=timezone.utc)
    unlock_at = unlock_at.astimezone(timezone.utc)
    if unlock_at <= datetime.now(timezone.utc):
        raise ValueError("Time-lock must be in the future.")
    return unlock_at.isoformat(timespec="seconds")


def _read_bounded_vault_manifest(
    archive_bytes: bytes,
    *,
    max_manifest_bytes: int,
    max_members: int,
) -> list[dict]:
    with zipfile.ZipFile(BytesIO(archive_bytes)) as bundle:
        members = bundle.infolist()
        if len(members) > max_members:
            raise ValueError("archive contains too many members")
        manifests = [member for member in members if member.filename == "manifest.json"]
        if len(manifests) != 1:
            raise ValueError("archive must contain exactly one manifest.json")
        manifest_info = manifests[0]
        if manifest_info.file_size > max_manifest_bytes:
            raise ValueError("manifest.json is too large")
        with bundle.open(manifest_info) as handle:
            manifest_bytes = handle.read(max_manifest_bytes + 1)
        if len(manifest_bytes) > max_manifest_bytes:
            raise ValueError("manifest.json is too large")
    manifest = json_module.loads(manifest_bytes)
    if not isinstance(manifest, list):
        raise ValueError("manifest.json must contain an array")
    if len(manifest) > max_members:
        raise ValueError("manifest contains too many assets")
    if any(not isinstance(item, dict) for item in manifest):
        raise ValueError("manifest assets must be objects")
    return manifest


def _asset_payload(asset: EncryptedAsset) -> dict:
    return {
        "id": asset.id,
        "filename": asset.original_filename,
        "algorithm": asset.algorithm,
        "format": asset.image_format,
        "size": {"width": asset.width, "height": asset.height},
        "tags": [tag for tag in asset.tags.split(",") if tag],
        "notes": asset.notes,
        "content_hash": asset.metadata.get("content_hash"),
        "entropy_bits": asset.metadata.get("entropy_bits"),
        "unlock_after": _asset_unlock_after(asset),
        "created_at": asset.created_at,
    }


def _format_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    size = float(value)
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    if unit == 0:
        return f"{value} {units[unit]}"
    return f"{size:.1f} {units[unit]}"
