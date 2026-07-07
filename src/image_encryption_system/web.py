from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
from io import BytesIO
import json as json_module
from math import ceil
from pathlib import Path
import secrets
import zipfile
from sqlite3 import IntegrityError
from threading import Lock
import time
from typing import Callable, TypeVar

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

from .config import Config
from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
)
from .storage import EncryptedAsset, User, VaultStore
from .uploads import asset_aad, encrypt_upload


F = TypeVar("F", bound=Callable)


class CredentialThrottle:
    def __init__(self, *, max_attempts: int, window_seconds: int, lockout_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
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


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    _validate_runtime_secrets(app)
    Image.MAX_IMAGE_PIXELS = app.config["MAX_IMAGE_PIXELS"]

    app.config["INSTANCE_DIR"] = Path(app.config["INSTANCE_DIR"])
    app.config["DATABASE_PATH"] = Path(app.config["DATABASE_PATH"])
    app.config["VAULT_DIR"] = Path(app.config["VAULT_DIR"])
    app.config["KEY_DIR"] = Path(app.config["KEY_DIR"])

    store = VaultStore(
        database_path=app.config["DATABASE_PATH"],
        vault_dir=app.config["VAULT_DIR"],
        key_dir=app.config["KEY_DIR"],
    )
    store.init()
    app.extensions["vault_store"] = store
    app.extensions["credential_throttle"] = CredentialThrottle(
        max_attempts=app.config["AUTH_RATE_LIMIT_ATTEMPTS"],
        window_seconds=app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"],
        lockout_seconds=app.config["AUTH_RATE_LIMIT_LOCKOUT_SECONDS"],
    )

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health() -> Response:
        return jsonify(
            {
                "status": "ok",
                "service": "image-encryption-system",
                "version": "0.6.0",
            }
        )

    @app.context_processor
    def inject_globals() -> dict:
        return {
            "current_user": _current_user(store),
            "csrf_token": _csrf_token,
            "format_bytes": _format_bytes,
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
        try:
            user = store.create_user(username, password)
        except IntegrityError:
            flash("That username is already registered.", "error")
            return redirect(url_for("register_form"))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("register_form"))

        session.clear()
        session["user_id"] = user.id
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
        session["user_id"] = user.id
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
        return render_template(
            "dashboard.html",
            assets=assets,
            stats=stats,
            audit_events=audit_events,
            audit_summary=audit_summary,
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
                "version": "0.6.0",
                "authentication": "Bearer JWT from POST /api/token",
                "endpoints": [
                    {"method": "GET", "path": "/health", "description": "Service health"},
                    {"method": "GET", "path": "/api/docs", "description": "This API catalog"},
                    {"method": "POST", "path": "/api/token", "description": "Issue JWT"},
                    {"method": "GET", "path": "/api/stats", "description": "Vault stats and audit summary"},
                    {"method": "GET", "path": "/api/images", "description": "List encrypted assets"},
                    {"method": "POST", "path": "/api/images", "description": "Upload and encrypt image"},
                    {"method": "GET", "path": "/api/images/<id>", "description": "Fetch asset metadata"},
                    {"method": "POST", "path": "/api/images/<id>/decrypt", "description": "Decrypt asset"},
                    {"method": "DELETE", "path": "/api/images/<id>", "description": "Delete asset"},
                    {"method": "GET", "path": "/api/audit", "description": "Recent audit events"},
                    {"method": "GET", "path": "/api/audit/verify", "description": "Verify tamper-evident audit chain"},
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
            store.change_user_password(user.id, old_password, new_password)
            store.record_audit(user.id, "password", "Account password changed")
            flash("Password updated and RSA private key re-wrapped.", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        except Exception as exc:
            flash(f"Password change failed: {exc}", "error")
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
            with zipfile.ZipFile(BytesIO(upload.read())) as bundle:
                manifest = json_module.loads(bundle.read("manifest.json"))
            imported = len(manifest) if isinstance(manifest, list) else 0
            store.record_audit(user.id, "import", f"Validated vault manifest with {imported} assets")
            flash(f"Manifest validated ({imported} assets). Ciphertext remains encrypted.", "success")
        except (KeyError, json_module.JSONDecodeError, zipfile.BadZipFile) as exc:
            flash(f"Invalid vault archive: {exc}", "error")
        return redirect(url_for("dashboard"))

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
            flash(f"Audit chain valid ({result['checked']} events). Tip: {result['tip'][:12]}…", "success")
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
                filename=upload.filename,
                image_bytes=image_bytes,
                algorithm=algorithm,
                passphrase=passphrase if algorithm == AES_GCM_PASSPHRASE else None,
                public_key_pem=public_key,
            )
            unlock_after = request.form.get("unlock_after", "").strip()
            if unlock_after:
                metadata["unlock_after"] = unlock_after
            asset = store.save_asset(
                user_id=user.id,
                original_filename=upload.filename,
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
        except (CryptoError, ValueError, UnidentifiedImageError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        flash("Image encrypted and stored in the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/preview")
    @login_required(store)
    def preview_image(asset_id: int) -> Response:
        user = _current_user(store)
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
            store.record_audit(user.id, "decrypt", f"In-page preview for {asset.original_filename}")
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
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
        try:
            asset = _owned_asset(store, asset_id, user)
            _assert_unlocked(asset)
            ciphertext = store.read_ciphertext(asset)
            aad = _aad_from_metadata(asset)
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
            store.record_audit(
                user.id,
                "decrypt",
                f"Decrypted preview for {asset.original_filename}",
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
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
        token = jwt.encode(
            {
                "sub": str(user.id),
                "iss": app.config["JWT_ISSUER"],
                "iat": now,
                "exp": now + timedelta(hours=2),
            },
            app.config["JWT_SECRET"],
            algorithm="HS256",
        )
        return jsonify({"token": token, "token_type": "Bearer", "expires_in": 7200})

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
                filename=upload.filename,
                image_bytes=image_bytes,
                algorithm=algorithm,
                passphrase=passphrase,
                public_key_pem=public_key,
            )
            asset = store.save_asset(
                user_id=user.id,
                original_filename=upload.filename,
                algorithm=algorithm,
                mime_type=str(image_info["mime_type"]),
                image_format=str(image_info["format"]),
                width=int(image_info["width"]),
                height=int(image_info["height"]),
                metadata=metadata,
                ciphertext=ciphertext,
                tags=request.form.get("tags", ""),
            )
            store.record_audit(user.id, "upload", f"API encrypted {asset.original_filename}")
            return jsonify({"image": _asset_payload(asset)}), 201
        except (CryptoError, ValueError, UnidentifiedImageError) as exc:
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
            store.record_audit(user.id, "decrypt", f"API decrypted {asset.original_filename}")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 423
        except (LookupError, PermissionError, CryptoError) as exc:
            status = 404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 400
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
                )
                g.api_user = store.get_user(int(payload["sub"]))
            except Exception:
                return jsonify({"error": "invalid bearer token"}), 401
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def _current_user(store: VaultStore) -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    try:
        return store.get_user(int(user_id))
    except LookupError:
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
    if not app.config.get("REQUIRE_STRONG_SECRETS"):
        return

    weak_values = {
        "dev-secret-change-me-dev-secret-change-me",
        "change-me-before-deploying-use-at-least-32-bytes",
        "change-me-too-use-at-least-32-bytes",
    }
    for key in ("SECRET_KEY", "JWT_SECRET"):
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
    remote = request.remote_addr or "unknown"
    return f"{remote}:{username.strip().lower() or 'anonymous'}"


def _aad_from_metadata(asset: EncryptedAsset) -> bytes:
    aad = asset.metadata.get("aad", {})
    return asset_aad(
        int(aad.get("user_id", asset.user_id)),
        str(aad.get("original_filename", asset.original_filename)),
        str(aad.get("mime_type", asset.mime_type)),
    )


def _assert_unlocked(asset: EncryptedAsset) -> None:
    unlock_after = asset.metadata.get("unlock_after")
    if not unlock_after:
        return
    try:
        unlock_at = datetime.fromisoformat(str(unlock_after))
        if unlock_at.tzinfo is None:
            unlock_at = unlock_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return
    if datetime.now(timezone.utc) < unlock_at:
        raise ValueError(f"Time-locked until {unlock_at.isoformat(timespec='seconds')}")


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
        "unlock_after": asset.metadata.get("unlock_after"),
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
