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
from hashlib import sha256
import hmac
from io import BytesIO
from math import ceil
from pathlib import Path
import secrets
from sqlite3 import IntegrityError
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
from markupsafe import Markup, escape
from PIL import Image, UnidentifiedImageError
from werkzeug.exceptions import RequestEntityTooLarge

from .config import APP_VERSION, Config
from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
    pack_ies,
    unwrap_data_key,
    wrap_data_key_passphrase,
    wrap_data_key_rsa,
)
from .security import LoginGuard
from .storage import AssetShare, EncryptedAsset, LinkShare, User, VaultStore


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
    if "CSRF_ENABLED" not in app.config:
        app.config["CSRF_ENABLED"] = not bool(app.config.get("TESTING"))

    app.config["INSTANCE_DIR"] = Path(app.config["INSTANCE_DIR"])
    app.config["DATABASE_PATH"] = Path(app.config["DATABASE_PATH"])
    app.config["VAULT_DIR"] = Path(app.config["VAULT_DIR"])
    app.config["KEY_DIR"] = Path(app.config["KEY_DIR"])
    app.config["MAX_CONTENT_LENGTH"] = int(app.config.get("MAX_CONTENT_LENGTH", 8 * 1024 * 1024))

    store = VaultStore(
        database_path=app.config["DATABASE_PATH"],
        vault_dir=app.config["VAULT_DIR"],
        key_dir=app.config["KEY_DIR"],
        audit_key=str(app.config["AUDIT_HMAC_KEY"]).encode("utf-8"),
    )
    store.init()
    app.extensions["vault_store"] = store
    app.extensions["login_guard"] = LoginGuard(
        store,
        max_attempts=int(app.config.get("LOGIN_RATE_LIMIT", 5)),
        window_seconds=int(app.config.get("LOGIN_RATE_WINDOW_SECONDS", 600)),
        lockout_threshold=int(app.config.get("LOGIN_LOCKOUT_THRESHOLD", 8)),
        lockout_seconds=int(app.config.get("LOGIN_LOCKOUT_SECONDS", 900)),
    )

    @app.context_processor
    def inject_globals() -> dict:
        return {
            "current_user": _current_user(store),
            "csrf_token": _ensure_csrf_token(),
            "csrf_field": _csrf_field(),
            "algorithms": [
                (AES_GCM_PASSPHRASE, "AES-GCM passphrase"),
                (RSA_HYBRID, "RSA hybrid"),
            ],
        }

    @app.before_request
    def csrf_protect():
        _ensure_csrf_token()
        if request.method != "POST" or not current_app.config.get("CSRF_ENABLED"):
            return None
        if request.path.startswith("/api/") or request.path.startswith("/l/"):
            return None
        expected = session.get("csrf_token") or ""
        submitted = request.form.get("csrf_token") or ""
        if not expected or not submitted or not hmac.compare_digest(str(expected), str(submitted)):
            if _wants_json():
                return jsonify({"error": "missing or invalid CSRF token"}), 400
            return ("Missing or invalid CSRF token.", 400)

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error: RequestEntityTooLarge):
        limit_mb = int(app.config["MAX_CONTENT_LENGTH"]) // (1024 * 1024)
        if _wants_json():
            return jsonify({"error": f"upload exceeds the {limit_mb} MB limit"}), 413
        flash(f"File exceeds the {limit_mb} MB upload limit.", "error")
        return redirect(url_for("dashboard")), 413

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

        _establish_session(user)
        flash("Account created. Your RSA keys were generated and stored locally.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/login")
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        blocked = _guard_login(app, username, json_mode=False)
        if blocked is not None:
            return blocked

        user = store.authenticate_user(username, password)
        if not user:
            return _failed_login(app, username, json_mode=False)

        _login_success(app, store, user)
        _establish_session(user)
        flash("Signed in.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout() -> Response:
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("index"))

    @app.get("/account/password")
    @login_required(store)
    def password_form() -> str:
        return render_template("account.html")

    @app.post("/account/password")
    @login_required(store)
    def change_password() -> Response:
        user = _current_user(store)
        old_password = request.form.get("old_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
            return redirect(url_for("password_form"))
        try:
            store.change_password(user.id, old_password, new_password)
        except (ValueError, CryptoError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("password_form"))
        refreshed = store.get_user(user.id)
        session["token_version"] = refreshed.token_version
        _audit(store, user.id, "password_change")
        flash(
            "Password updated. Your RSA private key was re-encrypted. Other sessions were signed out.",
            "success",
        )
        return redirect(url_for("dashboard"))

    @app.post("/account/delete")
    @login_required(store)
    def delete_account() -> Response:
        user = _current_user(store)
        password = request.form.get("password") or ""
        try:
            store.delete_account(user.id, password)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("password_form"))
        session.clear()
        flash("Account deleted.", "success")
        return redirect(url_for("index"))

    @app.get("/dashboard")
    @login_required(store)
    def dashboard() -> str:
        user = _current_user(store)
        store.sweep_expired_shares()
        query = (request.args.get("q") or "").strip()
        algorithm = (request.args.get("algorithm") or "").strip() or None
        favorites_only = (request.args.get("favorites") or "").strip() in {"1", "true", "on"}
        assets = store.list_assets(
            user.id,
            query=query or None,
            algorithm=algorithm,
            favorites_only=favorites_only,
        )
        shared_items = store.list_shared_with_user(
            user.id, query=query or None, algorithm=algorithm
        )
        recipients = store.list_recipients_for_owner(user.id)
        links = store.list_link_shares_for_owner(user.id)
        return render_template(
            "dashboard.html",
            assets=assets,
            shared_items=shared_items,
            recipients=recipients,
            links=links,
            query=query,
            selected_algorithm=algorithm or "",
            favorites_only=favorites_only,
        )

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
            image_bytes = _strip_image_exif(image_bytes)
            image_info = _inspect_image(image_bytes)
            aad = _asset_aad(user.id, upload.filename, image_info["mime_type"])
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
            metadata = {
                **result.metadata,
                "aad": {
                    "user_id": user.id,
                    "original_filename": upload.filename,
                    "mime_type": image_info["mime_type"],
                },
            }
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
            _audit(store, user.id, "upload", asset.id)
        except (CryptoError, ValueError, UnidentifiedImageError) as exc:
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
            asset, share = _accessible_asset(store, asset_id, user)
            ciphertext = store.read_ciphertext(asset)
            store.ciphertext_sha256(asset)
            aad = _aad_from_metadata(asset)
            metadata = dict(asset.metadata)
            if share is not None:
                metadata["key_wrap"] = share.key_wrap
                plaintext = decrypt_image_bytes(
                    ciphertext,
                    metadata,
                    private_key_pem=store.read_private_key(user.id),
                    private_key_passphrase=request.form.get("private_key_passphrase") or None,
                    aad=aad,
                )
            else:
                plaintext = decrypt_image_bytes(
                    ciphertext,
                    metadata,
                    passphrase=request.form.get("passphrase") or None,
                    private_key_pem=store.read_private_key(user.id)
                    if asset.algorithm == RSA_HYBRID
                    else None,
                    private_key_passphrase=request.form.get("private_key_passphrase") or None,
                    aad=aad,
                )
            _audit(store, user.id, "decrypt", asset.id)
        except PermissionError as exc:
            if _wants_json():
                return jsonify({"error": str(exc)}), 403
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        except LookupError as exc:
            if _wants_json():
                return jsonify({"error": str(exc)}), 404
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        except (CryptoError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=False,
        )

    @app.post("/images/<int:asset_id>/share")
    @login_required(store)
    def share_image(asset_id: int) -> Response:
        user = _current_user(store)
        recipient_name = request.form.get("username", "")
        try:
            share = _share_asset(
                store,
                owner=user,
                asset_id=asset_id,
                recipient_username=recipient_name,
                passphrase=request.form.get("passphrase") or None,
                private_key_passphrase=request.form.get("private_key_passphrase") or None,
                expires_at=_parse_share_expiry(
                    request.form.get("expires_hours"),
                    request.form.get("expires_days"),
                ),
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        name = recipient_name.strip().lower()
        if share.expires_at:
            flash(f"Shared with {name}. Expires {share.expires_at}.", "success")
        else:
            flash(f"Shared with {name}.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/share/<int:share_id>/revoke")
    @login_required(store)
    def revoke_share(share_id: int) -> Response:
        user = _current_user(store)
        try:
            share = store.delete_share(share_id, user.id)
            _audit(store, user.id, "revoke", share.asset_id)
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        flash("Share revoked. The recipient can no longer decrypt this image.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/rotate-passphrase")
    @login_required(store)
    def rotate_passphrase(asset_id: int) -> Response:
        user = _current_user(store)
        old_passphrase = request.form.get("old_passphrase") or ""
        new_passphrase = request.form.get("new_passphrase") or ""
        try:
            asset = _owned_asset(store, asset_id, user)
            if asset.algorithm != AES_GCM_PASSPHRASE:
                raise ValueError("Only AES-GCM passphrase wraps can be rotated this way.")
            metadata = dict(asset.metadata)
            data_key = unwrap_data_key(metadata["key_wrap"], passphrase=old_passphrase)
            metadata["key_wrap"] = wrap_data_key_passphrase(data_key, new_passphrase)
            store.update_asset_metadata(asset.id, user.id, metadata)
            _audit(store, user.id, "rotate", asset.id)
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        flash("Passphrase wrap rotated. Use the new passphrase to decrypt.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/meta")
    @login_required(store)
    def update_image_meta(asset_id: int) -> Response:
        user = _current_user(store)
        favorite = str(request.form.get("favorite") or "").strip() in {"1", "true", "on", "yes"}
        try:
            asset = store.update_asset_details(
                asset_id,
                user.id,
                original_filename=request.form.get("filename"),
                notes=request.form.get("notes"),
                favorite=favorite,
            )
            _audit(store, user.id, "meta", asset.id)
        except (LookupError, PermissionError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        flash(f"Updated {asset.original_filename}.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/delete-many")
    @login_required(store)
    def delete_many_images() -> Response:
        user = _current_user(store)
        raw_ids = request.form.getlist("asset_id")
        ids: list[int] = []
        for value in raw_ids:
            try:
                ids.append(int(value))
            except (TypeError, ValueError):
                continue
        deleted = 0
        for asset_id in ids:
            try:
                asset = store.delete_asset(asset_id, user.id)
                _audit(store, user.id, "delete", asset.id)
                deleted += 1
            except (LookupError, PermissionError):
                continue
        flash(f"Deleted {deleted} encrypted image(s).", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/link")
    @login_required(store)
    def create_link_share(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            token, link = _create_link_share(
                store,
                owner=user,
                asset_id=asset_id,
                passphrase=request.form.get("passphrase") or None,
                private_key_passphrase=request.form.get("private_key_passphrase") or None,
                expires_at=_parse_share_expiry(
                    request.form.get("expires_hours"),
                    request.form.get("expires_days"),
                ),
                max_downloads=_parse_optional_int(request.form.get("max_downloads")),
                label=(request.form.get("label") or "").strip(),
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        url = url_for("open_link_share", token=token, _external=True)
        flash(
            f"Capability link created for download cap {link.max_downloads or 'unlimited'}. "
            f"Copy now (shown once): {url}",
            "success",
        )
        return redirect(url_for("dashboard"))

    @app.post("/link/<int:link_id>/revoke")
    @login_required(store)
    def revoke_link_share(link_id: int) -> Response:
        user = _current_user(store)
        try:
            link = store.delete_link_share(link_id, user.id)
            _audit(store, user.id, "revoke_link", link.asset_id)
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        flash("Capability link revoked.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/l/<token>")
    def open_link_share(token: str):
        store.sweep_expired_shares()
        try:
            link, asset = _resolve_link(store, token)
        except (LookupError, PermissionError) as exc:
            if _wants_json():
                return jsonify({"error": str(exc)}), 404
            return (str(exc), 404)
        return render_template("link.html", asset=asset, link=link, token=token)

    @app.post("/l/<token>/decrypt")
    def decrypt_link_share(token: str):
        try:
            plaintext, asset = _decrypt_link(store, token, count=True)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except (CryptoError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=True,
        )

    @app.get("/l/<token>/blob")
    def download_link_blob(token: str):
        try:
            link, asset = _resolve_link(store, token)
            store.ciphertext_sha256(asset)
            metadata = dict(asset.metadata)
            metadata["key_wrap"] = link.key_wrap
            blob = pack_ies(store.read_ciphertext(asset), metadata)
            store.increment_link_download(link.id)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return send_file(
            BytesIO(blob),
            mimetype="application/octet-stream",
            download_name=f"{asset.original_filename}.ies",
            as_attachment=True,
        )

    @app.post("/images/<int:asset_id>/delete")
    @login_required(store)
    def delete_image(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = store.delete_asset(asset_id, user.id)
            _audit(store, user.id, "delete", asset.id)
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        flash(f"Deleted {asset.original_filename}.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/images/<int:asset_id>/download")
    @login_required(store)
    def download_ciphertext(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = _owned_asset(store, asset_id, user)
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        blob = pack_ies(store.read_ciphertext(asset), asset.metadata)
        download_name = f"{asset.original_filename}.ies"
        return send_file(
            BytesIO(blob),
            mimetype="application/octet-stream",
            download_name=download_name,
            as_attachment=True,
        )

    @app.get("/audit")
    @login_required(store)
    def audit() -> str:
        user = _current_user(store)
        events = store.list_audit_events(user.id)
        return render_template("audit.html", events=events)

    @app.get("/audit.csv")
    @login_required(store)
    def audit_csv() -> Response:
        user = _current_user(store)
        events = store.list_audit_events(user.id, limit=2000)
        lines = ["id,action,asset_id,ip,created_at"]
        for event in events:
            asset = "" if event.asset_id is None else str(event.asset_id)
            ip = (event.ip or "").replace('"', '""')
            lines.append(
                f'{event.id},{event.action},{asset},"{ip}",{event.created_at}'
            )
        payload = "\n".join(lines) + "\n"
        return Response(
            payload,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="ies-audit-{user.username}.csv"'
            },
        )

    @app.get("/account/public-key")
    @login_required(store)
    def download_public_key() -> Response:
        user = _current_user(store)
        return send_file(
            BytesIO(store.read_public_key(user.id)),
            mimetype="application/x-pem-file",
            download_name=f"{user.username}-public.pem",
            as_attachment=True,
        )

    @app.get("/backup")
    @login_required(store)
    def download_backup() -> Response:
        user = _current_user(store)
        archive = store.export_backup(user.id)
        _audit(store, user.id, "backup")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return send_file(
            BytesIO(archive),
            mimetype="application/zip",
            download_name=f"ies-backup-{user.username}-{stamp}.zip",
            as_attachment=True,
        )

    @app.post("/restore")
    @login_required(store)
    def restore_backup() -> Response:
        user = _current_user(store)
        upload = request.files.get("backup")
        if upload is None or not upload.filename:
            flash("Choose a backup zip to restore.", "error")
            return redirect(url_for("dashboard"))
        try:
            restored = store.import_backup(user.id, upload.read())
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        _audit(store, user.id, "backup")
        flash(f"Restored {restored} encrypted image(s).", "success")
        return redirect(url_for("dashboard"))

    @app.post("/api/token")
    def api_token() -> Response:
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        blocked = _guard_login(app, username, json_mode=True)
        if blocked is not None:
            return blocked

        user = store.authenticate_user(username, password)
        if not user:
            return _failed_login(app, username, json_mode=True)

        _login_success(app, store, user)
        now = datetime.now(timezone.utc)
        lifetime_seconds = int(app.config["JWT_LIFETIME_SECONDS"])
        token = jwt.encode(
            {
                "sub": str(user.id),
                "iss": app.config["JWT_ISSUER"],
                "aud": app.config["JWT_AUDIENCE"],
                "ver": user.auth_version,
                "iat": now,
                "exp": now + timedelta(hours=2),
                "ver": user.token_version,
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
                "images": [_asset_payload(asset) for asset in store.list_assets(user.id)],
                "shared": [
                    {
                        **_asset_payload(item.asset),
                        "owner": item.owner_username,
                        "shared_at": item.share.created_at,
                        "expires_at": item.share.expires_at,
                        "expired": item.share.is_expired(),
                    }
                    for item in store.list_shared_with_user(user.id)
                ],
            }
        )

    @app.post("/api/images/<int:asset_id>/share")
    @jwt_required(store)
    def api_share_image(asset_id: int) -> Response:
        user = g.api_user
        payload = request.get_json(silent=True) or {}
        try:
            share = _share_asset(
                store,
                owner=user,
                asset_id=asset_id,
                recipient_username=str(payload.get("username", "")),
                passphrase=payload.get("passphrase") or None,
                private_key_passphrase=payload.get("private_key_passphrase") or None,
                expires_at=_parse_share_expiry(
                    payload.get("expires_hours"),
                    payload.get("expires_days"),
                ),
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(
            {
                "ok": True,
                "share_id": share.id,
                "asset_id": asset_id,
                "expires_at": share.expires_at,
            }
        )

    @app.post("/api/images/<int:asset_id>/link")
    @jwt_required(store)
    def api_create_link(asset_id: int) -> Response:
        user = g.api_user
        payload = request.get_json(silent=True) or {}
        try:
            token, link = _create_link_share(
                store,
                owner=user,
                asset_id=asset_id,
                passphrase=payload.get("passphrase") or None,
                private_key_passphrase=payload.get("private_key_passphrase") or None,
                expires_at=_parse_share_expiry(
                    payload.get("expires_hours"),
                    payload.get("expires_days"),
                ),
                max_downloads=_parse_optional_int(payload.get("max_downloads")),
                label=str(payload.get("label") or ""),
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(
            {
                "ok": True,
                "link_id": link.id,
                "token": token,
                "url": url_for("open_link_share", token=token, _external=True),
                "expires_at": link.expires_at,
                "max_downloads": link.max_downloads,
            }
        )

    @app.get("/api/audit")
    @jwt_required(store)
    def api_audit() -> Response:
        user = g.api_user
        return jsonify(
            {
                "events": [
                    {
                        "id": event.id,
                        "action": event.action,
                        "asset_id": event.asset_id,
                        "ip": event.ip,
                        "created_at": event.created_at,
                    }
                    for event in store.list_audit_events(user.id)
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
                token_version = int(payload.get("ver", 1))
                if token_version != user.token_version:
                    raise ValueError("token version mismatch")
                g.api_user = user
            except Exception:
                return jsonify({"error": "invalid bearer token"}), 401
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def _ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _csrf_field() -> Markup:
    token = escape(_ensure_csrf_token())
    return Markup(f'<input type="hidden" name="csrf_token" value="{token}">')


def _establish_session(user: User) -> None:
    session.clear()
    session["user_id"] = user.id
    session["token_version"] = user.token_version
    session["last_seen"] = time.time()


def _current_user(store: VaultStore) -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    try:
        user = store.get_user(int(user_id))
    except LookupError:
        session.clear()
        return None
    cookie_version = session.get("token_version", 1)
    try:
        cookie_version = int(cookie_version)
    except (TypeError, ValueError):
        session.clear()
        return None
    if cookie_version != user.token_version:
        session.clear()
        return None
    idle = int(current_app.config.get("SESSION_IDLE_SECONDS", 1800) or 0)
    if idle > 0:
        try:
            last_seen = float(session.get("last_seen") or 0)
        except (TypeError, ValueError):
            last_seen = 0.0
        now = time.time()
        if last_seen and now - last_seen > idle:
            session.clear()
            return None
        session["last_seen"] = now
    return user


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


def _accessible_asset(
    store: VaultStore, asset_id: int, user: User
) -> tuple[EncryptedAsset, AssetShare | None]:
    asset = store.get_asset(asset_id)
    if asset.user_id == user.id:
        return asset, None
    share = store.get_share(asset_id, user.id)
    if share is None or share.is_expired():
        raise PermissionError("You do not have access to this encrypted image.")
    return asset, share


def _share_asset(
    store: VaultStore,
    *,
    owner: User,
    asset_id: int,
    recipient_username: str,
    passphrase: str | None,
    private_key_passphrase: str | None,
    expires_at: str | None = None,
) -> AssetShare:
    asset = _owned_asset(store, asset_id, owner)
    recipient_name = recipient_username.strip().lower()
    if not recipient_name:
        raise ValueError("Recipient username is required.")
    if recipient_name == owner.username:
        raise ValueError("You already own this image.")
    recipient = store.get_user_by_username(recipient_name)
    if recipient is None:
        raise LookupError("No account exists with that username.")

    data_key = unwrap_data_key(
        asset.metadata["key_wrap"],
        passphrase=passphrase,
        private_key_pem=store.read_private_key(owner.id) if asset.algorithm == RSA_HYBRID else None,
        private_key_passphrase=private_key_passphrase if asset.algorithm == RSA_HYBRID else None,
    )
    recipient_wrap = wrap_data_key_rsa(data_key, store.read_public_key(recipient.id))
    share = store.create_share(
        asset_id=asset.id,
        recipient_user_id=recipient.id,
        key_wrap=recipient_wrap,
        expires_at=expires_at,
    )
    _audit(store, owner.id, "share", asset.id)
    return share


def _hash_link_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _create_link_share(
    store: VaultStore,
    *,
    owner: User,
    asset_id: int,
    passphrase: str | None,
    private_key_passphrase: str | None,
    expires_at: str | None = None,
    max_downloads: int | None = None,
    label: str = "",
) -> tuple[str, LinkShare]:
    asset = _owned_asset(store, asset_id, owner)
    if max_downloads is not None and max_downloads <= 0:
        raise ValueError("max_downloads must be greater than zero.")
    data_key = unwrap_data_key(
        asset.metadata["key_wrap"],
        passphrase=passphrase,
        private_key_pem=store.read_private_key(owner.id) if asset.algorithm == RSA_HYBRID else None,
        private_key_passphrase=private_key_passphrase if asset.algorithm == RSA_HYBRID else None,
    )
    token = secrets.token_urlsafe(32)
    wrap = wrap_data_key_passphrase(data_key, token)
    link = store.create_link_share(
        asset_id=asset.id,
        token_hash=_hash_link_token(token),
        key_wrap=wrap,
        expires_at=expires_at,
        max_downloads=max_downloads,
        label=label,
    )
    _audit(store, owner.id, "link", asset.id)
    return token, link


def _resolve_link(store: VaultStore, token: str) -> tuple[LinkShare, EncryptedAsset]:
    link = store.get_link_share_by_token_hash(_hash_link_token(token))
    if link is None:
        raise LookupError("Link not found.")
    if link.is_expired() or link.is_exhausted():
        raise PermissionError("This capability link is no longer valid.")
    return link, store.get_asset(link.asset_id)


def _decrypt_link(
    store: VaultStore, token: str, *, count: bool
) -> tuple[bytes, EncryptedAsset]:
    link, asset = _resolve_link(store, token)
    store.ciphertext_sha256(asset)
    metadata = dict(asset.metadata)
    metadata["key_wrap"] = link.key_wrap
    plaintext = decrypt_image_bytes(
        store.read_ciphertext(asset),
        metadata,
        passphrase=token,
        aad=_aad_from_metadata(asset),
    )
    if count:
        store.increment_link_download(link.id)
    return plaintext, asset


def _parse_optional_int(raw: object) -> int | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise ValueError("Expected a whole number.") from exc


def _guard_login(app: Flask, username: str, *, json_mode: bool):
    guard: LoginGuard = app.extensions["login_guard"]
    verdict = guard.precheck(request.remote_addr or "", username)
    if verdict == "locked":
        return _locked_response(json_mode)
    if verdict == "rate_limited":
        if json_mode:
            return jsonify({"error": "too many login attempts"}), 429
        flash("Too many sign-in attempts. Please wait and try again.", "error")
        return redirect(url_for("index")), 429
    return None


def _failed_login(app: Flask, username: str, *, json_mode: bool):
    guard: LoginGuard = app.extensions["login_guard"]
    if guard.record_failure(username):
        return _locked_response(json_mode)
    if json_mode:
        return jsonify({"error": "invalid credentials"}), 401
    flash("Invalid username or password.", "error")
    return redirect(url_for("index"))


def _locked_response(json_mode: bool):
    if json_mode:
        return jsonify({"error": "account locked"}), 403
    flash("This account is locked because of too many failed sign-in attempts.", "error")
    return redirect(url_for("index")), 403


def _login_success(app: Flask, store: VaultStore, user: User) -> None:
    guard: LoginGuard = app.extensions["login_guard"]
    guard.record_success(user.username)
    _audit(store, user.id, "login")


def _audit(store: VaultStore, user_id: int, action: str, asset_id: int | None = None) -> None:
    store.add_audit_event(user_id, action, asset_id=asset_id, ip=request.remote_addr)


def _asset_payload(asset: EncryptedAsset) -> dict:
    return {
        "id": asset.id,
        "filename": asset.original_filename,
        "algorithm": asset.algorithm,
        "format": asset.image_format,
        "size": {"width": asset.width, "height": asset.height},
        "created_at": asset.created_at,
        "notes": asset.notes,
        "favorite": asset.favorite,
    }


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.accept_mimetypes
    return accept["application/json"] > accept["text/html"]


def _allowed_extension(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def _credential_throttle_key(username: str) -> str:
    normalized = username.strip().lower() or "anonymous"
    identity_digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]
    return f"{_remote_address()}:{identity_digest}"


def _strip_image_exif(image_bytes: bytes) -> bytes:
    """Re-save pixels without EXIF so location and camera tags never enter ciphertext."""
    with Image.open(BytesIO(image_bytes)) as image:
        image.load()
        image_format = (image.format or "PNG").upper()
        if image_format == "JPG":
            image_format = "JPEG"
        if not _image_has_exif(image, image_bytes):
            return image_bytes

        cleaned = image.copy()
        cleaned.info.pop("exif", None)
        cleaned.info.pop("xmp", None)
        cleaned.getexif().clear()
        if image_format == "JPEG" and cleaned.mode not in {"RGB", "L", "CMYK"}:
            cleaned = cleaned.convert("RGB")

        output = BytesIO()
        save_kwargs: dict[str, object] = {"format": image_format}
        if image_format == "JPEG":
            save_kwargs["quality"] = 95
            save_kwargs["exif"] = b""
        cleaned.save(output, **save_kwargs)
        return output.getvalue()


def _image_has_exif(image: Image.Image, raw: bytes) -> bool:
    if image.info.get("exif"):
        return True
    try:
        if dict(image.getexif()):
            return True
    except Exception:
        pass
    return _jpeg_has_exif_marker(raw)


def _jpeg_has_exif_marker(data: bytes) -> bool:
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return False
    index = 2
    length = len(data)
    while index + 4 <= length and data[index] == 0xFF:
        marker = data[index + 1]
        if marker == 0xDA:
            break
        if marker in {0x00, 0xFF}:
            index += 1
            continue
        if marker == 0xD8 or marker == 0xD9 or 0xD0 <= marker <= 0xD7:
            index += 2
            continue
        seglen = int.from_bytes(data[index + 2 : index + 4], "big")
        if seglen < 2:
            break
        payload_start = index + 4
        payload_end = index + 2 + seglen
        if payload_end > length:
            break
        if marker == 0xE1 and data[payload_start : payload_start + 4] == b"Exif":
            return True
        index = payload_end
    return False


def _parse_share_expiry(raw_hours: object, raw_days: object) -> str | None:
    hours_text = "" if raw_hours is None else str(raw_hours).strip()
    days_text = "" if raw_days is None else str(raw_days).strip()
    if not hours_text and not days_text:
        return None
    try:
        hours = float(hours_text) if hours_text else float(days_text) * 24.0
    except ValueError as exc:
        raise ValueError("Expiry must be a number of hours or days.") from exc
    if hours <= 0:
        raise ValueError("Expiry must be greater than zero.")
    if hours > 24 * 365 * 20:
        raise ValueError("Expiry is too far in the future.")
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")


def _asset_aad(user_id: int, original_filename: str, mime_type: str) -> bytes:
    return f"user={user_id}|filename={original_filename}|mime={mime_type}".encode("utf-8")


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
