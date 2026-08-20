from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path
import secrets
from sqlite3 import IntegrityError
from typing import Callable, TypeVar
import zipfile

import jwt
from flask import (
    Flask,
    Response,
    abort,
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

from .config import VERSION, Config
from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
)
from .storage import EncryptedAsset, User, VaultStore
from .throttle import AttemptThrottle


F = TypeVar("F", bound=Callable)

API_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

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
    app.extensions["auth_throttle"] = AttemptThrottle(
        max_failures=int(app.config.get("AUTH_MAX_FAILURES", 5)),
        window_seconds=int(app.config.get("AUTH_WINDOW_SECONDS", 300)),
    )

    @app.context_processor
    def inject_globals() -> dict:
        return {
            "current_user": _current_user(store),
            "algorithms": [
                (AES_GCM_PASSPHRASE, "AES-GCM passphrase"),
                (RSA_HYBRID, "RSA hybrid"),
            ],
            "csrf_token": session.get("csrf_token", ""),
            "app_version": VERSION,
        }

    @app.before_request
    def _prepare_request() -> Response | None:
        session.permanent = True
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        if request.method in API_SAFE_METHODS:
            return None
        if request.path.startswith("/api/"):
            return None
        if current_app.config.get("TESTING") and not current_app.config.get("FORCE_CSRF"):
            return None
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(str(submitted), str(session.get("csrf_token", ""))):
            if request.accept_mimetypes.best == "application/json":
                return jsonify({"error": "invalid csrf token"}), 400
            abort(400)
        return None

    @app.after_request
    def _security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: blob:; "
            "style-src 'self'; "
            "script-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(429)
    def _too_many_requests(error) -> tuple[str, int] | tuple[Response, int]:
        retry_after = getattr(error, "description", None)
        if request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json":
            payload = {"error": "too many authentication attempts"}
            if isinstance(retry_after, str) and retry_after.isdigit():
                payload["retry_after"] = int(retry_after)
            return jsonify(payload), 429
        return render_template("throttled.html", retry_after=retry_after), 429

    @app.get("/health")
    def health() -> Response:
        return jsonify({"ok": True, "service": "image-encryption-system", "version": VERSION})

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
        session["csrf_token"] = secrets.token_urlsafe(32)
        store.record_audit(
            event_type="account.created",
            user_id=user.id,
            detail=user.username,
            ip_address=_client_ip(),
        )
        flash("Account created. Your RSA keys were generated and stored locally.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/login")
    def login() -> Response:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        blocked = _enforce_auth_throttle(app, store, username)
        if blocked:
            return blocked

        user = store.authenticate_user(username, password)
        if not user:
            _record_failed_auth(app, store, username)
            flash("Invalid username or password.", "error")
            return redirect(url_for("index"))

        _clear_auth_failures(app, store, username)
        session.clear()
        session["user_id"] = user.id
        session["csrf_token"] = secrets.token_urlsafe(32)
        store.record_audit(
            event_type="auth.login",
            user_id=user.id,
            ip_address=_client_ip(),
        )
        flash("Signed in.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout() -> Response:
        user = _current_user(store)
        if user:
            store.record_audit(
                event_type="auth.logout",
                user_id=user.id,
                ip_address=_client_ip(),
            )
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("index"))

    @app.get("/dashboard")
    @login_required(store)
    def dashboard() -> str:
        user = _current_user(store)
        assets = store.list_assets(user.id)
        return render_template("dashboard.html", assets=assets)

    @app.get("/settings")
    @login_required(store)
    def settings() -> str:
        user = _current_user(store)
        events = store.list_audit_for_user(user.id)
        return render_template("settings.html", events=events)

    @app.post("/settings/password")
    @login_required(store)
    def change_password() -> Response:
        user = _current_user(store)
        old_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if new_password != confirm:
            flash("New password confirmation does not match.", "error")
            return redirect(url_for("settings"))
        try:
            store.change_password(user.id, old_password, new_password)
        except (ValueError, CryptoError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("settings"))
        store.record_audit(
            event_type="account.password_changed",
            user_id=user.id,
            ip_address=_client_ip(),
        )
        flash("Password updated. Your RSA private key was re-wrapped.", "success")
        return redirect(url_for("settings"))

    @app.post("/vault/export")
    @login_required(store)
    def export_vault() -> Response:
        user = _current_user(store)
        assets = store.list_assets(user.id)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            manifest = {
                "version": VERSION,
                "username": user.username,
                "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "images": [],
            }
            for asset in assets:
                archive.writestr(asset.stored_filename, store.read_ciphertext(asset))
                manifest["images"].append(
                    {
                        "id": asset.id,
                        "filename": asset.original_filename,
                        "stored_filename": asset.stored_filename,
                        "algorithm": asset.algorithm,
                        "mime_type": asset.mime_type,
                        "format": asset.image_format,
                        "width": asset.width,
                        "height": asset.height,
                        "created_at": asset.created_at,
                        "metadata": asset.metadata,
                    }
                )
            archive.writestr("manifest.json", _json_bytes(manifest))
        buffer.seek(0)
        store.record_audit(
            event_type="vault.exported",
            user_id=user.id,
            detail=f"{len(assets)} images",
            ip_address=_client_ip(),
        )
        return send_file(
            buffer,
            mimetype="application/zip",
            download_name=f"{user.username}-vault-backup.zip",
            as_attachment=True,
        )

    @app.post("/images")
    @login_required(store)
    def upload_image() -> Response:
        user = _current_user(store)
        upload = request.files.get("image")
        algorithm = request.form.get("algorithm", AES_GCM_PASSPHRASE)
        passphrase = request.form.get("passphrase", "")

        if upload is None or not upload.filename:
            flash("Choose an image to encrypt.", "error")
            return redirect(url_for("dashboard"))

        if not _allowed_extension(upload.filename, app.config["ALLOWED_EXTENSIONS"]):
            flash("Unsupported file extension.", "error")
            return redirect(url_for("dashboard"))

        image_bytes = upload.read()
        try:
            image_info = _inspect_image(image_bytes)
            aad = _asset_aad(user.id, upload.filename, image_info["mime_type"])
            public_key = store.read_public_key(user.id) if algorithm == RSA_HYBRID else None
            result = encrypt_image_bytes(
                image_bytes,
                algorithm,
                passphrase=passphrase if algorithm == AES_GCM_PASSPHRASE else None,
                public_key_pem=public_key,
                aad=aad,
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
                original_filename=upload.filename,
                algorithm=algorithm,
                mime_type=image_info["mime_type"],
                image_format=image_info["format"],
                width=image_info["width"],
                height=image_info["height"],
                metadata=metadata,
                ciphertext=result.ciphertext,
            )
        except (CryptoError, ValueError, UnidentifiedImageError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        store.record_audit(
            event_type="image.encrypted",
            user_id=user.id,
            detail=f"{asset.original_filename} ({asset.algorithm})",
            ip_address=_client_ip(),
        )
        flash("Image encrypted and stored in the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/decrypt")
    @login_required(store)
    def decrypt_image(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = _owned_asset(store, asset_id, user)
            plaintext = _decrypt_owned_asset(store, user, asset, request.form)
        except (LookupError, PermissionError, CryptoError) as exc:
            store.record_audit(
                event_type="image.decrypt_failed",
                user_id=user.id,
                detail=str(asset_id),
                ip_address=_client_ip(),
            )
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        store.record_audit(
            event_type="image.decrypted",
            user_id=user.id,
            detail=asset.original_filename,
            ip_address=_client_ip(),
        )
        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=False,
        )

    @app.get("/images/<int:asset_id>/ciphertext")
    @login_required(store)
    def download_ciphertext(asset_id: int) -> Response:
        user = _current_user(store)
        asset = _owned_asset(store, asset_id, user)
        return send_file(
            BytesIO(store.read_ciphertext(asset)),
            mimetype="application/octet-stream",
            download_name=f"{asset.original_filename}.enc",
            as_attachment=True,
        )

    @app.post("/images/<int:asset_id>/delete")
    @login_required(store)
    def delete_image(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = _owned_asset(store, asset_id, user)
            store.delete_asset(asset)
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        store.record_audit(
            event_type="image.deleted",
            user_id=user.id,
            detail=asset.original_filename,
            ip_address=_client_ip(),
        )
        flash("Encrypted image deleted from the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/api/token")
    def api_token() -> Response:
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        blocked = _enforce_auth_throttle(app, store, username, api=True)
        if blocked:
            return blocked

        user = store.authenticate_user(username, password)
        if not user:
            _record_failed_auth(app, store, username)
            return jsonify({"error": "invalid credentials"}), 401

        _clear_auth_failures(app, store, username)
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
        store.record_audit(
            event_type="auth.token_issued",
            user_id=user.id,
            ip_address=_client_ip(),
        )
        return jsonify({"token": token, "token_type": "Bearer", "expires_in": 7200})

    @app.get("/api/images")
    @jwt_required(store)
    def api_images() -> Response:
        user = g.api_user
        return jsonify({"images": [_asset_json(asset) for asset in store.list_assets(user.id)]})

    @app.post("/api/images")
    @jwt_required(store)
    def api_upload() -> Response:
        user = g.api_user
        upload = request.files.get("image")
        algorithm = request.form.get("algorithm", AES_GCM_PASSPHRASE)
        passphrase = request.form.get("passphrase", "")
        if upload is None or not upload.filename:
            return jsonify({"error": "image file is required"}), 400
        if not _allowed_extension(upload.filename, app.config["ALLOWED_EXTENSIONS"]):
            return jsonify({"error": "unsupported file extension"}), 400
        image_bytes = upload.read()
        try:
            image_info = _inspect_image(image_bytes)
            aad = _asset_aad(user.id, upload.filename, image_info["mime_type"])
            public_key = store.read_public_key(user.id) if algorithm == RSA_HYBRID else None
            result = encrypt_image_bytes(
                image_bytes,
                algorithm,
                passphrase=passphrase if algorithm == AES_GCM_PASSPHRASE else None,
                public_key_pem=public_key,
                aad=aad,
            )
            asset = store.save_asset(
                user_id=user.id,
                original_filename=upload.filename,
                algorithm=algorithm,
                mime_type=image_info["mime_type"],
                image_format=image_info["format"],
                width=image_info["width"],
                height=image_info["height"],
                metadata={
                    **result.metadata,
                    "aad": {
                        "user_id": user.id,
                        "original_filename": upload.filename,
                        "mime_type": image_info["mime_type"],
                    },
                },
                ciphertext=result.ciphertext,
            )
        except (CryptoError, ValueError, UnidentifiedImageError) as exc:
            return jsonify({"error": str(exc)}), 400
        store.record_audit(
            event_type="image.encrypted",
            user_id=user.id,
            detail=f"{asset.original_filename} ({asset.algorithm})",
            ip_address=_client_ip(),
        )
        return jsonify(_asset_json(asset)), 201

    @app.post("/api/images/<int:asset_id>/decrypt")
    @jwt_required(store)
    def api_decrypt(asset_id: int) -> Response:
        user = g.api_user
        payload = request.get_json(silent=True) or {}
        try:
            asset = _owned_asset(store, asset_id, user)
            plaintext = _decrypt_owned_asset(store, user, asset, payload)
        except (LookupError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 404
        except CryptoError as exc:
            store.record_audit(
                event_type="image.decrypt_failed",
                user_id=user.id,
                detail=str(asset_id),
                ip_address=_client_ip(),
            )
            return jsonify({"error": str(exc)}), 400
        store.record_audit(
            event_type="image.decrypted",
            user_id=user.id,
            detail=asset.original_filename,
            ip_address=_client_ip(),
        )
        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=False,
        )

    @app.delete("/api/images/<int:asset_id>")
    @jwt_required(store)
    def api_delete(asset_id: int) -> Response:
        user = g.api_user
        try:
            asset = _owned_asset(store, asset_id, user)
            store.delete_asset(asset)
        except (LookupError, PermissionError) as exc:
            return jsonify({"error": str(exc)}), 404
        store.record_audit(
            event_type="image.deleted",
            user_id=user.id,
            detail=asset.original_filename,
            ip_address=_client_ip(),
        )
        return jsonify({"ok": True})

    @app.get("/api/audit")
    @jwt_required(store)
    def api_audit() -> Response:
        user = g.api_user
        return jsonify(
            {
                "events": [
                    {
                        "id": event.id,
                        "type": event.event_type,
                        "detail": event.detail,
                        "created_at": event.created_at,
                    }
                    for event in store.list_audit_for_user(user.id)
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


def _owned_asset(store: VaultStore, asset_id: int, user: User) -> EncryptedAsset:
    asset = store.get_asset(asset_id)
    if asset.user_id != user.id:
        raise PermissionError("You do not have access to this encrypted image.")
    return asset


def _decrypt_owned_asset(store: VaultStore, user: User, asset: EncryptedAsset, payload) -> bytes:
    ciphertext = store.read_ciphertext(asset)
    aad = _aad_from_metadata(asset)
    return decrypt_image_bytes(
        ciphertext,
        asset.metadata,
        passphrase=_field(payload, "passphrase"),
        private_key_pem=store.read_private_key(user.id) if asset.algorithm == RSA_HYBRID else None,
        private_key_passphrase=_field(payload, "private_key_passphrase"),
        aad=aad,
    )


def _field(payload, name: str) -> str | None:
    if hasattr(payload, "get"):
        value = payload.get(name)
    else:
        value = None
    if value is None:
        return None
    value = str(value)
    return value or None


def _allowed_extension(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def _inspect_image(image_bytes: bytes) -> dict[str, int | str]:
    if len(image_bytes) < 24:
        raise ValueError("File is too small to be a valid image.")
    with Image.open(BytesIO(image_bytes)) as image:
        image.verify()

    with Image.open(BytesIO(image_bytes)) as image:
        image_format = image.format or "UNKNOWN"
        mime_type = Image.MIME.get(image_format, "application/octet-stream")
        width, height = image.size
        return {
            "format": image_format,
            "mime_type": mime_type,
            "width": width,
            "height": height,
        }


def _asset_aad(user_id: int, original_filename: str, mime_type: str) -> bytes:
    return f"user={user_id}|filename={original_filename}|mime={mime_type}".encode("utf-8")


def _aad_from_metadata(asset: EncryptedAsset) -> bytes:
    aad = asset.metadata.get("aad", {})
    return _asset_aad(
        int(aad.get("user_id", asset.user_id)),
        str(aad.get("original_filename", asset.original_filename)),
        str(aad.get("mime_type", asset.mime_type)),
    )


def _asset_json(asset: EncryptedAsset) -> dict:
    return {
        "id": asset.id,
        "filename": asset.original_filename,
        "algorithm": asset.algorithm,
        "format": asset.image_format,
        "mime_type": asset.mime_type,
        "size": {"width": asset.width, "height": asset.height, "bytes": asset.byte_size},
        "created_at": asset.created_at,
    }


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def _throttle_key(username: str) -> str:
    return f"{_client_ip()}|{username.strip().lower()}"


def _enforce_auth_throttle(
    app: Flask, store: VaultStore, username: str, *, api: bool = False
) -> Response | None:
    retry_after = store.lockout_retry_after(username)
    if retry_after:
        return _throttle_response(retry_after, api=api)

    throttle: AttemptThrottle = app.extensions["auth_throttle"]
    decision = throttle.check(_throttle_key(username))
    if not decision.allowed:
        return _throttle_response(decision.retry_after, api=api)
    return None


def _record_failed_auth(app: Flask, store: VaultStore, username: str) -> None:
    throttle: AttemptThrottle = app.extensions["auth_throttle"]
    throttle.record_failure(_throttle_key(username))
    store.register_auth_failure(
        username,
        lockout_seconds=int(app.config.get("AUTH_LOCKOUT_SECONDS", 900)),
        max_failures=int(app.config.get("AUTH_MAX_FAILURES", 5)),
    )
    store.record_audit(
        event_type="auth.failed",
        detail=username.strip().lower()[:64],
        ip_address=_client_ip(),
    )


def _clear_auth_failures(app: Flask, store: VaultStore, username: str) -> None:
    throttle: AttemptThrottle = app.extensions["auth_throttle"]
    throttle.record_success(_throttle_key(username))
    store.clear_auth_failures(username)


def _throttle_response(retry_after: int, *, api: bool) -> Response:
    body = {"error": "too many authentication attempts", "retry_after": retry_after}
    response = jsonify(body) if api else Response(
        render_template("throttled.html", retry_after=retry_after),
        status=429,
        mimetype="text/html",
    )
    response.status_code = 429
    response.headers["Retry-After"] = str(max(1, retry_after))
    return response


def _json_bytes(payload: dict) -> bytes:
    import json

    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
