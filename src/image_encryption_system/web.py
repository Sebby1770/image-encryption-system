from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
from io import BytesIO
from pathlib import Path
import secrets
from sqlite3 import IntegrityError
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

from .config import Config
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
from .storage import AssetShare, EncryptedAsset, User, VaultStore


F = TypeVar("F", bound=Callable)


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
        if request.path.startswith("/api/"):
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
        session.clear()
        session["user_id"] = user.id
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
        _audit(store, user.id, "password_change")
        flash("Password updated. Your RSA private key was re-encrypted.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    @login_required(store)
    def dashboard() -> str:
        user = _current_user(store)
        query = (request.args.get("q") or "").strip()
        algorithm = (request.args.get("algorithm") or "").strip() or None
        assets = store.list_assets(user.id, query=query or None, algorithm=algorithm)
        shared_items = store.list_shared_with_user(
            user.id, query=query or None, algorithm=algorithm
        )
        recipients = store.list_recipients_for_owner(user.id)
        return render_template(
            "dashboard.html",
            assets=assets,
            shared_items=shared_items,
            recipients=recipients,
            query=query,
            selected_algorithm=algorithm or "",
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
            _audit(store, user.id, "upload", asset.id)
        except (CryptoError, ValueError, UnidentifiedImageError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        flash("Image encrypted and stored in the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/decrypt")
    @login_required(store)
    def decrypt_image(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset, share = _accessible_asset(store, asset_id, user)
            ciphertext = store.read_ciphertext(asset)
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
        except CryptoError as exc:
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
            _share_asset(
                store,
                owner=user,
                asset_id=asset_id,
                recipient_username=recipient_name,
                passphrase=request.form.get("passphrase") or None,
                private_key_passphrase=request.form.get("private_key_passphrase") or None,
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        flash(f"Shared with {recipient_name.strip().lower()}.", "success")
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
        return jsonify(
            {
                "images": [_asset_payload(asset) for asset in store.list_assets(user.id)],
                "shared": [
                    {
                        **_asset_payload(item.asset),
                        "owner": item.owner_username,
                        "shared_at": item.share.created_at,
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
            )
        except (LookupError, PermissionError, CryptoError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True, "share_id": share.id, "asset_id": asset_id})

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
                )
                g.api_user = store.get_user(int(payload["sub"]))
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


def _accessible_asset(
    store: VaultStore, asset_id: int, user: User
) -> tuple[EncryptedAsset, AssetShare | None]:
    asset = store.get_asset(asset_id)
    if asset.user_id == user.id:
        return asset, None
    share = store.get_share(asset_id, user.id)
    if share is None:
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
    )
    _audit(store, owner.id, "share", asset.id)
    return share


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
    }


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.accept_mimetypes
    return accept["application/json"] > accept["text/html"]


def _allowed_extension(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def _inspect_image(image_bytes: bytes) -> dict[str, int | str]:
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
