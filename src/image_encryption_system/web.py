from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path
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
from PIL import Image, UnidentifiedImageError

from .config import Config
from .crypto import (
    AES_GCM_PASSPHRASE,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
)
from .storage import EncryptedAsset, User, VaultStore


F = TypeVar("F", bound=Callable)


class CredentialThrottle:
    def __init__(self, *, max_attempts: int, window_seconds: int, lockout_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.failures: dict[str, list[float]] = {}
        self.locked_until: dict[str, float] = {}

    def is_limited(self, key: str) -> bool:
        now = time.monotonic()
        until = self.locked_until.get(key)
        if until is None:
            return False
        if until <= now:
            self.locked_until.pop(key, None)
            return False
        return True

    def record_failure(self, key: str) -> None:
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
        self.failures.pop(key, None)
        self.locked_until.pop(key, None)


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
    app.extensions["credential_throttle"] = CredentialThrottle(
        max_attempts=app.config["AUTH_RATE_LIMIT_ATTEMPTS"],
        window_seconds=app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"],
        lockout_seconds=app.config["AUTH_RATE_LIMIT_LOCKOUT_SECONDS"],
    )

    @app.context_processor
    def inject_globals() -> dict:
        return {
            "current_user": _current_user(store),
            "algorithms": [
                (AES_GCM_PASSPHRASE, "AES-GCM passphrase"),
                (RSA_HYBRID, "RSA hybrid"),
            ],
        }

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
    def login() -> Response:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        throttle = app.extensions["credential_throttle"]
        throttle_key = _credential_throttle_key(username)
        if throttle.is_limited(throttle_key):
            flash("Too many failed sign-in attempts. Please wait before trying again.", "error")
            return redirect(url_for("index"))

        user = store.authenticate_user(username, password)
        if not user:
            throttle.record_failure(throttle_key)
            flash("Invalid username or password.", "error")
            return redirect(url_for("index"))

        throttle.reset(throttle_key)
        session.clear()
        session["user_id"] = user.id
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
        assets = store.list_assets(user.id)
        return render_template("dashboard.html", assets=assets)

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
            store.save_asset(
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

        flash("Image encrypted and stored in the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/decrypt")
    @login_required(store)
    def decrypt_image(asset_id: int) -> Response:
        user = _current_user(store)
        try:
            asset = _owned_asset(store, asset_id, user)
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
                aad=aad,
            )
        except (LookupError, PermissionError, CryptoError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=False,
        )

    @app.post("/api/token")
    def api_token() -> Response:
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        throttle = app.extensions["credential_throttle"]
        throttle_key = _credential_throttle_key(username)
        if throttle.is_limited(throttle_key):
            return jsonify({"error": "too many failed attempts"}), 429

        user = store.authenticate_user(username, password)
        if not user:
            throttle.record_failure(throttle_key)
            return jsonify({"error": "invalid credentials"}), 401

        throttle.reset(throttle_key)
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
                "images": [
                    {
                        "id": asset.id,
                        "filename": asset.original_filename,
                        "algorithm": asset.algorithm,
                        "format": asset.image_format,
                        "size": {"width": asset.width, "height": asset.height},
                        "created_at": asset.created_at,
                    }
                    for asset in store.list_assets(user.id)
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


def _allowed_extension(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def _credential_throttle_key(username: str) -> str:
    remote = request.remote_addr or "unknown"
    return f"{remote}:{username.strip().lower() or 'anonymous'}"


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
