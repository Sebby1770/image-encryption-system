from __future__ import annotations

import hmac
import json
import secrets
import struct
import time
import warnings
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from sqlite3 import IntegrityError
from typing import Any, TypeVar

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
from flask.typing import ResponseReturnValue
from markupsafe import Markup, escape
from PIL import Image, ImageOps, ImageSequence, UnidentifiedImageError
from werkzeug.exceptions import RequestEntityTooLarge

from . import crypto
from .config import IMAGE_MIME_TYPES, PLACEHOLDER_SECRETS, Config
from .crypto import (
    AES_GCM_PASSPHRASE,
    ENVELOPE_V3,
    GCM_TAG_BYTES,
    MAX_METADATA_BYTES,
    MIN_SCRYPT_N,
    RSA_HYBRID,
    WRAP_RSA,
    WRAP_SCRYPT,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
    is_legacy_private_key,
    pack_ies,
    public_key_fingerprint,
    unwrap_data_key,
    validate_envelope,
    validate_key_wrap,
    web_aad,
    wrap_data_key_passphrase,
    wrap_data_key_rsa,
)
from .security import LoginGuard, RequestThrottle, validate_password
from .storage import (
    AssetShare,
    EncryptedAsset,
    LinkShare,
    User,
    VaultStore,
    load_or_create_secret,
)


class UnsupportedImageError(ValueError):
    """Raised when an upload decodes to a format or size the vault refuses."""


@dataclass(frozen=True)
class ImageInfo:
    format: str
    mime_type: str
    width: int
    height: int


F = TypeVar("F", bound=Callable)

# Every HTML page: no inline script or style, no framing, same-origin forms.
PAGE_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
# Decrypted plaintext: even if a non-image slipped through, it cannot run script,
# load anything, or be framed, and it is never written to a cache.
PLAINTEXT_CSP = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox"
SECRET_KEY_FILENAME = "flask-secret.key"
# Formats a browser can both encrypt and display again after decrypting. TIFF
# is server-mode only: browsers (other than Safari) cannot render it.
END_TO_END_FORMATS = frozenset({"PNG", "JPEG", "WEBP", "GIF", "BMP"})
END_TO_END_CONTEXT = frozenset(
    {
        "asset",
        "algorithm",
        "wrap",
        "owner",
        "filename",
        "mime",
        "format",
        "width",
        "height",
        "source",
    }
)
SERVER_SIDE_REFUSED = (
    "This image is end-to-end encrypted: open, share, and link it from your browser. "
    "The server never holds its key."
)


def _resolve_secrets(app: Flask) -> bytes | None:
    """Replace unset or published placeholder secrets before anything signs.

    Returns the operator-supplied audit key, or None to let the store use its
    persisted per-instance key.
    """
    secret = app.config.get("SECRET_KEY")
    if not secret or secret in PLACEHOLDER_SECRETS:
        if secret:
            app.logger.warning("SECRET_KEY is a published placeholder value; ignoring it.")
        secret = load_or_create_secret(Path(app.config["KEY_DIR"]) / SECRET_KEY_FILENAME)
        app.config["SECRET_KEY"] = secret
    elif len(str(secret)) < 32:
        app.logger.warning("SECRET_KEY is shorter than 32 characters.")

    jwt_secret = app.config.get("JWT_SECRET")
    if not jwt_secret or jwt_secret in PLACEHOLDER_SECRETS:
        # Derived rather than reused, so the session and JWT keys are separate.
        app.config["JWT_SECRET"] = hmac.new(
            str(secret).encode("utf-8"), b"ies/jwt/v1", sha256
        ).hexdigest()

    audit_key = app.config.get("AUDIT_HMAC_KEY")
    if not audit_key or audit_key in PLACEHOLDER_SECRETS:
        return None
    return str(audit_key).encode("utf-8")


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
    app.config.setdefault("ALLOWED_IMAGE_FORMATS", Config.ALLOWED_IMAGE_FORMATS)
    app.config["MAX_IMAGE_PIXELS"] = int(
        app.config.get("MAX_IMAGE_PIXELS", Config.MAX_IMAGE_PIXELS)
    )
    audit_key = _resolve_secrets(app)

    store = VaultStore(
        database_path=app.config["DATABASE_PATH"],
        vault_dir=app.config["VAULT_DIR"],
        key_dir=app.config["KEY_DIR"],
        audit_key=audit_key,
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
    app.extensions["throttles"] = {
        name: RequestThrottle(
            store,
            f"throttle:{name}",
            limit=int(app.config.get(f"{name.upper()}_RATE_LIMIT", limit)),
            window_seconds=int(app.config.get(f"{name.upper()}_RATE_WINDOW_SECONDS", window)),
        )
        for name, limit, window in (("register", 5, 3600), ("decrypt", 30, 300), ("link", 20, 300))
    }

    @app.context_processor
    def inject_globals() -> dict[str, object]:
        return {
            "current_user": _current_user(store),
            "csrf_token": _ensure_csrf_token(),
            "csrf_field": _csrf_field(),
            "algorithms": [
                (AES_GCM_PASSPHRASE, "AES-GCM passphrase"),
                (RSA_HYBRID, "RSA hybrid"),
            ],
            "min_password_length": int(app.config.get("MIN_PASSWORD_LENGTH", 10)),
        }

    @app.before_request
    def csrf_protect() -> ResponseReturnValue | None:
        _ensure_csrf_token()
        if request.method != "POST" or not current_app.config.get("CSRF_ENABLED"):
            return None
        if request.path.startswith("/api/") or request.path.startswith("/l/"):
            return None
        expected = session.get("csrf_token") or ""
        # fetch() calls send the token as a header; a cross-site page cannot set
        # one without a CORS preflight this app never answers.
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        if not expected or not submitted or not hmac.compare_digest(str(expected), str(submitted)):
            if _wants_json():
                return jsonify({"error": "missing or invalid CSRF token"}), 400
            return ("Missing or invalid CSRF token.", 400)
        return None

    @app.after_request
    def security_headers(response: Response) -> Response:
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        # Capability-link tokens live in the URL path; never leak them via Referer.
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Content-Security-Policy", PAGE_CSP)
        headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
        )
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Only meaningful over TLS; asserting it on plain HTTP would pin the
        # browser to a scheme a development host does not serve.
        hsts = int(current_app.config.get("HSTS_SECONDS", 0) or 0)
        if hsts > 0 and request.is_secure:
            headers.setdefault("Strict-Transport-Security", f"max-age={hsts}; includeSubDomains")
        return response

    @app.get("/healthz")
    def healthz() -> ResponseReturnValue:
        """Liveness/readiness probe: confirms the process and database answer.

        Unauthenticated by design and deliberately empty of detail.
        """
        try:
            store.count_users()
        except Exception:
            return jsonify({"status": "unavailable"}), 503
        return jsonify({"status": "ok"})

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error: RequestEntityTooLarge) -> ResponseReturnValue:
        limit_mb = int(app.config["MAX_CONTENT_LENGTH"]) // (1024 * 1024)
        if _wants_json():
            return jsonify({"error": f"upload exceeds the {limit_mb} MB limit"}), 413
        flash(f"File exceeds the {limit_mb} MB upload limit.", "error")
        return redirect(url_for("dashboard")), 413

    @app.get("/")
    def index() -> ResponseReturnValue:
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return render_template("auth.html", mode="login")

    @app.get("/register")
    def register_form() -> ResponseReturnValue:
        return render_template("auth.html", mode="register")

    @app.post("/register")
    def register() -> ResponseReturnValue:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Each registration generates an RSA-3072 key pair, so an unthrottled
        # caller can burn CPU indefinitely without ever holding an account.
        if not _throttle(app, "register", request.remote_addr or "-"):
            flash("Too many accounts created from this address. Try again later.", "error")
            return redirect(url_for("register_form")), 429
        try:
            validate_password(
                password,
                username=username,
                min_length=int(app.config.get("MIN_PASSWORD_LENGTH", 10)),
            )
            user = store.create_user(username, password)
        except IntegrityError:
            flash("That username is already registered.", "error")
            return redirect(url_for("register_form"))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("register_form"))

        _establish_session(store, user)
        flash("Account created. Your RSA keys were generated and stored locally.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/login")
    def login() -> ResponseReturnValue:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        blocked = _guard_login(app, username, json_mode=False)
        if blocked is not None:
            return blocked

        user = store.authenticate_user(username, password)
        if not user:
            return _failed_login(app, username, json_mode=False)

        _login_success(app, store, user, password)
        _establish_session(store, user)
        flash("Signed in.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout() -> ResponseReturnValue:
        sid = session.get("sid")
        if isinstance(sid, str) and sid:
            store.delete_session(sid)
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("index"))

    @app.get("/account/password")
    @login_required(store)
    def password_form() -> ResponseReturnValue:
        user = _require_user(store)
        try:
            legacy_key = is_legacy_private_key(store.read_private_key(user.id))
        except (CryptoError, OSError):
            legacy_key = False
        return render_template(
            "account.html",
            fingerprint=public_key_fingerprint(store.read_public_key(user.id)),
            legacy_key=legacy_key,
        )

    @app.post("/account/password")
    @login_required(store)
    def change_password() -> ResponseReturnValue:
        user = _require_user(store)
        old_password = request.form.get("old_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
            return redirect(url_for("password_form"))
        try:
            validate_password(
                new_password,
                username=user.username,
                min_length=int(app.config.get("MIN_PASSWORD_LENGTH", 10)),
            )
            store.change_password(user.id, old_password, new_password)
        except (ValueError, CryptoError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("password_form"))
        refreshed = store.get_user(user.id)
        session["token_version"] = refreshed.token_version
        store.delete_user_sessions(user.id, keep_sid=str(session.get("sid") or ""))
        _audit(store, user.id, "password_change")
        flash(
            "Password updated. Your RSA private key was re-encrypted. "
            "Other sessions were signed out.",
            "success",
        )
        return redirect(url_for("dashboard"))

    @app.post("/account/delete")
    @login_required(store)
    def delete_account() -> ResponseReturnValue:
        user = _require_user(store)
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
    def dashboard() -> ResponseReturnValue:
        user = _require_user(store)
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
            scrypt_n=crypto.SCRYPT_N,
            max_upload_bytes=int(app.config["MAX_CONTENT_LENGTH"]),
            max_image_pixels=int(app.config["MAX_IMAGE_PIXELS"]),
        )

    @app.post("/images")
    @login_required(store)
    def upload_image() -> ResponseReturnValue:
        user = _require_user(store)
        upload = request.files.get("image")
        algorithm = request.form.get("algorithm", AES_GCM_PASSPHRASE)
        passphrase = request.form.get("passphrase", "")

        if upload is None or not upload.filename:
            flash("Choose an image to encrypt.", "error")
            return redirect(url_for("dashboard"))
        if request.form.get("mode") == "browser":
            # End-to-end was chosen but the page posted the plaintext anyway (the
            # module failed to run). Never store what the user meant to keep
            # from the server.
            flash(
                "End-to-end encryption did not run in your browser, so nothing was stored. "
                "Reload the page and try again, or choose server mode.",
                "error",
            )
            return redirect(url_for("dashboard"))

        if not _allowed_extension(upload.filename, app.config["ALLOWED_EXTENSIONS"]):
            flash("Unsupported file extension.", "error")
            return redirect(url_for("dashboard"))

        try:
            image_bytes, image_info = _prepare_upload(
                upload.read(),
                allowed_formats=app.config["ALLOWED_IMAGE_FORMATS"],
                max_pixels=app.config["MAX_IMAGE_PIXELS"],
            )
            public_key = store.read_public_key(user.id) if algorithm == RSA_HYBRID else None
            result = encrypt_image_bytes(
                image_bytes,
                algorithm,
                passphrase=passphrase if algorithm == AES_GCM_PASSPHRASE else None,
                public_key_pem=public_key,
                context={
                    "owner": user.id,
                    "filename": upload.filename[:255],
                    "mime": image_info.mime_type,
                    "format": image_info.format,
                    "width": image_info.width,
                    "height": image_info.height,
                    "source": "web",
                },
            )
            asset = store.save_asset(
                user_id=user.id,
                original_filename=upload.filename,
                algorithm=algorithm,
                mime_type=image_info.mime_type,
                image_format=image_info.format,
                width=image_info.width,
                height=image_info.height,
                metadata=result.metadata,
                ciphertext=result.ciphertext,
                asset_uuid=result.metadata["context"]["asset"],
            )
            _audit(store, user.id, "upload", asset.id)
        except (CryptoError, UnsupportedImageError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        flash("Image encrypted and stored in the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/decrypt")
    @login_required(store)
    def decrypt_image(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
        # Every attempt tests a passphrase or private-key password against real
        # ciphertext. Keyed per account, not per asset: keying on the asset
        # would let one user throttle another's shared image.
        if not _throttle(app, "decrypt", f"user:{user.id}"):
            message = "Too many decryption attempts. Wait a few minutes and try again."
            if _wants_json():
                return jsonify({"error": message}), 429
            flash(message, "error")
            return redirect(url_for("dashboard")), 429
        try:
            asset, share = _accessible_asset(store, asset_id, user)
            _require_server_side(asset)
            ciphertext = store.read_ciphertext(asset)
            store.ciphertext_sha256(asset)
            metadata = dict(asset.metadata)
            _check_sealed_context(asset, primary_wrap=share is None)
            if share is not None:
                metadata["key_wrap"] = share.key_wrap
                plaintext = decrypt_image_bytes(
                    ciphertext,
                    metadata,
                    private_key_pem=store.read_private_key(user.id),
                    private_key_passphrase=request.form.get("private_key_passphrase") or None,
                    aad=_legacy_aad(asset),
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
                    aad=_legacy_aad(asset),
                )
            response = _plaintext_response(plaintext, asset, as_attachment=False)
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
            if _wants_json():
                return jsonify({"error": str(exc)}), 400
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        return response

    @app.post("/images/<int:asset_id>/share")
    @login_required(store)
    def share_image(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
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
    def revoke_share(share_id: int) -> ResponseReturnValue:
        user = _require_user(store)
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
    def rotate_passphrase(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
        old_passphrase = request.form.get("old_passphrase") or ""
        new_passphrase = request.form.get("new_passphrase") or ""
        try:
            asset = _owned_asset(store, asset_id, user)
            _require_server_side(asset)
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
    def update_image_meta(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
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
    def delete_many_images() -> ResponseReturnValue:
        user = _require_user(store)
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
    def create_link_share(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
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
    def revoke_link_share(link_id: int) -> ResponseReturnValue:
        user = _require_user(store)
        try:
            link = store.delete_link_share(link_id, user.id)
            _audit(store, user.id, "revoke_link", link.asset_id)
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        flash("Capability link revoked.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/l/<token>")
    def open_link_share(token: str) -> ResponseReturnValue:
        # Capability links are unauthenticated and CSRF-exempt by design, so the
        # bearer token is the only secret. Bound token guessing per address.
        limited = _link_throttled(app)
        if limited is not None:
            return limited
        store.sweep_expired_shares()
        try:
            link, asset = _resolve_link(store, token)
        except (LookupError, PermissionError) as exc:
            if _wants_json():
                return jsonify({"error": str(exc)}), 404
            return (str(exc), 404)
        return render_template("link.html", asset=asset, link=link, token=token)

    @app.post("/l/<token>/decrypt")
    def decrypt_link_share(token: str) -> ResponseReturnValue:
        # Capability links are unauthenticated and CSRF-exempt by design, so the
        # bearer token is the only secret. Bound token guessing per address.
        limited = _link_throttled(app)
        if limited is not None:
            return limited
        try:
            return _decrypt_link(store, token)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except (CryptoError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/l/<token>/blob")
    def download_link_blob(token: str) -> ResponseReturnValue:
        # Capability links are unauthenticated and CSRF-exempt by design, so the
        # bearer token is the only secret. Bound token guessing per address.
        limited = _link_throttled(app)
        if limited is not None:
            return limited
        try:
            link, asset = _resolve_link(store, token)
            store.ciphertext_sha256(asset)
            metadata = dict(asset.metadata)
            metadata["key_wrap"] = link.key_wrap
            blob = pack_ies(store.read_ciphertext(asset), metadata)
            if not store.reserve_link_download(link.id):
                raise PermissionError("This capability link is no longer valid.")
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        response = send_file(
            BytesIO(blob),
            mimetype="application/octet-stream",
            download_name=f"{asset.original_filename}.ies",
            as_attachment=True,
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/images/<int:asset_id>/delete")
    @login_required(store)
    def delete_image(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
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
    def download_ciphertext(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
        try:
            asset = _owned_asset(store, asset_id, user)
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        blob = pack_ies(store.read_ciphertext(asset), asset.metadata)
        download_name = f"{asset.original_filename}.ies"
        response = send_file(
            BytesIO(blob),
            mimetype="application/octet-stream",
            download_name=download_name,
            as_attachment=True,
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/audit")
    @login_required(store)
    def audit() -> ResponseReturnValue:
        user = _require_user(store)
        events = store.list_audit_events(user.id)
        chain = store.verify_audit_chain(user.id)
        return render_template("audit.html", events=events, chain=chain)

    @app.get("/audit.csv")
    @login_required(store)
    def audit_csv() -> ResponseReturnValue:
        user = _require_user(store)
        events = store.list_audit_events(user.id, limit=2000)
        lines = ["id,action,asset_id,ip,created_at"]
        for event in events:
            asset = "" if event.asset_id is None else str(event.asset_id)
            ip = (event.ip or "").replace('"', '""')
            lines.append(f'{event.id},{event.action},{asset},"{ip}",{event.created_at}')
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
    def download_public_key() -> ResponseReturnValue:
        user = _require_user(store)
        return send_file(
            BytesIO(store.read_public_key(user.id)),
            mimetype="application/x-pem-file",
            download_name=f"{user.username}-public.pem",
            as_attachment=True,
        )

    @app.get("/backup")
    @login_required(store)
    def download_backup() -> ResponseReturnValue:
        user = _require_user(store)
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
    def restore_backup() -> ResponseReturnValue:
        user = _require_user(store)
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

    # ----------------------------------------------------------------------
    # End-to-end mode. The browser encrypts, decrypts, shares, and links; these
    # routes only ever receive ciphertext and key wraps the server cannot open.

    @app.post("/images/sealed")
    @login_required(store)
    def upload_sealed_image() -> ResponseReturnValue:
        user = _require_user(store)
        upload = request.files.get("ciphertext")
        if upload is None:
            return _json_error("Missing ciphertext.", 400)
        try:
            ciphertext = upload.read()
            metadata, context = _check_sealed_upload(
                store,
                user,
                request.form.get("envelope") or "",
                ciphertext,
                max_pixels=app.config["MAX_IMAGE_PIXELS"],
            )
            asset = store.save_asset(
                user_id=user.id,
                original_filename=context["filename"],
                algorithm=metadata["algorithm"],
                mime_type=context["mime"],
                image_format=context["format"],
                width=context["width"],
                height=context["height"],
                metadata=metadata,
                ciphertext=ciphertext,
                asset_uuid=context["asset"],
            )
        except (CryptoError, UnsupportedImageError, ValueError) as exc:
            return _json_error(str(exc), 400)
        _audit(store, user.id, "upload", asset.id)
        flash(
            "Image encrypted in your browser and stored. The server only received ciphertext.",
            "success",
        )
        return jsonify({"ok": True, "asset_id": asset.id}), 201

    @app.get("/images/<int:asset_id>/sealed")
    @login_required(store)
    def download_sealed(asset_id: int) -> ResponseReturnValue:
        """The ciphertext with the caller's own wrap: the owner's, or their share."""
        user = _require_user(store)
        try:
            asset, share = _accessible_asset(store, asset_id, user)
            store.ciphertext_sha256(asset)
            _check_sealed_context(asset, primary_wrap=share is None)
            metadata = dict(asset.metadata)
            if share is not None:
                metadata["key_wrap"] = share.key_wrap
            blob = pack_ies(store.read_ciphertext(asset), metadata)
        except PermissionError as exc:
            return _json_error(str(exc), 403)
        except LookupError as exc:
            return _json_error(str(exc), 404)
        except (CryptoError, ValueError) as exc:
            return _json_error(str(exc), 400)
        _audit(store, user.id, "fetch", asset.id)
        return _ciphertext_response(blob, f"{asset.original_filename}.ies")

    @app.post("/account/private-key")
    @login_required(store)
    def sealed_private_key() -> ResponseReturnValue:
        """The account's Scrypt-sealed private key, for unwrapping in the browser.

        POST with a CSRF token, throttled like decryption, never cached. The
        password that opens it is typed into the page and never sent here.
        """
        user = _require_user(store)
        if not _throttle(app, "decrypt", f"user:{user.id}"):
            return _json_error(
                "Too many decryption attempts. Wait a few minutes and try again.", 429
            )
        try:
            blob = store.read_private_key(user.id)
        except (CryptoError, OSError) as exc:
            return _json_error(str(exc), 400)
        if is_legacy_private_key(blob):
            return _json_error(
                "Sign out and back in once to upgrade your key protection, then try again.", 409
            )
        _audit(store, user.id, "key_fetch")
        response = jsonify({"owner": user.id, "private_key": json.loads(blob)})
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/users/<username>/public-key")
    @login_required(store)
    def user_public_key(username: str) -> ResponseReturnValue:
        _require_user(store)
        target = store.get_user_by_username(username)
        if target is None:
            return _json_error("No account exists with that username.", 404)
        return jsonify(
            {
                "username": target.username,
                "public_key": store.read_public_key(target.id).decode("ascii"),
            }
        )

    @app.post("/images/<int:asset_id>/shares/sealed")
    @login_required(store)
    def share_sealed(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
        payload = _json_payload()
        try:
            asset = _owned_asset(store, asset_id, user)
            _require_end_to_end(asset)
            recipient = _resolve_recipient(store, user, str(payload.get("username", "")))
            key_wrap = payload.get("key_wrap")
            if validate_key_wrap(key_wrap) != WRAP_RSA:
                raise CryptoError("A share must wrap the key to the recipient's public key.")
            assert isinstance(key_wrap, dict)
            share = store.create_share(
                asset_id=asset.id,
                recipient_user_id=recipient.id,
                key_wrap=key_wrap,
                expires_at=_parse_share_expiry(
                    payload.get("expires_hours"), payload.get("expires_days")
                ),
            )
        except PermissionError as exc:
            return _json_error(str(exc), 403)
        except LookupError as exc:
            return _json_error(str(exc), 404)
        except (CryptoError, ValueError) as exc:
            return _json_error(str(exc), 400)
        _audit(store, user.id, "share", asset.id)
        flash(f"Shared with {recipient.username} end-to-end.", "success")
        return jsonify(
            {
                "ok": True,
                "share_id": share.id,
                "username": recipient.username,
                "expires_at": share.expires_at,
            }
        )

    @app.post("/images/<int:asset_id>/links/sealed")
    @login_required(store)
    def link_sealed(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
        payload = _json_payload()
        try:
            asset = _owned_asset(store, asset_id, user)
            _require_end_to_end(asset)
            key_wrap = payload.get("key_wrap")
            # Link keys are 256-bit random values, so the KDF floor is plenty.
            if validate_key_wrap(key_wrap, min_scrypt_n=MIN_SCRYPT_N) != WRAP_SCRYPT:
                raise CryptoError("A link must wrap the key with its link secret.")
            assert isinstance(key_wrap, dict)
            max_downloads = _parse_optional_int(payload.get("max_downloads"))
            if max_downloads is not None and max_downloads <= 0:
                raise ValueError("max_downloads must be greater than zero.")
            token = secrets.token_urlsafe(32)
            link = store.create_link_share(
                asset_id=asset.id,
                token_hash=_hash_link_token(token),
                key_wrap=key_wrap,
                expires_at=_parse_share_expiry(
                    payload.get("expires_hours"), payload.get("expires_days")
                ),
                max_downloads=max_downloads,
                label=str(payload.get("label") or "").strip()[:80],
            )
        except PermissionError as exc:
            return _json_error(str(exc), 403)
        except LookupError as exc:
            return _json_error(str(exc), 404)
        except (CryptoError, ValueError) as exc:
            return _json_error(str(exc), 400)
        _audit(store, user.id, "link", asset.id)
        flash("End-to-end link created. Its key exists only in the link you copied.", "success")
        return jsonify(
            {
                "ok": True,
                "link_id": link.id,
                # The browser appends #<secret>; the fragment never reaches us.
                "url": url_for("open_link_share", token=token, _external=True),
                "expires_at": link.expires_at,
                "max_downloads": link.max_downloads,
            }
        )

    @app.post("/images/<int:asset_id>/rewrap")
    @login_required(store)
    def rewrap_sealed(asset_id: int) -> ResponseReturnValue:
        user = _require_user(store)
        payload = _json_payload()
        try:
            asset = _owned_asset(store, asset_id, user)
            _require_end_to_end(asset)
            if asset.algorithm != AES_GCM_PASSPHRASE:
                raise ValueError("Only passphrase-wrapped images can be rotated.")
            key_wrap = payload.get("key_wrap")
            if validate_key_wrap(key_wrap) != WRAP_SCRYPT:
                raise CryptoError("A rotated wrap must be a passphrase wrap.")
            metadata = dict(asset.metadata)
            metadata["key_wrap"] = key_wrap
            store.update_asset_metadata(asset.id, user.id, metadata)
        except PermissionError as exc:
            return _json_error(str(exc), 403)
        except LookupError as exc:
            return _json_error(str(exc), 404)
        except (CryptoError, ValueError) as exc:
            return _json_error(str(exc), 400)
        _audit(store, user.id, "rotate", asset.id)
        flash("Passphrase wrap rotated in your browser.", "success")
        return jsonify({"ok": True})

    @app.post("/api/token")
    def api_token() -> ResponseReturnValue:
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        blocked = _guard_login(app, username, json_mode=True)
        if blocked is not None:
            return blocked

        user = store.authenticate_user(username, password)
        if not user:
            return _failed_login(app, username, json_mode=True)

        _login_success(app, store, user, password)
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": str(user.id),
                "iss": app.config["JWT_ISSUER"],
                "aud": app.config["JWT_AUDIENCE"],
                "iat": now,
                "exp": now + timedelta(hours=2),
                "ver": user.token_version,
            },
            app.config["JWT_SECRET"],
            algorithm="HS256",
        )
        return jsonify({"token": token, "token_type": "Bearer", "expires_in": 7200})

    @app.get("/api/images")
    @jwt_required(store)
    def api_images() -> ResponseReturnValue:
        user = g.api_user
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
    def api_share_image(asset_id: int) -> ResponseReturnValue:
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
    def api_create_link(asset_id: int) -> ResponseReturnValue:
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
    def api_audit() -> ResponseReturnValue:
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
                ],
                "chain": asdict(store.verify_audit_chain(user.id)),
            }
        )

    return app


def _json_payload() -> dict[str, Any]:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def _ciphertext_response(blob: bytes, download_name: str) -> Response:
    response = send_file(
        BytesIO(blob),
        mimetype="application/octet-stream",
        download_name=download_name,
        as_attachment=True,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _check_sealed_upload(
    store: VaultStore,
    user: User,
    raw_envelope: str,
    ciphertext: bytes,
    *,
    max_pixels: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate an envelope sealed in a browser before storing it.

    The server can never decrypt it, so everything that can be checked is: a
    closed version 3 envelope sealed to this account with a complete browser
    context; an allow-listed type the browser can display, within the pixel
    ceiling; a well-formed wrap at today's KDF cost that matches the sealed
    algorithm; a digest that matches the bytes received; and a fresh asset id.
    What it cannot check is that the ciphertext really is that image, which is
    why the browser re-checks the format after decrypting before showing it.
    """
    if not raw_envelope or len(raw_envelope.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError("The envelope is missing or too large.")
    try:
        metadata = json.loads(raw_envelope)
    except json.JSONDecodeError as exc:
        raise ValueError("The envelope is not valid JSON.") from exc
    if validate_envelope(metadata) != ENVELOPE_V3:
        raise CryptoError("End-to-end uploads must use envelope version 3.")
    context = metadata["context"]
    if set(context) != END_TO_END_CONTEXT or context["source"] != "browser":
        raise CryptoError("End-to-end uploads must seal a complete browser context.")
    if context["owner"] != user.id:
        raise CryptoError("This envelope is sealed to a different account.")
    expected_wrap = WRAP_SCRYPT if metadata["algorithm"] == AES_GCM_PASSPHRASE else WRAP_RSA
    if validate_key_wrap(metadata["key_wrap"]) != expected_wrap or context["wrap"] != expected_wrap:
        raise CryptoError("The key wrap does not match the sealed algorithm.")
    image_format = context["format"]
    if image_format not in END_TO_END_FORMATS or IMAGE_MIME_TYPES[image_format] != context["mime"]:
        raise UnsupportedImageError("This file type is not accepted.")
    if context["width"] * context["height"] > max_pixels:
        raise UnsupportedImageError(f"Image is too large to process (over {max_pixels:,} pixels).")
    if len(ciphertext) <= GCM_TAG_BYTES:
        raise CryptoError("Encrypted image ciphertext is truncated.")
    if metadata.get("ciphertext_sha256") != sha256(ciphertext).hexdigest():
        raise CryptoError("Ciphertext integrity check failed.")
    if store.find_asset_by_uuid(context["asset"]) is not None:
        raise ValueError("An image with this asset id already exists.")
    return metadata, context


def _throttle(app: Flask, name: str, key: str) -> bool:
    """Record one attempt against a named throttle; False once it is full."""
    throttle = app.extensions.get("throttles", {}).get(name)
    return True if throttle is None else throttle.allow(key)


def _link_throttled(app: Flask) -> ResponseReturnValue | None:
    if _throttle(app, "link", f"ip:{request.remote_addr or '-'}"):
        return None
    message = "Too many link requests. Try again shortly."
    if _wants_json():
        return jsonify({"error": message}), 429
    return (message, 429)


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
                    options={"require": ["exp", "iat", "iss", "aud", "sub", "ver"]},
                )
                user = store.get_user(int(payload["sub"]))
                token_version = payload["ver"]
                if not isinstance(token_version, int) or token_version != user.token_version:
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


def _establish_session(store: VaultStore, user: User) -> None:
    """Start a fresh session bound to a server-side row that logout deletes."""
    session.clear()
    store.prune_sessions(max_age_seconds=_session_max_age())
    session["sid"] = store.create_session(user.id)
    session["user_id"] = user.id
    session["token_version"] = user.token_version
    session["last_seen"] = time.time()


def _session_max_age() -> int:
    return int(current_app.config.get("SESSION_MAX_AGE_SECONDS", 0) or 0)


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
    sid = session.get("sid")
    if not isinstance(sid, str) or not store.session_is_active(
        sid, user.id, max_age_seconds=_session_max_age()
    ):
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


def _require_user(store: VaultStore) -> User:
    """Return the signed-in user inside a view already guarded by login_required."""
    user = _current_user(store)
    if user is None:
        raise RuntimeError("login_required did not run before this view.")
    return user


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
    _require_server_side(asset)
    recipient = _resolve_recipient(store, owner, recipient_username)

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


def _resolve_recipient(store: VaultStore, owner: User, username: str) -> User:
    recipient_name = username.strip().lower()
    if not recipient_name:
        raise ValueError("Recipient username is required.")
    if recipient_name == owner.username:
        raise ValueError("You already own this image.")
    recipient = store.get_user_by_username(recipient_name)
    if recipient is None:
        raise LookupError("No account exists with that username.")
    return recipient


def _require_server_side(asset: EncryptedAsset) -> None:
    """Refuse to unwrap an end-to-end image's key on the server.

    Its key was never given to the server, so any route that asks for a
    passphrase or account password to unwrap it here would exist only to
    collect that secret. Such images are opened, shared, and linked in the
    browser instead.
    """
    if asset.end_to_end:
        raise CryptoError(SERVER_SIDE_REFUSED)


def _require_end_to_end(asset: EncryptedAsset) -> None:
    if not asset.end_to_end:
        raise ValueError(
            "This image was encrypted on the server; use the regular share and link forms."
        )


def _json_error(message: str, status: int) -> ResponseReturnValue:
    return jsonify({"error": message}), status


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
    _require_server_side(asset)
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


def _decrypt_link(store: VaultStore, token: str) -> Response:
    """Decrypt through a capability link, consuming one download atomically.

    The download is reserved *before* any work, so concurrent requests cannot
    exceed ``max_downloads``; it is handed back if decryption fails.
    """
    link, asset = _resolve_link(store, token)
    # The token in an end-to-end link's path only finds the row; the key that
    # unwraps the image lives in the URL fragment, which never reaches us.
    _require_server_side(asset)
    if not store.reserve_link_download(link.id):
        raise PermissionError("This capability link is no longer valid.")
    try:
        store.ciphertext_sha256(asset)
        _check_sealed_context(asset, primary_wrap=False)
        metadata = dict(asset.metadata)
        metadata["key_wrap"] = link.key_wrap
        plaintext = decrypt_image_bytes(
            store.read_ciphertext(asset),
            metadata,
            passphrase=token,
            aad=_legacy_aad(asset),
        )
        return _plaintext_response(plaintext, asset, as_attachment=True)
    except Exception:
        store.release_link_download(link.id)
        raise


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


def _login_success(app: Flask, store: VaultStore, user: User, password: str) -> None:
    guard: LoginGuard = app.extensions["login_guard"]
    guard.record_success(user.username)
    # Sign-in is the one moment the verified password is in hand, so it is
    # where a legacy PBKDF2 private key is resealed with Scrypt.
    try:
        if store.upgrade_private_key(user.id, password):
            _audit(store, user.id, "key_upgrade")
    except (CryptoError, OSError) as exc:
        app.logger.warning("Could not upgrade the private key for user %s: %s", user.id, exc)
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
        "end_to_end": asset.end_to_end,
    }


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.accept_mimetypes
    return accept["application/json"] > accept["text/html"]


def _allowed_extension(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


# Everything Pillow may raise while parsing hostile bytes. Anything here means
# "not an image we will accept", never an HTTP 500.
_IMAGE_ERRORS = (
    OSError,
    SyntaxError,
    ValueError,
    EOFError,
    IndexError,
    KeyError,
    TypeError,
    struct.error,
    UnidentifiedImageError,
    Image.DecompressionBombError,
    Image.DecompressionBombWarning,
)
# Image.info keys that describe how to render pixels, not who/where/when.
_RENDERING_INFO = {
    "icc_profile",
    "transparency",
    "gamma",
    "dpi",
    "duration",
    "loop",
    "background",
    "disposal",
}
# Keys that carry capture metadata (EXIF, XMP, IPTC/Photoshop, comments).
_METADATA_INFO = {"exif", "xmp", "XML:com.adobe.xmp", "comment", "photoshop", "iptc"}
# Formats that are always re-encoded: TIFF tags and per-frame GIF comment
# extensions can carry arbitrary text that Pillow does not surface on frame 0.
_ALWAYS_REENCODE = {"TIFF", "GIF"}


def _prepare_upload(
    image_bytes: bytes,
    *,
    allowed_formats: set[str],
    max_pixels: int,
) -> tuple[bytes, ImageInfo]:
    """Validate an upload, strip capture metadata, and describe the result."""
    _inspect_image(image_bytes, allowed_formats=allowed_formats, max_pixels=max_pixels)
    cleaned = _strip_image_metadata(image_bytes)
    # Re-inspect: EXIF orientation may have swapped width and height, and the
    # recorded (and sealed) dimensions must describe the bytes we actually store.
    return cleaned, _inspect_image(cleaned, allowed_formats=allowed_formats, max_pixels=max_pixels)


def _inspect_image(
    image_bytes: bytes,
    *,
    allowed_formats: set[str] | None = None,
    max_pixels: int | None = None,
) -> ImageInfo:
    """Identify an upload and refuse anything we are not willing to decode.

    ``Image.open`` only reads the header, so the pixel ceiling (summed over all
    frames) is applied from declared dimensions *before* anything decodes. Only
    the allow-listed decoders are consulted, and every parser error becomes
    ``UnsupportedImageError`` rather than escaping as a server error.
    """
    formats = sorted(allowed_formats) if allowed_formats is not None else None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(image_bytes), formats=formats) as image:
                image_format = image.format or "UNKNOWN"
                width, height = image.size
                frames = int(getattr(image, "n_frames", 1) or 1)
            with Image.open(BytesIO(image_bytes), formats=formats) as image:
                image.verify()
    except UnidentifiedImageError as exc:
        raise UnsupportedImageError("This file type is not accepted.") from exc
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise UnsupportedImageError("Image is too large to process.") from exc
    except _IMAGE_ERRORS as exc:
        raise UnsupportedImageError("The image file is damaged or unreadable.") from exc

    if allowed_formats is not None and image_format not in allowed_formats:
        raise UnsupportedImageError(f"{image_format} images are not accepted.")
    if max_pixels is not None and width * height * frames > max_pixels:
        raise UnsupportedImageError(
            f"Image is too large to process ({width}x{height} x {frames} frame(s) "
            f"exceeds {max_pixels:,} pixels)."
        )
    mime_type = IMAGE_MIME_TYPES.get(image_format, "application/octet-stream")
    return ImageInfo(format=image_format, mime_type=mime_type, width=width, height=height)


def _strip_image_metadata(image_bytes: bytes) -> bytes:
    """Re-encode the pixels without EXIF, XMP, IPTC, text chunks, or comments.

    Every upload is fully decoded here (which also rejects truncated files).
    Images with no capture metadata are stored byte-for-byte; anything else is
    re-encoded keeping only rendering information such as the ICC profile.
    EXIF orientation is applied to the pixels first so photos do not rotate.
    """
    try:
        with Image.open(BytesIO(image_bytes)) as image:
            image.load()
            image_format = image.format or "PNG"
            if not _image_has_metadata(image, image_bytes):
                return image_bytes
            if int(getattr(image, "n_frames", 1) or 1) > 1:
                return _reencode_frames(image, image_format)
            cleaned = ImageOps.exif_transpose(image) or image.copy()
            cleaned.info = {k: v for k, v in image.info.items() if k in _RENDERING_INFO}
            if image_format == "JPEG" and cleaned.mode not in {"RGB", "L", "CMYK"}:
                cleaned = cleaned.convert("RGB")
            output = BytesIO()
            cleaned.save(output, format=image_format, **_clean_save_options(image_format))
            return output.getvalue()
    except UnsupportedImageError:
        raise
    except _IMAGE_ERRORS as exc:
        raise UnsupportedImageError("The image file is damaged or unreadable.") from exc


def _reencode_frames(image: Image.Image, image_format: str) -> bytes:
    frames: list[Image.Image] = []
    durations: list[int] = []
    for frame in ImageSequence.Iterator(image):
        copy = frame.copy()
        durations.append(int(frame.info.get("duration", 0) or 0))
        copy.info = {k: v for k, v in frame.info.items() if k in _RENDERING_INFO}
        frames.append(copy)
    output = BytesIO()
    options = _clean_save_options(image_format)
    if image_format in {"GIF", "WEBP"}:
        options["duration"] = durations
        options["loop"] = int(image.info.get("loop", 0) or 0)
    frames[0].save(
        output,
        format=image_format,
        save_all=True,
        append_images=frames[1:],
        **options,
    )
    return output.getvalue()


def _clean_save_options(image_format: str) -> dict[str, Any]:
    # Explicit empty values: several Pillow encoders fall back to the source
    # image's info (or a frame's) when a key is absent.
    if image_format == "JPEG":
        return {"quality": 95, "exif": b"", "xmp": b"", "comment": b""}
    if image_format == "WEBP":
        return {"quality": 95, "exif": b"", "xmp": b""}
    if image_format == "GIF":
        return {"comment": b""}
    if image_format == "PNG":
        return {"exif": b""}
    return {}


def _image_has_metadata(image: Image.Image, raw: bytes) -> bool:
    image_format = image.format or ""
    if image_format in _ALWAYS_REENCODE:
        return True
    if any(image.info.get(key) for key in _METADATA_INFO):
        return True
    if getattr(image, "text", None):
        return True
    try:
        if dict(image.getexif()):
            return True
    except _IMAGE_ERRORS:
        return True
    return image_format == "JPEG" and _jpeg_has_metadata_segments(raw)


# APP0 (JFIF), APP2 (ICC profile) and APP14 (Adobe colour transform) describe
# rendering. Every other APPn segment and COM can carry capture metadata.
_JPEG_RENDERING_MARKERS = {0xE0, 0xE2, 0xEE}


def _jpeg_has_metadata_segments(data: bytes) -> bool:
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
        if marker == 0xFE or (0xE0 <= marker <= 0xEF and marker not in _JPEG_RENDERING_MARKERS):
            return True
        seglen = int.from_bytes(data[index + 2 : index + 4], "big")
        if seglen < 2:
            break
        index = index + 2 + seglen
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


def _legacy_aad(asset: EncryptedAsset) -> bytes | None:
    """AAD for version 1 rows that predate the recorded ``aad`` dict.

    Version 3 envelopes (and version 1 envelopes that carry their ``aad``) are
    self-describing, so ``None`` lets the envelope supply its own AAD.
    """
    if asset.metadata.get("version", 1) != 1 or isinstance(asset.metadata.get("aad"), dict):
        return None
    return web_aad(asset.user_id, asset.original_filename, asset.mime_type)


def _check_sealed_context(asset: EncryptedAsset, *, primary_wrap: bool) -> None:
    """Refuse a row whose fields disagree with the context sealed into its AAD.

    Version 3 binds the asset id, owner, algorithm, wrap type, MIME type,
    format, and dimensions. Swapping ciphertext and metadata between rows or
    users, or editing a row's recorded type, makes this check fail before any
    key is unwrapped. Version 1 envelopes predate the sealed context.
    """
    metadata = asset.metadata
    if validate_envelope(metadata) != ENVELOPE_V3:
        return
    context = metadata["context"]
    expected = {
        "asset": Path(asset.stored_filename).stem,
        "owner": asset.user_id,
        "algorithm": asset.algorithm,
        "mime": asset.mime_type,
        "format": asset.image_format,
        "width": asset.width,
        "height": asset.height,
    }
    mismatched = [key for key, value in expected.items() if context.get(key) != value]
    if primary_wrap and metadata["key_wrap"].get("type") != context.get("wrap"):
        mismatched.append("wrap")
    if mismatched:
        raise CryptoError(
            "This vault record does not match the context sealed into its ciphertext."
        )


def _plaintext_response(
    plaintext: bytes, asset: EncryptedAsset, *, as_attachment: bool
) -> Response:
    """Serve decrypted bytes only as the allow-listed image type they really are.

    The Content-Type comes from the allow-list, never from the stored row, and
    the bytes must parse as that format. This stops HTML or SVG that reached a
    row (for example through a crafted backup) from running on this origin.
    """
    mime_type = IMAGE_MIME_TYPES.get(asset.image_format)
    if mime_type is None or asset.mime_type != mime_type:
        raise ValueError("Refusing to serve content that is not an allow-listed image.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(plaintext), formats=[asset.image_format]) as image:
                detected = image.format
    except Exception as exc:
        raise ValueError("Decrypted content is not the image type on record.") from exc
    if detected != asset.image_format:
        raise ValueError("Decrypted content is not the image type on record.")
    response = send_file(
        BytesIO(plaintext),
        mimetype=mime_type,
        download_name=asset.original_filename,
        as_attachment=as_attachment,
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = PLAINTEXT_CSP
    return response
