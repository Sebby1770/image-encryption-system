from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import wraps
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from sqlite3 import IntegrityError
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
from markupsafe import Markup, escape
from PIL import Image, UnidentifiedImageError
from werkzeug.exceptions import RequestEntityTooLarge

from .config import KNOWN_INSECURE_SECRETS, Config
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
from .security import LoginGuard, PasswordPolicyError, RequestThrottle, validate_password
from .storage import AssetShare, EncryptedAsset, LinkShare, User, VaultStore


class UnsupportedImageError(ValueError):
    """Raised when an upload decodes to a format or size the vault refuses."""


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
    app.config.setdefault("ALLOWED_IMAGE_FORMATS", Config.ALLOWED_IMAGE_FORMATS)
    app.config["MAX_IMAGE_PIXELS"] = int(
        app.config.get("MAX_IMAGE_PIXELS", Config.MAX_IMAGE_PIXELS)
    )

    _assert_usable_secret(app)

    # Serving the session cookie without Secure over plain HTTP silently drops
    # it, which looks like a broken login rather than a misconfiguration. Fail
    # loudly at boot instead, and make the testing default explicit.
    if app.config.get("TESTING"):
        app.config.setdefault("SESSION_COOKIE_SECURE", False)
        app.config["SESSION_COOKIE_SECURE"] = False

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
    app.extensions["throttles"] = {
        name: RequestThrottle(
            store,
            f"throttle:{name}",
            limit=int(app.config.get(f"{name.upper()}_RATE_LIMIT", default_limit)),
            window_seconds=int(
                app.config.get(f"{name.upper()}_RATE_WINDOW_SECONDS", default_window)
            ),
        )
        for name, default_limit, default_window in (
            ("register", 5, 3600),
            ("decrypt", 30, 300),
            ("link", 20, 300),
        )
    }

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
            "min_password_length": int(app.config.get("MIN_PASSWORD_LENGTH", 10)),
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

    @app.after_request
    def security_headers(response: Response) -> Response:
        """Apply the browser-side half of the vault's threat model.

        The envelope crypto is only as good as the page that drives it: without
        these, a single injected script or a framing page can exfiltrate a
        decrypted image or a passphrase as the user types it. Every script and
        style the app serves is a same-origin file, so the policy needs no
        inline allowance and no nonce.
        """
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' blob: data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        # Only meaningful over TLS, and asserting it on a plain-HTTP development
        # run would pin the browser to a scheme that host does not serve.
        hsts = int(current_app.config.get("HSTS_SECONDS", 0) or 0)
        if hsts > 0 and request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", f"max-age={hsts}; includeSubDomains"
            )

        # Anything that carries plaintext, key material, or vault contents must
        # not be written to a shared cache or a browser's disk cache.
        if getattr(g, "sensitive_response", False):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error: RequestEntityTooLarge):
        limit_mb = int(app.config["MAX_CONTENT_LENGTH"]) // (1024 * 1024)
        if _wants_json():
            return jsonify({"error": f"upload exceeds the {limit_mb} MB limit"}), 413
        flash(f"File exceeds the {limit_mb} MB upload limit.", "error")
        return redirect(url_for("dashboard")), 413

    @app.get("/healthz")
    def healthz() -> Response:
        """Liveness and readiness for a container orchestrator or uptime check.

        Deliberately unauthenticated but deliberately empty of detail: it
        confirms the process is up and the vault database answers, and reveals
        nothing about accounts, assets, or configuration.
        """
        try:
            store.count_users()
        except Exception:
            return jsonify({"status": "unavailable"}), 503
        return jsonify({"status": "ok"})

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

        # Registration generates an RSA-3072 key pair, so an unauthenticated
        # caller could otherwise burn CPU indefinitely without ever holding an
        # account.
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
        except (PasswordPolicyError, ValueError) as exc:
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
            validate_password(
                new_password,
                username=user.username,
                min_length=int(app.config.get("MIN_PASSWORD_LENGTH", 10)),
            )
            store.change_password(user.id, old_password, new_password)
        except (PasswordPolicyError, ValueError, CryptoError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("password_form"))
        refreshed = store.get_user(user.id)
        session["token_version"] = refreshed.token_version
        _audit(store, user.id, "password_change")
        flash(
            "Password updated. Your RSA private key was re-encrypted. "
            "Other sessions were signed out.",
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

        if upload is None or not upload.filename:
            flash("Choose an image to encrypt.", "error")
            return redirect(url_for("dashboard"))

        if not _allowed_extension(upload.filename, app.config["ALLOWED_EXTENSIONS"]):
            flash("Unsupported file extension.", "error")
            return redirect(url_for("dashboard"))

        image_bytes = upload.read()
        try:
            # Identify and bound the image from its header before anything
            # decodes it: _strip_image_exif() calls Image.load(), which is where
            # a decompression bomb would actually allocate.
            image_info = _inspect_image(
                image_bytes,
                allowed_formats=app.config["ALLOWED_IMAGE_FORMATS"],
                max_pixels=app.config["MAX_IMAGE_PIXELS"],
            )
            image_bytes = _strip_image_exif(image_bytes)
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
        except (CryptoError, UnsupportedImageError, ValueError, UnidentifiedImageError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

        flash("Image encrypted and stored in the vault.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/images/<int:asset_id>/decrypt")
    @login_required(store)
    def decrypt_image(asset_id: int) -> Response:
        user = _current_user(store)

        # Each attempt tests a passphrase or a private-key password against real
        # ciphertext, so cap the rate per account rather than per asset: keying
        # on the asset would let one user throttle another's shared image.
        if not _throttle(app, "decrypt", f"user:{user.id}"):
            message = "Too many decryption attempts. Wait a few minutes and try again."
            if _wants_json():
                return jsonify({"error": message}), 429
            flash(message, "error")
            return redirect(url_for("dashboard")), 429

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

        _mark_sensitive()
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
        # Capability links are unauthenticated and bypass CSRF by design, so the
        # bearer token is the only secret. Throttle per caller address to bound
        # token guessing, and to stop a public link from being used to hammer
        # the vault.
        if not _throttle(app, "link", f"ip:{request.remote_addr or '-'}"):
            message = "Too many link requests. Try again shortly."
            if _wants_json():
                return jsonify({"error": message}), 429
            return (message, 429)

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
        # Capability links are unauthenticated and bypass CSRF by design, so the
        # bearer token is the only secret. Throttle per caller address to bound
        # token guessing, and to stop a public link from being used to hammer
        # the vault.
        if not _throttle(app, "link", f"ip:{request.remote_addr or '-'}"):
            message = "Too many link requests. Try again shortly."
            if _wants_json():
                return jsonify({"error": message}), 429
            return (message, 429)

        try:
            plaintext, asset = _decrypt_link(store, token, count=True)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except (CryptoError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        _mark_sensitive()
        return send_file(
            BytesIO(plaintext),
            mimetype=asset.mime_type,
            download_name=asset.original_filename,
            as_attachment=True,
        )

    @app.get("/l/<token>/blob")
    def download_link_blob(token: str):
        # Capability links are unauthenticated and bypass CSRF by design, so the
        # bearer token is the only secret. Throttle per caller address to bound
        # token guessing, and to stop a public link from being used to hammer
        # the vault.
        if not _throttle(app, "link", f"ip:{request.remote_addr or '-'}"):
            message = "Too many link requests. Try again shortly."
            if _wants_json():
                return jsonify({"error": message}), 429
            return (message, 429)

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
        _mark_sensitive()
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
        _mark_sensitive()
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
            lines.append(f'{event.id},{event.action},{asset},"{ip}",{event.created_at}')
        payload = "\n".join(lines) + "\n"
        _mark_sensitive()
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
        _mark_sensitive()
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
        _mark_sensitive()
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
                "ver": user.token_version,
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


def _assert_usable_secret(app: Flask) -> None:
    """Refuse to serve with a secret an attacker could already know.

    The signing key authenticates both the session cookie and API tokens, so a
    published value means anyone can mint either. Earlier releases shipped a
    constant fallback and started happily with it.
    """
    if app.config.get("TESTING"):
        return

    secret = str(app.config.get("SECRET_KEY") or "")
    if not secret:
        raise RuntimeError("SECRET_KEY is not configured.")
    if secret in KNOWN_INSECURE_SECRETS:
        raise RuntimeError(
            "SECRET_KEY is set to a publicly known development value. "
            "Unset it to have a random key generated, or supply your own."
        )
    if len(secret) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters.")

    jwt_secret = str(app.config.get("JWT_SECRET") or "")
    if jwt_secret in KNOWN_INSECURE_SECRETS:
        raise RuntimeError("JWT_SECRET is set to a publicly known development value.")


def _throttle(app: Flask, name: str, key: str) -> bool:
    """Record one attempt against a named throttle. False when it is full."""
    throttle: RequestThrottle | None = app.extensions.get("throttles", {}).get(name)
    if throttle is None:
        return True
    return throttle.allow(key)


def _mark_sensitive() -> None:
    """Flag the in-flight response as never-cacheable.

    Plaintext images, ciphertext downloads, key material, and backups all pass
    through ``send_file``, which sets caching headers appropriate for static
    assets. `security_headers` reads this flag and overrides them.
    """
    g.sensitive_response = True


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


def _decrypt_link(store: VaultStore, token: str, *, count: bool) -> tuple[bytes, EncryptedAsset]:
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


def _inspect_image(
    image_bytes: bytes,
    *,
    allowed_formats: set[str] | None = None,
    max_pixels: int | None = None,
) -> dict[str, int | str]:
    """Identify an upload and refuse anything we are not willing to decode.

    ``Image.open`` only reads the header, so the pixel-count ceiling is applied
    from the declared dimensions *before* any caller reaches ``image.load()``
    during EXIF stripping. A few megabytes of compressed input can otherwise
    decode into gigabytes of pixels.
    """
    with Image.open(BytesIO(image_bytes)) as image:
        image.verify()

    with Image.open(BytesIO(image_bytes)) as image:
        image_format = image.format or "UNKNOWN"
        mime_type = Image.MIME.get(image_format, "application/octet-stream")
        width, height = image.size

    if allowed_formats is not None and image_format not in allowed_formats:
        raise UnsupportedImageError(f"{image_format} images are not accepted.")

    if max_pixels is not None and width * height > max_pixels:
        raise UnsupportedImageError(
            f"Image is too large to process ({width}x{height} exceeds {max_pixels:,} pixels)."
        )

    return {
        "format": image_format,
        "mime_type": mime_type,
        "width": width,
        "height": height,
    }


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
    return f"user={user_id}|filename={original_filename}|mime={mime_type}".encode()


def _aad_from_metadata(asset: EncryptedAsset) -> bytes:
    aad = asset.metadata.get("aad", {})
    return _asset_aad(
        int(aad.get("user_id", asset.user_id)),
        str(aad.get("original_filename", asset.original_filename)),
        str(aad.get("mime_type", asset.mime_type)),
    )
