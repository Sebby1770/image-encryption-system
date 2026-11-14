"""Pages for cloaked exports and the Cipher Lab.

Registered from ``web.create_app()`` with :func:`register`. They live here,
not in ``web.py``, because they are self-contained: the cloak only repackages
ciphertext the owner can already download, and the lab never touches vault
data at all. Both reuse ``web``'s session, ownership, upload and throttle
helpers, and the app-wide CSRF hook covers their POSTs.
"""

from __future__ import annotations

import os
from io import BytesIO

from flask import (
    Flask,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask.typing import ResponseReturnValue

from . import web
from .cloak import BITS, CloakError, cloak, load_cover
from .covers import PALETTES
from .crypto import pack_ies
from .lab import LAB_SIZES, SAMPLES, prepare, run_lab, sample
from .lab.ciphers import CIPHER_INFO, CIPHER_NAMES
from .storage import VaultStore

MAX_SEED_CHARACTERS = 64


def _bits(raw: str | None) -> int | None:
    choice = (raw or "auto").strip()
    if choice == "auto":
        return None
    if choice not in {str(k) for k in BITS}:
        raise ValueError("Bits per coefficient must be auto, 1, 2, or 3.")
    return int(choice)


def _palette(raw: str | None) -> str:
    palette = (raw or "dusk").strip()
    if palette not in PALETTES:
        raise ValueError("Choose one of the listed cover styles.")
    return palette


def _seed(raw: str | None) -> bytes:
    text = (raw or "").strip()
    if len(text) > MAX_SEED_CHARACTERS:
        raise ValueError(f"A seed can be at most {MAX_SEED_CHARACTERS} characters.")
    return text.encode("utf-8") if text else os.urandom(16)


def register(app: Flask, store: VaultStore) -> None:
    """Add the cloak and lab routes to ``app``."""

    def owned_or_redirect(asset_id: int) -> tuple[web.EncryptedAsset | None, ResponseReturnValue]:
        user = web._require_user(store)
        try:
            return web._owned_asset(store, asset_id, user), ""
        except (LookupError, PermissionError) as exc:
            flash(str(exc), "error")
            return None, redirect(url_for("dashboard"))

    @app.get("/images/<int:asset_id>/cloak")
    @web.login_required(store)
    def cloak_form(asset_id: int) -> ResponseReturnValue:
        asset, refusal = owned_or_redirect(asset_id)
        if asset is None:
            return refusal
        payload_bytes = len(pack_ies(store.read_ciphertext(asset), asset.metadata))
        return render_template(
            "cloak.html",
            asset=asset,
            payload_bytes=payload_bytes,
            palettes=PALETTES,
            max_pixels=int(app.config["CLOAK_MAX_PIXELS"]),
            max_seed=MAX_SEED_CHARACTERS,
        )

    @app.post("/images/<int:asset_id>/cloak")
    @web.login_required(store)
    def cloak_download(asset_id: int) -> ResponseReturnValue:
        asset, refusal = owned_or_redirect(asset_id)
        if asset is None:
            return refusal
        user = web._require_user(store)
        if not web._throttle(app, "cloak", f"user:{user.id}"):
            return ("Too many cloak requests. Try again shortly.", 429)
        try:
            bits = _bits(request.form.get("bits"))
            palette = _palette(request.form.get("palette"))
            seed = _seed(request.form.get("seed"))
            source = request.form.get("cover") or "generated"
            cover = None
            if source == "upload":
                upload = request.files.get("cover_file")
                raw = upload.read() if upload is not None else b""
                if not raw:
                    raise ValueError("Choose a cover picture to upload.")
                web._inspect_image(
                    raw,
                    allowed_formats=set(app.config["ALLOWED_IMAGE_FORMATS"]),
                    max_pixels=int(app.config["MAX_IMAGE_PIXELS"]),
                )
                cover = load_cover(raw)
            elif source != "generated":
                raise ValueError("Choose a generated cover or upload your own.")
            payload = pack_ies(store.read_ciphertext(asset), asset.metadata)
            png, _report = cloak(
                payload,
                cover=cover,
                bits=bits,
                seed=seed,
                palette=palette,
                max_pixels=int(app.config["CLOAK_MAX_PIXELS"]),
            )
        except (CloakError, web.UnsupportedImageError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("cloak_form", asset_id=asset_id), code=303)
        response = send_file(
            BytesIO(png),
            mimetype="image/png",
            as_attachment=True,
            download_name=f"{asset.original_filename}.cloaked.png",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    def lab_size() -> int:
        size = int(app.config.get("LAB_IMAGE_SIZE", 256))
        return size if size in LAB_SIZES else 256

    def lab_page(error: str | None = None, status: int = 200) -> ResponseReturnValue:
        page = render_template(
            "lab.html",
            samples=SAMPLES,
            ciphers=CIPHER_INFO,
            size=lab_size(),
            error=error,
        )
        return page, status

    @app.get("/lab")
    @web.login_required(store)
    def lab_form() -> ResponseReturnValue:
        return lab_page()

    @app.post("/lab")
    @web.login_required(store)
    def lab_run() -> ResponseReturnValue:
        user = web._require_user(store)
        if not web._throttle(app, "lab", f"user:{user.id}"):
            return lab_page("Too many lab runs. Try again in a few minutes.", 429)
        try:
            names = request.form.getlist("cipher")
            if not names:
                raise ValueError("Choose at least one cipher.")
            unknown = [name for name in names if name not in CIPHER_NAMES]
            if unknown:
                raise ValueError("Unknown cipher: choose from the list.")
            size = lab_size()
            source = request.form.get("source") or "sample"
            if source == "sample":
                chosen = request.form.get("sample") or ""
                if chosen not in SAMPLES:
                    raise ValueError("Choose one of the built-in images.")
                image, label = sample(chosen, size), chosen.replace("-", " ")
            elif source == "upload":
                upload = request.files.get("image")
                raw = upload.read() if upload is not None else b""
                if not raw:
                    raise ValueError("Choose an image to upload.")
                web._inspect_image(
                    raw,
                    allowed_formats=set(app.config["ALLOWED_IMAGE_FORMATS"]),
                    max_pixels=int(app.config["MAX_IMAGE_PIXELS"]),
                )
                image, label = prepare(raw, size), "your upload"
            else:
                raise ValueError("Choose a built-in image or upload one.")
            report = run_lab(image, ciphers=names, source=label)
        except ValueError as exc:  # UnsupportedImageError is a ValueError
            return lab_page(str(exc), 400)
        response = make_response(render_template("lab_report.html", report=report.to_dict()))
        response.headers["Cache-Control"] = "no-store"
        return response
