"""Upload validation: decompression bombs and format smuggling.

``_strip_image_exif`` calls ``Image.load()``, which is where a decompression
bomb actually allocates. These tests pin the ordering (identify and bound the
image from its header first) as well as the limits themselves.
"""

from __future__ import annotations

from io import BytesIO

import pytest
from helpers import PASSWORD, make_app, register, with_csrf
from PIL import Image

from image_encryption_system.crypto import AES_GCM_PASSPHRASE
from image_encryption_system.web import UnsupportedImageError, _inspect_image


def _png(width: int, height: int) -> bytes:
    output = BytesIO()
    Image.new("RGB", (width, height), "#204060").save(output, format="PNG")
    return output.getvalue()


def _tiff() -> bytes:
    output = BytesIO()
    Image.new("RGB", (32, 32), "#800000").save(output, format="TIFF")
    return output.getvalue()


def test_inspect_accepts_an_ordinary_png():
    info = _inspect_image(_png(80, 48), allowed_formats={"PNG"}, max_pixels=10_000)
    assert info["format"] == "PNG"
    assert (info["width"], info["height"]) == (80, 48)


def test_inspect_refuses_images_over_the_pixel_ceiling():
    with pytest.raises(UnsupportedImageError, match="too large"):
        _inspect_image(_png(400, 400), allowed_formats={"PNG"}, max_pixels=1000)


def test_inspect_refuses_a_format_outside_the_allow_list():
    with pytest.raises(UnsupportedImageError, match="not accepted"):
        _inspect_image(_tiff(), allowed_formats={"PNG", "JPEG"}, max_pixels=10_000_000)


def test_pixel_ceiling_is_checked_before_any_decode(monkeypatch):
    """The ceiling must come from the header, not from a loaded image."""
    import image_encryption_system.web as web

    def explode(*_args, **_kwargs):
        raise AssertionError("EXIF stripping ran before the size check")

    monkeypatch.setattr(web, "_strip_image_exif", explode)

    with pytest.raises(UnsupportedImageError):
        _inspect_image(_png(400, 400), allowed_formats={"PNG"}, max_pixels=1000)


def test_oversized_upload_is_rejected_by_the_route(tmp_path):
    app = make_app(tmp_path, MAX_IMAGE_PIXELS=1000)
    client = app.test_client()
    register(client, "clerk", PASSWORD)

    response = client.post(
        "/images",
        data=with_csrf(
            client,
            {
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": "a long image passphrase",
                "image": (BytesIO(_png(400, 400)), "bomb.png"),
            },
        ),
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"too large to process" in response.data


def test_disallowed_format_is_rejected_by_the_route(tmp_path):
    app = make_app(tmp_path, ALLOWED_IMAGE_FORMATS={"PNG"})
    client = app.test_client()
    register(client, "clerk", PASSWORD)

    # A TIFF renamed to .png passes the extension check, so the decoded format
    # is the only thing standing between the vault and an unexpected decoder.
    response = client.post(
        "/images",
        data=with_csrf(
            client,
            {
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": "a long image passphrase",
                "image": (BytesIO(_tiff()), "actually-a-tiff.png"),
            },
        ),
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"not accepted" in response.data


def test_ordinary_upload_still_succeeds(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "clerk", PASSWORD)

    response = client.post(
        "/images",
        data=with_csrf(
            client,
            {
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": "a long image passphrase",
                "image": (BytesIO(_png(80, 48)), "holiday.png"),
            },
        ),
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"encrypted and stored" in response.data
