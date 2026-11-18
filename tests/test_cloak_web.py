"""The Cloak page: download any vault image hidden inside an ordinary PNG.

Cloaking repackages the same bytes as the `.ies` download, so it needs only
ciphertext and works for end-to-end images without touching a key. It is
owner-only, CSRF-protected and throttled like other heavy routes.
"""

from __future__ import annotations

from io import BytesIO

import pytest
from helpers import (
    browser_envelope,
    csrf_token,
    encrypt_png,
    make_app,
    post_sealed,
    register,
    sample_png,
)
from PIL import Image

from image_encryption_system.cloak import uncloak
from image_encryption_system.crypto import unpack_ies


def _vault(tmp_path, **overrides):
    app = make_app(tmp_path, CSRF_ENABLED=True, **overrides)
    alice = app.test_client()
    register(alice, "alice")
    encrypt_png(alice, filename="secret.png")
    asset = app.extensions["vault_store"].list_assets(1)[0]
    return app, alice, asset


def _post_cloak(client, asset_id, *, csrf=True, **fields):
    data = {"cover": "generated", "palette": "dusk", "seed": "fixed seed", "bits": "auto", **fields}
    if csrf:
        data["csrf_token"] = csrf_token(client)
    return client.post(f"/images/{asset_id}/cloak", data=data, content_type="multipart/form-data")


def test_owner_gets_a_png_that_uncloaks_to_the_ies_download(tmp_path) -> None:
    _app, alice, asset = _vault(tmp_path)

    response = _post_cloak(alice, asset.id)

    assert response.status_code == 200
    assert response.mimetype == "image/png"
    assert "no-store" in response.headers["Cache-Control"]
    assert "secret.png.cloaked.png" in response.headers["Content-Disposition"]
    assert uncloak(response.data) == alice.get(f"/images/{asset.id}/download").data


def test_the_same_seed_gives_the_same_picture(tmp_path) -> None:
    _app, alice, asset = _vault(tmp_path)
    first = _post_cloak(alice, asset.id).data
    assert _post_cloak(alice, asset.id).data == first
    assert _post_cloak(alice, asset.id, seed="another seed").data != first


def test_end_to_end_images_can_be_cloaked(tmp_path) -> None:
    app = make_app(tmp_path, CSRF_ENABLED=True)
    alice = app.test_client()
    register(alice, "alice")
    metadata, ciphertext = browser_envelope(1)
    asset_id = post_sealed(alice, metadata, ciphertext).get_json()["asset_id"]

    response = _post_cloak(alice, asset_id)

    assert response.status_code == 200
    hidden_ciphertext, hidden_metadata = unpack_ies(uncloak(response.data))
    assert hidden_ciphertext == ciphertext
    assert hidden_metadata["context"]["source"] == "browser"
    assert hidden_metadata["version"] == 4


def test_custom_cover_is_validated(tmp_path) -> None:
    _app, alice, asset = _vault(tmp_path)

    response = _post_cloak(
        alice, asset.id, cover="upload", cover_file=(BytesIO(sample_png()), "cover.png")
    )
    assert response.status_code == 200
    with Image.open(BytesIO(response.data)) as image:
        assert image.width >= 80 and image.height >= 48
    assert uncloak(response.data) == alice.get(f"/images/{asset.id}/download").data

    for bad in (b"not an image at all", b""):
        refused = _post_cloak(
            alice, asset.id, cover="upload", cover_file=(BytesIO(bad), "cover.png")
        )
        assert refused.status_code == 303
        assert refused.headers["Location"].endswith(f"/images/{asset.id}/cloak")


@pytest.mark.parametrize(
    "fields",
    [{"bits": "9"}, {"palette": "neon"}, {"seed": "x" * 65}, {"cover": "sideways"}],
    ids=["bits", "palette", "seed", "cover"],
)
def test_bad_options_are_refused_cleanly(tmp_path, fields) -> None:
    _app, alice, asset = _vault(tmp_path)
    response = _post_cloak(alice, asset.id, **fields)
    assert response.status_code == 303
    page = alice.get(response.headers["Location"]).get_data(as_text=True)
    assert "flash-error" in page


def test_only_the_owner_can_cloak(tmp_path) -> None:
    app, _alice, asset = _vault(tmp_path)
    bob = app.test_client()
    register(bob, "bob")

    page = bob.get(f"/images/{asset.id}/cloak")
    assert page.status_code == 302
    assert page.headers["Location"].endswith("/dashboard")
    refused = _post_cloak(bob, asset.id)
    assert refused.status_code == 302
    assert refused.mimetype != "image/png"
    missing = bob.get("/images/9999/cloak")
    assert missing.status_code == 302


def test_cloak_requires_login_csrf_and_is_throttled(tmp_path) -> None:
    app, alice, asset = _vault(tmp_path, CLOAK_RATE_LIMIT=1)
    assert _post_cloak(alice, asset.id, csrf=False).status_code == 400
    assert _post_cloak(alice, asset.id).status_code == 200
    limited = _post_cloak(alice, asset.id)
    assert limited.status_code == 429
    assert limited.mimetype != "image/png"

    stranger = app.test_client()
    assert stranger.get(f"/images/{asset.id}/cloak").status_code == 302


def test_cloak_page_describes_the_image(tmp_path) -> None:
    _app, alice, asset = _vault(tmp_path)
    page = alice.get(f"/images/{asset.id}/cloak").get_data(as_text=True)
    assert "secret.png" in page
    assert 'name="palette"' in page and 'value="alpine"' in page
    assert 'name="bits"' in page
    assert "css/lab.css" in page
    assert "recompress" in page.lower()


def test_dashboard_links_to_the_cloak_page(tmp_path) -> None:
    _app, alice, asset = _vault(tmp_path)
    assert f'href="/images/{asset.id}/cloak"' in alice.get("/dashboard").get_data(as_text=True)


def test_cloaks_run_one_at_a_time(tmp_path, monkeypatch) -> None:
    # Each cloak can take hundreds of megabytes; a second request waits its turn.
    import threading
    import time

    from helpers import login

    from image_encryption_system import cloak as cloak_module
    from image_encryption_system import lab_routes

    app, alice, asset = _vault(tmp_path)
    second = app.test_client()
    login(second, "alice")
    running, peak, guard = [0], [0], threading.Lock()

    def slow_cloak(*args, **kwargs):
        with guard:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.3)
        with guard:
            running[0] -= 1
        return cloak_module.cloak(*args, **kwargs)

    monkeypatch.setattr(lab_routes, "cloak", slow_cloak)
    results = []
    threads = [
        threading.Thread(target=lambda c=c: results.append(_post_cloak(c, asset.id).status_code))
        for c in (alice, second)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [200, 200]
    assert peak[0] == 1
