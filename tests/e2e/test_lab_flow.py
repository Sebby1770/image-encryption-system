"""The Cipher Lab and cloaked exports in a real browser, with the page CSP on."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helpers import make_app, sample_png  # noqa: E402

from image_encryption_system.cloak import uncloak  # noqa: E402

pytestmark = pytest.mark.e2e

PASSWORD = "correct horse battery"
IMAGE_PASS = "a very secret image passphrase"


@pytest.fixture()
def live_app(tmp_path):
    return make_app(tmp_path, CSRF_ENABLED=True, LAB_IMAGE_SIZE=64)


def _user(browser, base_url: str, username: str, problems: list[str]):
    context = browser.new_context(base_url=base_url, accept_downloads=True)
    page = context.new_page()
    page.on("console", lambda msg: problems.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda exc: problems.append(str(exc)))
    page.goto("/register")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url("**/dashboard")
    return page


def test_lab_runs_from_the_browser(live_server, browser) -> None:
    problems: list[str] = []
    page = _user(browser, live_server, "alice", problems)

    page.click(".nav-links >> text=Lab")
    page.wait_for_url("**/lab")
    page.select_option("select[name=sample]", "test-card")
    with page.expect_navigation(timeout=60_000):
        page.click("text=Run the lab")

    scorecard = page.inner_text(".lab-scorecard")
    assert "Arnold cat map" in scorecard and "Broken" in scorecard
    assert "Strong + committing" in scorecard
    page.click("#cipher-aes-ecb summary")
    assert page.is_visible("#cipher-aes-ecb img[src^='data:image/jpeg']")
    assert page.is_visible("#cipher-aes-ecb .lab-histogram")
    assert problems == []


def test_cloak_download_from_the_browser(live_server, live_app, browser, tmp_path) -> None:
    problems: list[str] = []
    page = _user(browser, live_server, "alice", problems)
    page.wait_for_function("() => !document.querySelector('#mode-browser').disabled")

    source = tmp_path / "photo.png"
    source.write_bytes(sample_png())
    page.set_input_files("input[name=image]", str(source))
    page.select_option("#algorithm-select", "AES-GCM")
    page.fill("#passphrase-field input", IMAGE_PASS)
    with page.expect_navigation(timeout=30_000):
        page.click("#upload-form button[type=submit]")

    store = live_app.extensions["vault_store"]
    asset = store.list_assets(store.get_user_by_username("alice").id)[0]
    assert asset.end_to_end and asset.metadata["version"] == 4

    card = page.locator(".vault-list > .asset-list .asset-card").first
    card.locator("a", has_text="Cloak").click()
    page.wait_for_url("**/cloak")
    page.fill("input[name=seed]", "e2e")
    with page.expect_download() as download_info:
        page.click("text=Download cloaked PNG")
    cloaked = Path(download_info.value.path()).read_bytes()
    assert download_info.value.suggested_filename == "photo.png.cloaked.png"

    ies = page.request.get(f"/images/{asset.id}/download").body()
    assert uncloak(cloaked) == ies
    assert problems == []
