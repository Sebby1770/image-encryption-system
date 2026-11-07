"""End-to-end mode in a real browser.

Alice encrypts a geotagged photo in her browser, views it, shares it with Bob,
creates a link for someone without an account, and rotates her passphrase.
Every request the pages send is recorded, and the test proves that neither the
image, its passphrase, Bob's password, nor the link key ever reached the
server — and that the GPS tag never survived into the vault.
"""

from __future__ import annotations

import base64
import sys
from io import BytesIO
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from helpers import PASSWORD  # noqa: E402

playwright_sync = pytest.importorskip("playwright.sync_api")
pytestmark = pytest.mark.e2e

IMAGE_PASS = "an end-to-end image passphrase"
NEW_PASS = "a rotated end-to-end passphrase"
GPS_MARKER = "GPS-SECRET-48.8584N-2.2945E"


def _geotagged_jpeg(size=(80, 48), orientation: int = 1) -> bytes:
    image = Image.new("RGB", size)
    image.putdata([(x * 3 % 256, y * 5 % 256, 90) for y in range(size[1]) for x in range(size[0])])
    exif = Image.Exif()
    exif[0x0112] = orientation
    exif[0x9286] = GPS_MARKER
    exif.get_ifd(0x8825)[2] = (48.0, 51.0, 29.0)
    output = BytesIO()
    image.save(output, format="JPEG", quality=92, exif=exif)
    return output.getvalue()


class Recorder:
    """Every request body and URL a set of pages sends to the server."""

    def __init__(self) -> None:
        self.bodies: list[bytes] = []
        self.urls: list[str] = []
        self.problems: list[str] = []

    def attach(self, page) -> None:
        page.on("request", self._request)
        page.on(
            "console", lambda msg: self.problems.append(msg.text) if msg.type == "error" else None
        )
        page.on("pageerror", lambda exc: self.problems.append(str(exc)))

    def _request(self, request) -> None:
        self.urls.append(request.url)
        body = request.post_data_buffer
        if body:
            self.bodies.append(body)

    def sent(self, needle: bytes) -> bool:
        """True if any request carried ``needle``, raw or in a common encoding."""
        variants = _encodings(needle)
        return any(v in body for v in variants for body in self.bodies) or any(
            v.decode("latin-1") in url for v in variants for url in self.urls
        )


def _encodings(needle: bytes) -> set[bytes]:
    """``needle`` raw, form-encoded, percent-encoded, and base64 at each alignment.

    Base64 of a slice only appears inside base64 of the whole when the slice
    starts on a 3-byte boundary of the original, so try all three offsets.
    """
    text = needle.decode("latin-1")
    found = {
        needle,
        quote_plus(text, encoding="latin-1").encode(),
        quote(text, encoding="latin-1").encode(),
    }
    for shift in range(3):
        usable = (len(needle) - shift) // 3 * 3
        if usable >= 30:
            found.add(base64.b64encode(needle[shift : shift + usable]))
    return found


def _user(browser, base_url, username, recorder):
    context = browser.new_context(base_url=base_url, accept_downloads=True)
    page = context.new_page()
    recorder.attach(page)
    page.goto("/register")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url("**/dashboard")
    _wait_for_module(page)
    return page


def _wait_for_module(page) -> None:
    page.wait_for_function("() => !document.querySelector('#mode-browser').disabled")


def _click_expecting_reload(page, selector) -> None:
    """Click something whose end-to-end work ends in a page reload.

    If the work fails the page stays put and explains why in its status line,
    so surface that instead of a bare timeout.
    """
    try:
        with page.expect_navigation(timeout=30_000):
            page.click(selector)
    except playwright_sync.TimeoutError as exc:
        raise AssertionError(page.inner_text("#e2e-status")) from exc
    _wait_for_module(page)


def _saved_bytes(page, selector: str) -> tuple[bytes, str]:
    """Click a "Save image" link and return the downloaded bytes and name.

    The page CSP forbids fetch() of blob: URLs (connect-src is 'self'), so the
    test reads the plaintext the way a person would: by saving it.
    """
    with page.expect_download() as download:
        page.click(selector)
    saved = download.value
    return Path(saved.path()).read_bytes(), saved.suggested_filename


def test_end_to_end_flow_never_exposes_plaintext_or_secrets(
    live_server, live_app, browser, tmp_path
) -> None:
    recorder = Recorder()
    photo = _geotagged_jpeg()
    source = tmp_path / "eiffel.jpg"
    source.write_bytes(photo)

    bob = _user(browser, live_server, "bob", recorder)
    alice = _user(browser, live_server, "alice", recorder)

    # Upload: end-to-end is the default once the module has loaded.
    assert alice.is_checked("#mode-browser")
    alice.set_input_files("input[name=image]", str(source))
    alice.select_option("#algorithm-select", "AES-GCM")
    alice.fill("#passphrase-field input", IMAGE_PASS)
    _click_expecting_reload(alice, "#upload-form button[type=submit]")
    assert "encrypted in your browser" in alice.inner_text(".flash-stack")
    card = alice.locator(".vault-list > .asset-list .asset-card").first
    assert "End-to-end" in card.inner_text()
    assert "80x48" in card.inner_text()

    store = live_app.extensions["vault_store"]
    asset = store.list_assets(store.get_user_by_username("alice").id)[0]
    assert asset.end_to_end
    assert asset.metadata["context"]["source"] == "browser"

    # View it: decrypted in the page, and the GPS tag is gone.
    card.locator("form.e2e-open input[name=secret]").fill(IMAGE_PASS)
    card.locator("form.e2e-open button[type=submit]").click()
    alice.wait_for_selector("#viewer[open] #viewer-image[src^='blob:']")
    alice.wait_for_function("() => document.querySelector('#viewer-image').naturalWidth === 80")
    shown, name = _saved_bytes(alice, "#viewer-save")
    assert name == "eiffel.jpg"
    assert shown[:3] == b"\xff\xd8\xff"
    assert GPS_MARKER.encode() not in shown
    with Image.open(BytesIO(shown)) as decoded, Image.open(BytesIO(photo)) as expected:
        assert decoded.tobytes() == expected.tobytes()  # stripping kept every pixel
    alice.click("#viewer [data-close]")

    # Share with Bob end-to-end and compare fingerprints like people would.
    card.locator("button.e2e-share-open").click()
    alice.fill("#e2e-share-form input[name=username]", "bob")
    alice.fill("#e2e-share-form input[name=secret]", IMAGE_PASS)
    alice.click("#e2e-share-form [data-submit]")
    alice.wait_for_selector("#e2e-share-form [data-result]:not([hidden])")
    result = alice.inner_text("#e2e-share-form [data-result]")
    bob.goto("/account/password")
    assert bob.inner_text("#key-fingerprint").strip() in result
    _click_expecting_reload(alice, "#e2e-share-modal [data-close]")
    assert "Shared with bob end-to-end" in alice.inner_text(".flash-stack")

    # Bob opens it in his browser with his own password.
    bob.goto("/dashboard")
    _wait_for_module(bob)
    inbox = bob.locator(".shared-inbox .asset-card").first
    assert "End-to-end" in inbox.inner_text()
    inbox.locator("input[name=secret]").fill(PASSWORD)
    inbox.locator("button[type=submit]").click()
    bob.wait_for_function("() => document.querySelector('#viewer-image')?.naturalWidth === 80")
    assert _saved_bytes(bob, "#viewer-save")[0] == shown

    # A link for someone without an account; its key lives in the fragment.
    card = alice.locator(".vault-list > .asset-list .asset-card").first
    card.locator("button.e2e-link-open").click()
    alice.fill("#e2e-link-form input[name=max_downloads]", "1")
    alice.fill("#e2e-link-form input[name=secret]", IMAGE_PASS)
    alice.click("#e2e-link-form [data-submit]")
    alice.wait_for_selector("#e2e-link-form [data-link-output]:not([hidden])")
    link = alice.input_value("#e2e-link-form [data-link-url]")
    base, fragment = link.split("#", 1)
    assert len(fragment) == 43

    stranger_context = browser.new_context(accept_downloads=True)
    stranger = stranger_context.new_page()
    recorder.attach(stranger)
    stranger.goto(link)
    stranger.click("#link-decrypt")
    stranger.wait_for_function("() => document.querySelector('#link-image')?.naturalWidth === 80")
    assert _saved_bytes(stranger, "#link-save")[0] == shown
    # The cap of one is spent: a second visitor gets nothing.
    second = stranger_context.new_page()
    response = second.goto(link)
    assert response.status == 404
    assert "no longer valid" in second.inner_text("body")
    _click_expecting_reload(alice, "#e2e-link-modal [data-close]")

    # Rotate the passphrase in the browser; only the new one opens the image.
    card = alice.locator(".vault-list > .asset-list .asset-card").first
    card.locator("summary", has_text="Rotate passphrase").click()
    card.locator("form.e2e-rotate input[name=old_passphrase]").fill(IMAGE_PASS)
    card.locator("form.e2e-rotate input[name=new_passphrase]").fill(NEW_PASS)
    _click_expecting_reload(alice, ".vault-list form.e2e-rotate button[type=submit]")
    assert "rotated in your browser" in alice.inner_text(".flash-stack")
    card = alice.locator(".vault-list > .asset-list .asset-card").first
    card.locator("form.e2e-open input[name=secret]").fill(IMAGE_PASS)
    card.locator("form.e2e-open button[type=submit]").click()
    alice.wait_for_selector("#e2e-status[data-kind='error']")
    assert "did not unlock" in alice.inner_text("#e2e-status")
    card.locator("form.e2e-open input[name=secret]").fill(NEW_PASS)
    card.locator("form.e2e-open button[type=submit]").click()
    alice.wait_for_function("() => document.querySelector('#viewer-image')?.naturalWidth === 80")

    # What the server saw: ciphertext and wraps, never these.
    for secret in [photo[200:600], shown[200:600], GPS_MARKER.encode()]:
        assert not recorder.sent(secret)
    for secret in [IMAGE_PASS, NEW_PASS, fragment]:
        assert not recorder.sent(secret.encode())
    # Bob's account password went to the server once, at registration, and
    # never again: the share was opened with his key in the page.
    password_forms = _encodings(PASSWORD.encode())
    password_posts = [b for b in recorder.bodies if any(v in b for v in password_forms)]
    assert len(password_posts) == 2  # alice's and bob's registration forms
    assert not any(base.split("/l/")[1] + "#" in url for url in recorder.urls)
    assert GPS_MARKER.encode() not in store.read_ciphertext(asset)
    assert recorder.problems == [], recorder.problems


def test_a_rotated_jpeg_is_stored_upright(live_server, live_app, browser, tmp_path) -> None:
    recorder = Recorder()
    source = tmp_path / "portrait.jpg"
    source.write_bytes(_geotagged_jpeg(size=(80, 48), orientation=6))
    alice = _user(browser, live_server, "alice", recorder)
    alice.set_input_files("input[name=image]", str(source))
    alice.fill("#passphrase-field input", IMAGE_PASS)
    _click_expecting_reload(alice, "#upload-form button[type=submit]")
    assert "encrypted in your browser" in alice.inner_text(".flash-stack")
    asset = live_app.extensions["vault_store"].list_assets(1)[0]
    # EXIF orientation 6 means "rotate 90 degrees": the stored image is 48x80.
    assert (asset.width, asset.height) == (48, 80)
    assert recorder.problems == [], recorder.problems


def test_without_the_module_browser_mode_cannot_be_chosen(live_server, browser) -> None:
    context = browser.new_context(base_url=live_server, java_script_enabled=False)
    page = context.new_page()
    page.goto("/register")
    page.fill("input[name=username]", "alice")
    page.fill("input[name=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url("**/dashboard")
    assert page.is_disabled("#mode-browser")
    assert page.is_checked("#mode-server")


def _share_in_dialog(page, card, username: str, secret: str) -> None:
    card.locator("button.e2e-share-open").click()
    page.fill("#e2e-share-form input[name=username]", username)
    page.fill("#e2e-share-form input[name=secret]", secret)
    page.click("#e2e-share-form [data-submit]")
    page.wait_for_selector("#e2e-share-form [data-result]:not([hidden])")
    _click_expecting_reload(page, "#e2e-share-modal [data-close]")


def _open_shared(page, filename: str) -> None:
    inbox = page.locator(".shared-inbox .asset-card", has_text=filename).first
    secret = inbox.locator("input[name=secret]")
    if secret.get_attribute("placeholder") != "Unlocked for this page":
        secret.fill(PASSWORD)
    inbox.locator("button[type=submit]").click()
    page.wait_for_function("() => document.querySelector('#viewer-image')?.naturalWidth > 0")
    page.click("#viewer [data-close]")


def test_batch_upload_then_rekey_cuts_off_a_dropped_recipient(
    live_server, live_app, browser, tmp_path
) -> None:
    recorder = Recorder()
    paths = []
    for index in range(3):
        path = tmp_path / f"batch-{index}.jpg"
        path.write_bytes(_geotagged_jpeg(size=(40 + index, 30)))
        paths.append(str(path))

    bob = _user(browser, live_server, "bob", recorder)
    carol = _user(browser, live_server, "carol", recorder)
    alice = _user(browser, live_server, "alice", recorder)

    # Three images in one go, all sealed in the browser.
    alice.set_input_files("input[name=image]", paths)
    assert "3 images selected" in alice.inner_text("#drop-hint")
    alice.fill("#passphrase-field input", IMAGE_PASS)
    _click_expecting_reload(alice, "#upload-form button[type=submit]")
    assert "Encrypted 3 of 3 images" in alice.inner_text("#e2e-status")
    store = live_app.extensions["vault_store"]
    alice_id = store.get_user_by_username("alice").id
    assets = store.list_assets(alice_id)
    assert len(assets) == 3 and all(asset.end_to_end for asset in assets)

    # Share one with both Bob and Carol; both can open it.
    card = alice.locator(".vault-list > .asset-list .asset-card", has_text="batch-0.jpg")
    _share_in_dialog(alice, card, "bob", IMAGE_PASS)
    card = alice.locator(".vault-list > .asset-list .asset-card", has_text="batch-0.jpg")
    _share_in_dialog(alice, card, "carol", IMAGE_PASS)
    for page in (bob, carol):
        page.goto("/dashboard")
        _wait_for_module(page)
        _open_shared(page, "batch-0.jpg")
    asset = next(a for a in store.list_assets(alice_id) if a.original_filename == "batch-0.jpg")
    before = store.read_ciphertext(asset)

    # Re-key, keeping Carol and dropping Bob.
    card = alice.locator(".vault-list > .asset-list .asset-card", has_text="batch-0.jpg")
    card.locator("summary", has_text="Re-key").click()
    card.locator("form.e2e-rekey input[name=keep][value=bob]").uncheck()
    card.locator("form.e2e-rekey input[name=secret]").fill(IMAGE_PASS)
    _click_expecting_reload(
        alice, ".vault-list .asset-card:has-text('batch-0.jpg') form.e2e-rekey button[type=submit]"
    )
    assert "Re-keyed in your browser: kept 1 share(s)" in alice.inner_text(".flash-stack")
    assert store.read_ciphertext(store.get_asset(asset.id)) != before

    bob.goto("/dashboard")
    _wait_for_module(bob)
    assert bob.locator(".shared-inbox .asset-card", has_text="batch-0.jpg").count() == 0
    carol.goto("/dashboard")
    _wait_for_module(carol)
    _open_shared(carol, "batch-0.jpg")

    assert not recorder.sent(IMAGE_PASS.encode())
    assert recorder.problems == [], recorder.problems


def test_dropping_files_on_the_upload_panel_selects_them(live_server, browser) -> None:
    recorder = Recorder()
    alice = _user(browser, live_server, "alice", recorder)
    alice.evaluate(
        """() => {
            const transfer = new DataTransfer();
            const bytes = new Uint8Array([137, 80, 78, 71]);
            for (const name of ["one.png", "two.png"]) {
                transfer.items.add(new File([bytes], name, { type: "image/png" }));
            }
            const form = document.querySelector("#upload-form");
            const init = { dataTransfer: transfer, bubbles: true, cancelable: true };
            form.dispatchEvent(new DragEvent("dragover", init));
            form.dispatchEvent(new DragEvent("drop", init));
        }"""
    )
    assert alice.evaluate("() => document.querySelector('input[name=image]').files.length") == 2
    assert "2 images selected" in alice.inner_text("#drop-hint")
    assert recorder.problems == [], recorder.problems


def _real_problems(recorder: Recorder) -> list[str]:
    """Console errors other than the browser's own note about a refused request."""
    return [p for p in recorder.problems if "Failed to load resource" not in p]


def test_an_expired_session_never_reports_a_false_success(
    live_server, live_app, browser, tmp_path
) -> None:
    """A fetch() after the session ended used to follow the sign-in redirect to
    an HTML page with status 200 and call it success: "Encrypted 2 of 2" while
    nothing was stored."""
    recorder = Recorder()
    paths = []
    for index in range(2):
        path = tmp_path / f"late-{index}.jpg"
        path.write_bytes(_geotagged_jpeg(size=(30 + index, 20)))
        paths.append(str(path))
    alice = _user(browser, live_server, "alice", recorder)
    store = live_app.extensions["vault_store"]
    alice_id = store.get_user_by_username("alice").id

    store.delete_user_sessions(alice_id)  # idle timeout, or a sign-out elsewhere
    alice.set_input_files("input[name=image]", paths)
    alice.fill("#passphrase-field input", IMAGE_PASS)
    alice.click("#upload-form button[type=submit]")
    alice.wait_for_selector("#e2e-status[data-kind='error']", timeout=15_000)
    assert "session has ended" in alice.inner_text("#e2e-status").lower()
    assert store.list_assets(alice_id) == []

    # Signing in again shows no leftover success notice either.
    alice.goto("/")
    alice.fill("input[name=username]", "alice")
    alice.fill("input[name=password]", PASSWORD)
    alice.click("button[type=submit]")
    alice.wait_for_url("**/dashboard")
    _wait_for_module(alice)
    assert alice.is_hidden("#e2e-status")
    assert "Encrypted 2 of 2" not in alice.inner_text("body")
    assert _real_problems(recorder) == [], recorder.problems


def test_a_truncated_link_key_does_not_spend_a_capped_download(
    live_server, browser, tmp_path
) -> None:
    """Copy-paste that cuts off the end of a link used to spend its only
    download on a key that could never work."""
    recorder = Recorder()
    source = tmp_path / "once.jpg"
    source.write_bytes(_geotagged_jpeg())
    alice = _user(browser, live_server, "alice", recorder)
    alice.set_input_files("input[name=image]", str(source))
    alice.fill("#passphrase-field input", IMAGE_PASS)
    _click_expecting_reload(alice, "#upload-form button[type=submit]")
    card = alice.locator(".vault-list > .asset-list .asset-card").first
    card.locator("button.e2e-link-open").click()
    alice.fill("#e2e-link-form input[name=max_downloads]", "1")
    alice.fill("#e2e-link-form input[name=secret]", IMAGE_PASS)
    alice.click("#e2e-link-form [data-submit]")
    alice.wait_for_selector("#e2e-link-form [data-link-output]:not([hidden])")
    link = alice.input_value("#e2e-link-form [data-link-url]")

    visitor = browser.new_context(accept_downloads=True)
    cut_short = visitor.new_page()
    recorder.attach(cut_short)
    cut_short.goto(link[:-6])
    assert cut_short.is_disabled("#link-decrypt")
    assert "incomplete" in cut_short.inner_text("#e2e-status")

    # The whole link still works: the cap of one was not spent.
    whole = visitor.new_page()
    recorder.attach(whole)
    whole.goto(link)
    whole.click("#link-decrypt")
    whole.wait_for_function("() => document.querySelector('#link-image')?.naturalWidth > 0")
    assert recorder.problems == [], recorder.problems
