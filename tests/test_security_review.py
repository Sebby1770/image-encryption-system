"""Regression tests for the phase 1 adversarial security review.

Every test in the first part reproduced a real defect before its fix landed.
The "checked and fine" tests at the bottom pin down behaviour that was probed
and found correct, so a later change cannot silently regress it.
"""

from __future__ import annotations

import contextlib
import json
import os
import struct
import threading
import zipfile
import zlib
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from helpers import (
    PASSWORD,
    bearer_headers,
    encrypt_png,
    login,
    logout,
    make_app,
    raw_db,
    register,
    sample_png,
    with_csrf,
)
from PIL import Image, PngImagePlugin

from image_encryption_system import web as web_module
from image_encryption_system.cli import main as ies_main
from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    pack_ies,
    unpack_ies,
    web_aad,
    wrap_data_key_passphrase,
)
from image_encryption_system.web import create_app

FIXTURES = Path(__file__).parent / "fixtures"
IMAGE_PASS = "image passphrase"
XMP_WITH_GPS = (
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
    b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description xmlns:exif="http://ns.adobe.com/exif/1.0/" '
    b'exif:GPSLatitude="51,30.0N" exif:GPSLongitude="0,7.0W"/>'
    b"</rdf:RDF></x:xmpmeta>"
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _store(app):
    return app.extensions["vault_store"]


def _user(app, username):
    return _store(app).get_user_by_username(username)


def _upload(client, data: bytes, filename: str, passphrase: str = IMAGE_PASS):
    return client.post(
        "/images",
        data=with_csrf(
            client,
            {
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": passphrase,
                "image": (BytesIO(data), filename),
            },
        ),
        content_type="multipart/form-data",
    )


def _decrypt(client, asset_id: int, passphrase: str = IMAGE_PASS):
    return client.post(
        f"/images/{asset_id}/decrypt",
        data=with_csrf(client, {"passphrase": passphrase}),
    )


def _upload_and_decrypt(app, client, data: bytes, filename: str) -> bytes:
    response = _upload(client, data, filename)
    assert response.status_code == 302
    alice = _user(app, "alice")
    asset = _store(app).list_assets(alice.id)[0]
    decrypted = _decrypt(client, asset.id)
    assert decrypted.status_code == 200, decrypted.data[:200]
    return decrypted.data


def _backup_zip(manifest_assets: list[dict], blobs: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, blob in blobs.items():
            archive.writestr(name, blob)
        archive.writestr("manifest.json", json.dumps({"version": 2, "assets": manifest_assets}))
    return buffer.getvalue()


def _restore(client, archive: bytes):
    return client.post(
        "/restore",
        data=with_csrf(client, {"backup": (BytesIO(archive), "backup.zip")}),
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def _png_header_only(width: int, height: int) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\0" * 16))
        + chunk(b"IEND", b"")
    )


def _jpeg(**save_kwargs) -> bytes:
    buffer = BytesIO()
    Image.new("RGB", (40, 30), "#2b6cb0").save(buffer, format="JPEG", **save_kwargs)
    return buffer.getvalue()


def _gps_exif() -> bytes:
    exif = Image.Exif()
    exif[0x010F] = "TestCam"  # Make
    exif[0x8825] = {1: "N", 2: (51.0, 30.0, 0.0), 3: "W", 4: (0.0, 7.0, 0.0)}  # GPS IFD
    return exif.tobytes()


def _placeholder_secret() -> str:
    # The published default from config.py, assembled at runtime.
    return "-".join(["dev-secret-change-me"] * 2)


# --------------------------------------------------------------------------- #
# F1: restored backups could smuggle HTML that was served inline (stored XSS)
# --------------------------------------------------------------------------- #


def _share_with_bob(app, alice_client, asset_id: int) -> None:
    shared = alice_client.post(
        f"/images/{asset_id}/share",
        data=with_csrf(alice_client, {"username": "bob", "passphrase": IMAGE_PASS}),
        follow_redirects=True,
    )
    assert b"Shared with bob" in shared.data


def _legacy_v1_envelope(plaintext: bytes, aad_context: dict, aad: bytes) -> tuple[bytes, dict]:
    """Build a version 1 envelope exactly as the pre-review code wrote them."""
    data_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
    metadata = {
        "version": 1,
        "algorithm": AES_GCM_PASSPHRASE,
        "image_nonce": b64encode(nonce).decode(),
        "key_wrap": wrap_data_key_passphrase(data_key, IMAGE_PASS),
        "aad": aad_context,
    }
    return ciphertext, metadata


def _evil_envelope(owner_id: int, mime: str) -> tuple[bytes, dict]:
    payload = b"<html><body><script>fetch('/api/audit')</script></body></html>"
    return _legacy_v1_envelope(
        payload,
        {"user_id": owner_id, "original_filename": "cat.png", "mime_type": mime},
        web_aad(owner_id, "cat.png", mime),
    )


def test_restore_rejects_assets_that_are_not_allow_listed_images(tmp_path) -> None:
    app = make_app(tmp_path)
    alice = app.test_client()
    register(alice, "alice")
    ciphertext, metadata = _evil_envelope(_user(app, "alice").id, "text/html")
    archive = _backup_zip(
        [
            {
                "original_filename": "cat.png",
                "algorithm": AES_GCM_PASSPHRASE,
                "mime_type": "text/html",
                "image_format": "PNG",
                "width": 1,
                "height": 1,
                "metadata": metadata,
                "blob": "assets/evil.enc",
            }
        ],
        {"assets/evil.enc": ciphertext},
    )

    _restore(alice, archive)

    assert _store(app).list_assets(_user(app, "alice").id) == []


def test_decrypt_never_serves_non_image_plaintext_to_a_share_recipient(tmp_path) -> None:
    """A row that already holds HTML (e.g. restored before the fix) must not execute."""
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register(alice, "alice")
    register(bob, "bob")
    owner = _user(app, "alice")
    ciphertext, metadata = _evil_envelope(owner.id, "text/html")
    asset = _store(app).save_asset(
        user_id=owner.id,
        original_filename="cat.png",
        algorithm=AES_GCM_PASSPHRASE,
        mime_type="text/html",
        image_format="PNG",
        width=1,
        height=1,
        metadata=metadata,
        ciphertext=ciphertext,
    )
    _share_with_bob(app, alice, asset.id)

    response = bob.post(
        f"/images/{asset.id}/decrypt",
        data=with_csrf(bob, {"private_key_passphrase": PASSWORD}),
    )

    assert b"<script>" not in response.data
    assert response.status_code != 200


# --------------------------------------------------------------------------- #
# F2: decrypted images were cacheable and not sandboxed
# --------------------------------------------------------------------------- #


def test_decrypted_responses_are_no_store_nosniff_and_sandboxed(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    asset = _store(app).list_assets(_user(app, "alice").id)[0]

    response = _decrypt(client, asset.id)

    assert response.status_code == 200
    assert "no-store" in response.headers.get("Cache-Control", "")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "sandbox" in response.headers.get("Content-Security-Policy", "")


# --------------------------------------------------------------------------- #
# F3: capability-link download cap could be exceeded by concurrent requests
# --------------------------------------------------------------------------- #


def test_link_download_cap_holds_under_concurrency(tmp_path, monkeypatch) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    asset = _store(app).list_assets(_user(app, "alice").id)[0]
    created = client.post(
        f"/api/images/{asset.id}/link",
        json={"passphrase": IMAGE_PASS, "max_downloads": 1},
        headers=bearer_headers(client, "alice"),
    )
    token = created.get_json()["token"]

    # Hold every request that reaches decryption until a second one arrives, so
    # both pass any check-then-increment window before either increments.
    barrier = threading.Barrier(2)
    real_decrypt = web_module.decrypt_image_bytes

    def slow_decrypt(*args, **kwargs):
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=2)
        return real_decrypt(*args, **kwargs)

    monkeypatch.setattr(web_module, "decrypt_image_bytes", slow_decrypt)
    statuses: list[int] = []

    def fetch() -> None:
        statuses.append(app.test_client().post(f"/l/{token}/decrypt").status_code)

    threads = [threading.Thread(target=fetch) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(statuses) == [200, 403]
    link = _store(app).list_link_shares_for_owner(_user(app, "alice").id)[asset.id][0]
    assert link.download_count == 1


# --------------------------------------------------------------------------- #
# F4: a backup could reference one blob many times (disk amplification)
# --------------------------------------------------------------------------- #


def test_restore_rejects_a_blob_referenced_more_than_once(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    exported = client.get("/backup").data
    with zipfile.ZipFile(BytesIO(exported)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        blob_name = manifest["assets"][0]["blob"]
        blob = archive.read(blob_name)
    item = manifest["assets"][0]

    response = _restore(client, _backup_zip([item] * 25, {blob_name: blob}))

    assert b"Restored" not in response.data
    assert len(_store(app).list_assets(_user(app, "alice").id)) == 1


# --------------------------------------------------------------------------- #
# F5: the published default SECRET_KEY/JWT_SECRET were used when unset
# --------------------------------------------------------------------------- #


def test_unset_secrets_do_not_fall_back_to_the_published_default(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("JWT_SECRET", raising=False)
    app = create_app(
        {
            "TESTING": True,
            "INSTANCE_DIR": tmp_path,
            "DATABASE_PATH": tmp_path / "vault.sqlite3",
            "VAULT_DIR": tmp_path / "vault",
            "KEY_DIR": tmp_path / "keys",
        }
    )
    client = app.test_client()
    register(client, "alice")
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {
            "sub": "1",
            "iss": app.config["JWT_ISSUER"],
            "iat": now,
            "exp": now + timedelta(hours=1),
            "ver": 1,
        },
        _placeholder_secret(),
        algorithm="HS256",
    )

    response = client.get("/api/images", headers={"Authorization": f"Bearer {forged}"})

    assert response.status_code == 401
    assert app.config["SECRET_KEY"] != _placeholder_secret()


# --------------------------------------------------------------------------- #
# F6: logout did not invalidate a copied session cookie
# --------------------------------------------------------------------------- #


def test_logout_invalidates_a_copied_session_cookie(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    stolen = client.get_cookie("session").value

    logout(client)
    attacker = app.test_client()
    attacker.set_cookie("session", stolen)
    response = attacker.get("/dashboard")

    assert response.status_code == 302


# --------------------------------------------------------------------------- #
# F7: unknown usernames skipped password hashing (timing user enumeration)
# --------------------------------------------------------------------------- #


def test_login_hashes_a_password_even_for_unknown_users(tmp_path, monkeypatch) -> None:
    from image_encryption_system import storage

    app = make_app(tmp_path)
    client = app.test_client()
    calls: list[str] = []
    real_check = storage.check_password_hash

    def counting_check(pwhash: str, password: str) -> bool:
        calls.append(password)
        return real_check(pwhash, password)

    monkeypatch.setattr(storage, "check_password_hash", counting_check)

    login(client, "nobody-here", "whatever password")

    assert len(calls) == 1


# --------------------------------------------------------------------------- #
# F8: location metadata outside EXIF survived "EXIF stripping"
# --------------------------------------------------------------------------- #


def test_gps_exif_and_comment_are_stripped_from_jpeg(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    original = _jpeg(exif=_gps_exif(), comment=b"shot at 51.5N 0.1W")

    plaintext = _upload_and_decrypt(app, client, original, "gps.jpg")

    with Image.open(BytesIO(plaintext)) as image:
        exif = image.getexif()
        assert exif.get_ifd(0x8825) == {}
        assert 0x010F not in exif
        assert not image.info.get("comment")
    assert b"51.5N" not in plaintext


def test_xmp_gps_is_stripped_from_jpeg(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")

    plaintext = _upload_and_decrypt(app, client, _jpeg(xmp=XMP_WITH_GPS), "xmp.jpg")

    assert b"GPSLatitude" not in plaintext


def test_xmp_and_text_chunks_are_stripped_from_png(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    info = PngImagePlugin.PngInfo()
    info.add_itxt("XML:com.adobe.xmp", XMP_WITH_GPS.decode())
    info.add_text("Comment", "home: 51.5N 0.1W")
    buffer = BytesIO()
    Image.new("RGB", (40, 30), "#276749").save(buffer, format="PNG", pnginfo=info)

    plaintext = _upload_and_decrypt(app, client, buffer.getvalue(), "xmp.png")

    assert b"GPSLatitude" not in plaintext
    assert b"51.5N" not in plaintext


def test_gif_comment_is_stripped_and_animation_kept(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    frames = [Image.new("RGB", (20, 20), color) for color in ("red", "green", "blue")]
    buffer = BytesIO()
    frames[0].save(
        buffer,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        comment=b"home: 51.5N",
        duration=80,
        loop=0,
    )

    plaintext = _upload_and_decrypt(app, client, buffer.getvalue(), "anim.gif")

    assert b"51.5N" not in plaintext
    with Image.open(BytesIO(plaintext)) as image:
        assert getattr(image, "n_frames", 1) == 3


# --------------------------------------------------------------------------- #
# F9: hostile image headers raised uncaught errors (HTTP 500)
# --------------------------------------------------------------------------- #


def test_pixel_bomb_header_is_rejected_without_an_exception(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")

    response = _upload(client, _png_header_only(20_000, 20_000), "bomb.png")

    assert response.status_code == 302
    assert _store(app).list_assets(_user(app, "alice").id) == []


def test_truncated_jpeg_is_rejected_without_an_exception(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    whole = _jpeg(exif=_gps_exif())

    response = _upload(client, whole[: len(whole) // 2], "cut.jpg")

    assert response.status_code == 302
    assert _store(app).list_assets(_user(app, "alice").id) == []


# --------------------------------------------------------------------------- #
# F10: AAD did not bind file identity, algorithm, format, or dimensions
# --------------------------------------------------------------------------- #


def _two_uploads(app, client):
    for color in ("#c53030", "#2f855a"):
        buffer = BytesIO()
        Image.new("RGB", (80, 48), color).save(buffer, format="PNG")
        assert _upload(client, buffer.getvalue(), "same.png").status_code == 302
    return sorted(_store(app).list_assets(_user(app, "alice").id), key=lambda a: a.id)


def test_swapping_ciphertext_and_metadata_between_files_fails(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    first, second = _two_uploads(app, client)
    vault = tmp_path / "vault"
    first_blob = (vault / first.stored_filename).read_bytes()
    second_blob = (vault / second.stored_filename).read_bytes()
    (vault / first.stored_filename).write_bytes(second_blob)
    (vault / second.stored_filename).write_bytes(first_blob)
    with raw_db(tmp_path) as db:
        for target, source in ((first, second), (second, first)):
            db.execute(
                "UPDATE encrypted_assets SET metadata_json = ? WHERE id = ?",
                (json.dumps(source.metadata), target.id),
            )

    response = _decrypt(client, first.id)

    assert response.status_code != 200


def test_tampering_with_recorded_format_or_dimensions_fails(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    asset = _store(app).list_assets(_user(app, "alice").id)[0]
    with raw_db(tmp_path) as db:
        db.execute(
            "UPDATE encrypted_assets SET image_format = 'GIF', mime_type = 'image/gif', "
            "width = 4000 WHERE id = ?",
            (asset.id,),
        )

    response = _decrypt(client, asset.id)

    assert response.status_code != 200


# --------------------------------------------------------------------------- #
# F11: the documented HMAC audit chain did not exist
# --------------------------------------------------------------------------- #


def test_audit_chain_detects_an_edited_event(tmp_path) -> None:
    app = make_app(tmp_path, AUDIT_HMAC_KEY="audit-" + "k" * 40)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    store = _store(app)
    alice = _user(app, "alice")
    assert store.verify_audit_chain(alice.id).ok

    with raw_db(tmp_path) as db:
        db.execute(
            "UPDATE audit_events SET action = 'login' WHERE action = 'upload' AND user_id = ?",
            (alice.id,),
        )

    report = store.verify_audit_chain(alice.id)
    assert not report.ok
    assert report.first_bad_id is not None


def test_audit_chain_detects_a_deleted_event(tmp_path) -> None:
    app = make_app(tmp_path, AUDIT_HMAC_KEY="audit-" + "k" * 40)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    login(client, "alice")
    store = _store(app)
    alice = _user(app, "alice")
    with raw_db(tmp_path) as db:
        db.execute("DELETE FROM audit_events WHERE action = 'upload' AND user_id = ?", (alice.id,))

    assert not store.verify_audit_chain(alice.id).ok


# --------------------------------------------------------------------------- #
# F12: malformed envelope fields crashed the CLI with a traceback
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("image_nonce", 5),
        ("image_nonce", "!!not base64!!"),
        ("key_wrap", ["not", "a", "dict"]),
        ("aad", {"user_id": "one"}),
        ("version", "one"),
    ],
)
def test_cli_rejects_malformed_envelope_fields_cleanly(tmp_path, capsys, field, value) -> None:
    vault = tmp_path / "in.ies"
    ciphertext, metadata = unpack_ies((FIXTURES / "legacy-v1-cli.ies").read_bytes())
    metadata[field] = value
    vault.write_bytes(pack_ies(ciphertext, metadata))

    code = ies_main(
        [
            "decrypt",
            str(vault),
            "--passphrase",
            "legacy fixture passphrase",
            "--out",
            str(tmp_path / "out.png"),
        ]
    )

    assert code == 1
    assert capsys.readouterr().err.startswith("error:")


# --------------------------------------------------------------------------- #
# Backwards compatibility: version 1 envelopes written before this review
# --------------------------------------------------------------------------- #


def test_legacy_v1_cli_file_still_decrypts(tmp_path) -> None:
    out = tmp_path / "out.png"
    code = ies_main(
        [
            "decrypt",
            str(FIXTURES / "legacy-v1-cli.ies"),
            "--passphrase",
            "legacy fixture passphrase",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert out.read_bytes() == (FIXTURES / "legacy-v1-cli.png").read_bytes()


def test_legacy_v1_web_download_still_decrypts_with_the_cli(tmp_path) -> None:
    out = tmp_path / "out.png"
    code = ies_main(
        [
            "decrypt",
            str(FIXTURES / "legacy-v1-web.ies"),
            "--passphrase",
            "legacy fixture passphrase",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    # Compared against the recorded plaintext, not a fresh sample_png(): PNG
    # encoding varies across Pillow releases (12.3 changes the bytes of the
    # identical image), which made this test fail with no code change.
    assert out.read_bytes() == (FIXTURES / "legacy-v1-web.png").read_bytes()


def test_legacy_v1_backup_restores_and_decrypts_in_the_web_app(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")

    restored = _restore(client, (FIXTURES / "legacy-v1-backup.zip").read_bytes())
    assert b"Restored 1 encrypted image" in restored.data
    asset = _store(app).list_assets(_user(app, "alice").id)[0]
    assert asset.metadata["version"] == 1

    response = _decrypt(client, asset.id, passphrase="legacy fixture passphrase")
    assert response.status_code == 200
    assert response.data == (FIXTURES / "legacy-v1-web.png").read_bytes()


# --------------------------------------------------------------------------- #
# Checked and fine: probed during the review, pinned here against regressions
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("variant", ["none", "wrong-key", "hs512"])
def test_jwt_algorithm_confusion_is_rejected(tmp_path, variant) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "1",
        "iss": app.config["JWT_ISSUER"],
        "iat": now,
        "exp": now + timedelta(hours=1),
        "ver": 1,
    }
    if variant == "none":
        token = jwt.encode(claims, None, algorithm="none")
    elif variant == "wrong-key":
        token = jwt.encode(claims, "x" * 48, algorithm="HS256")
    else:
        token = jwt.encode(claims, app.config["JWT_SECRET"], algorithm="HS512")

    response = client.get("/api/images", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_jwt_without_a_ver_claim_is_rejected(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": "1", "iss": app.config["JWT_ISSUER"], "iat": now, "exp": now + timedelta(hours=1)},
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )

    response = client.get("/api/images", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_jwt_is_rejected_after_a_password_change(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    headers = bearer_headers(client, "alice")
    assert client.get("/api/images", headers=headers).status_code == 200

    client.post(
        "/account/password",
        data=with_csrf(
            client,
            {
                "old_password": PASSWORD,
                "new_password": "a brand new password",
                "confirm_password": "a brand new password",
            },
        ),
    )

    assert client.get("/api/images", headers=headers).status_code == 401


@pytest.mark.parametrize("spelling", ["ALICE", " alice ", "Alice", "ａlice"])
def test_lockout_cannot_be_bypassed_by_case_or_unicode(tmp_path, spelling) -> None:
    app = make_app(tmp_path, LOGIN_LOCKOUT_THRESHOLD=3, LOGIN_RATE_LIMIT=100)
    client = app.test_client()
    register(client, "alice")
    logout(client)
    for _ in range(3):
        login(client, "alice", "wrong password!")

    response = login(client, spelling, PASSWORD)

    assert response.status_code in {302, 403}
    assert client.get("/dashboard").status_code == 302


def test_every_state_changing_html_route_requires_csrf(tmp_path) -> None:
    app = make_app(tmp_path, CSRF_ENABLED=True)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    exempt_prefixes = ("/api/", "/l/")
    checked = 0
    for rule in app.url_map.iter_rules():
        methods = (rule.methods or set()) - {"GET", "HEAD", "OPTIONS"}
        if not methods or rule.rule.startswith(exempt_prefixes) or rule.endpoint == "static":
            continue
        path = rule.rule
        for argument in rule.arguments:
            path = path.replace(f"<int:{argument}>", "1").replace(f"<{argument}>", "1")
        for method in methods:
            response = client.open(path, method=method, data={})
            assert response.status_code == 400, (method, path)
            checked += 1
    assert checked >= 15


def test_api_routes_ignore_session_cookies(tmp_path) -> None:
    """JSON routes are CSRF-exempt only because they require a bearer token."""
    app = make_app(tmp_path, CSRF_ENABLED=True)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)

    assert client.get("/api/images").status_code == 401
    assert client.post("/api/images/1/share", json={"username": "bob"}).status_code == 401


def test_upload_filename_cannot_traverse_paths(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")

    _upload(client, sample_png(), "../../../../etc/passwd.png")

    asset = _store(app).list_assets(_user(app, "alice").id)[0]
    assert "/" not in asset.original_filename and ".." not in asset.original_filename
    assert (tmp_path / "vault" / asset.stored_filename).is_file()
    assert not (tmp_path.parent / "etc").exists()


def test_restore_cannot_touch_another_users_data(tmp_path) -> None:
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register(alice, "alice")
    register(bob, "bob")
    encrypt_png(alice)
    alice_asset = _store(app).list_assets(_user(app, "alice").id)[0]
    before = (tmp_path / "vault" / alice_asset.stored_filename).read_bytes()
    exported = alice.get("/backup").data

    _restore(bob, exported)

    assert (tmp_path / "vault" / alice_asset.stored_filename).read_bytes() == before
    assert _store(app).get_asset(alice_asset.id).user_id == _user(app, "alice").id


def test_restore_rejects_zip_slip_member_names(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    archive = _backup_zip(
        [{"blob": "../../escape.enc", "metadata": {}}], {"../../escape.enc": b"x" * 32}
    )

    _restore(client, archive)

    assert _store(app).list_assets(_user(app, "alice").id) == []
    assert not (tmp_path.parent / "escape.enc").exists()


def test_revoked_and_expired_shares_stop_decrypting(tmp_path) -> None:
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register(alice, "alice")
    register(bob, "bob")
    encrypt_png(alice)
    asset = _store(app).list_assets(_user(app, "alice").id)[0]
    _share_with_bob(app, alice, asset.id)

    def bob_decrypts() -> int:
        return bob.post(
            f"/images/{asset.id}/decrypt",
            data=with_csrf(bob, {"private_key_passphrase": PASSWORD}),
            headers={"Accept": "application/json"},
        ).status_code

    assert bob_decrypts() == 200
    share_id = _store(app).get_share(asset.id, _user(app, "bob").id).id
    alice.post(f"/share/{share_id}/revoke", data=with_csrf(alice))
    assert bob_decrypts() == 403

    _share_with_bob(app, alice, asset.id)
    with raw_db(tmp_path) as db:
        db.execute("UPDATE shares SET expires_at = '2000-01-01T00:00:00+00:00'")
    assert bob_decrypts() == 403


def test_link_tokens_are_high_entropy_and_stored_hashed(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    encrypt_png(client)
    headers = bearer_headers(client, "alice")
    tokens = [
        client.post(
            "/api/images/1/link", json={"passphrase": IMAGE_PASS}, headers=headers
        ).get_json()["token"]
        for _ in range(3)
    ]

    assert len(set(tokens)) == 3
    assert all(len(token) >= 43 for token in tokens)  # 32 random bytes, base64url
    raw = (tmp_path / "vault.sqlite3").read_bytes()
    assert not any(token.encode() in raw for token in tokens)
    guest = app.test_client()
    alice_id = _user(app, "alice").id
    link_id = _store(app).list_link_shares_for_owner(alice_id)[1][0].id
    client.post(f"/link/{link_id}/revoke", data=with_csrf(client))
    revoked = [guest.post(f"/l/{token}/decrypt").status_code for token in tokens]
    assert sorted(revoked) == [200, 200, 404]
