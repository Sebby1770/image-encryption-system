"""Account private keys are wrapped with Scrypt + AES-GCM, not OpenSSL's PBKDF2.

``BestAvailableEncryption`` writes PKCS#8 PBES2 with PBKDF2-HMAC-SHA256 at
OpenSSL's default of 2,048 iterations. That made the RSA private key — which
unwraps every RSA-hybrid image and every share — by far the cheapest secret on
disk to brute-force: roughly a thousand times cheaper per guess than the Scrypt
wrap the vault uses everywhere else. The files were also written 0644.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from io import BytesIO

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from helpers import PASSWORD, login, logout, make_app, register, sample_png, with_csrf

from image_encryption_system import crypto
from image_encryption_system.cli import main as cli_main
from image_encryption_system.crypto import (
    PRIVATE_KEY_FORMAT,
    RSA_HYBRID,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
    generate_rsa_key_pair,
    is_legacy_private_key,
    load_private_key,
    private_key_owner,
    rewrap_private_key,
    wrap_private_key,
)

NEW_PASSWORD = "an entirely new account password"
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


def _legacy_pem(passphrase: str) -> tuple[bytes, bytes]:
    """A key pair stored the way every release before this one stored it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _upload_rsa(client) -> None:
    response = client.post(
        "/images",
        data=with_csrf(
            client,
            {"algorithm": RSA_HYBRID, "image": (BytesIO(sample_png()), "rsa.png")},
        ),
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"Image encrypted and stored" in response.data


def _decrypt_first(client, password: str = PASSWORD):
    store = client.application.extensions["vault_store"]
    asset = store.list_assets(1)[0]
    return client.post(
        f"/images/{asset.id}/decrypt",
        data=with_csrf(client, {"private_key_passphrase": password}),
    )


def test_registration_wraps_the_private_key_with_scrypt(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    store = app.extensions["vault_store"]

    blob = store.read_private_key(1)
    assert not is_legacy_private_key(blob)
    assert b"BEGIN" not in blob
    wrapped = json.loads(blob)
    assert wrapped["format"] == PRIVATE_KEY_FORMAT
    assert wrapped["owner"] == 1
    assert wrapped["kdf"]["type"] == "scrypt"
    assert wrapped["kdf"]["n"] == crypto.SCRYPT_N
    assert not store.legacy_private_key_path(1).exists()

    _upload_rsa(client)
    assert _decrypt_first(client).status_code == 200


@pytest.mark.production_kdf
def test_new_private_keys_use_the_production_scrypt_cost() -> None:
    blob, _public = generate_rsa_key_pair("account password", owner=7)
    assert json.loads(blob)["kdf"]["n"] == 2**16


@posix_only
def test_private_key_files_are_owner_only(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    store = app.extensions["vault_store"]
    mode = stat.S_IMODE(os.stat(store.private_key_path(1)).st_mode)
    assert mode == 0o600


def test_legacy_pem_still_decrypts_and_is_upgraded_at_sign_in(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    _upload_rsa(client)
    store = app.extensions["vault_store"]

    # Put the account back into the pre-upgrade state, under the same public key
    # so the image uploaded above stays decryptable.
    current = load_private_key(store.read_private_key(1), PASSWORD)
    legacy = current.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode()),
    )
    store.private_key_path(1).unlink()
    store.legacy_private_key_path(1).write_bytes(legacy)
    assert is_legacy_private_key(store.read_private_key(1))

    # A session from before the upgrade keeps working on the legacy file...
    assert _decrypt_first(client).status_code == 200

    # ...and the next sign-in replaces it with the Scrypt wrap.
    logout(client)
    login(client, "alice")
    assert not store.legacy_private_key_path(1).exists()
    upgraded = store.read_private_key(1)
    assert not is_legacy_private_key(upgraded)
    assert private_key_owner(upgraded) == 1
    assert _decrypt_first(client).status_code == 200


def test_api_sign_in_also_upgrades_a_legacy_key(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    store = app.extensions["vault_store"]
    legacy, public = _legacy_pem(PASSWORD)
    store.private_key_path(1).unlink()
    store.legacy_private_key_path(1).write_bytes(legacy)
    store.public_key_path(1).write_bytes(public)

    response = client.post("/api/token", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 200
    assert not is_legacy_private_key(store.read_private_key(1))


def test_change_password_rewraps_with_scrypt(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    _upload_rsa(client)
    store = app.extensions["vault_store"]
    # Swap to a legacy file holding the same key, as an un-upgraded account has.
    key = load_private_key(store.read_private_key(1), PASSWORD)
    legacy = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode()),
    )
    store.private_key_path(1).unlink()
    store.legacy_private_key_path(1).write_bytes(legacy)

    response = client.post(
        "/account/password",
        data=with_csrf(
            client,
            {
                "old_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "confirm_password": NEW_PASSWORD,
            },
        ),
        follow_redirects=True,
    )
    assert b"Password updated" in response.data
    assert not store.legacy_private_key_path(1).exists()
    assert not is_legacy_private_key(store.read_private_key(1))
    assert _decrypt_first(client, PASSWORD).status_code == 302  # flashed error
    assert _decrypt_first(client, NEW_PASSWORD).status_code == 200


def test_delete_account_removes_both_key_formats(tmp_path) -> None:
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "alice")
    store = app.extensions["vault_store"]
    store.legacy_private_key_path(1).write_bytes(b"stale legacy copy")
    response = client.post(
        "/account/delete",
        data=with_csrf(client, {"password": PASSWORD}),
        follow_redirects=True,
    )
    assert b"Account deleted" in response.data
    assert not store.private_key_path(1).exists()
    assert not store.legacy_private_key_path(1).exists()
    assert not store.public_key_path(1).exists()


def test_a_key_file_moved_to_another_account_is_refused(tmp_path) -> None:
    app = make_app(tmp_path)
    alice = app.test_client()
    bob = app.test_client()
    register(alice, "alice")
    register(bob, "bob")
    store = app.extensions["vault_store"]
    # Someone with write access to the key directory swaps Bob's key for Alice's.
    store.private_key_path(2).write_bytes(store.private_key_path(1).read_bytes())
    with pytest.raises(CryptoError, match="does not belong"):
        store.read_private_key(2)


def test_wrapped_key_round_trips_and_binds_its_owner() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    blob = wrap_private_key(key, "key password one", owner=3)
    loaded = load_private_key(blob, "key password one", owner=3)
    assert loaded.private_numbers() == key.private_numbers()
    with pytest.raises(CryptoError):
        load_private_key(blob, "wrong password here")
    with pytest.raises(CryptoError, match="does not belong"):
        load_private_key(blob, "key password one", owner=4)

    # The owner is sealed into the AAD: editing it breaks the tag, not just the check.
    edited = json.loads(blob)
    edited["owner"] = 4
    with pytest.raises(CryptoError):
        load_private_key(json.dumps(edited).encode(), "key password one", owner=4)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("format", "something-else"),
        ("version", 2),
        ("extra", "field"),
        ("nonce", "AAAA"),
        ("owner", "1"),
        ("owner", True),
    ],
)
def test_wrapped_key_structure_is_closed(field, value) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrapped = json.loads(wrap_private_key(key, "key password one", owner=1))
    wrapped[field] = value
    with pytest.raises(CryptoError):
        load_private_key(json.dumps(wrapped).encode(), "key password one")


def test_hostile_kdf_cost_is_rejected_before_any_work() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrapped = json.loads(wrap_private_key(key, "key password one"))
    wrapped["kdf"]["n"] = 2**30
    started = time.perf_counter()
    with pytest.raises(CryptoError, match="Scrypt"):
        load_private_key(json.dumps(wrapped).encode(), "key password one")
    assert time.perf_counter() - started < 1.0


def test_rewrap_accepts_legacy_pem_and_returns_the_scrypt_format() -> None:
    legacy, public = _legacy_pem("old password 1")
    rotated = rewrap_private_key(legacy, "old password 1", "new password 2", owner=9)
    assert not is_legacy_private_key(rotated)
    assert private_key_owner(rotated) == 9
    result = encrypt_image_bytes(b"pixels", RSA_HYBRID, public_key_pem=public)
    plaintext = decrypt_image_bytes(
        result.ciphertext,
        result.metadata,
        private_key_pem=rotated,
        private_key_passphrase="new password 2",
    )
    assert plaintext == b"pixels"
    with pytest.raises(CryptoError):
        rewrap_private_key(legacy, "not the password", "new password 2")


def test_cli_keygen_writes_the_scrypt_format_and_pem_on_request(tmp_path) -> None:
    image = tmp_path / "in.png"
    image.write_bytes(sample_png())
    for flag, legacy in (([], False), (["--pem"], True)):
        private = tmp_path / f"key-{legacy}"
        public = tmp_path / f"pub-{legacy}.pem"
        assert (
            cli_main(
                [
                    "keygen",
                    "--passphrase",
                    "cli key password",
                    "--out-private",
                    str(private),
                    "--out-public",
                    str(public),
                    *flag,
                ]
            )
            == 0
        )
        assert is_legacy_private_key(private.read_bytes()) is legacy
        sealed = tmp_path / f"out-{legacy}.ies"
        restored = tmp_path / f"restored-{legacy}.png"
        assert (
            cli_main(["encrypt", str(image), "--public-key", str(public), "-o", str(sealed)]) == 0
        )
        assert (
            cli_main(
                [
                    "decrypt",
                    str(sealed),
                    "--private-key",
                    str(private),
                    "--passphrase",
                    "cli key password",
                    "-o",
                    str(restored),
                ]
            )
            == 0
        )
        assert restored.read_bytes() == image.read_bytes()
