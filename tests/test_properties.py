"""Property-based tests for the envelope, the KDF bounds, and round trips."""

from __future__ import annotations

import string
import tempfile
import time
from functools import lru_cache
from io import BytesIO
from pathlib import Path

import pytest
from helpers import make_app, register, with_csrf
from hypothesis import assume, given
from hypothesis import strategies as st
from PIL import Image

from image_encryption_system.cli import main as ies_main
from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    MAX_SCRYPT_MEMORY_BYTES,
    MAX_SCRYPT_WORK_FACTOR,
    SCRYPT_N,
    SCRYPT_R,
    CryptoError,
    decrypt_image_bytes,
    encrypt_image_bytes,
    pack_ies,
    unpack_ies,
)

PASSPHRASE = "property test passphrase"


def _decrypt_ies(blob: bytes, passphrase: str = PASSPHRASE) -> bytes:
    ciphertext, metadata = unpack_ies(blob)
    return decrypt_image_bytes(ciphertext, metadata, passphrase=passphrase)


@lru_cache(maxsize=1)
def _cli_blob() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "photo.png"
        source.write_bytes(_png(9, 7, (10, 200, 30)))
        out = Path(tmp) / "photo.ies"
        assert ies_main(["encrypt", str(source), "-p", PASSPHRASE, "-o", str(out)]) == 0
        return out.read_bytes()


@lru_cache(maxsize=1)
def _web_session():
    tmp = Path(tempfile.mkdtemp())
    app = make_app(tmp)
    client = app.test_client()
    register(client, "prop")
    return app, client


@lru_cache(maxsize=1)
def _web_blob() -> bytes:
    app, client = _web_session()
    _upload(client, _png(12, 5, (1, 2, 3)), "web.png")
    asset_id = app.extensions["vault_store"].list_assets(1)[-1].id
    return client.get(f"/images/{asset_id}/download").data


def _png(width: int, height: int, color: tuple[int, int, int]) -> bytes:
    buffer = BytesIO()
    Image.new("RGB", (width, height), color).save(buffer, format="PNG")
    return buffer.getvalue()


def _upload(client, data: bytes, filename: str):
    return client.post(
        "/images",
        data=with_csrf(
            client,
            {
                "algorithm": AES_GCM_PASSPHRASE,
                "passphrase": PASSPHRASE,
                "image": (BytesIO(data), filename),
            },
        ),
        content_type="multipart/form-data",
    )


def _flip(blob: bytes, data) -> bytes:
    index = data.draw(st.integers(0, len(blob) - 1), label="index")
    mask = data.draw(st.integers(1, 255), label="xor mask")
    mutated = bytearray(blob)
    mutated[index] ^= mask
    return bytes(mutated)


# --------------------------------------------------------------------------- #
# Tampering: every byte of an .ies file is authenticated
# --------------------------------------------------------------------------- #


def test_unmodified_blobs_decrypt() -> None:
    assert _decrypt_ies(_cli_blob()).startswith(b"\x89PNG")
    assert _decrypt_ies(_web_blob()).startswith(b"\x89PNG")


@given(st.data())
def test_flipping_any_byte_of_a_cli_file_fails_to_decrypt(data) -> None:
    with pytest.raises(CryptoError):
        _decrypt_ies(_flip(_cli_blob(), data))


@given(st.data())
def test_flipping_any_byte_of_a_web_download_fails_to_decrypt(data) -> None:
    with pytest.raises(CryptoError):
        _decrypt_ies(_flip(_web_blob(), data))


@given(data=st.data())
def test_flipping_any_byte_of_the_header_is_rejected_by_the_cli(data, tmp_path_factory) -> None:
    """The same property through the real `ies decrypt` entry point."""
    blob = _cli_blob()
    header_len = len(blob) - len(unpack_ies(blob)[0])
    index = data.draw(st.integers(0, header_len - 1), label="header index")
    mask = data.draw(st.integers(1, 255), label="xor mask")
    mutated = bytearray(blob)
    mutated[index] ^= mask
    tmp = tmp_path_factory.mktemp("flip")
    (tmp / "in.ies").write_bytes(bytes(mutated))

    code = ies_main(["decrypt", str(tmp / "in.ies"), "-p", PASSPHRASE, "-o", str(tmp / "o")])

    assert code == 1
    assert not (tmp / "o").exists()


# --------------------------------------------------------------------------- #
# KDF bounds: out-of-range Scrypt parameters are refused, and refused cheaply
# --------------------------------------------------------------------------- #


def _in_bounds(n: int, r: int, p: int) -> bool:
    return (
        SCRYPT_N <= n <= MAX_SCRYPT_WORK_FACTOR
        and n & (n - 1) == 0
        and 1 <= r <= 32
        and 1 <= p <= 16
        and 128 * n * r <= MAX_SCRYPT_MEMORY_BYTES
        and n * r * p <= MAX_SCRYPT_WORK_FACTOR * SCRYPT_R
    )


_power_or_any = st.one_of(
    st.integers(0, 40).map(lambda e: 2**e),
    st.integers(-(2**40), 2**40),
)


@given(n=_power_or_any, r=st.integers(-4, 2**20), p=st.integers(-4, 2**20))
def test_out_of_bounds_kdf_parameters_are_rejected_quickly(n, r, p) -> None:
    assume(not _in_bounds(n, r, p))
    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase=PASSPHRASE)
    metadata = result.metadata
    metadata["key_wrap"] = {**metadata["key_wrap"], "n": n, "r": r, "p": p}

    started = time.perf_counter()
    with pytest.raises(CryptoError):
        decrypt_image_bytes(result.ciphertext, metadata, passphrase=PASSPHRASE)

    assert time.perf_counter() - started < 1.0


@given(n=st.integers(-3, 2**23), r=st.integers(-3, 40), p=st.integers(-3, 20))
def test_kdf_validator_accepts_exactly_the_documented_region(n, r, p) -> None:
    from image_encryption_system.crypto import _validate_scrypt_parameters

    if _in_bounds(n, r, p):
        _validate_scrypt_parameters(n=n, r=r, p=p)
    else:
        with pytest.raises(CryptoError):
            _validate_scrypt_parameters(n=n, r=r, p=p)


@given(value=st.one_of(st.text(max_size=8), st.floats(), st.none(), st.lists(st.integers())))
def test_non_integer_kdf_parameters_are_rejected(value) -> None:
    result = encrypt_image_bytes(b"pixels", AES_GCM_PASSPHRASE, passphrase=PASSPHRASE)
    metadata = result.metadata
    metadata["key_wrap"] = {**metadata["key_wrap"], "n": value}
    with pytest.raises(CryptoError):
        decrypt_image_bytes(result.ciphertext, metadata, passphrase=PASSPHRASE)


# --------------------------------------------------------------------------- #
# Round trips: CLI, web, and CLI-on-web-download agree
# --------------------------------------------------------------------------- #

_filenames = st.text(
    alphabet=string.ascii_letters + string.digits + "-_ éü漢",
    min_size=1,
    max_size=40,
).map(lambda stem: f"{stem}.png")
_passphrases = st.text(min_size=1, max_size=64).filter(lambda s: len(s.encode()) <= 1024)


@given(payload=st.binary(min_size=1, max_size=4096), passphrase=_passphrases, name=_filenames)
def test_cli_round_trips_arbitrary_bytes(payload, passphrase, name, tmp_path_factory) -> None:
    tmp = tmp_path_factory.mktemp("cli")
    source = tmp / "input.bin"
    source.write_bytes(payload)
    renamed = tmp / name.replace("/", "_")
    source.rename(renamed)

    assert ies_main(["encrypt", str(renamed), "-p", passphrase, "-o", str(tmp / "x.ies")]) == 0
    assert ies_main(["decrypt", str(tmp / "x.ies"), "-p", passphrase, "-o", str(tmp / "y")]) == 0
    assert (tmp / "y").read_bytes() == payload


@given(
    width=st.integers(1, 64),
    height=st.integers(1, 64),
    color=st.tuples(st.integers(0, 255), st.integers(0, 255), st.integers(0, 255)),
    name=_filenames,
)
def test_web_upload_round_trips_and_its_download_opens_in_the_cli(
    width, height, color, name, tmp_path_factory
) -> None:
    app, client = _web_session()
    original = _png(width, height, color)
    assert _upload(client, original, name).status_code == 302
    asset = app.extensions["vault_store"].list_assets(1)[0]
    assert (asset.width, asset.height) == (width, height)

    decrypted = client.post(
        f"/images/{asset.id}/decrypt", data=with_csrf(client, {"passphrase": PASSPHRASE})
    )
    assert decrypted.status_code == 200
    assert decrypted.data == original

    tmp = tmp_path_factory.mktemp("web")
    (tmp / "d.ies").write_bytes(client.get(f"/images/{asset.id}/download").data)
    assert ies_main(["decrypt", str(tmp / "d.ies"), "-p", PASSPHRASE, "-o", str(tmp / "o")]) == 0
    assert (tmp / "o").read_bytes() == original


@given(payload=st.binary(min_size=1, max_size=2048), passphrase=_passphrases)
def test_crypto_round_trip_and_repacking_is_stable(payload, passphrase) -> None:
    result = encrypt_image_bytes(payload, AES_GCM_PASSPHRASE, passphrase=passphrase)
    blob = pack_ies(result.ciphertext, result.metadata)
    ciphertext, metadata = unpack_ies(blob)
    assert pack_ies(ciphertext, metadata) == blob
    assert decrypt_image_bytes(ciphertext, metadata, passphrase=passphrase) == payload
