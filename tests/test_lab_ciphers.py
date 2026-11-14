"""Every lab cipher must give back exactly the image it was given.

Weak or strong, each cipher is lossless, keyed, and reads only its own payload
when decrypting, so the tamper test and the attacks measure the real thing.
"""

from __future__ import annotations

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.extra.numpy import arrays

from image_encryption_system.lab import imaging
from image_encryption_system.lab.base import Ciphertext, LabDecryptError, check_image
from image_encryption_system.lab.ciphers import CIPHER_NAMES, IMPLEMENTED, make_cipher

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
EXPECTED_NAMES = (
    "arnold",
    "logistic-xor",
    "hyperchaos",
    "wavelet",
    "wht",
    "drpe",
    "neural",
    "aes-ecb",
    "aes-ctr-fixed-iv",
    "aes-gcm",
    "aes-gcm-v4",
)
BYTE_CIPHERS = [name for name in IMPLEMENTED if name not in {"wht", "drpe"}]


def _random_image(seed: int, size: int = 32) -> np.ndarray:
    return np.random.default_rng(seed).integers(0, 256, (size, size, 3), dtype=np.uint8)


def test_registry_lists_the_eleven_ciphers_in_order() -> None:
    assert CIPHER_NAMES == EXPECTED_NAMES
    assert set(IMPLEMENTED) <= set(CIPHER_NAMES)
    for name in IMPLEMENTED:
        cipher = make_cipher(name, KEY)
        assert cipher.name == name
        assert cipher.title and cipher.family and cipher.summary


def test_make_cipher_refuses_unknown_names_and_bad_keys() -> None:
    with pytest.raises(ValueError):
        make_cipher("rot13", KEY)
    with pytest.raises(ValueError):
        make_cipher("arnold", b"too short")


@pytest.mark.parametrize("name", IMPLEMENTED)
@pytest.mark.parametrize("sample", imaging.SAMPLES)
@pytest.mark.parametrize("size", [32, 64])
def test_round_trip_exact(name, sample, size) -> None:
    image = imaging.sample(sample, size)
    cipher = make_cipher(name, KEY)
    ciphertext = cipher.encrypt(image)
    assert ciphertext.shape == image.shape
    assert ciphertext.view.shape == image.shape and ciphertext.view.dtype == np.uint8
    assert np.array_equal(cipher.decrypt(ciphertext), image)


@pytest.mark.parametrize("name", IMPLEMENTED)
def test_round_trip_property(name) -> None:
    cipher = make_cipher(name, KEY)

    @settings(max_examples=10, deadline=None)
    @given(arrays(np.uint8, (32, 32, 3), elements=st.integers(0, 255)))
    def check(image):
        assert np.array_equal(cipher.decrypt(cipher.encrypt(image)), image)

    check()


@pytest.mark.parametrize("name", IMPLEMENTED)
def test_wrong_key_does_not_decrypt(name) -> None:
    image = _random_image(1)
    ciphertext = make_cipher(name, KEY).encrypt(image)
    other = make_cipher(name, OTHER_KEY)
    try:
        opened = other.decrypt(ciphertext)
    except LabDecryptError:
        return  # authenticated ciphers refuse outright
    assert np.mean(np.any(opened != image, axis=-1)) > 0.5


@pytest.mark.parametrize("name", BYTE_CIPHERS)
def test_byte_ciphertexts_expose_their_pixels(name) -> None:
    image = _random_image(2)
    ciphertext = make_cipher(name, KEY).encrypt(image)
    assert ciphertext.pixels is not None
    assert ciphertext.pixels.shape == image.shape and ciphertext.pixels.dtype == np.uint8
    assert np.array_equal(ciphertext.view, ciphertext.pixels)


@pytest.mark.parametrize("name", IMPLEMENTED)
def test_decrypt_reads_the_payload_not_the_rendering(name) -> None:
    image = _random_image(3)
    cipher = make_cipher(name, KEY)
    ciphertext = cipher.encrypt(image)
    blank = np.zeros_like(ciphertext.view)
    disguised = Ciphertext(
        payload=ciphertext.payload,
        shape=ciphertext.shape,
        pixels=None if ciphertext.pixels is None else blank,
        view=blank,
    )
    assert np.array_equal(cipher.decrypt(disguised), image)


def test_hyperchaos_diffuses_one_pixel_over_the_whole_image() -> None:
    image = imaging.sample("landscape", 64)
    nudged = image.copy()
    nudged[20, 30, 1] ^= 1
    cipher = make_cipher("hyperchaos", KEY)
    first = np.frombuffer(cipher.encrypt(image).payload, np.uint8)
    second = np.frombuffer(cipher.encrypt(nudged).payload, np.uint8)
    assert np.mean(first != second) > 0.99


def test_arnold_only_moves_pixels() -> None:
    image = _random_image(4)
    ciphertext = make_cipher("arnold", KEY).encrypt(image)
    assert sorted(map(tuple, image.reshape(-1, 3))) == sorted(
        map(tuple, ciphertext.pixels.reshape(-1, 3))
    )


@pytest.mark.parametrize(
    "image",
    [
        np.zeros((32, 32), np.uint8),
        np.zeros((32, 64, 3), np.uint8),
        np.zeros((48, 48, 3), np.uint8),
        np.zeros((32, 32, 3), np.float64),
        np.zeros((32, 32, 4), np.uint8),
    ],
    ids=["grey", "not-square", "not-a-lab-size", "float", "rgba"],
)
def test_check_image_refuses_bad_shapes(image) -> None:
    with pytest.raises(ValueError):
        check_image(image)
    with pytest.raises(ValueError):
        make_cipher("arnold", KEY).encrypt(image)


def test_key_material_is_cached_per_instance_not_forever(monkeypatch) -> None:
    # A web lab run uses a fresh random key; caching material globally by key
    # would keep every run's keystreams alive for the life of the server.
    from image_encryption_system.lab import classic

    calls = []
    real = classic.chaos.logistic_sequence

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(classic.chaos, "logistic_sequence", counting)
    image = _random_image(5)
    cipher = make_cipher("logistic-xor", KEY)
    cipher.encrypt(image)
    cipher.decrypt(cipher.encrypt(image))
    assert len(calls) == 1
    make_cipher("logistic-xor", KEY).encrypt(image)
    assert len(calls) == 2
