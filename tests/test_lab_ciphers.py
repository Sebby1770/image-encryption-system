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


@pytest.mark.parametrize(("name", "bytes_per_value"), [("wht", 8), ("drpe", 16)])
def test_float_payload_sizes(name, bytes_per_value) -> None:
    ciphertext = make_cipher(name, KEY).encrypt(_random_image(6, 64))
    assert len(ciphertext.payload) == bytes_per_value * 3 * 64 * 64
    assert ciphertext.pixels is None


@pytest.mark.parametrize("name", ["wht", "drpe"])
def test_tampering_a_float_ciphertext_shows_in_the_image(name) -> None:
    image = _random_image(7)
    cipher = make_cipher(name, KEY)
    ciphertext = cipher.encrypt(image)
    index, mask = cipher.tamper_position(ciphertext)
    damaged = bytearray(ciphertext.payload)
    damaged[index] ^= mask
    opened = cipher.decrypt(Ciphertext(bytes(damaged), ciphertext.shape, None, ciphertext.view))
    assert opened.dtype == np.uint8
    assert (opened != image).any()


def test_neural_cipher_maps_equal_patches_equally() -> None:
    image = np.zeros((32, 32, 3), np.uint8)
    image[0:4, 0:4] = (10, 20, 30)
    image[8:12, 16:20] = (10, 20, 30)
    pixels = make_cipher("neural", KEY).encrypt(image).pixels
    assert np.array_equal(pixels[0:4, 0:4], pixels[8:12, 16:20])
    assert not np.array_equal(pixels[0:4, 0:4], pixels[4:8, 0:4])


def test_neural_cipher_mixes_within_a_patch() -> None:
    image = _random_image(8)
    nudged = image.copy()
    nudged[1, 1, 0] ^= 1
    cipher = make_cipher("neural", KEY)
    before, after = cipher.encrypt(image).pixels, cipher.encrypt(nudged).pixels
    changed = np.argwhere(np.any(before != after, axis=-1))
    assert changed.size and (changed < 4).all()  # only that 4x4 patch changes...
    assert np.sum(before[:4, :4] != after[:4, :4]) > 24  # ...but most of it does


def test_every_registered_name_is_implemented() -> None:
    assert IMPLEMENTED == CIPHER_NAMES


def test_aes_ecb_matches_cryptography() -> None:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from image_encryption_system.lab import keys

    image = _random_image(9)
    encryptor = Cipher(algorithms.AES(keys.derive(KEY, "aes-ecb", 32)), modes.ECB()).encryptor()
    expected = encryptor.update(image.tobytes()) + encryptor.finalize()
    assert make_cipher("aes-ecb", KEY).encrypt(image).payload == expected


def test_ctr_reuses_its_iv_for_every_image() -> None:
    cipher = make_cipher("aes-ctr-fixed-iv", KEY)
    a, b = _random_image(10), _random_image(11)
    stream_a = np.frombuffer(cipher.encrypt(a).payload, np.uint8) ^ a.ravel()
    stream_b = np.frombuffer(cipher.encrypt(b).payload, np.uint8) ^ b.ravel()
    assert np.array_equal(stream_a, stream_b)


@pytest.mark.parametrize(("name", "overhead"), [("aes-gcm", 12 + 16), ("aes-gcm-v4", 12 + 32 + 16)])
def test_gcm_payload_layouts(name, overhead) -> None:
    image = _random_image(12, 64)
    cipher = make_cipher(name, KEY)
    first, second = cipher.encrypt(image), cipher.encrypt(image)
    assert len(first.payload) == 3 * 64 * 64 + overhead
    assert first.payload != second.payload  # a fresh nonce every time
    assert cipher.randomized and cipher.authenticated
    fixed = cipher.encrypt(image, nonce=bytes(12))
    assert fixed.payload == cipher.encrypt(image, nonce=bytes(12)).payload


@pytest.mark.parametrize("name", ["aes-gcm", "aes-gcm-v4"])
def test_gcm_ciphers_refuse_any_tampering(name) -> None:
    image = _random_image(13)
    cipher = make_cipher(name, KEY)
    ciphertext = cipher.encrypt(image)
    for index in (0, 13, len(ciphertext.payload) // 2, len(ciphertext.payload) - 1):
        damaged = bytearray(ciphertext.payload)
        damaged[index] ^= 0x01
        with pytest.raises(LabDecryptError):
            cipher.decrypt(Ciphertext(bytes(damaged), ciphertext.shape, None, ciphertext.view))


def test_v4_lab_cipher_uses_the_vault_construction() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from image_encryption_system.crypto import derive_v4_keys
    from image_encryption_system.lab import keys

    image = _random_image(14)
    cipher = make_cipher("aes-gcm-v4", KEY)
    payload = cipher.encrypt(image).payload
    nonce, commitment, sealed = payload[:12], payload[12:44], payload[44:]
    data_key = keys.derive(KEY, "aes-gcm-v4", 32)
    image_key, expected_commitment = derive_v4_keys(data_key, nonce, cipher.AAD)
    assert commitment == expected_commitment
    assert AESGCM(image_key).decrypt(nonce, sealed, cipher.AAD) == image.tobytes()
    assert cipher.gcm_key_for(nonce) == image_key
    assert cipher.pack(nonce, sealed) == payload
