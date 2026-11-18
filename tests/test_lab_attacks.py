"""Real attacks on the lab ciphers.

Each attack sees only what an attacker would: the target ciphertext and an
encryption oracle under the same key (or, for the key-commitment attack, its
own two keys). Success means it recovered the exact target image, or exposed
the weakness it tests for.
"""

from __future__ import annotations

import numpy as np
import pytest

from image_encryption_system.lab import attacks, imaging
from image_encryption_system.lab.ciphers import CIPHER_NAMES, make_cipher

KEY = bytes(range(32))
SIZE = 64


@pytest.fixture(scope="module")
def target() -> np.ndarray:
    return imaging.sample("landscape", SIZE)


def _structure(name, image):
    cipher = make_cipher(name, KEY)
    return attacks.structure_attack(cipher, cipher.encrypt(image), truth=image)


@pytest.mark.parametrize(
    ("name", "queries"),
    [("arnold", 1), ("logistic-xor", 1), ("aes-ctr-fixed-iv", 1), ("wavelet", 3)],
)
def test_structure_attack_breaks(name, queries, target) -> None:
    result = _structure(name, target)
    assert result.applicable and result.success, result.finding
    assert result.queries == queries
    assert result.oracle_calls >= queries
    assert np.array_equal(result.recovered, target)


@pytest.mark.parametrize("name", ["hyperchaos", "neural", "aes-ecb", "aes-gcm", "aes-gcm-v4"])
def test_structure_attack_fails_on(name, target) -> None:
    result = _structure(name, target)
    assert result.applicable
    assert not result.success
    assert result.recovered is None or not np.array_equal(result.recovered, target)


@pytest.mark.parametrize("name", ["wht", "drpe"])
def test_structure_attack_needs_byte_ciphertexts(name, target) -> None:
    result = _structure(name, target)
    assert not result.applicable and not result.success


@pytest.mark.parametrize("name", ["wht", "drpe"])
def test_impulse_attack_breaks_linear_ciphers(name, target) -> None:
    cipher = make_cipher(name, KEY)
    result = attacks.impulse_attack(cipher, cipher.encrypt(target), truth=target)
    assert result.applicable and result.success, result.finding
    assert result.queries == 1
    assert np.array_equal(result.recovered, target)


def test_impulse_attack_only_applies_to_linear_ciphers(target) -> None:
    cipher = make_cipher("hyperchaos", KEY)
    result = attacks.impulse_attack(cipher, cipher.encrypt(target), truth=target)
    assert not result.applicable and not result.success


@pytest.mark.parametrize("name", CIPHER_NAMES)
def test_pattern_leak_flags_only_ecb_and_neural(name) -> None:
    probe = imaging.sample("test-card", SIZE)
    result = attacks.pattern_leak(make_cipher(name, KEY), probe)
    assert result.success == (name in {"aes-ecb", "neural"}), result.finding
    assert result.recovered is not None and result.recovered.shape == probe.shape


@pytest.mark.parametrize("name", CIPHER_NAMES)
def test_determinism_flags_every_cipher_but_gcm(name, target) -> None:
    result = attacks.determinism(make_cipher(name, KEY), target)
    assert result.success == (name not in {"aes-gcm", "aes-gcm-v4"})


@pytest.mark.parametrize("name", CIPHER_NAMES)
def test_tamper_is_refused_only_by_gcm(name, target) -> None:
    result = attacks.tamper(make_cipher(name, KEY), target)
    refused = name in {"aes-gcm", "aes-gcm-v4"}
    assert result.success == (not refused), result.finding
    if not refused:
        assert result.recovered is not None
        assert (result.recovered != target).any()


def test_salamander_succeeds_on_gcm_and_fails_on_v4(target) -> None:
    decoy = imaging.sample("gradient", SIZE)
    half = SIZE * SIZE * 3 // 2
    solved_block_start = half - 16

    plain = attacks.salamander("aes-gcm", target, decoy)
    assert plain.applicable and plain.success, plain.finding
    assert plain.recovered.tobytes()[:solved_block_start] == target.tobytes()[:solved_block_start]
    assert plain.extra.tobytes()[half:] == decoy.tobytes()[half:]
    assert not np.array_equal(plain.recovered, plain.extra)

    committed = attacks.salamander("aes-gcm-v4", target, decoy)
    assert committed.applicable and not committed.success
    assert "commitment" in committed.finding
    assert (
        committed.recovered.tobytes()[:solved_block_start] == target.tobytes()[:solved_block_start]
    )


@pytest.mark.parametrize("name", ["arnold", "hyperchaos", "wht", "neural", "aes-ecb"])
def test_salamander_does_not_apply_without_authentication(name, target) -> None:
    result = attacks.salamander(name, target, imaging.sample("gradient", SIZE))
    assert not result.applicable and not result.success
    assert "authentication" in result.finding


def test_run_attacks_reports_every_attack_in_order(target) -> None:
    results = attacks.run_attacks(
        make_cipher("arnold", KEY),
        target,
        probe=imaging.sample("test-card", SIZE),
        decoy=imaging.sample("gradient", SIZE),
    )
    assert [r.key for r in results] == list(attacks.ATTACKS)
    assert all(r.label and r.finding for r in results)
    assert results[0].success  # the structure attack breaks Arnold


def test_attacks_never_see_the_key(target, monkeypatch) -> None:
    # The structure attack may only call the cipher's encrypt (the oracle).
    cipher = make_cipher("logistic-xor", KEY)
    ciphertext = cipher.encrypt(target)

    def no_decrypt(*_args, **_kwargs):
        raise AssertionError("the attack called decrypt")

    monkeypatch.setattr(cipher, "decrypt", no_decrypt)
    del cipher.key
    assert attacks.structure_attack(cipher, ciphertext, truth=target).success
