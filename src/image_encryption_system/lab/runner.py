"""Run the whole lab on one image: every cipher, scored and attacked.

The verdict comes from the attacks, never from the statistics: a cipher that
passes every statistical row can still be broken, and each row is a 5% test
that a strong cipher fails now and then by chance.

1. **Broken**: the structure or impulse attack recovered the image.
2. **Leaks**: it acts as a codebook, encrypts the same image the same way
   twice, or decrypts a tampered ciphertext without noticing.
3. **Strong, not key-committing**: only the two-key forgery succeeded.
4. **Strong + committing**: nothing here worked.
"""

from __future__ import annotations

import math
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np

from .attacks import AttackResult, run_attacks
from .base import Image, check_image
from .ciphers import CIPHER_NAMES, make_cipher
from .imaging import data_uri, sample, to_jpeg, to_png
from .metrics import MetricResult, score

BROKEN, LEAKS = "Broken", "Leaks"
STRONG, COMMITTING = "Strong, not key-committing", "Strong + committing"
_SLUGS = {BROKEN: "broken", LEAKS: "leaks", STRONG: "strong", COMMITTING: "committing"}
_STATISTICS = (
    "entropy",
    "local_entropy",
    "chi_square",
    "correlation",
    "npcr_uaci",
    "key_sensitivity",
)
_OUTCOMES = {
    "structure": ("Broken", "Resisted"),
    "impulse": ("Broken", "Resisted"),
    "pattern": ("Leaks", "No codebook"),
    "determinism": ("Leaks", "Randomised"),
    "tamper": ("Undetected", "Refused"),
    "salamander": ("Forged", "Defeated"),
}


@dataclass
class CipherResult:
    name: str
    title: str
    family: str
    summary: str
    key_bits: int
    key_note: str
    randomized: bool
    authenticated: bool
    metrics: list[MetricResult]
    attacks: list[AttackResult]
    verdict: str
    seconds: float
    images: dict[str, tuple[bytes, str]] = field(default_factory=dict)
    histogram: list[float] = field(default_factory=list)


@dataclass
class LabReport:
    size: int
    source: str
    plaintext_png: bytes
    plaintext_histogram: list[float]
    results: list[CipherResult]
    created: str

    def to_dict(self) -> dict[str, Any]:
        """Everything in the report, JSON-safe: images as data URIs, no NaN or infinity."""
        return {
            "size": self.size,
            "source": self.source,
            "created": self.created,
            "plaintext": data_uri(self.plaintext_png, "image/png"),
            "plaintext_histogram": self.plaintext_histogram,
            "results": [_result_dict(result) for result in self.results],
        }


def _attack(result: CipherResult, key: str) -> AttackResult:
    return next(attack for attack in result.attacks if attack.key == key)


def verdict(result: CipherResult) -> str:
    succeeded = {attack.key for attack in result.attacks if attack.success}
    if succeeded & {"structure", "impulse"}:
        return BROKEN
    if succeeded & {"pattern", "determinism", "tamper"}:
        return LEAKS
    if "salamander" in succeeded:
        return STRONG
    return COMMITTING


def _headline(result: CipherResult) -> str:
    """The finding that decided the verdict."""
    order = {
        BROKEN: ("structure", "impulse"),
        LEAKS: ("pattern", "tamper", "determinism"),
        STRONG: ("salamander",),
        COMMITTING: ("salamander", "tamper"),
    }[result.verdict]
    for key in order:
        attack = _attack(result, key)
        if attack.success or result.verdict == COMMITTING:
            return attack.finding
    return ""


def _safe(value: float | None) -> float | None:
    if value is None or not math.isfinite(value):
        return None
    return float(value)


def _display(metric: MetricResult) -> str:
    value = metric.value
    if metric.key == "round_trip":
        return "exact" if metric.passed else "mismatch"
    if value is None:
        return "n/a"
    if metric.key in {"npcr_uaci", "key_sensitivity"}:
        return f"{value:.4f}% / {metric.extra['uaci']:.4f}%"
    if metric.key == "speed":
        return f"{value:,.1f} MB/s" if math.isfinite(value) else "instant"
    if metric.key == "expansion":
        return f"{value:.2f}x"
    if metric.key == "chi_square":
        return f"{value:,.1f}"
    if metric.key == "local_entropy":
        return f"{value:.5f}"
    return f"{value:.4f}"


def _mark(passed: bool | None) -> str:
    return "pass" if passed is True else "fail" if passed is False else "info"


def _result_dict(result: CipherResult) -> dict[str, Any]:
    judged = [m for m in result.metrics if m.key in _STATISTICS and m.passed is not None]
    return {
        "name": result.name,
        "title": result.title,
        "family": result.family,
        "summary": result.summary,
        "key_bits": result.key_bits,
        "key_note": result.key_note,
        "randomized": result.randomized,
        "authenticated": result.authenticated,
        "verdict": result.verdict,
        "verdict_slug": _SLUGS[result.verdict],
        "headline": _headline(result),
        "statistics": {"passed": sum(1 for m in judged if m.passed), "judged": len(judged)},
        "seconds": _safe(result.seconds),
        "histogram": result.histogram,
        "metrics": [
            {
                "key": m.key,
                "label": m.label,
                "value": _safe(m.value),
                "per_channel": [_safe(v) for v in m.per_channel],
                "passed": m.passed,
                "mark": _mark(m.passed),
                "display": _display(m),
                "detail": m.detail,
                "extra": {k: _safe(v) for k, v in m.extra.items()},
            }
            for m in result.metrics
        ],
        "attacks": [
            {
                "key": a.key,
                "label": a.label,
                "applicable": a.applicable,
                "success": a.success,
                "outcome": "n/a" if not a.applicable else _OUTCOMES[a.key][0 if a.success else 1],
                "queries": a.queries,
                "oracle_calls": a.oracle_calls,
                "finding": a.finding,
            }
            for a in result.attacks
        ],
        "images": {name: data_uri(data, mime) for name, (data, mime) in result.images.items()},
    }


def _histogram(image: Image) -> list[float]:
    counts = np.bincount(image.ravel(), minlength=256).reshape(64, 4).sum(axis=1)
    peak = max(int(np.max(counts)), 1)
    return [round(float(c) / peak, 4) for c in counts]


def _evidence(attacks: list[AttackResult]) -> dict[str, tuple[bytes, str]]:
    images: dict[str, tuple[bytes, str]] = {}
    for attack in attacks:
        if attack.key == "tamper" and attack.recovered is not None:
            images["tampered"] = (to_jpeg(attack.recovered), "image/jpeg")
        elif attack.key == "pattern" and attack.success and attack.recovered is not None:
            images["pattern"] = (to_jpeg(attack.recovered), "image/jpeg")
        elif attack.key == "salamander" and attack.recovered is not None:
            images["salamander-1"] = (to_jpeg(attack.recovered), "image/jpeg")
            if attack.extra is not None:
                images["salamander-2"] = (to_jpeg(attack.extra), "image/jpeg")
    return images


def run_lab(
    image: Image,
    *,
    ciphers: Sequence[str] | None = None,
    key: bytes | None = None,
    source: str = "custom",
) -> LabReport:
    """Encrypt, score and attack ``image`` with each cipher (all eleven by default)."""
    size = check_image(image)
    names = list(CIPHER_NAMES if ciphers is None else ciphers)
    if not names:
        raise ValueError("Choose at least one cipher.")
    unknown = [name for name in names if name not in CIPHER_NAMES]
    if unknown:
        raise ValueError(f"Unknown lab cipher: {', '.join(unknown)}.")
    key = os.urandom(32) if key is None else key
    probe, decoy = sample("test-card", size), sample("gradient", size)

    results = []
    for name in CIPHER_NAMES:
        if name not in names:
            continue
        cipher = make_cipher(name, key)
        started = time.perf_counter()
        ciphertext = cipher.encrypt(image)
        seconds = max(time.perf_counter() - started, 1e-9)
        attacks = run_attacks(cipher, image, probe=probe, decoy=decoy)
        result = CipherResult(
            name=cipher.name,
            title=cipher.title,
            family=cipher.family,
            summary=cipher.summary,
            key_bits=cipher.key_bits,
            key_note=cipher.key_note,
            randomized=cipher.randomized,
            authenticated=cipher.authenticated,
            metrics=score(cipher, image, ciphertext, key=key, seconds=seconds),
            attacks=attacks,
            verdict="",
            seconds=seconds,
            images={"cipher": (to_jpeg(ciphertext.view), "image/jpeg"), **_evidence(attacks)},
            histogram=_histogram(ciphertext.view),
        )
        result.verdict = verdict(result)
        results.append(result)

    return LabReport(
        size=size,
        source=source,
        plaintext_png=to_png(image),
        plaintext_histogram=_histogram(image),
        results=results,
        created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
