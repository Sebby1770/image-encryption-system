import os

import pytest
from hypothesis import HealthCheck, settings

from image_encryption_system import crypto

# Scrypt makes each decryption take tens of milliseconds, so wall-clock
# deadlines would only produce flaky failures.
settings.register_profile(
    "default",
    deadline=None,
    max_examples=60,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
settings.register_profile(
    "ci",
    deadline=None,
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "default"))


@pytest.fixture(autouse=True)
def _fast_kdf(request, monkeypatch):
    """Run the suite at the cheapest accepted Scrypt cost.

    The production default (2^16) costs ~300 ms per derivation, and the suite
    wraps thousands of keys — the property tests alone wrap hundreds. The cost
    value changes no code path, only work, so tests run at the floor and a test
    marked ``production_kdf`` pins the real default instead.
    """
    if request.node.get_closest_marker("production_kdf") is None:
        monkeypatch.setattr(crypto, "SCRYPT_N", crypto.MIN_SCRYPT_N)
