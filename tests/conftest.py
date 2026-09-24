import os

from hypothesis import HealthCheck, settings

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
