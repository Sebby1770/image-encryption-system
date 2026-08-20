from image_encryption_system.throttle import AttemptThrottle


def test_throttle_allows_then_blocks() -> None:
    throttle = AttemptThrottle(max_failures=2, window_seconds=60)
    assert throttle.check("ip|alice").allowed is True
    first = throttle.record_failure("ip|alice")
    assert first.allowed is True
    second = throttle.record_failure("ip|alice")
    assert second.allowed is False
    assert second.retry_after >= 1
    assert throttle.check("ip|alice").allowed is False


def test_success_clears_failures() -> None:
    throttle = AttemptThrottle(max_failures=2, window_seconds=60)
    throttle.record_failure("ip|bob")
    throttle.record_success("ip|bob")
    assert throttle.check("ip|bob").allowed is True
    assert throttle.check("ip|bob").remaining == 2
