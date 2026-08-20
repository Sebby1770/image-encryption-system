from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
import time


@dataclass(frozen=True)
class ThrottleDecision:
    allowed: bool
    retry_after: int = 0
    remaining: int = 0


class AttemptThrottle:
    """In-memory sliding-window throttle for credential endpoints."""

    def __init__(self, max_failures: int = 5, window_seconds: int = 300):
        self.max_failures = max(1, max_failures)
        self.window_seconds = max(1, window_seconds)
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> ThrottleDecision:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            hits = self._failures[key]
            if len(hits) >= self.max_failures:
                retry_after = max(1, int(self.window_seconds - (now - hits[0])))
                return ThrottleDecision(allowed=False, retry_after=retry_after, remaining=0)
            return ThrottleDecision(
                allowed=True,
                remaining=self.max_failures - len(hits),
            )

    def record_failure(self, key: str) -> ThrottleDecision:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            self._failures[key].append(now)
            self._prune(key, now)
            hits = self._failures[key]
            remaining = max(0, self.max_failures - len(hits))
            if len(hits) >= self.max_failures:
                retry_after = max(1, int(self.window_seconds - (now - hits[0])))
                return ThrottleDecision(allowed=False, retry_after=retry_after, remaining=0)
            return ThrottleDecision(allowed=True, remaining=remaining)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def _prune(self, key: str, now: float) -> None:
        window_start = now - self.window_seconds
        hits = self._failures[key]
        while hits and hits[0] < window_start:
            hits.popleft()
        if not hits:
            self._failures.pop(key, None)
