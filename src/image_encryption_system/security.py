from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import monotonic


class LoginGuard:
    """In-memory login throttle and failed-attempt lockout."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window_seconds: int = 600,
        lockout_threshold: int = 8,
        lockout_seconds: int = 900,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_threshold = lockout_threshold
        self.lockout_seconds = lockout_seconds
        self._attempts: dict[tuple[str, str], list[float]] = defaultdict(list)
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}
        self._lock = Lock()

    def precheck(self, ip: str, username: str) -> str | None:
        """Return 'locked', 'rate_limited', or None if the attempt may proceed."""
        now = monotonic()
        username = _normalize(username)
        ip = ip or ""
        with self._lock:
            locked_until = self._lockouts.get(username)
            if locked_until is not None and now < locked_until:
                return "locked"
            if locked_until is not None and now >= locked_until:
                self._lockouts.pop(username, None)
                self._failures.pop(username, None)

            key = (ip, username)
            cutoff = now - self.window_seconds
            recent = [stamp for stamp in self._attempts[key] if stamp > cutoff]
            if len(recent) >= self.max_attempts:
                self._attempts[key] = recent
                return "rate_limited"
            recent.append(now)
            self._attempts[key] = recent
        return None

    def record_failure(self, username: str) -> bool:
        """Record a failed password check. True if the account is now locked."""
        now = monotonic()
        username = _normalize(username)
        with self._lock:
            window = max(self.lockout_seconds * 4, 3600)
            recent = [stamp for stamp in self._failures[username] if stamp > now - window]
            recent.append(now)
            self._failures[username] = recent
            if len(recent) >= self.lockout_threshold:
                self._lockouts[username] = now + self.lockout_seconds
                return True
        return False

    def record_success(self, username: str) -> None:
        username = _normalize(username)
        with self._lock:
            self._failures.pop(username, None)
            self._lockouts.pop(username, None)

    def is_locked(self, username: str) -> bool:
        username = _normalize(username)
        now = monotonic()
        with self._lock:
            locked_until = self._lockouts.get(username)
            return locked_until is not None and now < locked_until


def _normalize(username: str) -> str:
    return username.strip().lower()
