from __future__ import annotations

from threading import Lock
from time import time
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .storage import VaultStore


class LoginGuard:
    """SQLite-backed login throttle and failed-attempt lockout."""

    def __init__(
        self,
        store: VaultStore,
        *,
        max_attempts: int = 5,
        window_seconds: int = 600,
        lockout_threshold: int = 8,
        lockout_seconds: int = 900,
    ) -> None:
        self.store = store
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_threshold = lockout_threshold
        self.lockout_seconds = lockout_seconds
        self._lock = Lock()

    def precheck(self, ip: str, username: str) -> str | None:
        """Return 'locked', 'rate_limited', or None if the attempt may proceed."""
        now = time()
        username = _normalize(username)
        ip = ip or ""
        with self._lock:
            locked_until = self.store.login_guard_locked_until(username)
            if locked_until is not None and now < locked_until:
                return "locked"
            if locked_until is not None and now >= locked_until:
                self.store.login_guard_clear_failures(username)

            cutoff = now - self.window_seconds
            self.store.login_guard_prune("attempt", username, ip=ip, before=cutoff)
            recent = self.store.login_guard_stamps("attempt", username, ip=ip, since=cutoff)
            if len(recent) >= self.max_attempts:
                return "rate_limited"
            self.store.login_guard_add("attempt", username, ip=ip, created_at=now)
        return None

    def record_failure(self, username: str) -> bool:
        """Record a failed password check. True if the account is now locked."""
        now = time()
        username = _normalize(username)
        with self._lock:
            window = max(self.lockout_seconds * 4, 3600)
            cutoff = now - window
            self.store.login_guard_prune("failure", username, before=cutoff)
            self.store.login_guard_add("failure", username, created_at=now)
            recent = self.store.login_guard_stamps("failure", username, since=cutoff)
            if len(recent) >= self.lockout_threshold:
                self.store.login_guard_set_lockout(username, now + self.lockout_seconds)
                return True
        return False

    def record_success(self, username: str) -> None:
        username = _normalize(username)
        with self._lock:
            self.store.login_guard_clear_failures(username)

    def is_locked(self, username: str) -> bool:
        username = _normalize(username)
        now = time()
        with self._lock:
            locked_until = self.store.login_guard_locked_until(username)
            return locked_until is not None and now < locked_until


def _normalize(username: str) -> str:
    return username.strip().lower()
