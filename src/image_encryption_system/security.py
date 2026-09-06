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


class RequestThrottle:
    """Fixed-window throttle for surfaces outside the login flow.

    Reuses the ``login_guard`` table rather than introducing a second store, so
    counters survive a restart exactly as the login limiter's do. Each throttle
    gets its own ``kind`` so windows never share a bucket.

    The login limiter locks an *account* after repeated failures. This one only
    limits request rate against a caller-supplied key, because the endpoints it
    protects either have no account yet (registration) or would let an attacker
    lock out a victim by hammering their asset (decrypt, capability links).
    """

    def __init__(self, store: VaultStore, kind: str, *, limit: int, window_seconds: int) -> None:
        self.store = store
        self.kind = kind
        self.limit = limit
        self.window_seconds = window_seconds
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        """Record an attempt against ``key``. False once the window is full."""
        if self.limit <= 0:
            return True

        now = time()
        bucket = _normalize(key) or "-"
        with self._lock:
            cutoff = now - self.window_seconds
            self.store.login_guard_prune(self.kind, bucket, before=cutoff)
            recent = self.store.login_guard_stamps(self.kind, bucket, since=cutoff)
            if len(recent) >= self.limit:
                return False
            self.store.login_guard_add(self.kind, bucket, created_at=now)
        return True

    def reset(self, key: str) -> None:
        bucket = _normalize(key) or "-"
        with self._lock:
            self.store.login_guard_prune(self.kind, bucket, before=time() + 1)


class PasswordPolicyError(ValueError):
    """Raised when a chosen password does not meet the configured policy."""


def validate_password(password: str, *, username: str = "", min_length: int = 10) -> None:
    """Reject passwords that would undermine the vault they protect.

    The account password does more work here than in a typical application: it
    also wraps the user's RSA private key, so a weak choice weakens every image
    shared to that account, not just the session.

    The rules stay deliberately structural — length, some variety, and no reuse
    of the username or an obvious keyboard pattern. Anything stricter pushes
    people toward writing passwords down without measurably raising the bar.
    """
    if not isinstance(password, str) or not password:
        raise PasswordPolicyError("A password is required.")

    if len(password) < min_length:
        raise PasswordPolicyError(f"Password must be at least {min_length} characters.")

    if len(password.encode("utf-8")) > 1024:
        raise PasswordPolicyError("Password is too long.")

    normalized = password.strip().lower()

    if username and _normalize(username) and _normalize(username) in normalized:
        raise PasswordPolicyError("Password must not contain your username.")

    if len(set(password)) < 5:
        raise PasswordPolicyError("Password must use at least five different characters.")

    if normalized in _COMMON_PASSWORDS:
        raise PasswordPolicyError("That password is too common. Choose something else.")


# A short, deliberately non-exhaustive list. A real deployment should pair this
# with a breach-corpus check; the point here is to refuse the handful of choices
# that show up first in any credential-stuffing list.
_COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password123",
        "passw0rd123",
        "1234567890",
        "12345678901",
        "123456789012",
        "qwertyuiop",
        "qwerty12345",
        "letmein123",
        "iloveyou123",
        "administrator",
        "changeme123",
        "welcome123",
        "abc123456789",
        "trustno1234",
        "monkey123456",
        "dragon123456",
    }
)


def _normalize(username: str) -> str:
    return username.strip().lower()
