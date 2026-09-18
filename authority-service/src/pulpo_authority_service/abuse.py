from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import threading
import time
from typing import Callable


class AbuseLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("abuse limit exceeded")
        self.retry_after = max(1, retry_after)


@dataclass(frozen=True)
class AbuseLimits:
    request_limit: int = 60
    request_window_seconds: float = 60.0
    failure_limit: int = 5
    failure_window_seconds: float = 300.0
    lockout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if (
            self.request_limit <= 0
            or self.request_window_seconds <= 0
            or self.failure_limit <= 0
            or self.failure_window_seconds <= 0
            or self.lockout_seconds <= 0
        ):
            raise ValueError("abuse limits must be positive")


class InMemoryAbuseGuard:
    """Bounded per-process abuse control for the public authority HTTP surface.

    Production deployments with multiple replicas must enforce equivalent
    limits at a shared gateway or shared state layer; this guard is not a
    distributed rate limiter.
    """

    def __init__(
        self,
        limits: AbuseLimits | None = None,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.limits = limits or AbuseLimits()
        self._clock = clock or time.monotonic
        self._requests: dict[str, deque[float]] = {}
        self._failures: dict[str, deque[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.RLock()

    def check_request(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            self._prune(self._requests, key, now, self.limits.request_window_seconds)
            bucket = self._requests.setdefault(key, deque())
            if len(bucket) >= self.limits.request_limit:
                raise AbuseLimitExceeded(self._retry_after(bucket[0], now, self.limits.request_window_seconds))
            bucket.append(now)

    def check_failure_lockout(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            blocked_until = self._blocked_until.get(key, 0.0)
            if blocked_until > now:
                raise AbuseLimitExceeded(int(blocked_until - now + 0.999))
            if blocked_until:
                self._blocked_until.pop(key, None)

    def record_failure(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            self._prune(self._failures, key, now, self.limits.failure_window_seconds)
            bucket = self._failures.setdefault(key, deque())
            bucket.append(now)
            if len(bucket) >= self.limits.failure_limit:
                self._blocked_until[key] = now + self.limits.lockout_seconds
                bucket.clear()

    def clear_failures(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)

    @staticmethod
    def _prune(
        buckets: dict[str, deque[float]],
        key: str,
        now: float,
        window: float,
    ) -> None:
        bucket = buckets.setdefault(key, deque())
        cutoff = now - window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    @staticmethod
    def _retry_after(oldest: float, now: float, window: float) -> int:
        return max(1, int(oldest + window - now + 0.999))
