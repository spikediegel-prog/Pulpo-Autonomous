"""Passive command intake using the existing opaque-byte traffic router.

READY is transport delivery, never command authority. No executor, callback,
permit, protocol, journal, network, or canonical writer is retained here.
"""
from dataclasses import dataclass
import json
from threading import Lock


@dataclass(frozen=True, slots=True)
class CommandTrafficSettings:
    max_items: int = 128
    max_bytes: int = 1_048_576
    max_command_bytes: int = 65_536
    ttl_ns: int = 30_000_000_000

    def __post_init__(self):
        for name in ("max_items", "max_bytes", "max_command_bytes", "ttl_ns"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_command_bytes > self.max_bytes:
            raise ValueError("command must fit the queue byte budget")


class CommandTrafficRejected(RuntimeError):
    """Terminal transport rejection; do not convert it into retry authority."""
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason
        super().__init__(f"{status}:{reason}")


class CommandTrafficIntake:
    __slots__ = ("settings", "_router", "_lock")

    def __init__(self, settings):
        if type(settings) is not CommandTrafficSettings:
            raise ValueError("trusted CommandTrafficSettings required")
        # Reuse the previously built passive router; never vendor a second copy.
        from sentry_traffic import RouterConfig, TrafficRouter
        self.settings = settings
        self._router = TrafficRouter(RouterConfig(
            max_items=settings.max_items, max_bytes=settings.max_bytes,
            max_item_bytes=settings.max_command_bytes, ttl_ns=settings.ttl_ns,
            batch_size=1, deduplicate_pending=False, prioritize=False,
        ))
        self._lock = Lock()

    def check(self, command_id, action, now):
        values = (command_id, action, now)
        if any(type(value) is not str for value in values):
            raise CommandTrafficRejected("REJECT", "malformed_transport_input")
        # Bound allocation before serialization; encoded bytes are checked again.
        if sum(len(value) for value in values) > self.settings.max_command_bytes:
            raise CommandTrafficRejected("REJECT", "item_budget_exhausted")
        if not self._lock.acquire(blocking=False):
            raise CommandTrafficRejected("REJECT", "traffic_busy")
        try:
            try:
                body = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except UnicodeError as exc:
                raise CommandTrafficRejected("REJECT", "malformed_transport_input") from exc
            admission = self._router.submit(body)
            if admission.status != "QUEUED":
                raise CommandTrafficRejected(admission.status, admission.reason)
            batch = self._router.drain()
            if not batch.ready:
                raise CommandTrafficRejected("DROP", "ttl_budget_exhausted")
            if len(batch.ready) != 1 or batch.ready[0] is not body or batch.ready[0] != body:
                raise CommandTrafficRejected("REJECT", "transport_identity_mismatch")
        except CommandTrafficRejected:
            raise
        except Exception as exc:
            raise CommandTrafficRejected("REJECT", "traffic_unavailable") from exc
        finally:
            self._lock.release()
        # Never decode routed data into a new command or return an authorization.
        # The existing owner continues with its original arguments exactly once.

    def snapshot(self):
        with self._lock:
            return self._router.snapshot()
