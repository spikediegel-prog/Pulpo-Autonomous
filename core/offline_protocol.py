from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from .envelope import ExecutionEnvelope


class ConnectivityState(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    RECONNECTING = "reconnecting"
    RECONCILING = "reconciling"


class ExecutionState(str, Enum):
    PLANNED = "planned"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    OBSERVED_SUCCESS = "observed_success"
    OBSERVED_FAILURE = "observed_failure"
    UNKNOWN = "unknown"
    SAFE_FALLBACK = "safe_fallback"


@dataclass(frozen=True)
class OfflineMissionLease:
    """A bounded continuation window; it never creates or extends authority."""

    envelope: ExecutionEnvelope
    lease_id: str
    principal: str
    policy_id: str
    deployment_id: str
    session_id: str
    nonce: str
    max_disconnected: timedelta
    safe_fallback: str
    issued_at: datetime
    max_commands: int | None = None

    def __post_init__(self) -> None:
        if self.max_disconnected <= timedelta(0):
            raise ValueError("max_disconnected_must_be_positive")
        if not self.safe_fallback:
            raise ValueError("safe_fallback_required")
        if self.max_commands is not None and self.max_commands <= 0:
            raise ValueError("max_commands_must_be_positive")

    @classmethod
    def issue(
        cls,
        envelope: ExecutionEnvelope,
        *,
        lease_id: str,
        principal: str,
        policy_id: str,
        deployment_id: str,
        session_id: str,
        nonce: str,
        max_disconnected: timedelta,
        safe_fallback: str,
        issued_at: datetime | None = None,
        max_commands: int | None = None,
    ) -> "OfflineMissionLease":
        return cls(
            envelope=envelope,
            lease_id=lease_id,
            principal=principal,
            policy_id=policy_id,
            deployment_id=deployment_id,
            session_id=session_id,
            nonce=nonce,
            max_disconnected=max_disconnected,
            safe_fallback=safe_fallback,
            issued_at=issued_at or datetime.now(timezone.utc),
            max_commands=max_commands,
        )

    def active_at(self, now: datetime) -> bool:
        return self.envelope.is_active(now)

    def disconnected_until(self, disconnected_at: datetime) -> datetime:
        return disconnected_at + self.max_disconnected

    def allows_offline_at(self, disconnected_at: datetime, now: datetime) -> bool:
        if not self.active_at(now):
            return False
        return now <= self.disconnected_until(disconnected_at)

    def authority_binding(self) -> dict[str, Any]:
        return {
            "permit_id": self.envelope.permit_id,
            "lease_id": self.lease_id,
            "principal": self.principal,
            "policy_id": self.policy_id,
            "deployment_id": self.deployment_id,
            "session_id": self.session_id,
            "nonce": self.nonce,
        }


@dataclass
class OfflineProtocol:
    lease: OfflineMissionLease
    connectivity: ConnectivityState = ConnectivityState.CONNECTED
    disconnected_at: datetime | None = None

    def disconnect(self, now: datetime) -> None:
        if self.connectivity != ConnectivityState.CONNECTED:
            return
        self.connectivity = ConnectivityState.DISCONNECTED
        self.disconnected_at = now

    def reconnect(self) -> None:
        if self.connectivity == ConnectivityState.DISCONNECTED:
            self.connectivity = ConnectivityState.RECONNECTING

    def begin_reconciliation(self) -> None:
        if self.connectivity != ConnectivityState.RECONNECTING:
            raise ValueError("reconciliation_requires_reconnecting")
        self.connectivity = ConnectivityState.RECONCILING

    def finish_reconciliation(self) -> None:
        if self.connectivity != ConnectivityState.RECONCILING:
            raise ValueError("reconciliation_requires_reconciling")
        self.connectivity = ConnectivityState.CONNECTED
        self.disconnected_at = None

    def can_execute(self, now: datetime) -> bool:
        if self.connectivity == ConnectivityState.RECONCILING:
            return False
        if self.connectivity == ConnectivityState.DISCONNECTED:
            if self.disconnected_at is None:
                return False
            return self.lease.allows_offline_at(self.disconnected_at, now)
        return self.lease.active_at(now)

    def fallback_required(self, now: datetime) -> bool:
        return not self.can_execute(now)

    def can_fallback(self) -> bool:
        return self.connectivity != ConnectivityState.RECONCILING
