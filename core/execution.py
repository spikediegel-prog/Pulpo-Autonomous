from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .journal import DurableJournal
from .offline_protocol import ExecutionState, OfflineProtocol


@dataclass
class ExecutionTracker:
    protocol: OfflineProtocol
    journal: DurableJournal

    def plan(self, command_id: str, action: str, now: str) -> ExecutionState:
        self.journal.append(
            "planned",
            {"command_id": command_id, "action": action, "at": now},
        )
        return ExecutionState.PLANNED

    def send(self, command_id: str, now: str) -> ExecutionState:
        if not self.protocol.can_execute(_parse_time(now)):
            self.journal.append("vetoed", {"command_id": command_id, "at": now})
            raise PermissionError("offline_authority_unavailable")
        self.journal.append("sent", {"command_id": command_id, "at": now})
        return ExecutionState.SENT

    def execute(self, command_id: str, action: str, now: str) -> ExecutionState:
        existing = self._existing_state(command_id)
        if existing is not None:
            return existing
        if action != self.protocol.lease.envelope.action:
            self.journal.append(
                "vetoed",
                {"command_id": command_id, "reason": "action_outside_lease", "at": now},
            )
            raise PermissionError("offline_action_not_authorized")
        if not self.protocol.can_execute(_parse_time(now)):
            return self.run_safe_fallback(now)
        if self._command_count() >= (self.protocol.lease.max_commands or float("inf")):
            return self.run_safe_fallback(now)
        self.plan(command_id, action, now)
        return self.send(command_id, now)

    def run_safe_fallback(self, now: str) -> ExecutionState:
        if not self.protocol.can_fallback():
            raise PermissionError("safe_fallback_blocked_during_reconciliation")
        self.journal.append(
            "safe_fallback",
            {"fallback": self.protocol.lease.safe_fallback, "at": now},
        )
        return ExecutionState.SAFE_FALLBACK

    def observe(self, command_id: str, state: ExecutionState, now: str) -> ExecutionState:
        if state not in {
            ExecutionState.OBSERVED_SUCCESS,
            ExecutionState.OBSERVED_FAILURE,
            ExecutionState.UNKNOWN,
        }:
            raise ValueError("observation_state_required")
        self.journal.append(
            state.value,
            {"command_id": command_id, "at": now},
        )
        return state

    def _command_count(self) -> int:
        return len(
            {
                record.payload["command_id"]
                for record in self.journal.read()
                if record.event == "sent"
            }
        )

    def _existing_state(self, command_id: str) -> ExecutionState | None:
        state_by_event = {
            "planned": ExecutionState.PLANNED,
            "sent": ExecutionState.SENT,
            "observed_success": ExecutionState.OBSERVED_SUCCESS,
            "observed_failure": ExecutionState.OBSERVED_FAILURE,
            "unknown": ExecutionState.UNKNOWN,
        }
        matching = [
            record
            for record in self.journal.read()
            if record.payload.get("command_id") == command_id
            and record.event in state_by_event
        ]
        return state_by_event[matching[-1].event] if matching else None


def _parse_time(value: str):
    return datetime.fromisoformat(value)
