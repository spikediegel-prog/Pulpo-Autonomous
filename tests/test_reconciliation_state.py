"""Reconciliation-state exposure (Control Center design v0, item 5.5).

The snapshot must report whether a reconciliation is in progress, for
how long, and when the last one completed -- and it must never display
"reconciling" unless a source actually reports it. The only source in
this tree is the deployment's own ``OfflineProtocol``: it is the one
component that runs reconciliation, so the freeze reads its
timestamps, and anything unreported stays "unknown".

Adversarial note: a snapshot that claims "reconciling" on a guess, or
a future-dated claim from a clock that disagrees with the freeze
clock, is the failure this contract exists to prevent (design section
3). Every test below that tampers with the reported state asserts the
snapshot refuses it or reports Unknown.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import ExecutionEnvelope, OfflineMissionLease, OfflineProtocol
from core.offline_protocol import ConnectivityState
from pulpo import GovernanceKernel, Policy, PulpoOrchestrator
from pulpo.observer_snapshot import (
    export_observer_snapshot,
    freeze_observer_snapshot,
    load_observer_snapshot,
)
from pulpo.state import InMemoryKernelState

KERNEL_SECRET = "test-kernel-secret".encode("utf-8")
START = datetime(2030, 1, 1, tzinfo=timezone.utc)
# Fixed freeze clock: 2030-01-01 00:30 UTC, halfway through the test
# lease's envelope window (issued 00:00, expires 02:00).
CLOCK_NS = int(datetime(2030, 1, 1, 0, 30, tzinfo=timezone.utc).timestamp() * 1_000_000_000)


def _ns(moment: datetime) -> int:
    return int(moment.timestamp() * 1_000_000_000)


def _kernel():
    kernel = GovernanceKernel(
        Policy(frozenset({"read"}), 0),
        secret=KERNEL_SECRET,
        state=InMemoryKernelState(),
        clock=lambda: 2_000_000,
    )
    return PulpoOrchestrator(kernel)


def _lease(*, deployment_id: str = "deployment-1", lease_id: str = "lease-1"):
    envelope = ExecutionEnvelope(
        permit_id="permit-1",
        action="observe",
        target="unit-1",
        machine_id="unit-1",
        domain="robotics",
        issued_at=START,
        expires_at=START + timedelta(hours=2),
    )
    return OfflineMissionLease.issue(
        envelope,
        lease_id=lease_id,
        principal="operator-1",
        policy_id="policy-1",
        deployment_id=deployment_id,
        session_id="session-1",
        nonce="nonce-1",
        max_disconnected=timedelta(hours=1),
        safe_fallback="fans_on",
        issued_at=START,
        max_commands=3,
    )


def _reconciling_protocol(lease, *, since: datetime) -> OfflineProtocol:
    """Drive a protocol to RECONCILING at an explicit time."""
    protocol = OfflineProtocol(lease)
    protocol.disconnect(START)
    protocol.reconnect()
    protocol.begin_reconciliation(since)
    return protocol


def _completed_protocol(lease, *, since: datetime, until: datetime) -> OfflineProtocol:
    """Drive a protocol through one full reconciliation cycle."""
    protocol = _reconciling_protocol(lease, since=since)
    protocol.finish_reconciliation(until)
    return protocol


class ReconciliationProtocolTests(unittest.TestCase):
    def test_begin_records_start_and_finish_records_completion(self):
        lease = _lease()
        protocol = OfflineProtocol(lease)
        began = START + timedelta(minutes=5)
        finished = START + timedelta(minutes=12)
        protocol.disconnect(START)
        protocol.reconnect()
        protocol.begin_reconciliation(began)
        self.assertEqual(protocol.connectivity, ConnectivityState.RECONCILING)
        self.assertEqual(protocol.reconciling_since, began)
        self.assertIsNone(protocol.last_reconciliation_completed_at)
        protocol.finish_reconciliation(finished)
        self.assertEqual(protocol.connectivity, ConnectivityState.CONNECTED)
        self.assertIsNone(protocol.reconciling_since)
        self.assertEqual(protocol.last_reconciliation_completed_at, finished)
        self.assertIsNone(protocol.disconnected_at)

    def test_begin_and_finish_default_to_utc_now(self):
        lease = _lease()
        protocol = OfflineProtocol(lease)
        protocol.disconnect(START)
        protocol.reconnect()
        protocol.begin_reconciliation()
        self.assertIsNotNone(protocol.reconciling_since)
        self.assertIsNotNone(protocol.reconciling_since.tzinfo)
        protocol.finish_reconciliation()
        self.assertIsNotNone(protocol.last_reconciliation_completed_at)
        self.assertIsNone(protocol.reconciling_since)

    def test_begin_requires_reconnecting_and_finish_requires_reconciling(self):
        protocol = OfflineProtocol(_lease())
        with self.assertRaises(ValueError):
            protocol.begin_reconciliation(START)
        protocol.disconnect(START)
        with self.assertRaises(ValueError):
            protocol.finish_reconciliation(START)

    def test_execution_is_blocked_while_reconciling(self):
        protocol = _reconciling_protocol(_lease(), since=START + timedelta(minutes=5))
        now = START + timedelta(minutes=6)
        self.assertFalse(protocol.can_execute(now))
        self.assertTrue(protocol.fallback_required(now))
        self.assertFalse(protocol.can_fallback())


class ReconciliationSnapshotTests(unittest.TestCase):
    def _freeze(self, orchestrator, **kwargs):
        return freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS, **kwargs)

    def test_no_protocol_reports_unknown_even_with_a_lease(self):
        orchestrator = _kernel()
        snapshot = self._freeze(orchestrator, leases=[_lease()])
        self.assertEqual(snapshot.deployment_id, "deployment-1")
        self.assertEqual(snapshot.reconciliation_state, "unknown")
        self.assertIsNone(snapshot.reconciliation_since_ns)
        self.assertIsNone(snapshot.last_reconciliation_completed_ns)

    def test_idle_protocol_reports_idle_with_no_completion(self):
        orchestrator = _kernel()
        protocol = OfflineProtocol(_lease())
        snapshot = self._freeze(
            orchestrator, leases=[protocol.lease], protocols=[protocol]
        )
        self.assertEqual(snapshot.reconciliation_state, "idle")
        self.assertIsNone(snapshot.reconciliation_since_ns)
        self.assertIsNone(snapshot.last_reconciliation_completed_ns)

    def test_completed_reconciliation_reports_last_completed(self):
        orchestrator = _kernel()
        began = START + timedelta(minutes=5)
        finished = START + timedelta(minutes=12)
        protocol = _completed_protocol(_lease(), since=began, until=finished)
        snapshot = self._freeze(
            orchestrator, leases=[protocol.lease], protocols=[protocol]
        )
        self.assertEqual(snapshot.reconciliation_state, "idle")
        self.assertIsNone(snapshot.reconciliation_since_ns)
        self.assertEqual(snapshot.last_reconciliation_completed_ns, _ns(finished))

    def test_reconciling_protocol_reports_state_and_since(self):
        orchestrator = _kernel()
        began = START + timedelta(minutes=5)
        protocol = _reconciling_protocol(_lease(), since=began)
        snapshot = self._freeze(
            orchestrator, leases=[protocol.lease], protocols=[protocol]
        )
        self.assertEqual(snapshot.reconciliation_state, "reconciling")
        self.assertEqual(snapshot.reconciliation_since_ns, _ns(began))
        # "For how long" is measured from the start to the freeze.
        self.assertEqual(
            snapshot.frozen_at_ns - snapshot.reconciliation_since_ns,
            _ns(START + timedelta(minutes=30)) - _ns(began),
        )
        self.assertIsNone(snapshot.last_reconciliation_completed_ns)

    def test_second_reconciliation_keeps_first_completion(self):
        orchestrator = _kernel()
        protocol = _completed_protocol(
            _lease(),
            since=START + timedelta(minutes=5),
            until=START + timedelta(minutes=12),
        )
        protocol.disconnect(START + timedelta(minutes=15))
        protocol.reconnect()
        protocol.begin_reconciliation(START + timedelta(minutes=16))
        snapshot = self._freeze(
            orchestrator, leases=[protocol.lease], protocols=[protocol]
        )
        self.assertEqual(snapshot.reconciliation_state, "reconciling")
        self.assertEqual(
            snapshot.reconciliation_since_ns, _ns(START + timedelta(minutes=16))
        )
        self.assertEqual(
            snapshot.last_reconciliation_completed_ns,
            _ns(START + timedelta(minutes=12)),
        )

    def test_earliest_start_wins_across_protocols(self):
        orchestrator = _kernel()
        early = _reconciling_protocol(
            _lease(lease_id="lease-early"), since=START + timedelta(minutes=5)
        )
        late = _reconciling_protocol(
            _lease(lease_id="lease-late"), since=START + timedelta(minutes=10)
        )
        snapshot = self._freeze(
            orchestrator,
            leases=[early.lease, late.lease],
            protocols=[late, early],
        )
        self.assertEqual(snapshot.reconciliation_state, "reconciling")
        self.assertEqual(
            snapshot.reconciliation_since_ns, _ns(START + timedelta(minutes=5))
        )

    def test_latest_completion_wins_across_protocols(self):
        orchestrator = _kernel()
        first = _completed_protocol(
            _lease(lease_id="lease-first"),
            since=START + timedelta(minutes=5),
            until=START + timedelta(minutes=12),
        )
        second = _completed_protocol(
            _lease(lease_id="lease-second"),
            since=START + timedelta(minutes=15),
            until=START + timedelta(minutes=20),
        )
        snapshot = self._freeze(
            orchestrator,
            leases=[first.lease, second.lease],
            protocols=[first, second],
        )
        self.assertEqual(snapshot.reconciliation_state, "idle")
        self.assertEqual(
            snapshot.last_reconciliation_completed_ns,
            _ns(START + timedelta(minutes=20)),
        )

    def test_protocols_for_other_deployments_are_ignored(self):
        orchestrator = _kernel()
        other = _reconciling_protocol(
            _lease(deployment_id="deployment-2", lease_id="lease-2"),
            since=START + timedelta(minutes=5),
        )
        snapshot = self._freeze(
            orchestrator, leases=[_lease()], protocols=[other]
        )
        self.assertEqual(snapshot.deployment_id, "deployment-1")
        self.assertEqual(snapshot.reconciliation_state, "unknown")
        self.assertIsNone(snapshot.reconciliation_since_ns)
        self.assertIsNone(snapshot.last_reconciliation_completed_ns)

    def test_reconciling_without_a_start_is_rejected(self):
        orchestrator = _kernel()
        protocol = OfflineProtocol(
            _lease(), connectivity=ConnectivityState.RECONCILING
        )
        with self.assertRaises(ValueError):
            self._freeze(
                orchestrator, leases=[protocol.lease], protocols=[protocol]
            )

    def test_future_dated_reconciliation_is_rejected(self):
        orchestrator = _kernel()
        # Reconciliation began after the freeze clock: the deployment's
        # clock and the freeze clock disagree; fail closed.
        future = _reconciling_protocol(
            _lease(), since=START + timedelta(minutes=45)
        )
        with self.assertRaises(ValueError):
            self._freeze(
                orchestrator, leases=[future.lease], protocols=[future]
            )
        completed_late = _completed_protocol(
            _lease(),
            since=START + timedelta(minutes=5),
            until=START + timedelta(minutes=45),
        )
        with self.assertRaises(ValueError):
            self._freeze(
                orchestrator,
                leases=[completed_late.lease],
                protocols=[completed_late],
            )

    def test_snapshot_validation_rejects_contradictory_states(self):
        orchestrator = _kernel()
        snapshot = self._freeze(orchestrator)
        with self.assertRaises(ValueError):
            replace(snapshot, reconciliation_state="reconciling")
        with self.assertRaises(ValueError):
            replace(snapshot, reconciliation_state="idle", reconciliation_since_ns=CLOCK_NS)
        with self.assertRaises(ValueError):
            replace(
                snapshot,
                reconciliation_state="unknown",
                reconciliation_since_ns=CLOCK_NS,
            )
        with self.assertRaises(ValueError):
            replace(
                snapshot,
                reconciliation_state="reconciling",
                reconciliation_since_ns=CLOCK_NS + 1,
            )
        with self.assertRaises(ValueError):
            replace(
                snapshot,
                last_reconciliation_completed_ns=CLOCK_NS + 1,
            )
        with self.assertRaises(ValueError):
            replace(snapshot, reconciliation_state="failed")

    def test_freeze_rejects_non_protocol_inputs(self):
        orchestrator = _kernel()
        with self.assertRaises(TypeError):
            self._freeze(orchestrator, protocols=[_lease()])
        with self.assertRaises(TypeError):
            self._freeze(orchestrator, protocols="not-a-sequence-of-protocols")

    def test_freeze_does_not_mutate_the_protocol(self):
        orchestrator = _kernel()
        protocol = _reconciling_protocol(_lease(), since=START + timedelta(minutes=5))
        before = (protocol.connectivity, protocol.reconciling_since)
        self._freeze(
            orchestrator, leases=[protocol.lease], protocols=[protocol]
        )
        self.assertEqual(
            (protocol.connectivity, protocol.reconciling_since), before
        )

    def test_reconciliation_round_trips_through_export_and_load(self):
        orchestrator = _kernel()
        protocol = _reconciling_protocol(_lease(), since=START + timedelta(minutes=5))
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "observer-snapshot.json"
            exported = export_observer_snapshot(
                orchestrator,
                destination,
                leases=[protocol.lease],
                protocols=[protocol],
                clock=lambda: CLOCK_NS,
            )
            loaded = load_observer_snapshot(destination)
            self.assertEqual(loaded, exported)
            self.assertEqual(loaded.reconciliation_state, "reconciling")
            self.assertEqual(
                loaded.reconciliation_since_ns, _ns(START + timedelta(minutes=5))
            )

    def test_older_documents_without_a_report_still_load(self):
        # Documents frozen by the PR #44/#46/#47 builds carry
        # "unknown" with both timestamps None; the new states are
        # additive, so those documents still load unchanged.
        orchestrator = _kernel()
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "observer-snapshot.json"
            exported = export_observer_snapshot(
                orchestrator, destination, clock=lambda: CLOCK_NS
            )
            loaded = load_observer_snapshot(destination)
            self.assertEqual(loaded, exported)
            self.assertEqual(loaded.reconciliation_state, "unknown")


if __name__ == "__main__":
    unittest.main()
