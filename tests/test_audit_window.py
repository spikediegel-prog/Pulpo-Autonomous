"""Bounded audit-window reads (Control Center design v0, item 5.6).

The Evidence page can show records only if the §5.1 snapshot provides
a bounded window contract -- otherwise it shows summaries, not records.
The window is the tail of the audit chain, as record summaries (event,
sequence, time, hashes -- never payloads), with the sequence range and
total so the CC can say "showing the last N of M" and never present a
partial window as the whole audit. The unbounded ``_verb_audit`` stays
full-secret-only and out of the read-only role: no new service verb is
added here, and the read-only verb set is pinned unchanged.

Adversarial note: a window that silently drops records, miscounts its
range, or leaks a payload would let the CC display a partial chain as
the whole audit -- or leak authority content into an observer document.
Every test below that tampers with the chain, the window, or the frozen
document asserts the freeze refuses it or the loader rejects it, and
none of them asserts enforcement from a successful read.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path

from pulpo import GovernanceKernel, Policy, PulpoOrchestrator
from pulpo.incident_channel import freeze_incident_report
from pulpo.observer_snapshot import (
    AUDIT_WINDOW_MAX_BYTES,
    AUDIT_WINDOW_MAX_RECORDS,
    MAX_OBSERVER_SNAPSHOT_BYTES,
    ObserverAuditRecord,
    ObserverAuditWindow,
    export_observer_snapshot,
    freeze_observer_snapshot,
    load_observer_snapshot,
)
from pulpo.service import READ_ONLY_VERBS
from pulpo.state import AuditSigner, InMemoryKernelState

AUDIT_SECRET = "unit-test-secret".encode("utf-8")
KERNEL_SECRET = "unit-test-secret".encode("utf-8")
CLOCK_NS = int(datetime(2030, 1, 1, 0, 30, tzinfo=timezone.utc).timestamp() * 1_000_000_000)


def _kernel(*, signing: bool = False):
    if signing:
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
    else:
        state = InMemoryKernelState()
    kernel = GovernanceKernel(
        Policy(frozenset({"read"}), 0),
        secret=KERNEL_SECRET,
        state=state,
        clock=lambda: 2_000_000,
    )
    return kernel, state, PulpoOrchestrator(kernel)


def _chain(state, count, *, event="event", start_ts=1_000_000):
    for index in range(count):
        state.append(f"{event}-{index}", {"index": index}, start_ts + index)


def _write_document(payload, name="snapshot.json"):
    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / name
    path.write_text(json.dumps(payload))
    os.chmod(path, 0o600)
    return tmp, path


class AuditWindowTests(unittest.TestCase):
    def test_empty_chain_window_is_empty_and_complete(self):
        _, _, orchestrator = _kernel()
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        window = snapshot.audit_window
        self.assertIs(type(window), ObserverAuditWindow)
        self.assertEqual(window.records, ())
        self.assertEqual(window.window_start_sequence, 0)
        self.assertEqual(window.window_end_sequence, 0)
        self.assertEqual(window.total_records, 0)
        self.assertTrue(window.complete)
        self.assertEqual(snapshot.audit_records, 0)
        self.assertIsNone(snapshot.audit_tip)

    def test_short_chain_window_is_the_whole_chain(self):
        kernel, state, orchestrator = _kernel()
        _chain(state, 3)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        window = snapshot.audit_window
        self.assertEqual(window.total_records, 3)
        self.assertEqual(
            (window.window_start_sequence, window.window_end_sequence), (0, 3)
        )
        self.assertTrue(window.complete)
        self.assertEqual([record.event for record in window.records], ["event-0", "event-1", "event-2"])
        self.assertEqual([record.sequence for record in window.records], [0, 1, 2])
        self.assertEqual(
            [record.timestamp_ns for record in window.records],
            [1_000_000, 1_000_001, 1_000_002],
        )
        # Chain linkage is visible inside the window, anchored at genesis.
        self.assertEqual(window.records[0].previous_hash, "0" * 64)
        self.assertEqual(window.records[1].previous_hash, window.records[0].hash)
        self.assertEqual(window.records[2].previous_hash, window.records[1].hash)
        self.assertEqual(snapshot.audit_tip, window.records[-1].hash)
        self.assertTrue(all(not record.has_signature for record in window.records))

    def test_long_chain_window_covers_the_last_fifty(self):
        _, state, orchestrator = _kernel()
        _chain(state, 60)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        window = snapshot.audit_window
        self.assertEqual(window.total_records, 60)
        self.assertEqual(
            (window.window_start_sequence, window.window_end_sequence), (10, 60)
        )
        self.assertFalse(window.complete)
        self.assertEqual(len(window.records), AUDIT_WINDOW_MAX_RECORDS)
        self.assertEqual(window.records[0].event, "event-10")
        self.assertEqual(window.records[-1].event, "event-59")
        self.assertEqual(window.records[0].sequence, 10)
        self.assertEqual(window.records[-1].sequence, 59)
        # The window's first record links to the record before the
        # window, which the snapshot does not carry -- it is still a
        # 64-hex hash, never a guessed link.
        self.assertEqual(len(window.records[0].previous_hash), 64)

    def test_requested_count_limits_the_window(self):
        _, state, orchestrator = _kernel()
        _chain(state, 20)
        snapshot = freeze_observer_snapshot(
            orchestrator, audit_window_records=5, clock=lambda: CLOCK_NS
        )
        window = snapshot.audit_window
        self.assertEqual(
            (window.window_start_sequence, window.window_end_sequence), (15, 20)
        )
        self.assertEqual(window.total_records, 20)
        self.assertFalse(window.complete)
        self.assertEqual([record.event for record in window.records], [f"event-{i}" for i in range(15, 20)])

    def test_requested_zero_is_an_empty_window_not_an_error(self):
        _, state, orchestrator = _kernel()
        _chain(state, 4)
        snapshot = freeze_observer_snapshot(
            orchestrator, audit_window_records=0, clock=lambda: CLOCK_NS
        )
        window = snapshot.audit_window
        self.assertEqual(window.records, ())
        self.assertEqual(
            (window.window_start_sequence, window.window_end_sequence), (4, 4)
        )
        self.assertEqual(window.total_records, 4)
        self.assertFalse(window.complete)

    def test_requested_count_equal_to_the_chain_is_complete(self):
        _, state, orchestrator = _kernel()
        _chain(state, 7)
        snapshot = freeze_observer_snapshot(
            orchestrator, audit_window_records=7, clock=lambda: CLOCK_NS
        )
        self.assertTrue(snapshot.audit_window.complete)

    def test_malformed_requested_counts_fail_closed(self):
        _, state, orchestrator = _kernel()
        _chain(state, 3)
        for bad in (AUDIT_WINDOW_MAX_RECORDS + 1, -1, True, 1.5, "5"):
            with self.subTest(requested=bad):
                with self.assertRaisesRegex(
                    ValueError, "observer_audit_window_records_invalid"
                ):
                    freeze_observer_snapshot(
                        orchestrator,
                        audit_window_records=bad,
                        clock=lambda: CLOCK_NS,
                    )

    def test_window_carries_summaries_never_payloads(self):
        _, state, orchestrator = _kernel()
        state.append("permit_issued", {"marker": "payload-must-not-appear"}, 1_000_000)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        self.assertEqual(snapshot.audit_window.records[0].event, "permit_issued")
        self.assertNotIn("payload", asdict(snapshot.audit_window.records[0]))
        self.assertNotIn("payload-must-not-appear", json.dumps(asdict(snapshot)))

    def test_signed_chain_records_report_signatures(self):
        _, state, orchestrator = _kernel(signing=True)
        _chain(state, 2)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        self.assertTrue(all(record.has_signature for record in snapshot.audit_window.records))
        # The signature value itself stays with the chain: the window
        # reports presence, not the HMAC.
        self.assertNotIn("signature", asdict(snapshot.audit_window.records[0]))

    def test_byte_budget_drops_the_oldest_records_first(self):
        _, state, orchestrator = _kernel()
        # Each summary is ~40 KiB; two never fit the 64 KiB budget, one does.
        for index in range(3):
            state.append("x" * 40_000 + f"-{index}", {"index": index}, 1_000_000 + index)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        window = snapshot.audit_window
        self.assertEqual(window.total_records, 3)
        self.assertEqual(
            (window.window_start_sequence, window.window_end_sequence), (2, 3)
        )
        self.assertFalse(window.complete)
        self.assertEqual(len(window.records), 1)
        self.assertTrue(window.records[0].event.endswith("-2"))

    def test_a_single_record_over_the_budget_leaves_an_empty_window(self):
        _, state, orchestrator = _kernel()
        state.append("x" * (AUDIT_WINDOW_MAX_BYTES + 1), {"index": 0}, 1_000_000)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        window = snapshot.audit_window
        self.assertEqual(window.records, ())
        self.assertEqual(
            (window.window_start_sequence, window.window_end_sequence), (1, 1)
        )
        self.assertEqual(window.total_records, 1)
        self.assertFalse(window.complete)

    def test_tampered_tail_record_fails_the_freeze(self):
        _, state, orchestrator = _kernel()
        _chain(state, 3)
        # Freeze the incident report first so the tamper is exercised
        # by the window derivation alone, not by the derivation of
        # the report.
        report = freeze_incident_report(orchestrator)
        state._audit[-1]["hash"] = "not-a-hash"
        with self.assertRaisesRegex(
            ValueError, "observer_audit_window_record_invalid"
        ):
            freeze_observer_snapshot(
                orchestrator, incident_report=report, clock=lambda: CLOCK_NS
            )

    def test_missing_envelope_field_fails_the_freeze(self):
        _, state, orchestrator = _kernel()
        _chain(state, 3)
        report = freeze_incident_report(orchestrator)
        del state._audit[-1]["timestamp_ns"]
        with self.assertRaisesRegex(
            ValueError, "observer_audit_window_record_invalid"
        ):
            freeze_observer_snapshot(
                orchestrator, incident_report=report, clock=lambda: CLOCK_NS
            )

    def test_window_invariants_reject_contradictions(self):
        _, state, orchestrator = _kernel()
        _chain(state, 3)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        good = snapshot.audit_window

        def _with_window(window):
            return replace(snapshot, audit_window=window)

        # Each case is a thunk: the contradiction raises at
        # construction, so it must be built inside the assertion.
        def _complete_but_partial():
            return _with_window(
                ObserverAuditWindow(
                    records=good.records[:2],
                    window_start_sequence=0,
                    window_end_sequence=2,
                    total_records=3,
                    complete=True,
                )
            )

        def _range_disagrees_with_records():
            return _with_window(
                ObserverAuditWindow(
                    records=good.records,
                    window_start_sequence=1,
                    window_end_sequence=3,
                    total_records=3,
                    complete=False,
                )
            )

        def _broken_hash_link():
            broken_link = ObserverAuditRecord(
                sequence=1,
                event="event-1",
                timestamp_ns=1_000_001,
                hash=good.records[1].hash,
                previous_hash="f" * 64,
                has_signature=False,
            )
            return _with_window(
                ObserverAuditWindow(
                    records=(good.records[0], broken_link, good.records[2]),
                    window_start_sequence=0,
                    window_end_sequence=3,
                    total_records=3,
                    complete=True,
                )
            )

        def _genesis_link_is_not_zero():
            bad_genesis = ObserverAuditRecord(
                sequence=0,
                event="event-0",
                timestamp_ns=1_000_000,
                hash=good.records[0].hash,
                previous_hash="f" * 64,
                has_signature=False,
            )
            return _with_window(
                ObserverAuditWindow(
                    records=(bad_genesis, good.records[1], good.records[2]),
                    window_start_sequence=0,
                    window_end_sequence=3,
                    total_records=3,
                    complete=True,
                )
            )

        cases = {
            "complete but partial": _complete_but_partial,
            "range disagrees with records": _range_disagrees_with_records,
            "broken hash link": _broken_hash_link,
            "genesis link is not zero": _genesis_link_is_not_zero,
        }
        for label, build in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ValueError, "invalid_observer_audit_window"
                ):
                    build()

        with self.assertRaisesRegex(ValueError, "invalid_observer_audit_record"):
            ObserverAuditRecord(
                sequence=0,
                event="event-0",
                timestamp_ns=1_000_000,
                hash="not-a-hash",
                previous_hash="0" * 64,
                has_signature=False,
            )

    def test_freeze_does_not_mutate_the_chain(self):
        kernel, state, orchestrator = _kernel()
        _chain(state, 5)
        before = json.dumps(kernel.audit, sort_keys=True)
        freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        self.assertEqual(json.dumps(kernel.audit, sort_keys=True), before)

    def test_repeated_freezes_agree_except_the_derived_report_time(self):
        _, state, orchestrator = _kernel()
        _chain(state, 12)
        first = asdict(freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS))
        second = asdict(freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS))
        # The derived incident report carries its own wall-clock freeze
        # time, so it is the only moving part -- the audit window
        # itself is deterministic from the chain.
        self.assertEqual(first["audit_window"], second["audit_window"])
        self.assertEqual(
            {key: value for key, value in first.items() if key != "incident_report_frozen_at_ns"},
            {key: value for key, value in second.items() if key != "incident_report_frozen_at_ns"},
        )

    def test_export_load_round_trip_preserves_the_window(self):
        _, state, orchestrator = _kernel()
        _chain(state, 60)
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "snapshot.json"
            exported = export_observer_snapshot(
                orchestrator, destination, clock=lambda: CLOCK_NS
            )
            self.assertLess(
                destination.stat().st_size, MAX_OBSERVER_SNAPSHOT_BYTES
            )
            loaded = load_observer_snapshot(destination)
        self.assertEqual(loaded.audit_window, exported.audit_window)
        self.assertIs(type(loaded.audit_window.records[0]), ObserverAuditRecord)
        self.assertEqual(loaded.audit_window.total_records, 60)
        self.assertFalse(loaded.audit_window.complete)

    def test_older_document_without_a_window_loads_as_none(self):
        _, state, orchestrator = _kernel()
        _chain(state, 3)
        good = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        document = asdict(good)
        del document["audit_window"]
        tmp, path = _write_document(document)
        try:
            loaded = load_observer_snapshot(path)
        finally:
            tmp.cleanup()
        self.assertIsNone(loaded.audit_window)
        self.assertEqual(loaded.audit_records, 3)
        self.assertEqual(loaded.audit_tip, good.audit_tip)

    def test_window_section_validated_exactly_on_load(self):
        _, state, orchestrator = _kernel()
        _chain(state, 3)
        good = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        cases = {}

        missing_field = json.loads(json.dumps(asdict(good)))
        del missing_field["audit_window"]["complete"]
        cases["missing window field"] = missing_field

        extra_field = json.loads(json.dumps(asdict(good)))
        extra_field["audit_window"]["unexpected"] = 1
        cases["extra window field"] = extra_field

        missing_record_field = json.loads(json.dumps(asdict(good)))
        del missing_record_field["audit_window"]["records"][0]["hash"]
        cases["missing record field"] = missing_record_field

        extra_record_field = json.loads(json.dumps(asdict(good)))
        extra_record_field["audit_window"]["records"][0]["payload"] = {}
        cases["extra record field"] = extra_record_field

        broken_link = json.loads(json.dumps(asdict(good)))
        broken_link["audit_window"]["records"][1]["previous_hash"] = "f" * 64
        cases["broken hash link"] = broken_link

        false_complete = json.loads(json.dumps(asdict(good)))
        false_complete["audit_window"]["records"] = false_complete["audit_window"]["records"][:2]
        false_complete["audit_window"]["window_end_sequence"] = 2
        cases["partial window claiming complete"] = false_complete

        for label, payload in cases.items():
            with self.subTest(label=label):
                tmp, path = _write_document(payload)
                try:
                    with self.assertRaises(ValueError):
                        load_observer_snapshot(path)
                finally:
                    tmp.cleanup()

    def test_top_level_fields_still_exact_apart_from_the_window(self):
        _, state, orchestrator = _kernel()
        _chain(state, 3)
        good = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        missing = asdict(good)
        del missing["audit_records"]
        extra = dict(asdict(good), unexpected=1)
        for payload in (missing, extra):
            tmp, path = _write_document(payload)
            try:
                with self.assertRaises(ValueError):
                    load_observer_snapshot(path)
            finally:
                tmp.cleanup()

    def test_no_audit_verb_in_the_read_only_role(self):
        # §5.6 adds no service verb: the window lives in the frozen
        # snapshot, so the read-only role's verb set is exactly the
        # §5.2 set, and the unbounded `audit` verb stays out of it.
        self.assertEqual(
            READ_ONLY_VERBS,
            frozenset(
                {
                    "health",
                    "verify_audit",
                    "verify_audit_report",
                    "state_source_id",
                    "policy_hash",
                    "directive_status",
                    "directive_hash_status",
                }
            ),
        )
        self.assertNotIn("audit", READ_ONLY_VERBS)


if __name__ == "__main__":
    unittest.main()
