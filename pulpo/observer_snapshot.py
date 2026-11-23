"""Versioned, bounded, frozen observer snapshot for the Autonomous CC.

Control Center design v0, item 5.1: the single JSON document the Control
Center polls. It replaces the five-way stitching of design section 2.11
(MCP snapshot file, frozen incident report file, whole journal file,
anchor store file, live service verbs) with one contract produced by a
kernel-side freeze function in the same shape as ``freeze_mcp_snapshot``
and ``freeze_incident_report``.

Read-only by construction, like the two freeze functions it follows:

- the freeze is a pure read over the orchestrator and the deployment
  inputs the caller supplies (leases, journal, anchor store, drift
  evaluations, incident report); it appends nothing to the audit chain
  or the journal, mints or extends no lease, issues no permit, and
  holds no kernel, state, or authority reference afterwards -- the
  returned snapshot carries only primitives;
- the snapshot is frozen: repeated freezes with the same clock are
  byte-identical, and a failed load never returns a stale good value;
- absent sources are represented as unavailable or unknown, never
  invented. In particular: reconciliation state is ``"unknown"`` because
  no surface exposes it today (design item 5.5); a drift head's
  calibration age is ``None`` unless the deployment supplies it through
  ``drift_calibration_age_days`` (the drift feed reports the last age a
  sample carried — ``DriftEvaluation`` itself does not carry it), and
  the same holds for the head's calibration provenance (last
  calibration, interval, deadline, rated-life expiry, last span
  check), supplied through the ``drift_*`` mappings; a lease or
  journal record with no device identity carries ``device_id: None``,
  which the CC renders as "Unknown device" (design section 4.6) --
  identity is never guessed into a device.

Size bound: 1 MiB (``MAX_OBSERVER_SNAPSHOT_BYTES``), the incident
report's precedent. Export prefights the serialized size before
anything is published, and the loader rejects anything larger.
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Sequence

from core.drift import DriftEvaluation
from core.journal import DurableJournal
from core.offline_protocol import (
    ConnectivityState,
    OfflineMissionLease,
    OfflineProtocol,
)

from .anchor import AnchorStore, AnchorVerifier, verify_anchored_audit
from .incident_channel import IncidentReport, freeze_incident_report
from .mcp_boundary import MCPBoundaryError, _publish_snapshot
from .mcp_plugin import read_snapshot_document
from .orchestrator import PulpoOrchestrator

OBSERVER_SNAPSHOT_SCHEMA = "pulpo.observer-snapshot.v0"
MAX_OBSERVER_SNAPSHOT_BYTES = 1_048_576

LEASE_STATES = frozenset({"active", "expired"})
DRIFT_DECISIONS = frozenset({"TRUSTED", "SUSPECT", "UNTRUSTED", "UNKNOWN"})
# Reconciliation states this contract can report (design item 5.5).
# ``unknown``: no protocol was supplied, so nothing reports it.
# ``idle``: a protocol was supplied and none of its missions is
# reconciling. ``reconciling``: at least one supplied protocol is
# reconciling, and ``reconciliation_since_ns`` says since when. There
# is no ``failed`` state: the protocol has no failure transition -- a
# reconciliation that never finishes simply stays reconciling, and its
# growing duration is itself the signal. Never report "reconciling"
# from a source that does not actually report it.
RECONCILIATION_STATES = frozenset({"unknown", "idle", "reconciling"})

#: Calibration-provenance fields on ``ObserverDriftHead``. These are
#: purely additive, optional provenance: a document frozen before they
#: existed carries none of them, and the loader reads each missing one
#: as ``None`` (unknown), never as a guessed value. Every other field
#: on every section is still enforced exactly -- a missing required
#: field or an unknown extra field still rejects the document. The
#: lease field ``commands_remaining`` (design item 5.3) is NOT in this
#: set: documents without it are still rejected, as the item 5.3
#: change record states. The difference is deliberate: absence of a
#: provenance field is semantically identical to ``None`` ("unknown,
#: never invented"), while the lease count is a page-required value
#: whose absence means the document predates the surface that carries
#: it. This set is the contract's evolution rule for additive optional
#: fields going forward.
DRIFT_HEAD_PROVENANCE_FIELDS = frozenset(
    {
        "last_calibration_ns",
        "calibration_interval_days",
        "next_calibration_due_ns",
        "rated_life_expiry_ns",
        "span_check_passed",
        "span_check_ns",
    }
)

#: Nanoseconds in one day, for deriving a calibration deadline from a
#: last-calibration time plus an interval in days.
_NS_PER_DAY = 86_400 * 1_000_000_000

#: Maximum audit records in one frozen window (design item 5.6), and
#: the maximum canonical-JSON bytes the window section may occupy. A
#: summary record is ~200-300 bytes, so 50 records are ~15 KiB -- far
#: inside the 1 MiB snapshot cap; the byte budget guards degenerate
#: event names, not ordinary chains.
AUDIT_WINDOW_MAX_RECORDS = 50
AUDIT_WINDOW_MAX_BYTES = 65_536

#: Top-level snapshot fields a document frozen before they existed
#: may omit. A missing ``audit_window`` reads as ``None`` ("this
#: document carries no audit window"), never as a guessed window --
#: the Evidence page's designed fallback without a window is
#: summaries, not records (design 4.1), so absence of the section is
#: semantically identical to ``None``. This extends the
#: ``DRIFT_HEAD_PROVENANCE_FIELDS`` evolution rule to additive
#: optional top-level sections; every other top-level field is still
#: enforced exactly -- a missing required field or an unknown extra
#: field still rejects the document.
OPTIONAL_SNAPSHOT_FIELDS = frozenset({"audit_window"})


def _is_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _number(value: object) -> bool:
    return type(value) is int and value >= 0


def _positive_number(value: object) -> bool:
    return type(value) is int and value > 0


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _non_empty_str(value: object) -> bool:
    return type(value) is str and bool(value)


def _optional_non_empty_str(value: object) -> bool:
    return value is None or _non_empty_str(value)


def _optional_hex(value: object, length: int) -> bool:
    return value is None or _is_hex(value, length)


def _datetime_to_ns(moment: datetime) -> int:
    """Convert an aware datetime to epoch nanoseconds; naive times fail."""

    if not isinstance(moment, datetime) or moment.tzinfo is None:
        raise ValueError("observer_snapshot_time_invalid")
    return int(moment.timestamp() * 1_000_000_000)


def _datetime_from_ns(moment_ns: int) -> datetime:
    seconds, remainder_ns = divmod(moment_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(
        microseconds=remainder_ns // 1_000
    )


@dataclass(frozen=True, slots=True)
class ObserverSignatureSummary:
    """Signing coverage of the audit chain, from ``verify_audit_report``.

    Counts are the report's own: when verification fails it returns early,
    so signed + unsigned may be below total -- the failure is reported by
    ``audit_valid`` on the snapshot, not hidden by this summary.
    """

    signing_enabled: bool
    signed_records: int
    unsigned_records: int
    legacy_records: int
    total_records: int

    def __post_init__(self) -> None:
        if (
            type(self.signing_enabled) is not bool
            or not _number(self.signed_records)
            or not _number(self.unsigned_records)
            or not _number(self.legacy_records)
            or not _number(self.total_records)
        ):
            raise ValueError("invalid_observer_signature_summary")


@dataclass(frozen=True, slots=True)
class ObserverAnchorState:
    """Anchored-audit result, or the honest absence of an anchor store."""

    available: bool
    head_hash: str | None
    anchored_records: int
    verified: bool | None
    reason: str | None
    anchors_checked: int

    def __post_init__(self) -> None:
        if (
            type(self.available) is not bool
            or not _optional_hex(self.head_hash, 64)
            or not _number(self.anchored_records)
            or (self.verified is not None and type(self.verified) is not bool)
            or not _optional_non_empty_str(self.reason)
            or not _number(self.anchors_checked)
        ):
            raise ValueError("invalid_observer_anchor_state")
        # When no store was supplied, verified is None but the reason
        # names the absence ("anchor_store_absent") -- the absence
        # itself is the reportable fact, not a silent gap.
        if not self.available and self.verified is not None:
            raise ValueError("invalid_observer_anchor_state")


@dataclass(frozen=True, slots=True)
class ObserverJournalTip:
    """Verified journal tip, or the honest absence of a journal.

    A verification failure carries ``verified=False`` and the reason, and
    no tip fields at all: the CC shows Attention rather than a partial
    tail (design section 4.2).
    """

    available: bool
    sequence: int | None
    last_event: str | None
    last_record_hash: str | None
    verified: bool | None
    verification_reason: str | None
    deployment_id: str | None
    device_id: str | None

    def __post_init__(self) -> None:
        if (
            type(self.available) is not bool
            or (self.sequence is not None and not _positive_number(self.sequence))
            or not _optional_non_empty_str(self.last_event)
            or not _optional_hex(self.last_record_hash, 64)
            or (self.verified is not None and type(self.verified) is not bool)
            or not _optional_non_empty_str(self.verification_reason)
            or not _optional_non_empty_str(self.deployment_id)
            or not _optional_non_empty_str(self.device_id)
        ):
            raise ValueError("invalid_observer_journal_tip")
        if not self.available and (
            self.sequence is not None
            or self.last_event is not None
            or self.last_record_hash is not None
            or self.verified is not None
            or self.verification_reason is not None
        ):
            raise ValueError("invalid_observer_journal_tip")


@dataclass(frozen=True, slots=True)
class ObserverLeaseSummary:
    """One lease as the Missions page shows it (design sections 4.1, 4.6).

    ``window_remaining_ns`` is the governed envelope's remaining validity
    (``None`` when the envelope has no expiry); the lease's own offline
    bound is ``max_disconnected_ns``. ``device_id`` is ``None`` when the
    deployment supplied no device identity for this lease's deployment --
    the CC renders that as "Unknown device", never guessed.
    ``commands_remaining`` is the Missions page's "max commands
    remaining": ``max_commands`` minus the commands already sent under
    this lease. The lease type carries only the bound; the sent count
    lives in the execution journal (``ExecutionContext._command_count``),
    so only the deployment -- which pairs a lease with its execution
    context -- can supply it, via the freeze's ``commands_remaining``
    mapping keyed by lease id. ``None`` when the deployment did not
    supply it: the CC shows Unknown for that cell, never a guessed
    number. An unbounded lease (``max_commands`` is ``None``) has no
    remaining count, so ``commands_remaining`` must be ``None`` there.
    """

    lease_id: str
    principal: str
    deployment_id: str
    device_id: str | None
    safe_fallback: str
    issued_at_ns: int
    window_remaining_ns: int | None
    max_disconnected_ns: int
    max_commands: int | None
    commands_remaining: int | None
    state: str

    def __post_init__(self) -> None:
        if (
            not _non_empty_str(self.lease_id)
            or not _non_empty_str(self.principal)
            or not _non_empty_str(self.deployment_id)
            or not _optional_non_empty_str(self.device_id)
            or not _non_empty_str(self.safe_fallback)
            or not _number(self.issued_at_ns)
            or (self.window_remaining_ns is not None and not _number(self.window_remaining_ns))
            or not _positive_number(self.max_disconnected_ns)
            or (self.max_commands is not None and not _positive_number(self.max_commands))
            or (self.commands_remaining is not None and not _number(self.commands_remaining))
            or (
                self.max_commands is None
                and self.commands_remaining is not None
            )
            or (
                self.max_commands is not None
                and self.commands_remaining is not None
                and self.commands_remaining > self.max_commands
            )
            or self.state not in LEASE_STATES
        ):
            raise ValueError("invalid_observer_lease_summary")


@dataclass(frozen=True, slots=True)
class ObserverDriftHead:
    """One O2 head's latest drift evaluation, as the Sensors page shows it.

    ``calibration_age_days`` is ``None`` because ``DriftEvaluation`` does
    not carry it -- the evaluation's reasons still name a calibration
    failure when one applies. ``last_evaluated_ns`` is ``None`` unless the
    deployment supplied an evaluation time for this head. ``sensor_id``
    is the head's identity (e.g. ``O2-E04-01``); the drift monitor never
    authorizes a fan stop, so no fan-stop field exists here.

    Calibration provenance -- the expected side, next to the reported
    age, so the operator sees actual vs. should-be: ``last_calibration_ns``
    (when this head was actually calibrated), ``calibration_interval_days``
    (how often it should be calibrated, from the sensor profile),
    ``next_calibration_due_ns`` (the deadline: last calibration plus
    interval, or a deployment-supplied deadline), ``rated_life_expiry_ns``
    (when the sensor itself is past its rated life), and the last
    span check (``span_check_passed`` plus ``span_check_ns`` -- a failed
    span check is what makes a head UNTRUSTED). Every one of these is
    ``None`` unless the deployment supplied it, never invented; a fresh
    calibration (age 0, or a last-calibration time of right now) is a
    real value, not Unknown. A span-check result without a time, or a
    time without a result, is invalid -- both or neither.
    """

    sensor_id: str
    decision: str
    reasons: tuple[str, ...]
    raw_o2_pct: float
    drift_pct_per_hour: float
    step_change_pct_per_minute: float
    neighbor_median_pct: float | None
    neighbor_deviation_pct: float | None
    rate_limit_pct_per_hour: float
    step_limit_pct_per_minute: float
    max_neighbor_deviation_pct: float
    max_reading_age_seconds: float
    age_seconds: float
    calibration_age_days: float | None
    retrust_soak_minutes: float
    retrust_soak_required_minutes: float
    last_evaluated_ns: int | None
    last_calibration_ns: int | None
    calibration_interval_days: float | None
    next_calibration_due_ns: int | None
    rated_life_expiry_ns: int | None
    span_check_passed: bool | None
    span_check_ns: int | None

    def __post_init__(self) -> None:
        if (
            not _non_empty_str(self.sensor_id)
            or self.decision not in DRIFT_DECISIONS
            or type(self.reasons) is not tuple
            or any(not _non_empty_str(reason) for reason in self.reasons)
            or not _finite_number(self.raw_o2_pct)
            or not _finite_number(self.drift_pct_per_hour)
            or not _finite_number(self.step_change_pct_per_minute)
            or (self.neighbor_median_pct is not None and not _finite_number(self.neighbor_median_pct))
            or (self.neighbor_deviation_pct is not None and not _finite_number(self.neighbor_deviation_pct))
            or not _finite_number(self.rate_limit_pct_per_hour)
            or not _finite_number(self.step_limit_pct_per_minute)
            or not _finite_number(self.max_neighbor_deviation_pct)
            or not _finite_number(self.max_reading_age_seconds)
            or not _finite_number(self.age_seconds)
            or (self.calibration_age_days is not None and not _finite_number(self.calibration_age_days))
            or not _finite_number(self.retrust_soak_minutes)
            or not _finite_number(self.retrust_soak_required_minutes)
            or (self.last_evaluated_ns is not None and not _positive_number(self.last_evaluated_ns))
            or (self.last_calibration_ns is not None and not _number(self.last_calibration_ns))
            or (
                self.calibration_interval_days is not None
                and (
                    not _finite_number(self.calibration_interval_days)
                    or self.calibration_interval_days <= 0
                )
            )
            or (self.next_calibration_due_ns is not None and not _number(self.next_calibration_due_ns))
            or (
                self.next_calibration_due_ns is not None
                and self.last_calibration_ns is not None
                and self.next_calibration_due_ns < self.last_calibration_ns
            )
            or (self.rated_life_expiry_ns is not None and not _number(self.rated_life_expiry_ns))
            or (self.span_check_passed is not None and type(self.span_check_passed) is not bool)
            or (self.span_check_ns is not None and not _number(self.span_check_ns))
            or (self.span_check_passed is None) != (self.span_check_ns is None)
        ):
            raise ValueError("invalid_observer_drift_head")


@dataclass(frozen=True, slots=True)
class ObserverAuditRecord:
    """One audit-chain record as the observer may see it (design 5.6).

    A summary, not the record: event, position, time, and hashes --
    never the payload. Payloads are arbitrary dicts written by kernel
    append sites (a ``target_locked`` payload carries the full
    intent), and the snapshot contract is hashes and counts only, so
    no payload enters this document. ``has_signature`` reports
    whether the record carries a signature field; verification
    coverage is the signature summary's job.
    """

    sequence: int
    event: str
    timestamp_ns: int
    hash: str
    previous_hash: str
    has_signature: bool

    def __post_init__(self) -> None:
        if (
            not _number(self.sequence)
            or not _non_empty_str(self.event)
            or not _number(self.timestamp_ns)
            or not _is_hex(self.hash, 64)
            or not _is_hex(self.previous_hash, 64)
            or type(self.has_signature) is not bool
        ):
            raise ValueError("invalid_observer_audit_record")


@dataclass(frozen=True, slots=True)
class ObserverAuditWindow:
    """The bounded recent-records window over the audit chain (design 5.6).

    The window is the last ``len(records)`` records of a chain of
    ``total_records``, in chain order, covering
    ``[window_start_sequence, window_end_sequence)``. ``complete`` is
    true exactly when the window is the whole chain. A partial window
    is never presented as the whole audit: the CC reads "showing the
    last N of M" from start/end/total, and a window truncated by the
    byte budget reports the range it actually covers, never a
    silently shortened chain.
    """

    records: tuple[ObserverAuditRecord, ...]
    window_start_sequence: int
    window_end_sequence: int
    total_records: int
    complete: bool

    def __post_init__(self) -> None:
        if (
            type(self.records) is not tuple
            or any(type(record) is not ObserverAuditRecord for record in self.records)
            or not _number(self.window_start_sequence)
            or not _number(self.window_end_sequence)
            or not _number(self.total_records)
            or type(self.complete) is not bool
            or self.window_start_sequence > self.window_end_sequence
            or self.window_end_sequence > self.total_records
            or self.window_end_sequence - self.window_start_sequence
            != len(self.records)
            or self.complete
            != (
                self.window_start_sequence == 0
                and self.window_end_sequence == self.total_records
            )
            or any(
                record.sequence != self.window_start_sequence + index
                for index, record in enumerate(self.records)
            )
            or any(
                self.records[index].previous_hash != self.records[index - 1].hash
                for index in range(1, len(self.records))
            )
            or (
                self.records
                and self.window_start_sequence == 0
                and self.records[0].previous_hash != "0" * 64
            )
        ):
            raise ValueError("invalid_observer_audit_window")


@dataclass(frozen=True, slots=True)
class ObserverSnapshot:
    """The single frozen document the Control Center polls (design 5.1).

    Only primitives: strings, booleans, numbers, ``None``, and tuples of
    the frozen section dataclasses. No callbacks, no object references,
    no private key material, no permit or approval content -- hashes and
    counts only. The audit window carries record summaries (event,
    sequence, time, hashes), never payloads.
    """

    source_id: str
    deployment_id: str | None
    device_id: str | None
    frozen_at_ns: int
    policy_hash: str
    audit_valid: bool
    audit_records: int
    audit_tip: str | None
    audit_window: ObserverAuditWindow | None
    signatures: ObserverSignatureSummary
    anchor: ObserverAnchorState
    journal: ObserverJournalTip
    leases: tuple[ObserverLeaseSummary, ...]
    drift_heads: tuple[ObserverDriftHead, ...]
    incidents: int
    near_misses: int
    incident_report_available: bool
    incident_report_frozen_at_ns: int | None
    reconciliation_state: str
    reconciliation_since_ns: int | None
    last_reconciliation_completed_ns: int | None
    schema: str = OBSERVER_SNAPSHOT_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != OBSERVER_SNAPSHOT_SCHEMA
            or not _is_hex(self.source_id, 32)
            or not _optional_non_empty_str(self.deployment_id)
            or not _optional_non_empty_str(self.device_id)
            or not _positive_number(self.frozen_at_ns)
            or not _is_hex(self.policy_hash, 64)
            or type(self.audit_valid) is not bool
            or not _number(self.audit_records)
            or not _optional_hex(self.audit_tip, 64)
            or (
                self.audit_window is not None
                and type(self.audit_window) is not ObserverAuditWindow
            )
            or type(self.signatures) is not ObserverSignatureSummary
            or type(self.anchor) is not ObserverAnchorState
            or type(self.journal) is not ObserverJournalTip
            or type(self.leases) is not tuple
            or any(type(lease) is not ObserverLeaseSummary for lease in self.leases)
            or type(self.drift_heads) is not tuple
            or any(type(head) is not ObserverDriftHead for head in self.drift_heads)
            or not _number(self.incidents)
            or not _number(self.near_misses)
            or type(self.incident_report_available) is not bool
            or (
                self.incident_report_frozen_at_ns is not None
                and not _positive_number(self.incident_report_frozen_at_ns)
            )
            or self.reconciliation_state not in RECONCILIATION_STATES
            or (
                self.reconciliation_since_ns is not None
                and not _positive_number(self.reconciliation_since_ns)
            )
            or (
                self.last_reconciliation_completed_ns is not None
                and not _positive_number(self.last_reconciliation_completed_ns)
            )
        ):
            raise ValueError("invalid_observer_snapshot")
        if not self.incident_report_available and self.incident_report_frozen_at_ns is not None:
            raise ValueError("invalid_observer_snapshot")
        # A reconciliation in progress must say since when, and a state
        # that is not "reconciling" must not claim a start time; neither
        # timestamp may postdate the freeze itself.
        if (self.reconciliation_state == "reconciling") != (
            self.reconciliation_since_ns is not None
        ):
            raise ValueError("invalid_observer_snapshot")
        if (
            self.reconciliation_since_ns is not None
            and self.reconciliation_since_ns > self.frozen_at_ns
        ) or (
            self.last_reconciliation_completed_ns is not None
            and self.last_reconciliation_completed_ns > self.frozen_at_ns
        ):
            raise ValueError("invalid_observer_snapshot")


def _lease_commands_remaining(
    lease: OfflineMissionLease,
    commands_remaining: Mapping[str, int] | None,
) -> int | None:
    """Resolve one lease's remaining-command count from the deployment map.

    ``None`` when the deployment supplied no count for this lease: the
    CC shows Unknown, never a guessed number. A count for an unbounded
    lease, or a count above the lease's bound, is contradictory input
    and fails closed -- the deployment computes remaining as bound
    minus commands sent, so neither case can arise from a correct
    caller. An entry for a lease id the snapshot does not carry is
    ignored here; it is the caller's stale input, not this lease's
    state.
    """

    if commands_remaining is None:
        return None
    remaining = commands_remaining.get(lease.lease_id)
    if remaining is None:
        return None
    if lease.max_commands is None or remaining > lease.max_commands:
        raise ValueError("observer_commands_remaining_invalid")
    return remaining


def _reconciliation_state(
    protocols: Sequence[OfflineProtocol],
    deployment_id: str | None,
    frozen_at_ns: int,
) -> tuple[str, int | None, int | None]:
    """Derive the snapshot's reconciliation triple from deployment protocols.

    Only protocols for the resolved deployment report: a reconciliation
    on another deployment is not this snapshot's to show, and with no
    resolved deployment there is nothing to attribute it to. A
    reconciling protocol without a recorded start is contradictory
    input and fails closed, as is any timestamp after the freeze --
    the deployment's clock and the freeze clock disagree, and the
    snapshot must not paper over that with a future-dated claim.
    """
    if deployment_id is None:
        return "unknown", None, None
    matching = [
        protocol
        for protocol in protocols
        if protocol.lease.deployment_id == deployment_id
    ]
    if not matching:
        return "unknown", None, None
    last_completed_ns: int | None = None
    for protocol in matching:
        if protocol.last_reconciliation_completed_at is not None:
            completed_ns = _datetime_to_ns(protocol.last_reconciliation_completed_at)
            if completed_ns > frozen_at_ns:
                raise ValueError("observer_reconciliation_time_invalid")
            if last_completed_ns is None or completed_ns > last_completed_ns:
                last_completed_ns = completed_ns
    reconciling = [
        protocol
        for protocol in matching
        if protocol.connectivity == ConnectivityState.RECONCILING
    ]
    if not reconciling:
        return "idle", None, last_completed_ns
    since_values: list[int] = []
    for protocol in reconciling:
        if protocol.reconciling_since is None:
            raise ValueError("observer_reconciliation_since_missing")
        since_ns = _datetime_to_ns(protocol.reconciling_since)
        if since_ns > frozen_at_ns:
            raise ValueError("observer_reconciliation_time_invalid")
        since_values.append(since_ns)
    # Earliest start: "for how long" is measured from the longest
    # running reconciliation.
    return "reconciling", min(since_values), last_completed_ns


def _lease_summary(
    lease: OfflineMissionLease,
    *,
    device_id: str | None,
    commands_remaining: int | None,
    now: datetime,
) -> ObserverLeaseSummary:
    envelope = lease.envelope
    if envelope.expires_at is None:
        window_remaining_ns = None
    else:
        remaining = (envelope.expires_at - now).total_seconds() * 1_000_000_000
        window_remaining_ns = max(0, int(remaining))
    return ObserverLeaseSummary(
        lease_id=lease.lease_id,
        principal=lease.principal,
        deployment_id=lease.deployment_id,
        device_id=device_id,
        safe_fallback=lease.safe_fallback,
        issued_at_ns=_datetime_to_ns(lease.issued_at),
        window_remaining_ns=window_remaining_ns,
        max_disconnected_ns=int(lease.max_disconnected.total_seconds() * 1_000_000_000),
        max_commands=lease.max_commands,
        commands_remaining=commands_remaining,
        state="active" if lease.active_at(now) else "expired",
    )


def _drift_next_calibration_due_ns(
    last_calibration_ns: int | None,
    calibration_interval_days: float | None,
    supplied_due_ns: int | None,
) -> int | None:
    """Resolve one head's calibration deadline.

    A deployment-supplied deadline wins when present, but only when it
    is consistent: it must not precede the last calibration. Otherwise
    the deadline is derived -- last calibration plus interval -- when
    both are known. With neither, the deadline is unknown, never
    guessed. A supplied deadline that precedes the last calibration is
    contradictory input and fails closed.
    """

    if supplied_due_ns is not None:
        if last_calibration_ns is not None and supplied_due_ns < last_calibration_ns:
            raise ValueError("observer_drift_calibration_due_invalid")
        return supplied_due_ns
    if last_calibration_ns is None or calibration_interval_days is None:
        return None
    return last_calibration_ns + int(calibration_interval_days * _NS_PER_DAY)


def _audit_record_summary(sequence: int, record: dict[str, Any]) -> ObserverAuditRecord:
    """Summarize one audit-chain record for the observer window.

    Event, position, time, and hashes only -- never the payload. A
    record missing its envelope fields, or carrying a malformed one,
    is contradictory input and fails closed with a named error rather
    than a bare ``KeyError``; the snapshot cannot honestly window a
    chain it cannot read. Whether the record carries a signature is
    reported as a boolean; the signature value itself stays with the
    chain.
    """
    try:
        return ObserverAuditRecord(
            sequence=sequence,
            event=record["event"],
            timestamp_ns=record["timestamp_ns"],
            hash=record["hash"],
            previous_hash=record["previous_hash"],
            has_signature="signature" in record,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("observer_audit_window_record_invalid") from exc


def _audit_window(
    records: Sequence[dict[str, Any]],
    requested: int | None,
) -> ObserverAuditWindow:
    """Derive the bounded recent-records window over the audit chain.

    The window is the tail of the chain: the last ``requested``
    records (the cap when unrequested), in chain order, with the
    sequence range and total so the CC can say "showing the last N
    of M". Two bounds apply: the record count cap and a byte budget
    on the window's canonical JSON; when the budget binds, the
    oldest records drop first and the window reports the range it
    actually covers. A chain shorter than the request is the whole
    chain, and ``complete`` says so. A single record larger than the
    budget leaves an empty window -- the CC shows summaries, not a
    truncated record.
    """
    if requested is None:
        count = AUDIT_WINDOW_MAX_RECORDS
    else:
        if (
            type(requested) is not int
            or requested < 0
            or requested > AUDIT_WINDOW_MAX_RECORDS
        ):
            raise ValueError("observer_audit_window_records_invalid")
        count = requested
    total = len(records)
    start = max(0, total - count)
    chosen = [
        _audit_record_summary(sequence, record)
        for sequence, record in enumerate(records[start:], start=start)
    ]
    while chosen:
        encoded = json.dumps(
            [asdict(summary) for summary in chosen],
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(encoded.encode("utf-8")) <= AUDIT_WINDOW_MAX_BYTES:
            break
        chosen.pop(0)
    start = total - len(chosen)
    return ObserverAuditWindow(
        records=tuple(chosen),
        window_start_sequence=start,
        window_end_sequence=total,
        total_records=total,
        complete=start == 0,
    )


def _drift_head_summary(
    evaluation: DriftEvaluation,
    *,
    last_evaluated_ns: int | None,
    calibration_age_days: float | None,
    last_calibration_ns: int | None,
    calibration_interval_days: float | None,
    next_calibration_due_ns: int | None,
    rated_life_expiry_ns: int | None,
    span_check_passed: bool | None,
    span_check_ns: int | None,
) -> ObserverDriftHead:
    return ObserverDriftHead(
        sensor_id=evaluation.sensor_id,
        decision=evaluation.decision,
        reasons=tuple(evaluation.reasons),
        raw_o2_pct=evaluation.raw_o2_pct,
        drift_pct_per_hour=evaluation.drift_pct_per_hour,
        step_change_pct_per_minute=evaluation.step_change_pct_per_minute,
        neighbor_median_pct=evaluation.neighbor_median_pct,
        neighbor_deviation_pct=evaluation.neighbor_deviation_pct,
        rate_limit_pct_per_hour=evaluation.rate_limit_pct_per_hour,
        step_limit_pct_per_minute=evaluation.step_limit_pct_per_minute,
        max_neighbor_deviation_pct=evaluation.max_neighbor_deviation_pct,
        max_reading_age_seconds=evaluation.max_reading_age_seconds,
        age_seconds=evaluation.age_seconds,
        # DriftEvaluation does not carry calibration age: it is supplied
        # by the deployment (the drift feed reports the last age a
        # sample carried), and stays None when no sample reported one.
        # A calibration failure is still visible in reasons either way.
        calibration_age_days=calibration_age_days,
        retrust_soak_minutes=evaluation.retrust_soak_minutes,
        retrust_soak_required_minutes=evaluation.retrust_soak_required_minutes,
        last_evaluated_ns=last_evaluated_ns,
        # Calibration provenance is deployment-supplied maintenance
        # fact, not evaluation output: the last calibration date, the
        # profile interval, the deadline (supplied, else derived from
        # the two), the rated-life expiry, and the last span check.
        # Each stays None when the deployment did not supply it.
        last_calibration_ns=last_calibration_ns,
        calibration_interval_days=calibration_interval_days,
        next_calibration_due_ns=_drift_next_calibration_due_ns(
            last_calibration_ns,
            calibration_interval_days,
            next_calibration_due_ns,
        ),
        rated_life_expiry_ns=rated_life_expiry_ns,
        span_check_passed=span_check_passed,
        span_check_ns=span_check_ns,
    )


def freeze_observer_snapshot(
    orchestrator: PulpoOrchestrator,
    *,
    deployment_id: str | None = None,
    device_id: str | None = None,
    device_ids: Mapping[str, str] | None = None,
    leases: Sequence[OfflineMissionLease] = (),
    protocols: Sequence[OfflineProtocol] = (),
    commands_remaining: Mapping[str, int] | None = None,
    journal: DurableJournal | None = None,
    anchor_store: AnchorStore | None = None,
    anchor_verifier: AnchorVerifier | None = None,
    drift_evaluations: Sequence[DriftEvaluation] = (),
    drift_evaluated_at_ns: Mapping[str, int] | None = None,
    drift_calibration_age_days: Mapping[str, float] | None = None,
    drift_last_calibration_ns: Mapping[str, int] | None = None,
    drift_calibration_interval_days: Mapping[str, float] | None = None,
    drift_next_calibration_due_ns: Mapping[str, int] | None = None,
    drift_rated_life_expiry_ns: Mapping[str, int] | None = None,
    drift_span_check_passed: Mapping[str, bool] | None = None,
    drift_span_check_ns: Mapping[str, int] | None = None,
    incident_report: IncidentReport | None = None,
    audit_window_records: int | None = None,
    clock: Callable[[], int] | None = None,
) -> ObserverSnapshot:
    """Freeze one capability-free observer snapshot from trusted Pulpo.

    Pure read: nothing is appended to the audit chain or the journal, no
    lease is minted or extended, no permit is issued. The caller supplies
    what the deployment already holds -- leases, journal, anchor store,
    drift evaluations, incident report -- and anything not supplied is
    reported as unavailable or unknown, never synthesized.

    Identity resolution, in order: an explicit ``deployment_id`` wins,
    else the first supplied lease's deployment, else ``None``. Device
    identity comes from ``device_id``, else ``device_ids`` keyed by the
    resolved deployment for the snapshot and by each lease's deployment
    for its summary; anything unmapped stays ``None`` ("Unknown device"
    in the CC). ``commands_remaining`` is an optional mapping keyed by
    lease id, supplied by the deployment from its execution journals;
    a lease with no entry reports ``None`` (Unknown in the CC), never
    a guessed count. ``protocols`` is the deployment's offline
    protocols, supplied the same way as ``leases``: the snapshot
    reports ``reconciling`` with its start time when one of them is
    reconciling, ``idle`` with the last completion time when one is
    supplied and none is reconciling, and ``unknown`` when none is
    supplied for this deployment -- the CC must never display
    "reconciling" unless a protocol actually reports it. A
    reconciling protocol records its start in
    ``OfflineProtocol.reconciling_since`` and its last completion in
    ``last_reconciliation_completed_at``; both are timestamps of
    transitions the protocol itself made, not journal-verified
    history, and both are lost if the deployment restarts before
    freezing. ``drift_calibration_age_days`` is an optional
    mapping keyed by sensor id, supplied by the deployment from its
    drift feed (the last calibration age a sample reported for that
    head); a head with no entry reports ``None``, never a guessed age.
    Calibration provenance is the same shape, one optional mapping per
    field, all keyed by sensor id: ``drift_last_calibration_ns`` (when
    the head was last calibrated), ``drift_calibration_interval_days``
    (how often it should be calibrated, from the sensor profile),
    ``drift_next_calibration_due_ns`` (a deployment-supplied deadline;
    when absent, the deadline is derived as last calibration plus
    interval when both are known), ``drift_rated_life_expiry_ns``
    (when the sensor is past its rated life), and the last span check
    as ``drift_span_check_passed`` plus ``drift_span_check_ns`` -- a
    head must appear in both span-check mappings or neither, and a
    supplied deadline must not precede the last calibration. Any head
    with no entry reports ``None`` for that field, never a guessed
    value. ``audit_window_records`` caps the recent-records window
    over the audit chain (design item 5.6): the last that many
    records, summaries only (event, sequence, time, hashes -- never
    payloads), capped at ``AUDIT_WINDOW_MAX_RECORDS``; unrequested,
    the window takes the cap. ``clock`` returns epoch nanoseconds and
    defaults to ``time.time_ns``; it also derives the ``now`` lease
    windows are measured against, so one frozen clock pins the whole
    document.
    """

    if type(orchestrator) is not PulpoOrchestrator:
        raise TypeError("canonical PulpoOrchestrator required")
    if deployment_id is not None and not _non_empty_str(deployment_id):
        raise ValueError("observer_deployment_id_invalid")
    if device_id is not None and not _non_empty_str(device_id):
        raise ValueError("observer_device_id_invalid")
    if device_ids is not None and (
        not isinstance(device_ids, Mapping)
        or any(not _non_empty_str(key) or not _non_empty_str(value) for key, value in device_ids.items())
    ):
        raise ValueError("observer_device_ids_invalid")
    if not isinstance(leases, Sequence) or any(
        type(lease) is not OfflineMissionLease for lease in leases
    ):
        raise TypeError("observer_leases_invalid")
    if not isinstance(protocols, Sequence) or any(
        type(protocol) is not OfflineProtocol for protocol in protocols
    ):
        raise TypeError("observer_protocols_invalid")
    if commands_remaining is not None and (
        not isinstance(commands_remaining, Mapping)
        or any(
            not _non_empty_str(key) or not _number(value)
            for key, value in commands_remaining.items()
        )
    ):
        raise ValueError("observer_commands_remaining_invalid")
    if journal is not None and type(journal) is not DurableJournal:
        raise TypeError("observer_journal_invalid")
    # AnchorStore is a plain Protocol (not runtime-checkable): check the
    # shape structurally instead of isinstance.
    if anchor_store is not None and not (
        callable(getattr(anchor_store, "anchors", None))
        and callable(getattr(anchor_store, "append", None))
    ):
        raise TypeError("observer_anchor_store_invalid")
    if not isinstance(drift_evaluations, Sequence) or any(
        type(evaluation) is not DriftEvaluation for evaluation in drift_evaluations
    ):
        raise TypeError("observer_drift_evaluations_invalid")
    if drift_evaluated_at_ns is not None and (
        not isinstance(drift_evaluated_at_ns, Mapping)
        or any(
            not _non_empty_str(key) or not _positive_number(value)
            for key, value in drift_evaluated_at_ns.items()
        )
    ):
        raise ValueError("observer_drift_evaluated_at_ns_invalid")
    if drift_calibration_age_days is not None and (
        not isinstance(drift_calibration_age_days, Mapping)
        or any(
            not _non_empty_str(key)
            or not _finite_number(value)
            or value < 0
            for key, value in drift_calibration_age_days.items()
        )
    ):
        raise ValueError("observer_drift_calibration_age_days_invalid")
    if drift_last_calibration_ns is not None and (
        not isinstance(drift_last_calibration_ns, Mapping)
        or any(
            not _non_empty_str(key) or not _number(value)
            for key, value in drift_last_calibration_ns.items()
        )
    ):
        raise ValueError("observer_drift_last_calibration_ns_invalid")
    if drift_calibration_interval_days is not None and (
        not isinstance(drift_calibration_interval_days, Mapping)
        or any(
            not _non_empty_str(key)
            or not _finite_number(value)
            or value <= 0
            for key, value in drift_calibration_interval_days.items()
        )
    ):
        raise ValueError("observer_drift_calibration_interval_days_invalid")
    if drift_next_calibration_due_ns is not None and (
        not isinstance(drift_next_calibration_due_ns, Mapping)
        or any(
            not _non_empty_str(key) or not _number(value)
            for key, value in drift_next_calibration_due_ns.items()
        )
    ):
        raise ValueError("observer_drift_next_calibration_due_ns_invalid")
    if drift_rated_life_expiry_ns is not None and (
        not isinstance(drift_rated_life_expiry_ns, Mapping)
        or any(
            not _non_empty_str(key) or not _number(value)
            for key, value in drift_rated_life_expiry_ns.items()
        )
    ):
        raise ValueError("observer_drift_rated_life_expiry_ns_invalid")
    if drift_span_check_passed is not None and (
        not isinstance(drift_span_check_passed, Mapping)
        or any(
            not _non_empty_str(key) or type(value) is not bool
            for key, value in drift_span_check_passed.items()
        )
    ):
        raise ValueError("observer_drift_span_check_passed_invalid")
    if drift_span_check_ns is not None and (
        not isinstance(drift_span_check_ns, Mapping)
        or any(
            not _non_empty_str(key) or not _number(value)
            for key, value in drift_span_check_ns.items()
        )
    ):
        raise ValueError("observer_drift_span_check_ns_invalid")
    # A span check is a maintenance event with a result AND a time:
    # a head in one span-check mapping must be in the other, or the
    # deployment is reporting half a fact.
    if set(drift_span_check_passed or {}) != set(drift_span_check_ns or {}):
        raise ValueError("observer_drift_span_check_invalid")
    if incident_report is not None and type(incident_report) is not IncidentReport:
        raise TypeError("observer_incident_report_invalid")
    if clock is not None and not callable(clock):
        raise TypeError("observer_clock_invalid")

    frozen_at_ns = clock() if clock is not None else time.time_ns()
    if not _positive_number(frozen_at_ns):
        raise ValueError("observer_clock_invalid")
    now = _datetime_from_ns(frozen_at_ns)

    kernel = orchestrator.kernel
    evidence = orchestrator.evidence_snapshot()
    source_id = kernel.state_source_id()
    audit_report = kernel.verify_audit_report()

    signatures = ObserverSignatureSummary(
        signing_enabled=bool(audit_report["signing_enabled"]),
        signed_records=int(audit_report["signed_records"]),
        unsigned_records=int(audit_report["unsigned_records"]),
        legacy_records=int(audit_report["legacy_records"]),
        total_records=int(audit_report["total_records"]),
    )

    if anchor_store is None:
        anchor = ObserverAnchorState(
            available=False,
            head_hash=None,
            anchored_records=0,
            verified=None,
            reason="anchor_store_absent",
            anchors_checked=0,
        )
    else:
        anchors = anchor_store.anchors()
        verification = verify_anchored_audit(
            kernel.audit, anchors, verifier=anchor_verifier
        )
        anchor = ObserverAnchorState(
            available=True,
            head_hash=anchors[-1].head_hash if anchors else None,
            anchored_records=int(verification.anchored_records),
            verified=bool(verification.ok),
            reason=None if verification.ok else verification.reason,
            anchors_checked=int(verification.anchors_checked),
        )

    resolved_deployment_id = deployment_id
    if resolved_deployment_id is None and leases:
        resolved_deployment_id = leases[0].deployment_id
    resolved_device_id = device_id
    if resolved_device_id is None and device_ids is not None and resolved_deployment_id is not None:
        resolved_device_id = device_ids.get(resolved_deployment_id)

    if journal is None:
        journal_tip = ObserverJournalTip(
            available=False,
            sequence=None,
            last_event=None,
            last_record_hash=None,
            verified=None,
            verification_reason=None,
            deployment_id=None,
            device_id=None,
        )
    else:
        try:
            records = journal.read(verify=True)
        except ValueError:
            journal_tip = ObserverJournalTip(
                available=True,
                sequence=None,
                last_event=None,
                last_record_hash=None,
                verified=False,
                verification_reason="journal_integrity_failure",
                deployment_id=resolved_deployment_id,
                device_id=resolved_device_id,
            )
        else:
            tip = records[-1] if records else None
            journal_tip = ObserverJournalTip(
                available=True,
                sequence=tip.sequence if tip is not None else None,
                last_event=tip.event if tip is not None else None,
                last_record_hash=tip.record_hash if tip is not None else None,
                verified=True,
                verification_reason=None,
                deployment_id=resolved_deployment_id,
                device_id=resolved_device_id,
            )

    lease_summaries = tuple(
        _lease_summary(
            lease,
            device_id=(
                device_ids.get(lease.deployment_id)
                if device_ids is not None
                else None
            ),
            commands_remaining=_lease_commands_remaining(
                lease, commands_remaining
            ),
            now=now,
        )
        for lease in leases
    )

    drift_heads = tuple(
        _drift_head_summary(
            evaluation,
            last_evaluated_ns=(
                drift_evaluated_at_ns.get(evaluation.sensor_id)
                if drift_evaluated_at_ns is not None
                else None
            ),
            calibration_age_days=(
                drift_calibration_age_days.get(evaluation.sensor_id)
                if drift_calibration_age_days is not None
                else None
            ),
            last_calibration_ns=(
                drift_last_calibration_ns.get(evaluation.sensor_id)
                if drift_last_calibration_ns is not None
                else None
            ),
            calibration_interval_days=(
                drift_calibration_interval_days.get(evaluation.sensor_id)
                if drift_calibration_interval_days is not None
                else None
            ),
            next_calibration_due_ns=(
                drift_next_calibration_due_ns.get(evaluation.sensor_id)
                if drift_next_calibration_due_ns is not None
                else None
            ),
            rated_life_expiry_ns=(
                drift_rated_life_expiry_ns.get(evaluation.sensor_id)
                if drift_rated_life_expiry_ns is not None
                else None
            ),
            span_check_passed=(
                drift_span_check_passed.get(evaluation.sensor_id)
                if drift_span_check_passed is not None
                else None
            ),
            span_check_ns=(
                drift_span_check_ns.get(evaluation.sensor_id)
                if drift_span_check_ns is not None
                else None
            ),
        )
        for evaluation in drift_evaluations
    )

    # The incident report is derived audit-only when the deployment did
    # not supply one, exactly as freeze_incident_report does with
    # custody=None: counts only, no custody resolution.
    report = incident_report
    if report is None:
        report = freeze_incident_report(orchestrator)

    reconciliation_state, reconciliation_since_ns, last_reconciliation_completed_ns = (
        _reconciliation_state(protocols, resolved_deployment_id, frozen_at_ns)
    )

    return ObserverSnapshot(
        source_id=source_id,
        deployment_id=resolved_deployment_id,
        device_id=resolved_device_id,
        frozen_at_ns=frozen_at_ns,
        policy_hash=evidence.policy_hash,
        audit_valid=evidence.audit_valid,
        audit_records=evidence.audit_records,
        audit_tip=evidence.audit_tip,
        audit_window=_audit_window(kernel.audit, audit_window_records),
        signatures=signatures,
        anchor=anchor,
        journal=journal_tip,
        leases=lease_summaries,
        drift_heads=drift_heads,
        incidents=int(report.incidents),
        near_misses=int(report.near_misses),
        incident_report_available=True,
        incident_report_frozen_at_ns=int(report.observed_at_ns),
        reconciliation_state=reconciliation_state,
        reconciliation_since_ns=reconciliation_since_ns,
        last_reconciliation_completed_ns=last_reconciliation_completed_ns,
    )


def export_observer_snapshot(
    orchestrator: PulpoOrchestrator,
    destination: str | os.PathLike[str],
    **kwargs: Any,
) -> ObserverSnapshot:
    """Atomically export one frozen observer snapshot from trusted Pulpo.

    Size preflight: the snapshot is serialized exactly as
    ``_publish_snapshot`` will serialize it, and an over-limit snapshot
    fails here -- before anything is published -- so an export can never
    produce a file that ``load_observer_snapshot`` would reject.
    """

    snapshot = freeze_observer_snapshot(orchestrator, **kwargs)
    payload = json.dumps(asdict(snapshot), sort_keys=True, separators=(",", ":")) + "\n"
    if len(payload.encode("utf-8")) > MAX_OBSERVER_SNAPSHOT_BYTES:
        raise MCPBoundaryError("observer_snapshot_too_large")
    return _publish_snapshot(snapshot, destination)


def _load_section(value: object, section: type) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {item.name for item in fields(section)}:
        raise ValueError("snapshot_fields_invalid")
    return value


def load_observer_snapshot(path: str | os.PathLike[str]) -> ObserverSnapshot:
    """Load one frozen observer snapshot through the hardened reader.

    Any malformed, oversize, stale, or wrong-schema input raises: the
    caller (the CC) treats a load failure as Unknown, never as a stale
    good value. No field is defaulted from another field, and no record
    is guessed into a device. Two deliberate exceptions: a drift head
    from a document frozen before the calibration-provenance fields
    existed may omit any of ``DRIFT_HEAD_PROVENANCE_FIELDS``; each
    missing one reads as ``None`` (unknown), because absence of a
    provenance field is semantically identical to ``None``. And a
    document frozen before the audit window existed may omit
    ``audit_window`` (see ``OPTIONAL_SNAPSHOT_FIELDS``); it reads as
    ``None`` (no window in this document), for the same reason. Every
    other field on every section is still enforced exactly -- a
    missing required field or an unknown extra field still rejects
    the document, including a missing ``commands_remaining`` on a
    lease (design item 5.3).
    """

    value = read_snapshot_document(path, max_bytes=MAX_OBSERVER_SNAPSHOT_BYTES)
    snapshot_fields = {item.name for item in fields(ObserverSnapshot)}
    if not snapshot_fields - OPTIONAL_SNAPSHOT_FIELDS <= set(value) <= snapshot_fields:
        raise ValueError("snapshot_fields_invalid")
    # Documents frozen before the audit window existed omit it; it
    # reads as None (no window in this document).
    value.setdefault("audit_window", None)
    value["signatures"] = ObserverSignatureSummary(
        **_load_section(value["signatures"], ObserverSignatureSummary)
    )
    value["anchor"] = ObserverAnchorState(
        **_load_section(value["anchor"], ObserverAnchorState)
    )
    value["journal"] = ObserverJournalTip(
        **_load_section(value["journal"], ObserverJournalTip)
    )
    if value["audit_window"] is not None:
        window = value["audit_window"]
        if type(window) is not dict or set(window) != {
            item.name for item in fields(ObserverAuditWindow)
        }:
            raise ValueError("snapshot_nested_invalid")
        if type(window["records"]) is not list or any(
            type(record) is not dict
            or set(record) != {item.name for item in fields(ObserverAuditRecord)}
            for record in window["records"]
        ):
            raise ValueError("snapshot_nested_invalid")
        value["audit_window"] = ObserverAuditWindow(
            records=tuple(
                ObserverAuditRecord(**record) for record in window["records"]
            ),
            window_start_sequence=window["window_start_sequence"],
            window_end_sequence=window["window_end_sequence"],
            total_records=window["total_records"],
            complete=window["complete"],
        )
    if type(value["leases"]) is not list or any(
        type(lease) is not dict
        or set(lease) != {item.name for item in fields(ObserverLeaseSummary)}
        for lease in value["leases"]
    ):
        raise ValueError("snapshot_nested_invalid")
    value["leases"] = tuple(ObserverLeaseSummary(**lease) for lease in value["leases"])
    drift_head_fields = {item.name for item in fields(ObserverDriftHead)}
    required_drift_head_fields = drift_head_fields - DRIFT_HEAD_PROVENANCE_FIELDS
    if type(value["drift_heads"]) is not list or any(
        type(head) is not dict
        or not required_drift_head_fields <= set(head) <= drift_head_fields
        for head in value["drift_heads"]
    ):
        raise ValueError("snapshot_nested_invalid")
    drift_heads = []
    for head in value["drift_heads"]:
        if type(head["reasons"]) is not list:
            raise ValueError("snapshot_nested_invalid")
        drift_heads.append(
            ObserverDriftHead(
                **{
                    # Documents frozen before the provenance fields
                    # existed omit them; each reads as None (unknown).
                    **{name: None for name in DRIFT_HEAD_PROVENANCE_FIELDS},
                    **head,
                    "reasons": tuple(head["reasons"]),
                }
            )
        )
    value["drift_heads"] = tuple(drift_heads)
    return ObserverSnapshot(**value)
