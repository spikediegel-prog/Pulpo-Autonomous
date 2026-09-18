# Offline autonomy

Pulpo Autonomous supports bounded mission continuation when a robot, vehicle,
drone, or spacecraft loses its connection to the authority service. This is
not a disconnected authority grant. It is execution of authority that was
already granted by the canonical Pulpo kernel.

## Protocol

The unit follows this lifecycle:

```text
CONNECTED → DISCONNECTED → RECONNECTING → RECONCILING → CONNECTED
```

An `OfflineMissionLease` binds the continuation window to:

- the canonical permit;
- machine, principal, policy, deployment, and session identity;
- a unique nonce and lease ID;
- permit expiry;
- maximum disconnected duration;
- optional maximum command count;
- a pre-authorized safe fallback.

The unit can execute only while the original permit and the bounded offline
lease are active. Disconnection cannot extend the lease, increase its budget,
add objectives, or create retry authority.

## Execution and reconciliation

Command IDs are idempotent. A command already recorded as sent is not sent
again. The durable journal records planned, sent, vetoed, observed, unknown,
and safe-fallback events.

An uncertain result is recorded as `UNKNOWN`. It is not converted into
`OBSERVED_FAILURE`, and it does not authorize a retry. On reconnection,
execution is blocked during `RECONCILING` while the journal is compared with
canonical Pulpo state and external observations.

When the permit expires, the offline window ends, or the command budget is
exhausted, the unit records and enters the lease's already-authorized
`safe_fallback`. It cannot invent a new fallback while disconnected.

## Evidence and integrity

`core/journal.py` stores append-only JSONL records with sequence numbers and a
hash chain. Integrity verification fails closed if a record is modified,
removed, reordered, or appended with the wrong predecessor hash.

The journal is an evidence and local execution record. It is not a second
authority ledger, permit issuer, router, executor, or reconciliation source.
The canonical `pulpo/` kernel remains the sole authority source.

## Verified evidence

The focused test suite in `tests/test_offline_autonomy.py` verifies:

- disconnection preserves bounded authority but cannot extend it;
- reconciliation blocks execution;
- duplicate command IDs are not resent;
- expired leases use only the pre-authorized fallback;
- command budgets use only the pre-authorized fallback;
- unknown outcomes do not create retry authority;
- journal tampering fails closed.

Run it with:

```bash
python -m unittest tests.test_offline_autonomy -v
```

## Change record

- **Invariant addressed:** disconnection may preserve previously granted
  authority for a bounded period; it may never create, extend, or enlarge
  authority. Uncertain execution cannot create retry authority.
- **Authority change:** no authority is gained. The offline layer narrows
  execution using expiry, disconnected duration, command budget, idempotency,
  and reconciliation gates.
- **Canonical mutation:** the local journal appends execution evidence and
  consumption records. That mutation is controlled by the execution tracker
  and does not mutate canonical Pulpo authority state.
- **Exact success evidence:** the seven focused offline tests pass at the
  implementation commit, including expiry, replay, fallback, reconciliation,
  unknown-state, and journal-integrity cases.
- **Boundary not proved:** this does not prove radiation hardening, secure
  hardware storage, trusted clock behavior, transport security, real vehicle
  control, physical maneuver success, or production readiness.
- **Claim classification:** the protocol behavior is **Verified** by the
  focused tests; deployment and physical-system claims remain **Proposed** or
  **Unknown**.
- **Legacy behavior source:** Pulpo 1.0's canonical permit, policy, state, and
  evidence path is reused as the authority source without copying its control
  path into the autonomy adapters.
- **Temporal transfer:** no relevant historical checkpoint for this new
  offline mission-completion behavior was identified; no temporal proof is
  claimed.
