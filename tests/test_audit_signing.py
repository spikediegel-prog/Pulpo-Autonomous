"""Signed audit records (Phase 2, Item 1, port of upstream PR #357).

Every audit record appended after signing is enabled carries an HMAC
over its own hash under a dedicated per-deployment ``audit-secret``
that is deliberately NOT the kernel secret: a single theft must not
yield both permit minting and undetectable history forgery. The
signature is a sibling field excluded from the hashed body, so the
unkeyed chain math is unchanged.

Port notes (Pulpo Autonomous) — read before changing these tests:

* There is no ops CLI in this tree, so the upstream
  ``AuditSigningOpsTests`` class is not ported and no ``pulpo.ops``
  import appears here. Enablement is recorded in deployment config
  outside the state file; these tests drive the state/kernel layer
  directly.
* Audit records here carry delta fields (``delta``,
  ``previous_delta_root``, ``delta_root``) hashed into the record.
  The signature is therefore computed AFTER ``_attach_delta``, over
  the final hash — signing inside ``_audit_record`` (upstream's way)
  would sign a hash ``_attach_delta`` then changes. The
  ``rehash_suffix_keep_signatures`` helper below is delta-aware for
  the same reason: a rebuilt suffix keeps its stale signatures and
  must fail as ``audit_signature_invalid``, not
  ``audit_hash_mismatch``.
* ``verify_audit_report`` already existed in this tree (from the #371
  port) with a blanket rule that any present signature fails. These
  tests pin the replacement rule: a signature verifies against the
  state's signer, a missing one at/after the legacy prefix fails, and
  a present signature with no signer configured is an opaque field
  the chain verifies past legacy-style (disabling signing must not
  brick a chain signed under an earlier config).
* ``issue_permit`` requires ``expires_at_ns`` in this tree
  (bounded-expiry port); tests that mint permits pass one.
* The anchor interaction is pinned by
  ``test_anchor_over_signed_chain_verifies``: the ported #352
  ``pulpo/anchor.py`` ``_chain_valid`` excludes ``"signature"`` from
  the hashed body (the #357 commit's one-line anchor change), or
  anchoring a signed trail disagrees with the kernel's hash.

Adversarial transformation review: the eight passes (Flip, Reverse,
Invert, Inside-Out, Darken, Lighten, Amplify, Negate) for this change
are recorded in the PR body per ``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``.
Stop/continue decision recorded there: CONTINUE — signing observes
the audit trail and appends nothing to canonical kernel state beyond
the signature sibling field.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import tempfile
import unittest
from pathlib import Path

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
    anchor_records,
    verify_anchored_audit,
)
from pulpo.anchor import InMemoryAnchorStore
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_evidence import (
    CustodyEvidenceViolation,
    SQLiteCustodyEvidenceConvergence,
)
from pulpo.state import (
    AuditSigner,
    InMemoryKernelState,
    SQLiteKernelState,
    _attach_delta,
    _audit_record,
    _canonical,
)

SECRET = b"audit-secret"
WRONG_SECRET = b"wrong-audit-secret"
KERNEL_SECRET = b"kernel-secret"
NOW = 81_000_000


def _signed_kernel(secret: bytes = SECRET, legacy_records: int = 0):
    signer = AuditSigner(secret)
    state = InMemoryKernelState(audit_signer=signer, legacy_audit_records=legacy_records)
    kernel = GovernanceKernel(
        Policy(frozenset({"read"}), 100),
        secret=KERNEL_SECRET,
        state=state,
    )
    return kernel, state, signer


def _allow(kernel: GovernanceKernel):
    return kernel.evaluate(Intent("actor", "read", "resource:1", 0, "session"))


def _rehash_suffix_keep_signatures(state: InMemoryKernelState, start: int):
    """Rebuild the suffix from ``start`` with fresh hashes, keeping stale signatures.

    Delta-aware: each rebuilt record is re-hashed over the body
    including its recomputed delta, and the suffix's delta roots are
    re-chained from the record before ``start``. The signatures are
    left as they were, so they no longer match the new hashes — the
    kernel must refuse the suffix as ``audit_signature_invalid``,
    not as a hash/delta mismatch.
    """
    records = state.audit
    previous = records[start - 1]["hash"] if start else "0" * 64
    previous_root = (
        records[start - 1].get("delta_root", records[start - 1]["hash"])
        if start
        else "0" * 64
    )
    for record in records[start:]:
        record["previous_hash"] = previous
        delta = record.get("delta")
        if delta is not None:
            # The recomputed delta roots are written back into the
            # record: the kernel's verifier hashes the record as it
            # stands, so a helper-local body would not describe what
            # the verifier sees.
            record["previous_delta_root"] = previous_root
            record["delta_root"] = hashlib.sha256(
                previous_root.encode() + _canonical(delta)
            ).hexdigest()
        body = {key: value for key, value in record.items() if key not in ("hash", "signature")}
        record["hash"] = hashlib.sha256(_canonical(body)).hexdigest()
        previous = record["hash"]
        previous_root = record.get("delta_root", record["hash"])


class AuditSignerTests(unittest.TestCase):
    def test_signature_is_hmac_over_the_record_hash(self):
        signer = AuditSigner(SECRET)
        digest = "a" * 64
        expected = hmac.new(SECRET, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual(expected, signer.sign(digest))
        self.assertTrue(signer.verify(digest, expected))
        self.assertFalse(signer.verify("b" * 64, expected))

    def test_empty_secret_rejected(self):
        with self.assertRaises(ValueError):
            AuditSigner(b"")

    def test_verification_is_constant_time_and_rejects_wrong_hash(self):
        signer = AuditSigner(SECRET)
        signature = signer.sign("a" * 64)
        self.assertFalse(signer.verify("a" * 64, "not-a-signature"))
        self.assertFalse(signer.verify("a" * 64, None))
        self.assertFalse(signer.verify("a" * 64, 1234))
        self.assertTrue(signer.verify("a" * 64, signature))
        # A different secret's signature for the same hash never verifies.
        self.assertFalse(signer.verify("a" * 64, AuditSigner(WRONG_SECRET).sign("a" * 64)))


class SignedAuditLibraryTests(unittest.TestCase):
    def test_signed_chain_verifies_and_reports_coverage(self):
        kernel, state, _ = _signed_kernel()
        for _ in range(3):
            _allow(kernel)
        report = kernel.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertIsNone(report["reason"])
        self.assertEqual(3, report["total_records"])
        self.assertEqual(3, report["signed_records"])
        self.assertEqual(0, report["unsigned_records"])
        self.assertEqual(0, report["legacy_records"])
        self.assertTrue(report["signing_enabled"])
        self.assertTrue(kernel.verify_audit())
        for record in state.audit:
            self.assertIn("signature", record)

    def test_kernel_without_signer_stays_legacy(self):
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=InMemoryKernelState(),
        )
        for _ in range(3):
            _allow(kernel)
        report = kernel.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertFalse(report["signing_enabled"])
        self.assertEqual(3, report["unsigned_records"])
        self.assertEqual(0, report["signed_records"])
        self.assertTrue(kernel.verify_audit())

    def test_single_signature_replaced_with_garbage_refused(self):
        kernel, state, _ = _signed_kernel()
        for _ in range(3):
            _allow(kernel)
        state.audit[1]["signature"] = "garbage-signature"
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        self.assertEqual(1, report["failed_record"])
        self.assertFalse(kernel.verify_audit())

    def test_single_signature_stripped_refused(self):
        kernel, state, _ = _signed_kernel()
        for _ in range(3):
            _allow(kernel)
        del state.audit[1]["signature"]
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_missing", report["reason"])
        self.assertEqual(1, report["failed_record"])
        self.assertFalse(kernel.verify_audit())

    def test_signature_excluded_from_hashed_body(self):
        # The record hash covers every body field except "hash" and
        # "signature" — including the delta fields, which are part of
        # the body in this tree. Recomputing the hash from that body
        # must reproduce the stored hash, and the stored signature
        # must verify against it.
        kernel, state, signer = _signed_kernel()
        _allow(kernel)
        record = state.audit[0]
        body = {
            key: value
            for key, value in record.items()
            if key not in ("hash", "signature")
        }
        self.assertEqual(
            hashlib.sha256(_canonical(body)).hexdigest(),
            record["hash"],
        )
        self.assertTrue(signer.verify(record["hash"], record["signature"]))
        # And a body that still carries the signature hashes differently.
        body_with_signature = dict(body)
        body_with_signature["signature"] = record["signature"]
        self.assertNotEqual(
            hashlib.sha256(_canonical(body_with_signature)).hexdigest(),
            record["hash"],
        )

    def test_unsigned_record_after_signed_prefix_refused(self):
        # A writer that bypasses the signer and appends an unsigned
        # record to a signed chain: the verifier must refuse it as
        # missing, not silently accept the tail as unsigned.
        kernel, state, _ = _signed_kernel()
        _allow(kernel)
        _allow(kernel)
        previous = state.audit[-1]["hash"]
        previous_root = state.audit[-1].get("delta_root", state.audit[-1]["hash"])
        unsigned = _attach_delta(
            _audit_record(previous, "decision", {"outcome": "allow"}, NOW),
            previous_root,
        )
        self.assertNotIn("signature", unsigned)
        state._audit.append(unsigned)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_missing", report["reason"])
        self.assertEqual(2, report["failed_record"])
        self.assertFalse(kernel.verify_audit())

    def test_empty_signed_chain_cannot_tell_the_projection_it_is_signed(self):
        # A signed chain with zero records carries no evidence that it
        # is signed. An unsigned record projected into it is refused
        # at the next boot — availability loss, fail-closed — rather
        # than silently accepted as the chain's first record.
        kernel, state, _ = _signed_kernel()
        self.assertEqual(0, len(state.audit))
        unsigned = _attach_delta(
            _audit_record("0" * 64, "decision", {"outcome": "allow"}, NOW),
            "0" * 64,
        )
        state._audit.append(unsigned)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_missing", report["reason"])
        self.assertEqual(0, report["failed_record"])

    def test_legacy_prefix_verifies_unsigned_then_signed_tail(self):
        kernel, state, _ = _signed_kernel(legacy_records=2)
        # Two legacy records, appended unsigned before enablement.
        for _ in range(2):
            previous = state.audit[-1]["hash"] if state.audit else "0" * 64
            previous_root = (
                state.audit[-1].get("delta_root", state.audit[-1]["hash"])
                if state.audit
                else "0" * 64
            )
            state._audit.append(
                _attach_delta(
                    _audit_record(previous, "decision", {"outcome": "allow"}, NOW),
                    previous_root,
                )
            )
        # Two signed records after enablement, through the kernel.
        _allow(kernel)
        _allow(kernel)
        report = kernel.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertEqual(4, report["total_records"])
        self.assertEqual(2, report["legacy_records"])
        self.assertEqual(2, report["unsigned_records"])
        self.assertEqual(2, report["signed_records"])
        self.assertTrue(kernel.verify_audit())

    def test_signature_on_legacy_prefix_record_must_verify_when_signer_present(self):
        # A garbage signature on a legacy-prefix record is not
        # excused by the prefix: with a signer configured, any present
        # signature must verify.
        kernel, state, _ = _signed_kernel(legacy_records=2)
        for _ in range(2):
            previous = state.audit[-1]["hash"] if state.audit else "0" * 64
            previous_root = (
                state.audit[-1].get("delta_root", state.audit[-1]["hash"])
                if state.audit
                else "0" * 64
            )
            state._audit.append(
                _attach_delta(
                    _audit_record(previous, "decision", {"outcome": "allow"}, NOW),
                    previous_root,
                )
            )
        state.audit[0]["signature"] = "garbage-signature"
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        self.assertEqual(0, report["failed_record"])

    def test_rehash_suffix_keeps_stale_signatures_and_is_refused(self):
        # Mid-chain deletion with rehashing — the anchor's classic
        # case — is now refused at the record layer too: the rebuilt
        # suffix carries stale signatures.
        kernel, state, _ = _signed_kernel()
        for _ in range(3):
            _allow(kernel)
        _rehash_suffix_keep_signatures(state, 1)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        self.assertEqual(1, report["failed_record"])
        self.assertFalse(kernel.verify_audit())

    def test_payload_edit_with_rehash_refused_signed_in_memory(self):
        kernel, state, _ = _signed_kernel()
        _allow(kernel)
        _allow(kernel)
        record = state.audit[1]
        record["payload"] = {"outcome": "deny"}
        # Rebuild the suffix delta-aware, keeping the stale signature.
        _rehash_suffix_keep_signatures(state, 1)
        report = kernel.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        self.assertEqual(1, report["failed_record"])

    def test_signed_sqlite_chain_verifies_after_reopen(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        signer = AuditSigner(SECRET)
        state = SQLiteKernelState(path, audit_signer=signer)
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=state,
        )
        for _ in range(3):
            _allow(kernel)
        state.close()
        reopened = SQLiteKernelState(path, audit_signer=signer)
        kernel2 = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=reopened,
        )
        report = kernel2.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertEqual(3, report["signed_records"])
        self.assertTrue(kernel2.verify_audit())
        reopened.close()

    def test_signed_sqlite_chain_reopened_without_signer_verifies_legacy(self):
        # Disabling signing is a deployment decision: a chain signed
        # under an earlier config verifies legacy-style when reopened
        # without a signer, and its signatures count as unsigned
        # opaque fields rather than bricking the boot.
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        signer = AuditSigner(SECRET)
        state = SQLiteKernelState(path, audit_signer=signer)
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=state,
        )
        for _ in range(3):
            _allow(kernel)
        state.close()
        reopened = SQLiteKernelState(path)
        kernel2 = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=reopened,
        )
        report = kernel2.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertFalse(report["signing_enabled"])
        self.assertEqual(3, report["unsigned_records"])
        self.assertEqual(0, report["signed_records"])
        self.assertTrue(kernel2.verify_audit())
        reopened.close()

    def test_payload_edit_with_rehash_refused_signed_sqlite(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        signer = AuditSigner(SECRET)
        state = SQLiteKernelState(path, audit_signer=signer)
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=state,
        )
        _allow(kernel)
        _allow(kernel)
        state.close()
        # The kernel is constructed BEFORE tampering: its boot check
        # runs on construction and would raise StateIntegrityError over
        # a tampered chain, so the report must be read from this
        # already-constructed kernel — whose SQLite state re-reads the
        # rows live — rather than from a fresh boot.
        reopened = SQLiteKernelState(path, audit_signer=signer)
        kernel2 = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=reopened,
        )
        self.assertTrue(kernel2.verify_audit())
        # Tamper: rewrite the second record's payload and rehash the
        # suffix, delta-aware (recompute the delta and delta_root and
        # update delta_json), keeping the stale signature.
        from pulpo.state import _delta_for, _delta_state_root

        with sqlite3.connect(path) as connection:
            rows = connection.execute(
                "SELECT sequence, event, payload_json, previous_hash, timestamp_ns, hash, delta_json, previous_delta_root, delta_root FROM audit ORDER BY sequence"
            ).fetchall()
            self.assertEqual(2, len(rows))
            first_hash = rows[0][5]
            first_root = rows[0][8]
            record = {
                "event": rows[1][1],
                "payload": {"outcome": "deny"},
                "previous_hash": first_hash,
                "timestamp_ns": rows[1][4],
            }
            delta = _delta_for(record["event"], record["payload"])
            delta_root = _delta_state_root(first_root, delta)
            body = dict(record)
            body["delta"] = delta
            body["previous_delta_root"] = first_root
            body["delta_root"] = delta_root
            new_hash = hashlib.sha256(_canonical(body)).hexdigest()
            connection.execute(
                "UPDATE audit SET payload_json = ?, hash = ?, delta_json = ?, delta_root = ? WHERE sequence = ?",
                (
                    _canonical(record["payload"]).decode(),
                    new_hash,
                    _canonical(delta).decode(),
                    delta_root,
                    rows[1][0],
                ),
            )
        report = kernel2.verify_audit_report()
        self.assertFalse(report["ok"])
        self.assertEqual("audit_signature_invalid", report["reason"])
        self.assertEqual(1, report["failed_record"])
        reopened.close()

    def test_anchor_over_signed_chain_verifies(self):
        # The anchor/signature interaction: a signed trail must still
        # anchor and verify — _chain_valid excludes "signature" from
        # the hashed body, so the witness agrees with the kernel.
        kernel, state, _ = _signed_kernel()
        for _ in range(3):
            _allow(kernel)
        store = InMemoryAnchorStore()
        anchor = anchor_records(state.audit, store)
        self.assertIsNotNone(anchor)
        result = verify_anchored_audit(state.audit, store.anchors())
        self.assertTrue(result.ok)
        self.assertEqual("anchored_prefix_verified", result.reason)
        self.assertEqual(3, result.anchored_records)

    def test_kernel_rejects_signer_and_state_together(self):
        signer = AuditSigner(SECRET)
        state = InMemoryKernelState(audit_signer=signer)
        with self.assertRaises(ValueError):
            GovernanceKernel(
                Policy(frozenset({"read"}), 100),
                secret=KERNEL_SECRET,
                state=state,
                audit_signer=signer,
            )

    def test_kernel_accepts_signer_without_state(self):
        kernel, state, _ = _signed_kernel()
        _allow(kernel)
        self.assertEqual(1, kernel.verify_audit_report()["signed_records"])


class CustodyEvidenceSigningTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))
        state = SQLiteKernelState(self.path)
        state.close()
        self.custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"custody-secret",
            clock=lambda: NOW,
        )

    def _authorize(self):
        head = self.custody.snapshot()
        return self.custody.authorize_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            object_hash="1" * 64,
            target_hash="2" * 64,
            permit_hash="3" * 64,
            authorization_hash="4" * 64,
        )

    def _project(self, evidence):
        # authorize_attempt commits the obligation; projecting it is
        # all the convergence has to do (no claim/commit step).
        self._authorize()
        return evidence.project_all()

    def test_projection_without_signer_into_unsigned_chain(self):
        evidence = SQLiteCustodyEvidenceConvergence(self.custody)
        projected = self._project(evidence)
        self.assertEqual(1, len(projected))
        state = SQLiteKernelState(self.path)
        self.assertNotIn("signature", state.audit[0])
        state.close()

    def test_projection_with_signer_into_unsigned_chain_signs(self):
        evidence = SQLiteCustodyEvidenceConvergence(
            self.custody, audit_signer=AuditSigner(SECRET)
        )
        projected = self._project(evidence)
        self.assertEqual(1, len(projected))
        state = SQLiteKernelState(self.path, audit_signer=AuditSigner(SECRET))
        self.assertIn("signature", state.audit[0])
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=state,
        )
        self.assertTrue(kernel.verify_audit())
        state.close()

    def test_projection_without_signer_into_signed_chain_refused(self):
        # Seed a signed record into the canonical chain first, then
        # project without a signer: the guard refuses before writing.
        signer = AuditSigner(SECRET)
        state = SQLiteKernelState(self.path, audit_signer=signer)
        state.append("decision", {"outcome": "allow"}, NOW)
        state.close()
        evidence = SQLiteCustodyEvidenceConvergence(self.custody)
        with self.assertRaises(CustodyEvidenceViolation):
            self._project(evidence)
        state = SQLiteKernelState(self.path)
        self.assertEqual(1, len(state.audit))
        state.close()

    def test_projection_with_signer_into_signed_chain_signs(self):
        signer = AuditSigner(SECRET)
        state = SQLiteKernelState(self.path, audit_signer=signer)
        state.append("decision", {"outcome": "allow"}, NOW)
        state.close()
        evidence = SQLiteCustodyEvidenceConvergence(
            self.custody, audit_signer=signer
        )
        projected = self._project(evidence)
        self.assertEqual(1, len(projected))
        state = SQLiteKernelState(self.path, audit_signer=signer)
        self.assertEqual(2, len(state.audit))
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=state,
        )
        self.assertTrue(kernel.verify_audit())
        self.assertEqual(2, kernel.verify_audit_report()["signed_records"])
        state.close()


class ProjectionMigrationStateTests(unittest.TestCase):
    def _build_true_legacy_db(self, path: Path, records: int):
        """Build a legacy database exactly as the pre-#357 code did.

        The audit table carries the delta columns (those predate
        signing in this tree) and NO signature column; records are
        inserted without delta and without signature, so they read
        back with delta None — legacy records in this tree's sense.
        """
        with sqlite3.connect(path) as connection:
            connection.executescript(
                """
                CREATE TABLE audit (
                    sequence INTEGER PRIMARY KEY,
                    event TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    timestamp_ns INTEGER NOT NULL,
                    hash TEXT NOT NULL,
                    delta_json TEXT,
                    previous_delta_root TEXT,
                    delta_root TEXT
                );
                CREATE TABLE directives (
                    directive_hash TEXT PRIMARY KEY,
                    directive_json TEXT NOT NULL
                );
                CREATE TABLE permits (
                    permit_hash TEXT PRIMARY KEY,
                    approval_hash TEXT,
                    directive_hash TEXT,
                    issued_at_ns INTEGER,
                    expires_at_ns INTEGER,
                    spent INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE permit_directives (
                    permit_hash TEXT PRIMARY KEY,
                    directive_hash TEXT NOT NULL,
                    bound_at_ns INTEGER NOT NULL,
                    parent_directive_hash TEXT
                );
                CREATE TABLE audit_unique (
                    event TEXT NOT NULL,
                    identity_field TEXT NOT NULL,
                    identity_value_json TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    PRIMARY KEY (event, identity_field, identity_value_json)
                );
                """
            )
            previous = "0" * 64
            for index in range(records):
                record = _audit_record(
                    previous,
                    "decision",
                    {"outcome": "allow"},
                    NOW + index,
                )
                connection.execute(
                    """
                    INSERT INTO audit
                        (event, payload_json, previous_hash, timestamp_ns, hash)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record["event"],
                        _canonical(record["payload"]).decode(),
                        record["previous_hash"],
                        record["timestamp_ns"],
                        record["hash"],
                    ),
                )
                previous = record["hash"]

    def test_read_only_open_over_legacy_db_does_not_migrate(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        self._build_true_legacy_db(path, 2)
        state = SQLiteKernelState(path, migrate_schema=False)
        self.assertEqual(2, len(state.audit))
        self.assertFalse(state._audit_has_signature)
        columns = {
            row[1]
            for row in sqlite3.connect(path).execute("PRAGMA table_info(audit)").fetchall()
        }
        self.assertNotIn("signature", columns)
        state.close()

    def test_read_only_open_over_legacy_db_verifies_legacy(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        self._build_true_legacy_db(path, 2)
        state = SQLiteKernelState(path, migrate_schema=False)
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=state,
        )
        self.assertTrue(kernel.verify_audit())
        report = kernel.verify_audit_report()
        self.assertEqual(2, report["unsigned_records"])
        self.assertEqual(0, report["signed_records"])
        state.close()

    def test_mutating_open_migrates_legacy_db(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        self._build_true_legacy_db(path, 2)
        state = SQLiteKernelState(path)
        self.assertTrue(state._audit_has_signature)
        state.close()
        # Reopen with a signer and the legacy count: the two pre-existing
        # records verify unsigned, the new one is signed at append.
        state = SQLiteKernelState(
            path, audit_signer=AuditSigner(SECRET), legacy_audit_records=2
        )
        state.append("decision", {"outcome": "allow"}, NOW + 99)
        self.assertEqual(3, len(state.audit))
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 100),
            secret=KERNEL_SECRET,
            state=state,
        )
        report = kernel.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertEqual(2, report["unsigned_records"])
        self.assertEqual(1, report["signed_records"])
        state.close()

    def test_append_with_signer_without_signature_column_fails_loudly(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        self._build_true_legacy_db(path, 1)
        state = SQLiteKernelState(
            path, audit_signer=AuditSigner(SECRET), migrate_schema=False
        )
        with self.assertRaises(RuntimeError):
            state.append("decision", {"outcome": "allow"}, NOW)
        state.close()

    def test_unsigned_append_through_read_only_open_fails_loudly(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))
        self._build_true_legacy_db(path, 1)
        state = SQLiteKernelState(path, migrate_schema=False)
        with self.assertRaises(sqlite3.OperationalError):
            state.append("decision", {"outcome": "allow"}, NOW)
        state.close()


if __name__ == "__main__":
    unittest.main()
