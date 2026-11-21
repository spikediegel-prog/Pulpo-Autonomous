"""Phase 2, Item 4 — permit token v2: signed permit expiry and the policy TTL cap.

Port of upstream Ironnember/Pulpo1.0 #358 (head 31e556f17, merged).
Adapted for Autonomous, where most of #358 already exists: the v3
presenter-binding port (Item 4B, PR #24) brought the signed-expiry
token format (Autonomous jumps v1 straight to v3, so tokens are
``digest:nonce:issued:expiry:presenter_hash:signature``), the strict
``_token_time_ns`` guard, and the store's recorded-expiry re-check on
both backends. What this port adds is the remainder — the policy-side
TTL ceiling (``PERMIT_TTL_CEILING_NS``, 24 hours) validated at
``Policy`` construction — plus the tests that pin the expiry behavior
already present in this tree.

Fork divergences, kept deliberately (see pulpo/kernel.py and the
change record): the field is ``permit_ttl_ns`` here, not upstream's
``max_permit_ttl_ns``; its default is 5 minutes, not upstream's 4
hours; and this tree binds ``permit_ttl_ns`` into the policy hash
unconditionally, where upstream binds its field only when
non-default. The token-shape tests below are therefore written
against v3 (6 parts), not v2 (5 parts).

Not ported from upstream's test file: the v1-cutover tests (already
covered by tests/test_presenter_binding.py CutoverTests) and the ops
lifecycle tests (no ops CLI exists in this tree).

One more divergence the tests pin by assertion shape: an expired
permit refused at consume is recorded by the store as
``permit_rejected`` whose payload carries ``permit_expires_at_ns``
— this tree records no distinct ``permit_expired`` reason, unlike
upstream (whose kernel layer refuses with reason ``permit_expired``
before consulting the store; here expiry enforcement stays in the
state layer by the #373 port's design decision). The expiry tests
below therefore assert on the event + the expiry field, not on a
reason string.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.kernel import (
    DEFAULT_PERMIT_TTL_NS,
    PERMIT_TTL_CEILING_NS,
    UNBOUND_PRESENTER_HASH,
)
from pulpo.state import InMemoryKernelState, SQLiteKernelState

SECRET = "permit-ttl-test-secret".encode("utf-8")
T0 = 1_700_000_000_000_000_000
HOUR_NS = 3600 * 1_000_000_000
YEAR_NS = 365 * 24 * HOUR_NS
INTENT = Intent(
    principal="agent-1",
    action="wire.transfer",
    resource="acct:1",
    cost=500,
    session_id="s1",
)


def make_policy(**overrides):
    fields = {
        "allowed_actions": frozenset({"wire.transfer"}),
        "max_cost": 1000,
    }
    fields.update(overrides)
    return Policy(**fields)


def make_kernel(now, policy=None, state=None):
    return GovernanceKernel(
        policy or make_policy(),
        secret=SECRET,
        state=state if state is not None else InMemoryKernelState(),
        clock=lambda: now,
    )


def rejection_reasons(kernel):
    return [
        record["payload"].get("reason")
        for record in kernel.audit
        if record["event"] == "permit_rejected"
    ]


def rejected_records(kernel):
    return [
        record for record in kernel.audit if record["event"] == "permit_rejected"
    ]


class TokenV3ShapeTests(unittest.TestCase):
    def test_issued_token_is_v3_with_signed_expiry_at_policy_ttl(self):
        kernel = make_kernel(T0, policy=make_policy(permit_ttl_ns=2 * HOUR_NS))
        token = kernel.evaluate(INTENT).permit
        parts = token.split(":")
        # v3: digest:nonce:issued_at_ns:expires_at_ns:presenter_hash:signature.
        self.assertEqual(6, len(parts))
        digest, _nonce, issued_raw, expires_raw, presenter_hash, _signature = parts
        self.assertEqual(kernel.intent_hash(INTENT), digest)
        self.assertEqual(T0, int(issued_raw))
        self.assertEqual(T0 + 2 * HOUR_NS, int(expires_raw))
        # Unbound (bearer) permit: presenter hash of the empty string.
        self.assertEqual(UNBOUND_PRESENTER_HASH, presenter_hash)

    def test_default_policy_stamps_the_default_ttl(self):
        kernel = make_kernel(T0)
        token = kernel.evaluate(INTENT).permit
        _digest, _nonce, issued_raw, expires_raw, _presenter, _sig = token.split(":")
        self.assertEqual(DEFAULT_PERMIT_TTL_NS, int(expires_raw) - int(issued_raw))

    def test_policy_ttl_cap_validated_at_construction(self):
        for bad in (0, -1, True, "3600"):
            with self.assertRaises(ValueError):
                make_policy(permit_ttl_ns=bad)
        with self.assertRaises(ValueError):
            make_policy(permit_ttl_ns=PERMIT_TTL_CEILING_NS + 1)
        # The ceiling itself is admissible; the default is admissible.
        make_policy(permit_ttl_ns=PERMIT_TTL_CEILING_NS)
        make_policy()


class ExpiryEnforcementTests(unittest.TestCase):
    def test_expired_permit_refused_at_consume(self):
        policy = make_policy(permit_ttl_ns=HOUR_NS)
        issuer = make_kernel(T0, policy=policy)
        token = issuer.evaluate(INTENT).permit
        # A fresh kernel over the same state, one hour later: the token
        # is at its expiry and fails closed, like a revoked permit.
        state = issuer._state
        later = make_kernel(T0 + HOUR_NS, policy=policy, state=state)
        self.assertFalse(later.consume(token, INTENT))
        # This tree records no distinct permit_expired reason (see the
        # module docstring): the refusal is a permit_rejected whose
        # payload carries the recorded expiry.
        rejected = rejected_records(later)
        self.assertEqual(1, len(rejected))
        self.assertEqual(T0 + HOUR_NS, rejected[0]["payload"]["permit_expires_at_ns"])

    def test_permit_consumed_just_before_expiry_still_works(self):
        policy = make_policy(permit_ttl_ns=HOUR_NS)
        issuer = make_kernel(T0, policy=policy)
        token = issuer.evaluate(INTENT).permit
        just_in_time = make_kernel(
            T0 + HOUR_NS - 1, policy=policy, state=issuer._state
        )
        self.assertTrue(just_in_time.consume(token, INTENT))

    def test_ten_year_old_token_refused(self):
        # The design repro's headline case, at the fixed tree.
        issuer = make_kernel(T0)
        token = issuer.evaluate(INTENT).permit
        decade_later = make_kernel(T0 + 10 * YEAR_NS, state=issuer._state)
        self.assertFalse(decade_later.consume(token, INTENT))
        rejected = rejected_records(decade_later)
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            T0 + DEFAULT_PERMIT_TTL_NS, rejected[0]["payload"]["permit_expires_at_ns"]
        )

    def test_tampered_expiry_rejected_as_inauthentic(self):
        kernel = make_kernel(T0)
        token = kernel.evaluate(INTENT).permit
        digest, nonce, issued_raw, _expires_raw, presenter_hash, signature = token.split(":")
        # Extend the expiry a century; keep the original signature.
        forged = ":".join(
            [digest, nonce, issued_raw, str(T0 + 100 * YEAR_NS), presenter_hash, signature]
        )
        self.assertFalse(kernel.consume(forged, INTENT))
        self.assertIn("permit_signature_invalid", rejection_reasons(kernel))
        # The genuine token is untouched by the attempt.
        self.assertTrue(kernel.consume(token, INTENT))

    def test_tampered_issued_at_rejected_as_inauthentic(self):
        kernel = make_kernel(T0)
        token = kernel.evaluate(INTENT).permit
        digest, nonce, _issued_raw, expires_raw, presenter_hash, signature = token.split(":")
        forged = ":".join(
            [digest, nonce, str(T0 - 10 * YEAR_NS), expires_raw, presenter_hash, signature]
        )
        self.assertFalse(kernel.consume(forged, INTENT))
        self.assertIn("permit_signature_invalid", rejection_reasons(kernel))


class MalformedTokenTests(unittest.TestCase):
    """Malformed bearer input fails closed through the recorded
    rejection path — it never raises out of consume (Codex P2 on
    upstream PR #358, reproduced before the fix: Unicode digit
    fields pass str.isdigit() but int() rejects them, and over-long
    fields trip Python's integer-conversion limit)."""

    def malformed_variants(self, kernel):
        token = kernel.evaluate(INTENT).permit
        digest, nonce, issued, expiry, presenter_hash, signature = token.split(":")
        return {
            "unicode_digit_issued": ":".join([digest, nonce, "²", expiry, presenter_hash, signature]),
            "unicode_digit_expiry": ":".join([digest, nonce, issued, "²", presenter_hash, signature]),
            "overlong_expiry": ":".join([digest, nonce, issued, "9" * 5000, presenter_hash, signature]),
            "empty_issued": ":".join([digest, nonce, "", expiry, presenter_hash, signature]),
            "negative_expiry": ":".join([digest, nonce, issued, "-1", presenter_hash, signature]),
            "decimal_issued": ":".join([digest, nonce, "1.5", expiry, presenter_hash, signature]),
            "expiry_not_after_issued": ":".join(
                [digest, nonce, expiry, issued, presenter_hash, signature]
            ),
        }

    def test_malformed_time_fields_refused_without_raising(self):
        kernel = make_kernel(T0)
        for name, forged in self.malformed_variants(kernel).items():
            with self.subTest(variant=name):
                self.assertFalse(kernel.consume(forged, INTENT))
        reasons = rejection_reasons(kernel)
        self.assertEqual(
            len(self.malformed_variants(kernel)),
            reasons.count("permit_signature_invalid"),
        )


class StoreSecondLayerTests(unittest.TestCase):
    """Direct handle-level consume calls (no kernel) face the recorded
    expiry too — the Item 3 repro A path is expiry-bound as well."""

    def test_inmemory_store_refuses_consume_at_expiry(self):
        state = InMemoryKernelState()
        digest = GovernanceKernel.intent_hash(INTENT)
        state.issue_permit(
            "tok", digest, "policy_satisfied", T0, expires_at_ns=T0 + HOUR_NS
        )
        self.assertFalse(state.consume_permit("tok", digest, T0 + HOUR_NS))
        rejected = [
            record
            for record in state.audit
            if record["event"] == "permit_rejected"
        ]
        # No permit_status field in this tree (see the module
        # docstring); the refusal carries the recorded expiry.
        self.assertEqual(
            T0 + HOUR_NS, rejected[-1]["payload"]["permit_expires_at_ns"]
        )

    def test_inmemory_store_consumes_before_expiry(self):
        state = InMemoryKernelState()
        digest = GovernanceKernel.intent_hash(INTENT)
        state.issue_permit(
            "tok", digest, "policy_satisfied", T0, expires_at_ns=T0 + HOUR_NS
        )
        self.assertTrue(state.consume_permit("tok", digest, T0 + HOUR_NS - 1))

    def test_sqlite_store_refuses_consume_at_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            state = SQLiteKernelState(Path(directory) / "state.db")
            digest = GovernanceKernel.intent_hash(INTENT)
            state.issue_permit(
                "tok", digest, "policy_satisfied", T0, expires_at_ns=T0 + HOUR_NS
            )
            self.assertFalse(state.consume_permit("tok", digest, T0 + HOUR_NS))
            rejected = [
                record
                for record in state.audit
                if record["event"] == "permit_rejected"
            ]
            self.assertEqual(
                T0 + HOUR_NS, rejected[-1]["payload"]["permit_expires_at_ns"]
            )
            state.close()

    def test_sqlite_expiry_column_migration_and_null_expiry_rows(self):
        # A pre-v2 database (permits table without the expiry column)
        # gains the column on first mutating open; its existing rows
        # keep NULL expiry.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            state = SQLiteKernelState(path)
            state.close()

            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE permits_old (permit TEXT PRIMARY KEY, "
                "intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0)"
            )
            connection.execute(
                "INSERT INTO permits_old VALUES ('legacy-tok', 'd', 0)"
            )
            connection.execute("DROP TABLE permits")
            connection.execute("ALTER TABLE permits_old RENAME TO permits")
            connection.commit()
            connection.close()

            reopened = SQLiteKernelState(path)
            columns = {
                row[1]
                for row in reopened._connection.execute(
                    "PRAGMA table_info(permits)"
                ).fetchall()
            }
            self.assertIn("expires_at_ns", columns)
            row = reopened._connection.execute(
                "SELECT expires_at_ns FROM permits WHERE permit = 'legacy-tok'"
            ).fetchone()
            self.assertIsNone(row[0])
            reopened.close()


if __name__ == "__main__":
    unittest.main()
