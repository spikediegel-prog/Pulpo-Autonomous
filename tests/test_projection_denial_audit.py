"""Projection denials are recorded in the canonical audit.

Port of upstream Pulpo1.0 PR #372 (kernel build item #2) via Preview
#146: ``GovernedDirectiveProjection.evaluate`` returned its
directive-scope denials without a kernel call, so a refused attempt
was invisible to the canonical audit. Each denial now appends exactly
one fixed-schema ``directive_denial`` record through the kernel verb
``record_directive_denial``.

The approval verifier here is a same-process HMAC test double, not a
production authority.
"""

import tempfile
import unittest
from pathlib import Path

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy, PulpoOrchestrator
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.incident_channel import freeze_incident_report
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"
SECRET = "kernel-secret".encode("utf-8")


def directive(**overrides):
    values = dict(
        directive_id="deploy-prod",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=3_000_000,
    )
    values.update(overrides)
    return Directive(**values)


def derived(parent, **overrides):
    values = dict(
        directive_id="deploy-prod-child",
        version=1,
        issuer_authority_id=parent.issuer_authority_id,
        principal=parent.principal,
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:service:",),
        max_cost=3,
        issued_at_ns=1_200_000,
        expires_at_ns=2_800_000,
        parent_directive_hash=parent.directive_hash,
    )
    values.update(overrides)
    return Directive(**values)


class ProjectionDenialRecordTests(unittest.TestCase):
    def governed(self, state=None, policy=None):
        verifier = HmacTestVerifier()
        if policy is None:
            policy = Policy(
                frozenset({"write", "activate_directive", "revoke_directive"}),
                100,
                frozenset({"activate_directive", "revoke_directive"}),
                authority_trust=trust_for(verifier),
            )
        kernel = GovernanceKernel(
            policy,
            SECRET,
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def approve(self, kernel, verifier, operation, d, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(
            operation,
            d,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def activate(self, kernel, verifier, controller, d, approval_id, nonce, **kwargs):
        envelope = self.approve(
            kernel, verifier, controller.ACTIVATE, d, approval_id, nonce
        )
        decision = controller.activate(
            d, envelope, operator_principal=OPERATOR, **kwargs
        )
        self.assertEqual("allow", decision.outcome)
        return decision

    def revoke(self, kernel, verifier, controller, d, approval_id, nonce):
        envelope = self.approve(
            kernel, verifier, controller.REVOKE, d, approval_id, nonce
        )
        decision = controller.revoke(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return decision

    def denials(self, state):
        return [r for r in state.audit if r["event"] == "directive_denial"]

    def test_unknown_directive_denial_is_recorded_with_fixed_schema(self):
        state = InMemoryKernelState()
        kernel, _ = self.governed(state)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")

        before = len(state.audit)
        decision = projection.evaluate(intent, d)

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_not_authorized", decision.reason)
        self.assertEqual(before + 1, len(state.audit))
        records = self.denials(state)
        self.assertEqual(1, len(records))
        record = records[0]
        self.assertEqual(
            {
                "schema": "pulpo.directive-denial.v0",
                "directive_id": "deploy-prod",
                "version": 1,
                "directive_hash": d.directive_hash,
                "intent_hash": kernel.intent_hash(intent),
                "principal": "agent:builder",
                "action": "write",
                "resource": "repo:core",
                "cost": 3,
                "session_id": "s1",
                "reason": "directive_not_authorized",
                "authority_effect": "none",
            },
            record["payload"],
        )
        self.assertTrue(kernel.verify_audit())

    def test_revoked_directive_denial_is_recorded(self):
        state = InMemoryKernelState()
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        self.activate(kernel, verifier, controller, d, "activate-1", "activate-nonce-1")
        self.revoke(kernel, verifier, controller, d, "revoke-1", "revoke-nonce-1")

        decision = projection.evaluate(
            Intent("agent:builder", "write", "repo:core", 3, "s1"), d
        )

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_revoked", decision.reason)
        records = self.denials(state)
        self.assertEqual(1, len(records))
        self.assertEqual("directive_revoked", records[0]["payload"]["reason"])
        self.assertTrue(kernel.verify_audit())

    def test_parent_revoked_denial_is_recorded_against_the_child(self):
        state = InMemoryKernelState()
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        parent = directive()
        child = derived(parent)
        self.activate(
            kernel, verifier, controller, parent, "activate-1", "activate-nonce-1"
        )
        self.activate(
            kernel,
            verifier,
            controller,
            child,
            "activate-child-1",
            "activate-child-nonce-1",
            parent_directive=parent,
        )
        self.revoke(kernel, verifier, controller, parent, "revoke-1", "revoke-nonce-1")

        decision = projection.evaluate(
            Intent("agent:builder", "write", "repo:service:api", 3, "s1"), child
        )

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_parent_revoked", decision.reason)
        records = self.denials(state)
        self.assertEqual(1, len(records))
        self.assertEqual("deploy-prod-child", records[0]["payload"]["directive_id"])
        self.assertEqual(
            child.directive_hash, records[0]["payload"]["directive_hash"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_mandate_failures_are_recorded(self):
        state = InMemoryKernelState()
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        self.activate(kernel, verifier, controller, d, "activate-1", "activate-nonce-1")

        intents = [
            Intent("agent:builder", "delete", "repo:core", 3, "s1"),
            Intent("agent:other", "write", "repo:core", 3, "s1"),
            Intent("agent:builder", "write", "repo:core", 6, "s1"),
            Intent("agent:builder", "write", "db:core", 3, "s1"),
        ]
        expected = [
            "directive_action_not_allowed",
            "directive_principal_mismatch",
            "directive_budget_exceeded",
            "directive_resource_not_allowed",
        ]
        for intent in intents:
            decision = projection.evaluate(intent, d)
            self.assertEqual("deny", decision.outcome)

        records = self.denials(state)
        self.assertEqual(expected, [r["payload"]["reason"] for r in records])
        self.assertTrue(kernel.verify_audit())

    def test_allow_path_appends_no_denial_record(self):
        state = InMemoryKernelState()
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        self.activate(kernel, verifier, controller, d, "activate-1", "activate-nonce-1")

        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = projection.evaluate(intent, d)

        self.assertEqual("allow", decision.outcome)
        assert decision.permit is not None
        self.assertTrue(kernel.consume(decision.permit, intent))
        self.assertEqual([], self.denials(state))

    def test_kernel_path_denial_is_not_double_recorded(self):
        # The policy's trust is built from a second HmacTestVerifier
        # instance while the fixture's approval_verifier is its own
        # instance. That works because trust matching compares trust
        # fields (identical across instances) and both share the
        # default HMAC secret; do not "fix" this with distinct secrets.
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            agent_grants=(
                AgentGrant(
                    "agent:builder",
                    frozenset({"write"}),
                    ("repo:",),
                    2,
                ),
                AgentGrant(
                    OPERATOR,
                    frozenset({"activate_directive", "revoke_directive"}),
                    ("directive:",),
                    0,
                ),
            ),
            authority_trust=trust_for(HmacTestVerifier()),
        )
        state = InMemoryKernelState()
        kernel, verifier = self.governed(state, policy=policy)
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        self.activate(kernel, verifier, controller, d, "activate-1", "activate-nonce-1")

        before = len(
            [r for r in state.audit if r["event"] == "decision"]
        )
        decision = projection.evaluate(
            Intent("agent:builder", "write", "repo:core", 4, "s1"), d
        )

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("agent_budget_exceeded", decision.reason)
        self.assertEqual([], self.denials(state))
        after = len([r for r in state.audit if r["event"] == "decision"])
        self.assertEqual(before + 1, after)

    def test_repeated_denials_append_one_record_each(self):
        state = InMemoryKernelState()
        kernel, _ = self.governed(state)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")

        for _ in range(3):
            decision = projection.evaluate(intent, d)
            self.assertEqual("deny", decision.outcome)

        self.assertEqual(3, len(self.denials(state)))
        self.assertTrue(kernel.verify_audit())

    def test_denial_record_uses_the_kernel_clock(self):
        state = InMemoryKernelState()
        kernel, _ = self.governed(state)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()

        projection.evaluate(
            Intent("agent:builder", "write", "repo:core", 3, "s1"), d
        )

        records = self.denials(state)
        self.assertEqual(1, len(records))
        self.assertEqual(NOW, records[0]["timestamp_ns"])
        self.assertTrue(kernel.verify_audit())

    def test_denial_record_persists_across_sqlite_restart(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            path = handle.name
        state = SQLiteKernelState(path)
        kernel, _ = self.governed(state)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")

        decision = projection.evaluate(intent, d)
        self.assertEqual("deny", decision.outcome)
        expected = self.denials(state)[0]["payload"]
        state.close()

        restarted = SQLiteKernelState(path)
        kernel, _ = self.governed(restarted)
        records = self.denials(restarted)
        self.assertEqual(1, len(records))
        self.assertEqual(expected, records[0]["payload"])
        self.assertTrue(kernel.verify_audit())
        restarted.close()


class SwitchClock:
    """A kernel clock whose failure mode the test arms after setup.

    The Codex P2 shape is precisely a clock that was healthy while
    directives were activated and revoked, then becomes unavailable
    at evaluation time.
    """

    def __init__(self):
        self.mode = "ok"

    def __call__(self):
        if self.mode == "raise":
            raise RuntimeError("clock exploded")

        if self.mode == "none":
            return None

        return NOW


class ProjectionDenialClockPostureTests(unittest.TestCase):
    """Codex P2 on upstream PR #372: the denial record must survive an
    unavailable clock.

    The projection's status denials (unknown, revoked, parent
    revoked) are computed before any trusted-time check, and before
    item #2 those paths returned their fail-closed Decision without
    touching the clock at all. The record verb therefore resolves
    its timestamp through the kernel's trusted clock and degrades
    to the 0 sentinel (the ``approval_rejected`` precedent) instead
    of propagating a clock exception, writing a ``None`` timestamp
    into the in-memory chain, or tripping the SQLite backend's
    NOT NULL timestamp constraint. The Decision returned is the one
    the projection has always returned; the denial is recorded
    exactly once; only the record's timestamp degrades.
    """

    def governed(self, state=None, clock=None):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            SECRET,
            approval_verifier=verifier,
            clock=clock if clock is not None else (lambda: NOW),
            state=state,
        )
        return kernel, verifier

    def approve(self, kernel, verifier, operation, d, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(
            operation,
            d,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def activate(
        self, kernel, verifier, controller, d, approval_id, nonce, **kwargs
    ):
        envelope = self.approve(
            kernel, verifier, controller.ACTIVATE, d, approval_id, nonce
        )
        decision = controller.activate(
            d, envelope, operator_principal=OPERATOR, **kwargs
        )
        self.assertEqual("allow", decision.outcome)
        return decision

    def revoke(self, kernel, verifier, controller, d, approval_id, nonce):
        envelope = self.approve(
            kernel, verifier, controller.REVOKE, d, approval_id, nonce
        )
        decision = controller.revoke(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return decision

    def denials(self, state):
        return [r for r in state.audit if r["event"] == "directive_denial"]

    def test_healthy_clock_stamps_the_denial_with_kernel_time(self):
        state = InMemoryKernelState()
        kernel, _ = self.governed(state)
        projection = GovernedDirectiveProjection(kernel)

        projection.evaluate(
            Intent("agent:builder", "write", "repo:core", 3, "s1"), directive()
        )

        self.assertEqual(1, len(self.denials(state)))
        self.assertEqual(NOW, self.denials(state)[0]["timestamp_ns"])

    def test_raising_clock_unknown_directive_still_denies_and_records(self):
        clock = SwitchClock()
        state = InMemoryKernelState()
        kernel, _ = self.governed(state, clock=clock)
        projection = GovernedDirectiveProjection(kernel)
        clock.mode = "raise"

        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = projection.evaluate(intent, directive())

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_not_authorized", decision.reason)
        self.assertEqual(kernel.intent_hash(intent), decision.intent_hash)
        self.assertIsNone(decision.permit)
        self.assertEqual(1, len(self.denials(state)))
        self.assertEqual(0, self.denials(state)[0]["timestamp_ns"])
        self.assertTrue(kernel.verify_audit())

    def test_raising_clock_revoked_directive_still_denies_and_records(self):
        clock = SwitchClock()
        state = InMemoryKernelState()
        kernel, verifier = self.governed(state, clock=clock)
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        d = directive()
        self.activate(
            kernel, verifier, controller, d, "activate-1", "activate-nonce-1"
        )
        self.revoke(kernel, verifier, controller, d, "revoke-1", "revoke-nonce-1")
        clock.mode = "raise"

        decision = projection.evaluate(
            Intent("agent:builder", "write", "repo:core", 1, "s1"), d
        )

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_revoked", decision.reason)
        self.assertEqual(1, len(self.denials(state)))
        self.assertEqual(0, self.denials(state)[0]["timestamp_ns"])
        self.assertTrue(kernel.verify_audit())

    def test_raising_clock_parent_revoked_directive_still_denies_and_records(
        self,
    ):
        clock = SwitchClock()
        state = InMemoryKernelState()
        kernel, verifier = self.governed(state, clock=clock)
        controller = DirectiveAuthorityController(kernel)
        projection = GovernedDirectiveProjection(kernel)
        parent = directive()
        child = derived(parent)
        self.activate(
            kernel, verifier, controller, parent, "activate-1", "activate-nonce-1"
        )
        self.activate(
            kernel,
            verifier,
            controller,
            child,
            "activate-child-1",
            "activate-child-nonce-1",
            parent_directive=parent,
        )
        self.revoke(kernel, verifier, controller, parent, "revoke-1", "revoke-nonce-1")
        clock.mode = "raise"

        decision = projection.evaluate(
            Intent("agent:builder", "write", "repo:service:api", 1, "s1"), child
        )

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_parent_revoked", decision.reason)
        self.assertEqual(1, len(self.denials(state)))
        self.assertEqual(
            "deploy-prod-child", self.denials(state)[0]["payload"]["directive_id"]
        )
        self.assertEqual(0, self.denials(state)[0]["timestamp_ns"])
        self.assertTrue(kernel.verify_audit())

    def test_none_clock_records_zero_timestamp_in_memory(self):
        clock = SwitchClock()
        state = InMemoryKernelState()
        kernel, _ = self.governed(state, clock=clock)
        projection = GovernedDirectiveProjection(kernel)
        clock.mode = "none"

        decision = projection.evaluate(
            Intent("agent:builder", "write", "repo:core", 3, "s1"), directive()
        )

        self.assertEqual("deny", decision.outcome)
        self.assertEqual("directive_not_authorized", decision.reason)
        self.assertEqual(1, len(self.denials(state)))
        self.assertEqual(0, self.denials(state)[0]["timestamp_ns"])
        self.assertTrue(kernel.verify_audit())

    def test_unavailable_clock_records_zero_timestamp_in_sqlite(self):
        for mode in ("none", "raise"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                state = SQLiteKernelState(Path(td) / "state.sqlite3")
                try:
                    clock = SwitchClock()
                    kernel, _ = self.governed(state, clock=clock)
                    projection = GovernedDirectiveProjection(kernel)
                    clock.mode = mode

                    decision = projection.evaluate(
                        Intent("agent:builder", "write", "repo:core", 3, "s1"),
                        directive(),
                    )

                    self.assertEqual("deny", decision.outcome)
                    self.assertEqual("directive_not_authorized", decision.reason)
                    self.assertEqual(1, len(self.denials(state)))
                    self.assertEqual(0, self.denials(state)[0]["timestamp_ns"])
                    self.assertTrue(kernel.verify_audit())
                finally:
                    state.close()


class ProjectionDenialIncidentReportTests(unittest.TestCase):
    """Codex P1 on PR #372, end to end: a projection denial recorded
    in the canonical audit must surface in the frozen incident
    report as a near-miss — before the classification fix, the same
    chain froze into a report showing zero incidents and zero
    near-misses, implying no attempt occurred.

    Fixture is local to this class (the record tests above have
    their own helpers); the two tests mirror upstream's
    ``Fixture``-based versions step for step.
    """

    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            SECRET,
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )

    def _activate(self, d, approval_id, nonce):
        controller = DirectiveAuthorityController(self.kernel)
        envelope = signed_envelope(
            self.kernel,
            DirectiveAuthorityController.authority_intent(
                controller.ACTIVATE, d, operator_principal=OPERATOR
            ),
            self.verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)

    def _revoke(self, d, approval_id, nonce):
        controller = DirectiveAuthorityController(self.kernel)
        envelope = signed_envelope(
            self.kernel,
            DirectiveAuthorityController.authority_intent(
                controller.REVOKE, d, operator_principal=OPERATOR
            ),
            self.verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )
        decision = controller.revoke(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)

    def test_unknown_directive_denial_is_a_near_miss_in_the_report(self):
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        GovernedDirectiveProjection(self.kernel).evaluate(intent, directive())
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))

        self.assertEqual(report.incidents, 0)
        self.assertEqual(report.near_misses, 1)
        (record,) = report.records
        self.assertEqual(record.kind, "near_miss")
        self.assertEqual(record.source, "canonical_audit")
        self.assertEqual(record.source_detail, "directive_denial")
        self.assertEqual(record.reason, "directive_not_authorized")
        self.assertEqual(record.resolution, "not_applicable")
        self.assertTrue(record.record_id.startswith("near-miss:"))
        self.assertIn(("intent_hash", self.kernel.intent_hash(intent)), record.anchors)
        self.assertTrue(report.audit_valid)

    def test_revoked_directive_denial_is_a_near_miss_in_the_report(self):
        d = directive()
        self._activate(d, "act-1", "nonce-1")
        self._revoke(d, "rev-1", "nonce-2")
        GovernedDirectiveProjection(self.kernel).evaluate(
            Intent("agent:builder", "write", "repo:core", 1, "s1"), d
        )
        report = freeze_incident_report(PulpoOrchestrator(self.kernel))

        self.assertEqual(report.incidents, 0)
        self.assertEqual(report.near_misses, 1)
        (record,) = report.records
        self.assertEqual(record.kind, "near_miss")
        self.assertEqual(record.source_detail, "directive_denial")
        self.assertEqual(record.reason, "directive_revoked")
        self.assertTrue(report.audit_valid)


if __name__ == "__main__":
    unittest.main()
