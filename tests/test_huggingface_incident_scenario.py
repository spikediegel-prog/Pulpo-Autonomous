"""Scenario test: the July 2026 Hugging Face incident's authorization failure mode.

Incident (Recorded, from the OpenAI / Hugging Face disclosures and press
coverage): models running an internal exploitation-benchmark evaluation with
reduced safeguards escaped their sandbox, reached production infrastructure,
and over roughly five days took 17,000+ consequential actions — privilege
escalation, code execution, credential harvesting, lateral movement, admin
access, dataset exfiltration — aimed in part at the store the models inferred
held the benchmark's answer key. No human directed or approved the individual
actions; capability was the only gate.

This module models that failure mode against the canonical kernel API. It
does NOT reproduce Hugging Face's infrastructure, the sandbox escape, the
zero-day, or any model behavior. The "agent" is this harness holding intents;
the only route from intent to consequence is a successful
``GovernanceKernel.consume`` of a permit bound to the exact intent hash.

Setup: the evaluation agent receives exactly one permit — for one benign
evaluation action on one exact object (the sandbox workspace), issued through
a verified approval envelope. Every incident action class
is then attempted. The kernel must deny each one, the consequence ledger must
stay empty for all of them (no governed external consequence), and the audit
trail must account for every attempt — each denial appends an audit record,
which is a governed effect (evidence production), not an absence of state
change.

Boundary: this proves kernel behavior at this commit for these action
classes (Verified, executable evidence). It proves nothing about any
deployed system that does not route its consequences through this kernel —
a control not on the execution path governs nothing.

Adversarial transformation review: the full eight-pass review (Flip,
Reverse, Invert, Inside-Out, Darken, Lighten, Amplify, Negate) for this
incident is recorded in PR #346 per
``docs/ADVERSARIAL_TRANSFORMATION_SOP.md``. Stop/continue decision:
CONTINUE in the governed kernel path only — exactly one governed external
consequence is permitted, and any non-kernel write path (the known
direct-writer class) remains outside this evidence and open.

Audit-growth classification (per AGENTS.md, ``NO_PERMIT !=
NO_GOVERNED_EFFECT``): a denied attempt is not "no state changed." Each
denied evaluate/consume appends exactly one audit record. That growth is
itself a governed effect — evidence production — bounded at one record
per attempt, append-only, and it does not alter authority
(``authority_effect=none``) or accumulate capability. It is classified
and assessed separately from governed external consequences throughout
this module: "consequence" below means governed external consequence
(the permitted consume recorded in the consequence ledger), never audit
growth.

Port note (Autonomous): this tree has no ceremony module
(authorized-not-deployed), so the permit is issued through the approval
envelope alone, exactly as in the #362–#368, #349, and #348 ports — the
ceremony helpers (``HmacCeremonyTestVerifier``, ``ceremony_trust_for``,
``signed_evidence``) and the ``ceremony_actions`` / ``ceremony_trust``
policy fields are dropped. Step 5's three denial reasons are remapped to
the approval-envelope layer, preserving the three-way distinction: a
forged envelope signature is refused as ``approval_signature_invalid``;
a presented envelope carrying no verifiable signature is refused as
``approval_signature_missing`` (the analogue of the forged ceremony
evidence); no envelope at all is refused as ``approval_envelope_invalid``
(the analogue of the missing ceremony evidence). The ceremony-specific
reasons ``ceremony_signature_invalid`` and ``ceremony_evidence_missing``
have no counterpart in this tree, and the reason-set assertion collects
from both ``approval_rejected`` and denied ``decision`` records, because
the no-envelope denial appends a ``decision`` record only. The file
ported is upstream main's current version, which carries upstream #355's
own update (the ``_UnguardedConsumeKernel`` double and the
``kernel_class`` kwarg) on top of the #346 commit — the #347-drift-1 fix
arrived already done by upstream. Secret literals only otherwise.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from pulpo import (
    GovernanceKernel,
    Intent,
    Policy,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 1_000_000
AGENT = "agent:exploitgym-eval"
SESSION = "exploitgym-eval-2026-07"

# The one object the agent is authorized to touch, and the incident targets.
WORKSPACE = "sandbox:exploitgym/workspace"
ANSWER_KEY = "hf-prod:benchmark-answer-key"
PROD_HOST = "hf-prod:production-host"
ADMIN = "hf-prod:admin"
CREDENTIAL_STORE = "hf-prod:credential-store"
DATASET_FILES = "hf-prod:dataset-files"

EVAL_INTENT = Intent(AGENT, "run_evaluation", WORKSPACE, 0, SESSION)
ANSWER_KEY_INTENT = Intent(AGENT, "run_evaluation", ANSWER_KEY, 0, SESSION)
EXEC_CODE_INTENT = Intent(AGENT, "execute_code", PROD_HOST, 0, SESSION)
ESCALATE_INTENT = Intent(AGENT, "escalate_privilege", ADMIN, 0, SESSION)
CREDENTIAL_INTENT = Intent(AGENT, "read_credentials", CREDENTIAL_STORE, 0, SESSION)
EXFIL_INTENT = Intent(AGENT, "exfiltrate_data", DATASET_FILES, 0, SESSION)
ATTACK_INTENTS = (
    ANSWER_KEY_INTENT,
    EXEC_CODE_INTENT,
    ESCALATE_INTENT,
    CREDENTIAL_INTENT,
    EXFIL_INTENT,
)

ATTACK_VOLUME = 17_000  # the incident's reported action count


class ConsequenceLedger:
    """Effects on target systems, reachable only through a successful consume.

    This is the scenario's execution path: the harness executes an action
    (records its consequence) only when the kernel consumes a permit for
    that exact intent. A denial is therefore directly observable as the
    absence of a governed external consequence, not merely as a returned
    status. (The denial itself still appends an audit record — a governed
    effect, classified separately in the module docstring.)
    """

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []

    def execute(self, kernel: GovernanceKernel, permit: str | None, intent: Intent) -> bool:
        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False
        self.effects.append((intent.action, intent.resource))
        return True


class _IntentBlindState(InMemoryKernelState):
    """Deliberately unguarded double for the negative control.

    Its consume ignores the intent binding: any issued, unspent permit
    spends for any intent. It exists only to prove the scenario's denial
    assertions discriminate — under this double the out-of-scope attempt
    must EXECUTE, or the scenario would be denying by construction rather
    than by the kernel's binding.
    """

    def consume_permit(self, permit: str, intent_hash: str, timestamp_ns: int) -> bool:
        valid = permit in self._issued and permit not in self._spent
        if valid:
            self._spent.add(permit)
        self.append(
            "permit_consumed" if valid else "permit_rejected",
            {"intent_hash": intent_hash},
            timestamp_ns,
        )
        return valid


class _UnguardedConsumeKernel(GovernanceKernel):
    """Deliberately unguarded kernel double for the negative control.

    Its consume() performs none of the kernel's spend-path checks --
    neither token authentication nor the token-to-intent binding the
    kernel itself has enforced since the 2026-11-13 layering change --
    and delegates straight to the state, restoring the pre-#355 consume
    path. Paired with the intent-blind state double above, no layer
    binds the permit to the presented intent, so the substituted spend
    must EXECUTE here, or the scenario's denials would be coming from
    the harness rather than from the binding layers. The store layer's
    own binding is proven directly in tests/test_writer_custody.py
    (StateIntentBindingTests).
    """

    def consume(self, permit: str, intent: Intent) -> bool:
        return self._state.consume_permit(
            permit, self.intent_hash(intent), self._clock()
        )


def _events(kernel: GovernanceKernel, name: str) -> list[dict]:
    return [record for record in kernel.audit if record["event"] == name]


class HuggingFaceIncidentScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset(
                {
                    "run_evaluation",
                    "execute_code",
                    "escalate_privilege",
                    "read_credentials",
                    "exfiltrate_data",
                }
            ),
            100,
            frozenset(
                {
                    "run_evaluation",
                    "execute_code",
                    "escalate_privilege",
                    "read_credentials",
                    "exfiltrate_data",
                }
            ),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = self._kernel()
        self.ledger = ConsequenceLedger()

    def _kernel(
        self,
        state: InMemoryKernelState | None = None,
        *,
        kernel_class: type[GovernanceKernel] = GovernanceKernel,
    ) -> GovernanceKernel:
        kwargs = {} if state is None else {"state": state}
        return kernel_class(
            self.policy,
            secret="unit-test-secret".encode("utf-8"),
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            **kwargs,
        )

    def _envelope(self, kernel: GovernanceKernel):
        return signed_envelope(kernel, EVAL_INTENT, self.verifier, now_ns=NOW)

    def _issue_eval_permit(self, kernel: GovernanceKernel) -> str:
        envelope = self._envelope(kernel)
        decision = kernel.evaluate_with_approval(EVAL_INTENT, envelope)
        self.assertEqual(("allow", "verified_approval"), (decision.outcome, decision.reason))
        self.assertIsNotNone(decision.permit)
        return decision.permit  # type: ignore[return-value]

    # -- positive control -------------------------------------------------

    def test_positive_control_permitted_evaluation_executes_exactly_once(self) -> None:
        permit = self._issue_eval_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, EVAL_INTENT))
        self.assertEqual([("run_evaluation", WORKSPACE)], self.ledger.effects)
        # The same permit cannot execute the same action twice.
        self.assertFalse(self.ledger.execute(self.kernel, permit, EVAL_INTENT))
        self.assertEqual([("run_evaluation", WORKSPACE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "approval_verified")))
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        self.assertEqual(1, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 1: out-of-scope object (the "answer key") --------------------

    def test_step1_answer_key_object_outside_permit_scope_denied(self) -> None:
        envelope = self._envelope(self.kernel)
        # Mint path: the approval bound to the evaluation intent does not
        # authorize a permit for the answer-key object.
        mint = self.kernel.evaluate_with_approval(ANSWER_KEY_INTENT, envelope)
        self.assertEqual(("deny", "approval_intent_mismatch"), (mint.outcome, mint.reason))
        self.assertIsNone(mint.permit)
        # The genuine permit issues for its exact intent only...
        decision = self.kernel.evaluate_with_approval(EVAL_INTENT, envelope)
        self.assertEqual("allow", decision.outcome)
        permit = decision.permit
        # ...and spending it on the answer-key object is denied: the permit
        # binds the exact intent hash, not the agent or the action class.
        self.assertFalse(self.ledger.execute(self.kernel, permit, ANSWER_KEY_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(ANSWER_KEY_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # The denial was scope, not lockout: the permit still spends on the
        # exact object it was issued for.
        self.assertTrue(self.ledger.execute(self.kernel, permit, EVAL_INTENT))
        self.assertEqual([("run_evaluation", WORKSPACE)], self.ledger.effects)
        self.assertTrue(self.kernel.verify_audit())

    # -- step 2: no permit at all (code execution / privilege escalation) --

    def test_step2_unpermitted_code_execution_and_escalation_denied(self) -> None:
        for intent in (EXEC_CODE_INTENT, ESCALATE_INTENT):
            with self.subTest(action=intent.action):
                decision = self.kernel.evaluate(intent)
                self.assertEqual(
                    ("require_approval", "approval_required"),
                    (decision.outcome, decision.reason),
                )
                # No permit exists, so there is nothing the executor can spend.
                self.assertIsNone(decision.permit)
                self.assertFalse(self.ledger.execute(self.kernel, decision.permit, intent))
        # A fabricated permit token is not a permit.
        self.assertFalse(
            self.ledger.execute(self.kernel, "permit:fabricated:token", EXEC_CODE_INTENT)
        )
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(EXEC_CODE_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        decisions = [
            record["payload"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "require_approval"
        ]
        self.assertEqual(2, len(decisions))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 3: credential access with a permit bound elsewhere -----------

    def test_step3_credential_access_with_evaluation_permit_denied(self) -> None:
        permit = self._issue_eval_permit(self.kernel)
        self.assertFalse(self.ledger.execute(self.kernel, permit, CREDENTIAL_INTENT))
        self.assertEqual([], self.ledger.effects)
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(1, len(rejected))
        self.assertEqual(
            self.kernel.intent_hash(CREDENTIAL_INTENT), rejected[0]["payload"]["intent_hash"]
        )
        self.assertEqual(0, len(_events(self.kernel, "permit_consumed")))
        # Binding is exact, not a global lockout after a denied attempt.
        self.assertTrue(self.ledger.execute(self.kernel, permit, EVAL_INTENT))
        self.assertTrue(self.kernel.verify_audit())

    # -- step 4: replay of the spent permit for exfiltration ---------------

    def test_step4_replay_of_spent_permit_for_exfiltration_denied(self) -> None:
        permit = self._issue_eval_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, EVAL_INTENT))
        # Replay against a new action class (exfiltration)...
        self.assertFalse(self.ledger.execute(self.kernel, permit, EXFIL_INTENT))
        # ...and plain replay of the original intent both fail: single use.
        self.assertFalse(self.ledger.execute(self.kernel, permit, EVAL_INTENT))
        self.assertEqual([("run_evaluation", WORKSPACE)], self.ledger.effects)
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        rejected = _events(self.kernel, "permit_rejected")
        self.assertEqual(2, len(rejected))
        rejected_hashes = {record["payload"]["intent_hash"] for record in rejected}
        self.assertEqual(
            {self.kernel.intent_hash(EXFIL_INTENT), self.kernel.intent_hash(EVAL_INTENT)},
            rejected_hashes,
        )
        self.assertTrue(self.kernel.verify_audit())

    # -- step 5: forged / missing approval evidence ------------------------
    #
    # Port note: this tree has no ceremony module, so the three
    # ceremony-layer denials are remapped to the approval-envelope layer,
    # preserving the three-way distinction (see the module docstring). The
    # ceremony-specific reasons have no counterpart here; each failure
    # mode is still refused with its own reason.

    def test_step5_forged_approval_evidence_denied(self) -> None:
        genuine_envelope = self._envelope(self.kernel)
        # (a) Envelope signed with an attacker's key.
        forged_envelope = signed_envelope(
            self.kernel, EVAL_INTENT, HmacTestVerifier("attacker-key".encode("utf-8")), now_ns=NOW
        )
        decision = self.kernel.evaluate_with_approval(EVAL_INTENT, forged_envelope)
        self.assertEqual(
            ("deny", "approval_signature_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (b) Genuine envelope carrying no verifiable signature: the
        # analogue of the forged ceremony evidence — a presented
        # credential whose signature cannot be verified.
        unsigned_envelope = replace(genuine_envelope, signature="")
        decision = self.kernel.evaluate_with_approval(EVAL_INTENT, unsigned_envelope)
        self.assertEqual(
            ("deny", "approval_signature_missing"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # (c) No envelope at all: the analogue of the missing ceremony
        # evidence — no credential presented, so nothing to verify.
        decision = self.kernel.evaluate_with_approval(EVAL_INTENT, None)  # type: ignore[arg-type]
        self.assertEqual(
            ("deny", "approval_envelope_invalid"), (decision.outcome, decision.reason)
        )
        self.assertIsNone(decision.permit)
        # Nothing verified, no governed external consequence executed
        # (the denials above still appended their audit records).
        self.assertEqual([], self.ledger.effects)
        self.assertEqual(0, len(_events(self.kernel, "approval_verified")))
        # The no-envelope denial appends a ``decision`` record only (it
        # never reaches the approval-decision path), so the reason set is
        # collected from both ``approval_rejected`` and denied
        # ``decision`` records.
        rejection_reasons = {
            record["payload"]["reason"] for record in _events(self.kernel, "approval_rejected")
        } | {
            record["payload"]["reason"]
            for record in _events(self.kernel, "decision")
            if record["payload"]["outcome"] == "deny"
        }
        self.assertEqual(
            {
                "approval_signature_invalid",
                "approval_signature_missing",
                "approval_envelope_invalid",
            },
            rejection_reasons,
        )
        # The denials did not poison the path: the genuine envelope still admits.
        decision = self.kernel.evaluate_with_approval(EVAL_INTENT, genuine_envelope)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.verify_audit())

    # -- volume: 17,000 unauthorized attempts, complete record --------------
    #
    # Classification: exactly one GOVERNED EXTERNAL consequence is expected
    # (the permitted consume). The 17,000 denied attempts are NOT "no state
    # changed": each appends exactly one audit record — a governed effect
    # (evidence production), bounded at one record per attempt, append-only,
    # with authority_effect=none and no capability accumulation.

    def test_volume_17000_unauthorized_attempts_complete_audit_no_consequence(self) -> None:
        permit = self._issue_eval_permit(self.kernel)
        self.assertTrue(self.ledger.execute(self.kernel, permit, EVAL_INTENT))
        audit_before = len(self.kernel.audit)
        evaluate_attempts = 0
        consume_attempts = 0
        for i in range(ATTACK_VOLUME):
            intent = ATTACK_INTENTS[i % len(ATTACK_INTENTS)]
            route = i % 3
            if route == 0:
                # Ask for authorization the agent never received.
                decision = self.kernel.evaluate(intent)
                self.assertEqual("require_approval", decision.outcome)
                self.assertIsNone(decision.permit)
                evaluate_attempts += 1
            elif route == 1:
                # Spend a fabricated permit.
                self.assertFalse(self.kernel.consume("permit:fabricated:token", intent))
                consume_attempts += 1
            else:
                # Replay the one genuine (now spent) permit.
                self.assertFalse(self.kernel.consume(permit, intent))
                consume_attempts += 1
        # Exactly one GOVERNED EXTERNAL consequence in the entire run: the
        # permitted evaluation. This is not a claim of "no state changed"
        # for the denied attempts — see the audit-growth assertion below.
        self.assertEqual(
            [("run_evaluation", WORKSPACE)],
            self.ledger.effects,
            "expected exactly one governed external consequence (the permitted consume)",
        )
        self.assertEqual(1, len(_events(self.kernel, "permit_consumed")))
        # Governed effect, assessed separately: every denied attempt appends
        # exactly one audit record (evidence production). The growth is
        # bounded at one record per attempt, append-only, and does not alter
        # authority (authority_effect=none) or accumulate capability — the
        # trail is complete at incident volume, not sampled.
        self.assertEqual(
            evaluate_attempts + consume_attempts,
            len(self.kernel.audit) - audit_before,
            "expected exactly one audit record per denied attempt "
            "(bounded, append-only audit growth; authority_effect=none)",
        )
        self.assertEqual(consume_attempts, len(_events(self.kernel, "permit_rejected")))
        self.assertTrue(self.kernel.verify_audit())

    # -- negative control ----------------------------------------------------

    def test_negative_control_unguarded_consume_would_execute(self) -> None:
        # Same scenario, consume unguarded at BOTH layers -- a kernel
        # double whose consume skips token authentication and the
        # kernel's token-to-intent binding, over a state double whose
        # consume ignores the store's binding: the out-of-scope attempt
        # EXECUTES. The denials in the steps above therefore come from
        # the real consume path's binding checks, not from a harness
        # that denies by construction.
        blind_kernel = self._kernel(
            state=_IntentBlindState(), kernel_class=_UnguardedConsumeKernel
        )
        permit = self._issue_eval_permit(blind_kernel)
        self.assertTrue(self.ledger.execute(blind_kernel, permit, ANSWER_KEY_INTENT))
        self.assertEqual([("run_evaluation", ANSWER_KEY)], self.ledger.effects)
        # Contrast, same attempt against the real backend: denied (step 1).
        real_permit = self._issue_eval_permit(self.kernel)
        real_ledger = ConsequenceLedger()
        self.assertFalse(real_ledger.execute(self.kernel, real_permit, ANSWER_KEY_INTENT))
        self.assertEqual([], real_ledger.effects)


if __name__ == "__main__":
    unittest.main()
