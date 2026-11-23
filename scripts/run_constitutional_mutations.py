#!/usr/bin/env python3
"""Deliberately weaken Pulpo invariants and prove the existing tests detect it.

This script never mutates the checked-out branch permanently. Each mutation is
applied to one source file, one or more existing tests are run in a fresh Python
process with an isolated bytecode cache, and the original source bytes are
restored in a finally block.

A mutation is "killed" only when the selected existing regression test fails.
A surviving mutation means the test suite did not detect that constitutional
control being weakened and this proof fails closed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Sequence


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    old: str
    new: str
    tests: tuple[str, ...]


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "global_budget_upper_bound_removed",
        "pulpo/kernel.py",
        'if (\n            intent.cost < 0\n            or intent.cost\n            > self.policy.max_cost\n        ):\n            return "budget_exceeded"',
        'if (\n            intent.cost < 0\n        ):\n            return "budget_exceeded"',
        ("tests.test_kernel.GovernanceKernelTests.test_fail_closed_policy_boundaries",),
    ),
    Mutation(
        "global_action_allowlist_removed",
        "pulpo/kernel.py",
        'if (\n            intent.action\n            not in self.policy.allowed_actions\n        ):\n            return "action_not_allowed"',
        'if (\n            False\n            and intent.action\n            not in self.policy.allowed_actions\n        ):\n            return "action_not_allowed"',
        ("tests.test_kernel.GovernanceKernelTests.test_fail_closed_policy_boundaries",),
    ),
    Mutation(
        "agent_action_scope_removed",
        "pulpo/kernel.py",
        'if (\n                intent.action\n                not in grant.allowed_actions\n            ):\n                return "agent_action_not_allowed"',
        'if (\n                False\n                and intent.action\n                not in grant.allowed_actions\n            ):\n                return "agent_action_not_allowed"',
        ("tests.test_kernel.GovernanceKernelTests.test_agent_role_cannot_expand_its_action_or_resource",),
    ),
    Mutation(
        "agent_resource_scope_removed",
        "pulpo/kernel.py",
        'if not any(\n                intent.resource.startswith(\n                    prefix\n                )\n                for prefix\n                in grant.resource_prefixes\n            ):\n                return "agent_resource_not_allowed"',
        'if False and not any(\n                intent.resource.startswith(\n                    prefix\n                )\n                for prefix\n                in grant.resource_prefixes\n            ):\n                return "agent_resource_not_allowed"',
        ("tests.test_kernel.GovernanceKernelTests.test_agent_role_cannot_expand_its_action_or_resource",),
    ),
    Mutation(
        "agent_budget_upper_bound_removed",
        "pulpo/kernel.py",
        'if intent.cost > grant.max_cost:\n                return "agent_budget_exceeded"',
        'if False and intent.cost > grant.max_cost:\n                return "agent_budget_exceeded"',
        ("tests.test_kernel.GovernanceKernelTests.test_agent_budget_is_stricter_than_global_budget",),
    ),
    Mutation(
        "target_hash_binding_removed",
        "pulpo/kernel.py",
        'elif not hmac.compare_digest(\n                target.target_hash,\n                expected_target_hash,\n            ):',
        'elif False and not hmac.compare_digest(\n                target.target_hash,\n                expected_target_hash,\n            ):',
        (
            "tests.test_targets.TargetLockTests.test_exact_target_resolves_but_hash_mismatch_fails_closed",
            "tests.test_targets.TargetLockTests.test_mismatched_target_never_reaches_authority_evaluation",
        ),
    ),
    Mutation(
        "approval_intent_binding_removed",
        "pulpo/kernel.py",
        'if envelope.intent_hash != digest:\n            return self._approval_decide(\n                "approval_intent_mismatch",\n                digest,\n                envelope,\n            )',
        'if False and envelope.intent_hash != digest:\n            return self._approval_decide(\n                "approval_intent_mismatch",\n                digest,\n                envelope,\n            )',
        ("tests.test_authority.VerifiedApprovalTests.test_envelope_bindings_fail_closed_even_with_valid_authority_signature",),
    ),
    Mutation(
        "approval_policy_binding_removed",
        "pulpo/kernel.py",
        'if (\n            envelope.policy_hash\n            != self.policy_hash\n        ):\n            return self._approval_decide(\n                "approval_policy_mismatch",\n                digest,\n                envelope,\n            )',
        'if (\n            False\n            and envelope.policy_hash\n            != self.policy_hash\n        ):\n            return self._approval_decide(\n                "approval_policy_mismatch",\n                digest,\n                envelope,\n            )',
        ("tests.test_authority.VerifiedApprovalTests.test_envelope_bindings_fail_closed_even_with_valid_authority_signature",),
    ),
    Mutation(
        "approval_signature_verdict_ignored",
        "pulpo/kernel.py",
        'if signature_valid is not True:\n            return self._approval_decide(\n                "approval_signature_invalid",\n                digest,\n                envelope,\n            )',
        'if False and signature_valid is not True:\n            return self._approval_decide(\n                "approval_signature_invalid",\n                digest,\n                envelope,\n            )',
        ("tests.test_authority.VerifiedApprovalTests.test_invalid_or_missing_signature_fails_closed",),
    ),
    Mutation(
        "approval_id_replay_guard_removed",
        "pulpo/state.py",
        'if approval_id in self._approval_ids:\n            return "approval_id_replayed"',
        'if False and approval_id in self._approval_ids:\n            return "approval_id_replayed"',
        ("tests.test_authority.VerifiedApprovalTests.test_approval_id_and_nonce_are_each_single_use",),
    ),
    Mutation(
        "approval_nonce_replay_guard_removed",
        "pulpo/state.py",
        'if nonce in self._approval_nonces:\n            return "approval_nonce_replayed"',
        'if False and nonce in self._approval_nonces:\n            return "approval_nonce_replayed"',
        ("tests.test_authority.VerifiedApprovalTests.test_approval_id_and_nonce_are_each_single_use",),
    ),
    Mutation(
        "permit_spent_guard_removed",
        "pulpo/state.py",
        '                and issued[0] == intent_hash\n                and permit not in self._spent\n                and expires_at_ns is not None',
        '                and issued[0] == intent_hash\n                and expires_at_ns is not None',
        ("tests.test_kernel.GovernanceKernelTests.test_allowed_intent_gets_bound_one_use_permit",),
    ),
    Mutation(
        # Phase 2, Item 4 (remainder port of upstream #358): the
        # in-memory store's recorded-expiry re-check is the second
        # layer behind the kernel's signed-expiry authentication,
        # binding direct handle-level consume calls. Removing it
        # must be detected by the store second-layer tests: an
        # expired permit would then consume.
        "permit_store_expiry_check_removed_inmemory",
        "pulpo/state.py",
        '                and permit not in self._spent\n                and expires_at_ns is not None\n                and timestamp_ns < expires_at_ns',
        '                and permit not in self._spent\n                and expires_at_ns is not None',
        ("tests.test_permit_ttl.StoreSecondLayerTests.test_inmemory_store_refuses_consume_at_expiry",),
    ),
    Mutation(
        # Phase 2, Item 4 (remainder port of upstream #358): the same
        # second layer on the SQLite backend.
        "permit_store_expiry_check_removed_sqlite",
        "pulpo/state.py",
        '                and permit_row[1] == 0\n                and expires_at_ns is not None\n                and timestamp_ns < expires_at_ns',
        '                and permit_row[1] == 0\n                and expires_at_ns is not None',
        ("tests.test_permit_ttl.StoreSecondLayerTests.test_sqlite_store_refuses_consume_at_expiry",),
    ),
    Mutation(
        "directive_revocation_guard_removed",
        "pulpo/state.py",
        'return (\n            "directive_revoked"\n            if revoked\n            else "active"\n        )',
        'return (\n            "active"\n        )',
        ("tests.test_directives.DirectiveProofTests.test_revoked_directive_invalidates_previously_issued_permit",),
    ),
    Mutation(
        # The audit hash check lives in verify_audit_report (Phase 2,
        # Item 1 moved it out of verify_audit, which now delegates).
        # Removing it must be detected by the audit-integrity tests.
        "audit_record_hash_check_removed",
        "pulpo/kernel.py",
        'if not hmac.compare_digest(str(record["hash"]), expected):\n                    report.update({"ok": False, "reason": "audit_hash_mismatch", "failed_record": index})',
        'if False and not hmac.compare_digest(str(record["hash"]), expected):\n                    report.update({"ok": False, "reason": "audit_hash_mismatch", "failed_record": index})',
        ("tests.test_kernel.GovernanceKernelTests.test_audit_chain_detects_tampering",),
    ),
    Mutation(
        # Port of upstream PR #357 (Phase 2, Item 1): the signature
        # verification in verify_audit_report is what makes a forged
        # or garbage signature fail closed. Removing it must be
        # detected by the audit-signing tests.
        "audit_record_signature_check_removed",
        "pulpo/kernel.py",
        'if not signer.verify(record["hash"], signature):',
        'if False:',
        (
            "tests.test_audit_signing.SignedAuditLibraryTests.test_single_signature_replaced_with_garbage_refused",
        ),
    ),
    Mutation(
        # Port of upstream PR #357 (Phase 2, Item 1): the signature
        # requirement — every record at or after the legacy prefix must
        # carry one when signing is enabled — is what makes a stripped
        # signature fail closed instead of silently downgrading the
        # chain to unsigned. Removing it must be detected by the
        # audit-signing tests.
        "audit_record_signature_required_check_removed",
        "pulpo/kernel.py",
        'elif index >= legacy_records:',
        'elif False:',
        (
            "tests.test_audit_signing.SignedAuditLibraryTests.test_single_signature_stripped_refused",
        ),
    ),
    Mutation(
        # Phase 2, Item 3A: the typed-evidence requirement is the
        # control that refuses a bare-dict directive activation at the
        # state surface. Weakening it must be detected by the facade
        # tests (a dict then reaches the binding checks and raises the
        # wrong error / a subclass is admitted).
        "directive_evidence_type_check_removed",
        "pulpo/state.py",
        'if type(authority_evidence) is not VerifiedAuthorityEvidence:\n        raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")\n    evidence = authority_evidence',
        'if False and type(authority_evidence) is not VerifiedAuthorityEvidence:\n        raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")\n    evidence = authority_evidence',
        (
            "tests.test_capability_facade.TypedEvidenceGateTests.test_bare_dict_activation_refused_inmemory",
            "tests.test_capability_facade.TypedEvidenceGateTests.test_evidence_subclass_refused",
        ),
    ),
    Mutation(
        # Phase 2, Item 3A: the binding cross-check is the control that
        # refuses evidence naming a different directive than the one
        # being mutated. Weakening it must be detected by the facade
        # tests.
        "directive_evidence_binding_check_removed",
        "pulpo/state.py",
        'if (\n        evidence.operation != operation\n        or evidence.directive_id != directive_id\n        or evidence.directive_version != version\n        or evidence.directive_hash != directive_hash\n        or (check_parent and evidence.parent_directive_hash != parent_directive_hash)\n    ):',
        'if False and (\n        evidence.operation != operation\n        or evidence.directive_id != directive_id\n        or evidence.directive_version != version\n        or evidence.directive_hash != directive_hash\n        or (check_parent and evidence.parent_directive_hash != parent_directive_hash)\n    ):',
        (
            "tests.test_capability_facade.TypedEvidenceGateTests.test_evidence_bound_to_another_directive_refused",
        ),
    ),
    Mutation(
        # Codex P1 fix on PR #359: the completion verb's own filesystem
        # observation is the control that refuses evidence naming a
        # nonexistent or unobserved artifact. Replacing the observation
        # with a fabricated one must be detected by the facade tests.
        "target_completion_observation_removed",
        "pulpo/kernel.py",
        '        resolved_path, artifact_sha256, size_bytes = _observe_artifact_file(artifact_path)',
        '        resolved_path, artifact_sha256, size_bytes = (str(artifact_path), "0" * 64, 1)',
        (
            "tests.test_capability_facade.HonestFacadeFlowTests.test_kernel_verb_target_completion_observes_real_file",
            "tests.test_capability_facade.HonestFacadeFlowTests.test_kernel_verb_target_completion_refuses_unobserved_or_mismatched",
            "tests.test_capability_facade.HonestFacadeFlowTests.test_forged_target_completion_does_not_complete_target",
        ),
    ),
    Mutation(
        # Codex P1 fix on PR #359: the completion verb's intent-hash
        # cross-check binds the observed artifact to the exact locked
        # target's intent. Weakening it must be detected by the facade
        # tests.
        "target_completion_intent_check_removed",
        "pulpo/kernel.py",
        '        if not hmac.compare_digest(expected_intent_hash, intent_hash):',
        '        if False and not hmac.compare_digest(expected_intent_hash, intent_hash):',
        (
            "tests.test_capability_facade.HonestFacadeFlowTests.test_kernel_verb_target_completion_refuses_unobserved_or_mismatched",
        ),
    ),
    Mutation(
        # Codex P1 fix on PR #359: the outcome-memory verb's custody-
        # evidence requirement is the control that refuses a
        # self-asserted memory with no projected custody receipt behind
        # it. Weakening it must be detected by the facade tests.
        "outcome_memory_custody_evidence_check_removed",
        "pulpo/kernel.py",
        '        if len(custody_matches) != 1:',
        '        if False and len(custody_matches) != 1:',
        (
            "tests.test_capability_facade.HonestFacadeFlowTests.test_kernel_verb_outcome_memory_refuses_self_asserted_payloads",
            "tests.test_capability_facade.HonestFacadeFlowTests.test_forged_outcome_memory_is_not_returned_by_latest",
        ),
    ),
    Mutation(
        # Port of upstream PR #372 (kernel build item #2): the
        # projection's denial record call is what makes a
        # directive-scope denial visible to the canonical audit.
        # Removing it must be detected by the item #2 tests.
        "projection_denial_record_removed",
        "pulpo/directives.py",
        '        self.kernel.record_directive_denial(\n            intent,',
        '        None and self.kernel.record_directive_denial(\n            intent,',
        (
            "tests.test_projection_denial_audit.ProjectionDenialRecordTests.test_unknown_directive_denial_is_recorded_with_fixed_schema",
            "tests.test_projection_denial_audit.ProjectionDenialRecordTests.test_mandate_failures_are_recorded",
        ),
    ),
    Mutation(
        # PR #372 Codex P1 fix: the incident channel's near-miss
        # classification of directive_denial is what makes a recorded
        # projection denial visible in a frozen incident report.
        # Dropping the event from the set must be detected.
        "incident_channel_directive_denial_unclassified",
        "pulpo/incident_channel.py",
        '_AUDIT_NEAR_MISS_EVENTS = frozenset({"purchase_revalidation_failed", "permit_rejected", "approval_rejected", "directive_denial"})',
        '_AUDIT_NEAR_MISS_EVENTS = frozenset({"purchase_revalidation_failed", "permit_rejected", "approval_rejected"})',
        (
            "tests.test_incident_channel.IncidentChannelAuditFeedTests.test_directive_denial_audit_event_is_a_near_miss",
            "tests.test_projection_denial_audit.ProjectionDenialIncidentReportTests.test_unknown_directive_denial_is_a_near_miss_in_the_report",
        ),
    ),
    Mutation(
        # PR #372 Codex P2 fix: the denial verb's trusted-time
        # resolution is what keeps an unavailable clock from breaking
        # the fail-closed Decision. Restoring the raw clock read must
        # be detected by the clock-posture tests.
        "directive_denial_clock_unchecked",
        "pulpo/kernel.py",
        "        trusted_time = self._trusted_now()\n        record_time = 0 if trusted_time is None else trusted_time",
        "        record_time = self._clock()",
        (
            "tests.test_projection_denial_audit.ProjectionDenialClockPostureTests.test_raising_clock_unknown_directive_still_denies_and_records",
            "tests.test_projection_denial_audit.ProjectionDenialClockPostureTests.test_none_clock_records_zero_timestamp_in_memory",
            "tests.test_projection_denial_audit.ProjectionDenialClockPostureTests.test_unavailable_clock_records_zero_timestamp_in_sqlite",
        ),
    ),
    Mutation(
        # Port of upstream PR #371 (Phase 3, Item 3B): the service
        # boundary's request MAC is the authentication control — a
        # request that does not authenticate must never reach a verb.
        # Weakening it must be detected by the boundary tests.
        # Anchor updated by the Control Center §5.2 read-only role:
        # the MAC check now falls through to the read-only secret
        # before refusing, so the anchor is the whole if-block.
        "service_request_mac_check_removed",
        "pulpo/service.py",
        '            if not isinstance(claimed_mac, str) or not hmac.compare_digest(claimed_mac, expected):\n                if not self._authenticate_read_only(claimed_mac, body):\n                    raise ServiceRefusal("request_mac_invalid")\n                role = "read_only"',
        '            if False and (not isinstance(claimed_mac, str) or not hmac.compare_digest(claimed_mac, expected)):\n                if not self._authenticate_read_only(claimed_mac, body):\n                    raise ServiceRefusal("request_mac_invalid")\n                role = "read_only"',
        (
            "tests.test_service_boundary.AdversarialBoundaryTests.test_wrong_secret_and_tampered_args_refused_without_state_change",
        ),
    ),
    Mutation(
        # Control Center design §5.2: the read-only role gate is
        # what keeps a read-only credential from reaching a mutating
        # verb. Removing it must be detected by the read-only tests.
        "service_read_only_role_gate_removed",
        "pulpo/service.py",
        '                if role == "read_only" and verb not in READ_ONLY_VERBS:\n                    self._record_read_only_refusal(verb, now_ns)\n                    raise ServiceRefusal("read_only_role_forbidden")',
        '                if False and (role == "read_only" and verb not in READ_ONLY_VERBS):\n                    self._record_read_only_refusal(verb, now_ns)\n                    raise ServiceRefusal("read_only_role_forbidden")',
        (
            "tests.test_read_only_service_role.ReadOnlyRoleTests.test_every_mutating_verb_refused_for_read_only_credential",
        ),
    ),
    Mutation(
        # Control Center design §5.4: the journal append is the
        # feed's evidence commitment — an evaluation that is never
        # appended is a decision with no receipt. Removing it must
        # be detected by the ingestion tests.
        "drift_feed_journal_append_removed",
        "core/drift_feed.py",
        "        self._journal.append(JOURNAL_EVENT, evaluation.to_journal_payload())",
        "        pass  # journal append removed",
        (
            "tests.test_drift_ingestion.DriftIngestionTests.test_dying_sensor_end_to_end",
            "tests.test_drift_ingestion.DriftIngestionTests.test_repeated_identical_samples_are_each_recorded_and_persist",
        ),
    ),
    Mutation(
        # Calibration provenance on the drift head: the deadline is
        # derived as last calibration plus interval when the
        # deployment supplied no explicit deadline. Removing the
        # derivation must be detected by the provenance tests.
        "drift_calibration_due_derivation_removed",
        "pulpo/observer_snapshot.py",
        "    return last_calibration_ns + int(calibration_interval_days * _NS_PER_DAY)",
        "    return None  # calibration deadline derivation removed",
        (
            "tests.test_observer_snapshot.ObserverSnapshotTests.test_drift_head_carries_calibration_provenance",
            "tests.test_drift_ingestion.DriftIngestionTests.test_calibration_provenance_is_recorded_and_supplied",
        ),
    ),
    Mutation(
        # Reconciliation-state exposure (design item 5.5): the freeze
        # derives "reconciling" with its start time from the
        # deployment's protocols. Removing the derivation must be
        # detected by the reconciliation tests -- a snapshot that
        # reports "unknown" while a mission is reconciling hides the
        # mid-reconciliation state the CC exists to show.
        "reconciliation_state_derivation_removed",
        "pulpo/observer_snapshot.py",
        '    return "reconciling", min(since_values), last_completed_ns',
        '    return "unknown", None, None  # reconciliation state derivation removed',
        (
            "tests.test_reconciliation_state.ReconciliationSnapshotTests.test_reconciling_protocol_reports_state_and_since",
            "tests.test_reconciliation_state.ReconciliationSnapshotTests.test_earliest_start_wins_across_protocols",
        ),
    ),
    Mutation(
        # Port of upstream PR #371 (Phase 3, Item 3B): the nonce
        # replay check is what makes a captured request frame
        # single-use at the protocol layer, on top of the kernel's
        # own permit single-use.
        "service_replay_check_removed",
        "pulpo/service.py",
        '                if nonce in self._seen_nonces:\n                    raise ServiceRefusal("request_replayed")',
        '                if False and nonce in self._seen_nonces:\n                    raise ServiceRefusal("request_replayed")',
        (
            "tests.test_service_boundary.AdversarialBoundaryTests.test_replayed_request_refused",
        ),
    ),
    Mutation(
        # Port of upstream PR #371 (Phase 3, Item 3B): request
        # freshness — an expired request must fail closed before any
        # verb runs.
        "service_expiry_check_removed",
        "pulpo/service.py",
        '            if expires <= now_ns:\n                raise ServiceRefusal("request_expired")',
        '            if False and expires <= now_ns:\n                raise ServiceRefusal("request_expired")',
        (
            "tests.test_service_boundary.AdversarialBoundaryTests.test_expired_and_not_yet_valid_requests_refused",
        ),
    ),
    Mutation(
        # Port of upstream PR #371 (Phase 3, Item 3B): the client
        # verifies the response MAC before trusting any result; a
        # tampered response must be refused, never consumed.
        "service_response_mac_check_removed",
        "pulpo/service.py",
        '        if not isinstance(claimed_mac, str) or not hmac.compare_digest(claimed_mac, expected):\n            raise ServiceRefusal("response_mac_invalid")',
        '        if False and (not isinstance(claimed_mac, str) or not hmac.compare_digest(claimed_mac, expected)):\n            raise ServiceRefusal("response_mac_invalid")',
        (
            "tests.test_service_boundary.AdversarialBoundaryTests.test_response_tampering_detected_by_client",
        ),
    ),
    Mutation(
        # Port of upstream PR #373 (Phase 3, Item 4B): the
        # consume-side presenter gate is what makes a bound permit
        # unspendable by a token thief. Removing it must be detected
        # by the presenter-binding tests.
        "presenter_binding_check_removed",
        "pulpo/kernel.py",
        "            refusal = self._presenter_refusal(claims, digest, permit, presenter, presenter_proof)",
        "            refusal = None and self._presenter_refusal(claims, digest, permit, presenter, presenter_proof)",
        (
            "tests.test_presenter_binding.BoundConsumeTests.test_wrong_presenter_refused_and_permit_not_burned",
            "tests.test_presenter_binding.BoundConsumeTests.test_missing_proof_refused_and_permit_not_burned",
        ),
    ),
)


def _run_tests(root: Path, tests: Sequence[str]) -> subprocess.CompletedProcess[str]:
    # CPython's timestamp/size bytecode cache can otherwise reuse the previous
    # mutant when several same-sized source mutations happen within one second.
    # Give every mutant a unique cache so the subprocess must compile exactly
    # the source bytes currently on disk.
    with tempfile.TemporaryDirectory(prefix="pulpo-mutation-pycache-") as cache:
        env = os.environ.copy()
        env["PYTHONPYCACHEPREFIX"] = cache
        return subprocess.run(
            [sys.executable, "-W", "error", "-m", "unittest", *tests, "-v"],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )


def run(root: Path) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for mutation in MUTATIONS:
        path = root / mutation.path
        original = path.read_text(encoding="utf-8")
        occurrences = original.count(mutation.old)
        if occurrences != 1:
            results.append(
                {
                    "name": mutation.name,
                    "path": mutation.path,
                    "status": "invalid",
                    "reason": f"expected one mutation anchor, found {occurrences}",
                    "tests": list(mutation.tests),
                }
            )
            continue

        path.write_text(original.replace(mutation.old, mutation.new, 1), encoding="utf-8")
        try:
            completed = _run_tests(root, mutation.tests)
        finally:
            path.write_text(original, encoding="utf-8")

        status = "killed" if completed.returncode != 0 else "survived"
        results.append(
            {
                "name": mutation.name,
                "path": mutation.path,
                "status": status,
                "test_returncode": completed.returncode,
                "tests": list(mutation.tests),
            }
        )

    killed = sum(item["status"] == "killed" for item in results)
    survived = sum(item["status"] == "survived" for item in results)
    invalid = sum(item["status"] == "invalid" for item in results)
    total = len(results)
    return {
        "schema": "pulpo.constitutional-survival.v0",
        "authority_effect": "none",
        "provider_write_attempted": False,
        "mutations_total": total,
        "mutations_killed": killed,
        "mutations_survived": survived,
        "mutations_invalid": invalid,
        "survival_score": killed / total if total else 0.0,
        "result": "pass" if killed == total and survived == 0 and invalid == 0 else "fail",
        "mutations": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = run(root)
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
