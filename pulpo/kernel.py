"""Small, deterministic governance kernel with no runtime dependencies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Callable, Protocol

from .authority import ApprovalEnvelope, ApprovalVerifier, AuthorityTrust
from .state import (
    ApprovalUse,
    AuditSigner,
    DirectivePermitBinding,
    InMemoryKernelState,
    KernelState,
    SQLiteKernelState,
    VerifiedAuthorityEvidence,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _observe_artifact_file(path: str | Path) -> tuple[str, str, int]:
    """Hash one stable regular file through a descriptor-bound observation.

    The resolved path, descriptor identity, byte count, size, and metadata
    must remain stable for the whole observation. A writer racing the read
    therefore cannot produce completion evidence for a mixed or replaced
    artifact snapshot. This is the single implementation: the target
    reconciliation projection delegates here, and the kernel's
    ``record_target_completion`` verb observes through it, so a caller can
    never substitute a self-asserted hash for an observed one.
    """

    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("artifact_not_found") from exc

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except FileNotFoundError as exc:
        raise ValueError("artifact_changed_during_observation") from exc
    except OSError as exc:
        raise ValueError("artifact_unreadable") from exc

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("artifact_not_file")
        if before.st_size <= 0:
            raise ValueError("artifact_empty")

        digest = sha256()
        bytes_read = 0
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                bytes_read += len(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            path_after = os.stat(resolved, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("artifact_changed_during_observation") from exc

        stable_descriptor = (
            before.st_dev == after.st_dev
            and before.st_ino == after.st_ino
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
        )
        stable_path = (
            after.st_dev == path_after.st_dev
            and after.st_ino == path_after.st_ino
            and after.st_size == path_after.st_size
        )
        if bytes_read != before.st_size or not stable_descriptor or not stable_path:
            raise ValueError("artifact_changed_during_observation")

        return str(resolved), digest.hexdigest(), bytes_read
    finally:
        os.close(descriptor)


def _token_time_ns(raw: str) -> int | None:
    """Parse a token time field, or None when it is not well-formed."""

    if not raw or any(char not in "0123456789" for char in raw):
        return None

    try:
        return int(raw)
    except ValueError:
        # Overlong digit strings exceed the int() digit cap.
        return None


# Presenter binding (Phase 3, Item 4B -- token v3; ported from upstream #373
# via Preview #148). A permit may be bound at issuance to one presenter
# identity; the token's signed claims then carry the SHA-256 of that
# identity, and consumption requires a proof, signed by the presenter's
# key over the exact token and intent, that the kernel verifies against
# the presenter verifier registered for that identity at construction.
# An unbound permit carries the hash of the empty string as its
# presenter claim and remains a bearer <redacted> exactly as before -- unless
# the policy requires binding, in which case unbound permits are neither
# minted nor spent. Autonomous jumps straight from token v1
# (``digest:nonce:signature``) to v3: v1 strings fail closed at consume
# under this format.
PRESENTER_PROOF_SCHEMA = "pulpo.presenter-proof.v1"

UNBOUND_PRESENTER_HASH = sha256(b"").hexdigest()


class PresenterVerifier(Protocol):
    """Verification-only adapter for one presenter's key.

    Structurally the approval verifier's shape: the presenter signs
    ``GovernanceKernel.presenter_proof_payload(...)`` bytes with its
    own key; the kernel holds only verification. A deployment
    registers one verifier per presenter identity at kernel
    construction; the registry is deployment configuration, never
    policy, and never enters the audit chain.
    """

    def verify(self, payload: bytes, signature: str) -> bool:
        """Return true only for a proof signed by this presenter."""
        ...


@dataclass(frozen=True)
class Intent:
    principal: str
    action: str
    resource: str
    cost: int = 0
    session_id: str = "default"


@dataclass(frozen=True)
class LockedTarget:
    """Immutable proposed consequence recorded before authority evaluation.

    Locking a target creates no permit and has no authority effect. The target
    hash binds the exact intent plus target identity, version, and lock time so
    a later interface can resolve a short command such as ``fire`` to one
    durable object before asking the kernel for an authorization decision.
    """

    target_id: str
    version: int
    intent: Intent
    created_at_ns: int
    schema: str = "pulpo.target.v0"

    def __post_init__(self) -> None:
        if not self.target_id or self.version <= 0 or self.created_at_ns <= 0:
            raise ValueError(
                "target identity, version, and lock time must be valid"
            )
        if self.schema != "pulpo.target.v0":
            raise ValueError("unsupported target schema")

    @property
    def target_hash(self) -> str:
        return sha256(
            _canonical(
                {
                    "schema": self.schema,
                    "target_id": self.target_id,
                    "version": self.version,
                    "intent": asdict(self.intent),
                    "created_at_ns": self.created_at_ns,
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class TargetResolution:
    outcome: str
    reason: str
    target_id: str
    version: int
    expected_target_hash: str
    target: LockedTarget | None = None


@dataclass(frozen=True)
class AgentGrant:
    """Least-authority limits for one agent principal."""

    principal: str
    allowed_actions: frozenset[str]
    resource_prefixes: tuple[str, ...]
    max_cost: int

    def __post_init__(self) -> None:
        if not self.principal or not self.allowed_actions or not self.resource_prefixes:
            raise ValueError("agent grant fields must be non-empty")
        if any(not prefix for prefix in self.resource_prefixes):
            raise ValueError("resource prefixes must be non-empty")
        if self.max_cost < 0:
            raise ValueError("agent max_cost must be non-negative")


@dataclass(frozen=True)
class Policy:
    allowed_actions: frozenset[str]
    max_cost: int
    approval_actions: frozenset[str] = frozenset()
    agent_grants: tuple[AgentGrant, ...] = ()
    authority_trust: AuthorityTrust | None = None
    permit_ttl_ns: int = 300_000_000_000

    # Presenter binding (Phase 3, Item 4B): when true, every
    # permit this policy issues must be bound to a registered
    # presenter, and unbound permits are refused at consume.
    # Default false keeps the bearer <redacted> posture for policies
    # that do not opt in.
    require_presenter_binding: bool = False

    def __post_init__(self) -> None:
        principals = [
            grant.principal
            for grant in self.agent_grants
        ]

        if len(principals) != len(set(principals)):
            raise ValueError("agent principals must be unique")

        if any(
            not grant.allowed_actions.issubset(self.allowed_actions)
            for grant in self.agent_grants
        ):
            raise ValueError(
                "agent actions must be a subset of policy actions"
            )

        if self.approval_actions and self.authority_trust is None:
            raise ValueError(
                "approval actions require a pinned authority trust"
            )

        if self.authority_trust is not None and not self.approval_actions:
            raise ValueError(
                "authority trust requires at least one approval action"
            )

        if (
            isinstance(self.permit_ttl_ns, bool)
            or not isinstance(self.permit_ttl_ns, int)
            or self.permit_ttl_ns <= 0
        ):
            raise ValueError(
                "permit_ttl_ns must be a positive integer"
            )

        if not isinstance(self.require_presenter_binding, bool):
            raise ValueError("require_presenter_binding must be a bool")


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    intent_hash: str
    permit: str | None = None


class StateIntegrityError(RuntimeError):
    """Raised when persisted audit state cannot be trusted at bootstrap."""


class AuthorityTrustError(RuntimeError):
    """Raised when a configured verifier does not match pinned policy trust."""


class GovernanceKernel:
    """Evaluates intent, issues one-use permits, and maintains an audit chain."""

    def __init__(
        self,
        policy: Policy,
        secret: bytes | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        clock: Callable[[], int] | None = None,
        state: KernelState | None = None,
        presenter_verifiers: dict[str, PresenterVerifier] | None = None,
        audit_signer: AuditSigner | None = None,
        legacy_audit_records: int = 0,
    ) -> None:
        self.policy = policy
        self._secret = secret or secrets.token_bytes(32)
        self._explicit_secret = secret is not None
        self._policy_hash = self._compute_policy_hash()
        self._approval_verifier = approval_verifier
        # Presenter registry (Item 4B): presenter identity -> verifier.
        # Deployment configuration injected at construction, like the
        # approval verifier; copied so later mutation of the caller's
        # dict cannot change who this kernel will accept proofs from.
        self._presenter_verifiers: dict[str, PresenterVerifier] = dict(presenter_verifiers or {})
        self._clock = clock or time.time_ns
        if state is not None and (audit_signer is not None or legacy_audit_records):
            # The signer lives in the state layer (it signs at append);
            # a caller that hands in a state must have constructed that
            # state with its signer. Supplying both would leave two
            # sources of truth for which records must be signed, so
            # refuse rather than guess.
            raise ValueError("audit_signer/legacy_audit_records must be given on the state, not the kernel, when a state is supplied")
        self._state = (
            state
            if state is not None
            else InMemoryKernelState(audit_signer=audit_signer, legacy_audit_records=legacy_audit_records)
        )

        self._verified_audit_token: object | None = None

        if (
            self._approval_verifier is not None
            and not self._verifier_matches_trust(
                self._approval_verifier
            )
        ):
            raise AuthorityTrustError(
                "approval verifier does not match pinned authority trust"
            )

        try:
            audit_valid = self.verify_audit()
        except Exception as exc:
            raise StateIntegrityError(
                "kernel state audit chain is invalid"
            ) from exc

        if not audit_valid:
            raise StateIntegrityError(
                "kernel state audit chain is invalid"
            )

    @property
    def audit(self) -> list[dict[str, Any]]:
        return self._state.audit

    @staticmethod
    def intent_hash(intent: Intent) -> str:
        return sha256(
            _canonical(asdict(intent))
        ).hexdigest()

    def _compute_policy_hash(self) -> str:
        grants = [
            {
                "principal": grant.principal,
                "allowed_actions": sorted(grant.allowed_actions),
                "resource_prefixes": sorted(grant.resource_prefixes),
                "max_cost": grant.max_cost,
            }
            for grant in sorted(
                self.policy.agent_grants,
                key=lambda item: item.principal,
            )
        ]

        payload = {
            "schema": "pulpo.policy.v1",
            "allowed_actions": sorted(
                self.policy.allowed_actions
            ),
            "max_cost": self.policy.max_cost,
            "approval_actions": sorted(
                self.policy.approval_actions
            ),
            "agent_grants": grants,
            "authority_trust": (
                asdict(self.policy.authority_trust)
                if self.policy.authority_trust
                else None
            ),
            "permit_ttl_ns": self.policy.permit_ttl_ns,
        }

        if self.policy.require_presenter_binding:
            # Requiring presenter binding is an authority-relevant
            # policy choice (it retires the bearer <redacted>), so it binds
            # into the policy hash. Policies that do not require it
            # keep the exact pre-Item-4B hash.
            payload["require_presenter_binding"] = True

        return sha256(
            _canonical(payload)
        ).hexdigest()

    def _require_pinned_policy(self) -> None:
        """Fail closed if the evaluation policy drifted after construction.

        The policy is deployment configuration pinned at construction
        (Repro D, upstream #355): reassigning ``kernel.policy``
        afterwards silently swapped the evaluation policy with no audit
        record. Every decision point recomputes the policy hash from
        the live policy and compares it to the pinned hash; any drift
        — or a policy that can no longer be hashed at all — raises
        StateIntegrityError before any decision is recorded.
        """
        try:
            current = self._compute_policy_hash()
        except Exception as exc:
            raise StateIntegrityError("policy hash cannot be recomputed") from exc

        if not hmac.compare_digest(current, self._policy_hash):
            raise StateIntegrityError("policy changed after kernel construction")

    @property
    def policy_hash(self) -> str:
        return self._policy_hash

    def lock_target(
        self,
        target_id: str,
        intent: Intent,
        *,
        version: int = 1,
    ) -> LockedTarget:
        """Record an exact proposed target without granting authority."""

        existing = self.get_locked_target(
            target_id,
            version=version,
        )

        if existing is not None:
            if not hmac.compare_digest(
                self.intent_hash(existing.intent),
                self.intent_hash(intent),
            ):
                raise ValueError(
                    "target version is immutable"
                )
            return existing

        now_ns = self._trusted_now()

        if now_ns is None:
            raise RuntimeError(
                "target_clock_invalid"
            )

        target = LockedTarget(
            target_id,
            version,
            intent,
            now_ns,
        )

        self._state.append(
            "target_locked",
            {
                "schema": target.schema,
                "target_id": target.target_id,
                "version": target.version,
                "target_hash": target.target_hash,
                "intent": asdict(target.intent),
                "intent_hash": self.intent_hash(
                    target.intent
                ),
                "created_at_ns": target.created_at_ns,
                "authority_effect": "none",
            },
            now_ns,
        )

        return target

    def get_locked_target(
        self,
        target_id: str,
        *,
        version: int = 1,
    ) -> LockedTarget | None:
        """Resolve a locked target from the canonical audit chain."""

        if not target_id or version <= 0:
            return None

        self._require_audit_integrity()

        for record in self._state.iter_audit(
            event="target_locked",
            reverse=True,
        ):
            payload = record.get(
                "payload",
                {},
            )

            if (
                payload.get("target_id") != target_id
                or payload.get("version") != version
            ):
                continue

            try:
                intent_payload = payload["intent"]

                target = LockedTarget(
                    target_id=payload["target_id"],
                    version=payload["version"],
                    intent=Intent(**intent_payload),
                    created_at_ns=payload["created_at_ns"],
                    schema=payload["schema"],
                )

                stored_target_hash = payload[
                    "target_hash"
                ]
                stored_intent_hash = payload[
                    "intent_hash"
                ]

            except (
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise StateIntegrityError(
                    "locked target record is invalid"
                ) from exc

            if not hmac.compare_digest(
                target.target_hash,
                stored_target_hash,
            ):
                raise StateIntegrityError(
                    "locked target hash is invalid"
                )

            if not hmac.compare_digest(
                self.intent_hash(target.intent),
                stored_intent_hash,
            ):
                raise StateIntegrityError(
                    "locked target intent hash is invalid"
                )

            if payload.get("authority_effect") != "none":
                raise StateIntegrityError(
                    "locked target cannot carry authority"
                )

            return target

        return None

    def resolve_locked_target(
        self,
        target_id: str,
        expected_target_hash: str,
        *,
        version: int = 1,
    ) -> TargetResolution:
        """Fail closed unless a caller references the exact durable target."""

        now_ns = self._trusted_now()

        if now_ns is None:
            return TargetResolution(
                "deny",
                "target_clock_invalid",
                target_id,
                version,
                expected_target_hash,
            )

        if (
            not target_id
            or version <= 0
            or not isinstance(
                expected_target_hash,
                str,
            )
            or len(expected_target_hash) != 64
        ):
            result = TargetResolution(
                "deny",
                "target_reference_invalid",
                target_id,
                version,
                expected_target_hash,
            )

        else:
            target = self.get_locked_target(
                target_id,
                version=version,
            )

            if target is None:
                result = TargetResolution(
                    "deny",
                    "target_not_locked",
                    target_id,
                    version,
                    expected_target_hash,
                )

            elif not hmac.compare_digest(
                target.target_hash,
                expected_target_hash,
            ):
                result = TargetResolution(
                    "deny",
                    "target_hash_mismatch",
                    target_id,
                    version,
                    expected_target_hash,
                )

            else:
                result = TargetResolution(
                    "match",
                    "target_exact_match",
                    target_id,
                    version,
                    expected_target_hash,
                    target,
                )

        self._state.append(
            "target_resolution",
            {
                "outcome": result.outcome,
                "reason": result.reason,
                "target_id": target_id,
                "version": version,
                "expected_target_hash": expected_target_hash,
                "resolved_target_hash": (
                    result.target.target_hash
                    if result.target
                    else None
                ),
                "authority_effect": "none",
            },
            now_ns,
        )

        return result

    def evaluate_locked_target(
        self,
        target_id: str,
        expected_target_hash: str,
        *,
        version: int = 1,
        presenter: str | None = None,
    ) -> tuple[
        TargetResolution,
        Decision | None,
    ]:
        """Resolve an exact target, then delegate authority to the normal evaluator."""

        resolution = self.resolve_locked_target(
            target_id,
            expected_target_hash,
            version=version,
        )

        if (
            resolution.outcome != "match"
            or resolution.target is None
        ):
            return resolution, None

        return (
            resolution,
            self.evaluate(
                resolution.target.intent,
                presenter=presenter,
            ),
        )

    def evaluate(
        self,
        intent: Intent,
        *,
        presenter: str | None = None,
    ) -> Decision:
        self._require_pinned_policy()

        digest = self.intent_hash(intent)

        failure = self._policy_failure(
            intent
        )

        if failure:
            return self._decide(
                "deny",
                failure,
                digest,
            )

        if (
            intent.action
            in self.policy.approval_actions
        ):
            return self._decide(
                "require_approval",
                "approval_required",
                digest,
            )

        return self._issue_permit(
            digest,
            presenter=presenter,
        )

    def evaluate_with_approval(
        self,
        intent: Intent,
        envelope: ApprovalEnvelope,
        *,
        presenter: str | None = None,
    ) -> Decision:
        """Issue a permit only after verification by the configured authority."""

        self._require_pinned_policy()

        digest = self.intent_hash(
            intent
        )

        failure = self._policy_failure(
            intent
        )

        if failure:
            return self._decide(
                "deny",
                failure,
                digest,
            )

        if (
            intent.action
            not in self.policy.approval_actions
        ):
            if not isinstance(
                envelope,
                ApprovalEnvelope,
            ):
                return self._decide(
                    "deny",
                    "approval_envelope_invalid",
                    digest,
                )

            return self._approval_decide(
                "approval_not_required",
                digest,
                envelope,
            )

        if not isinstance(
            envelope,
            ApprovalEnvelope,
        ):
            return self._decide(
                "deny",
                "approval_envelope_invalid",
                digest,
            )

        verifier = self._approval_verifier

        if verifier is None:
            return self._approval_decide(
                "approval_verifier_unavailable",
                digest,
                envelope,
            )

        if not self._verifier_matches_trust(
            verifier
        ):
            return self._approval_decide(
                "approval_verifier_untrusted",
                digest,
                envelope,
            )

        if not envelope.signature:
            return self._approval_decide(
                "approval_signature_missing",
                digest,
                envelope,
            )

        trust = self.policy.authority_trust

        if trust is None:
            return self._approval_decide(
                "approval_trust_unavailable",
                digest,
                envelope,
            )

        if (
            envelope.authority_id
            != trust.authority_id
        ):
            return self._approval_decide(
                "approval_authority_mismatch",
                digest,
                envelope,
            )

        if (
            envelope.verifier_id
            != trust.verifier_id
        ):
            return self._approval_decide(
                "approval_verifier_mismatch",
                digest,
                envelope,
            )

        if envelope.key_id != trust.key_id:
            return self._approval_decide(
                "approval_key_mismatch",
                digest,
                envelope,
            )

        if (
            envelope.deployment_id
            != trust.deployment_id
        ):
            return self._approval_decide(
                "approval_deployment_mismatch",
                digest,
                envelope,
            )

        if (
            envelope.trust_hash
            != trust.trust_hash
        ):
            return self._approval_decide(
                "approval_trust_mismatch",
                digest,
                envelope,
            )

        if (
            envelope.session_id
            != intent.session_id
        ):
            return self._approval_decide(
                "approval_session_mismatch",
                digest,
                envelope,
            )

        if (
            envelope.principal
            != intent.principal
        ):
            return self._approval_decide(
                "approval_principal_mismatch",
                digest,
                envelope,
            )

        if envelope.intent_hash != digest:
            return self._approval_decide(
                "approval_intent_mismatch",
                digest,
                envelope,
            )

        if (
            envelope.policy_hash
            != self.policy_hash
        ):
            return self._approval_decide(
                "approval_policy_mismatch",
                digest,
                envelope,
            )

        now_ns = self._trusted_now()

        if now_ns is None:
            return self._approval_decide(
                "approval_clock_invalid",
                digest,
                envelope,
                timestamp_ns=0,
            )

        if now_ns < envelope.issued_at_ns:
            return self._approval_decide(
                "approval_not_yet_valid",
                digest,
                envelope,
                timestamp_ns=now_ns,
            )

        if (
            envelope.expires_at_ns
            - envelope.issued_at_ns
            > trust.max_approval_ttl_ns
        ):
            return self._approval_decide(
                "approval_ttl_exceeded",
                digest,
                envelope,
                timestamp_ns=now_ns,
            )

        if now_ns >= envelope.expires_at_ns:
            return self._approval_decide(
                "approval_expired",
                digest,
                envelope,
            )

        replay = (
            self._state.approval_replay_reason(
                envelope.approval_id,
                envelope.nonce,
            )
        )

        if replay:
            return self._approval_decide(
                replay,
                digest,
                envelope,
            )

        try:
            signature_valid = verifier.verify(
                envelope.signing_bytes(),
                envelope.signature,
            )

        except Exception:
            return self._approval_decide(
                "approval_verifier_failed",
                digest,
                envelope,
            )

        if signature_valid is not True:
            return self._approval_decide(
                "approval_signature_invalid",
                digest,
                envelope,
            )

        verified_at_ns = self._trusted_now()

        if verified_at_ns is None:
            return self._approval_decide(
                "approval_clock_invalid",
                digest,
                envelope,
                timestamp_ns=0,
            )

        if verified_at_ns < now_ns:
            return self._approval_decide(
                "approval_clock_rollback",
                digest,
                envelope,
                timestamp_ns=verified_at_ns,
            )

        if (
            verified_at_ns
            >= envelope.expires_at_ns
        ):
            return self._approval_decide(
                "approval_expired_during_verification",
                digest,
                envelope,
                timestamp_ns=verified_at_ns,
            )

        approval = ApprovalUse(
            envelope.approval_id,
            envelope.nonce,
            {
                "approval_id": envelope.approval_id,
                "authority_id": envelope.authority_id,
                "verifier_id": envelope.verifier_id,
                "key_id": envelope.key_id,
                "algorithm": trust.algorithm,
                "key_fingerprint": trust.key_fingerprint,
                "deployment_id": envelope.deployment_id,
                "trust_hash": envelope.trust_hash,
                "envelope_hash": envelope.envelope_hash,
                "signing_payload_hash": (
                    envelope.signing_payload_hash
                ),
                "intent_hash": digest,
                "policy_hash": self.policy_hash,
                "issued_at_ns": envelope.issued_at_ns,
                "expires_at_ns": envelope.expires_at_ns,
                "verified_at_ns": verified_at_ns,
            },
        )

        return self._issue_permit(
            digest,
            reason="verified_approval",
            approval=approval,
            envelope=envelope,
            timestamp_ns=verified_at_ns,
            presenter=presenter,
        )

    def _verifier_matches_trust(
        self,
        verifier: ApprovalVerifier,
    ) -> bool:
        trust = self.policy.authority_trust

        if trust is None:
            return False

        try:
            actual = (
                verifier.authority_id,
                verifier.verifier_id,
                verifier.key_id,
                verifier.algorithm,
                verifier.key_fingerprint,
            )

        except Exception:
            return False

        expected = (
            trust.authority_id,
            trust.verifier_id,
            trust.key_id,
            trust.algorithm,
            trust.key_fingerprint,
        )

        return actual == expected

    def _trusted_now(
        self,
    ) -> int | None:
        try:
            value = self._clock()

        except Exception:
            return None

        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
        ):
            return None

        return value

    def _policy_failure(
        self,
        intent: Intent,
    ) -> str | None:
        if (
            not intent.principal
            or not intent.session_id
            or not intent.action
            or not intent.resource
        ):
            return "incomplete_intent"

        if (
            intent.cost < 0
            or intent.cost
            > self.policy.max_cost
        ):
            return "budget_exceeded"

        if (
            intent.action
            not in self.policy.allowed_actions
        ):
            return "action_not_allowed"

        if self.policy.agent_grants:
            grant = next(
                (
                    item
                    for item in self.policy.agent_grants
                    if item.principal
                    == intent.principal
                ),
                None,
            )

            if grant is None:
                return "unknown_principal"

            if (
                intent.action
                not in grant.allowed_actions
            ):
                return "agent_action_not_allowed"

            if not any(
                intent.resource.startswith(
                    prefix
                )
                for prefix
                in grant.resource_prefixes
            ):
                return "agent_resource_not_allowed"

            if intent.cost > grant.max_cost:
                return "agent_budget_exceeded"

        return None

    def _issue_permit(
        self,
        digest: str,
        *,
        reason: str = "policy_satisfied",
        approval: ApprovalUse | None = None,
        envelope: ApprovalEnvelope | None = None,
        timestamp_ns: int | None = None,
        presenter: str | None = None,
    ) -> Decision:
        self._require_pinned_policy()

        # Presenter binding (Phase 3, Item 4B) is enforced in this
        # funnel so every issuance path inherits it: a policy that
        # requires binding mints no unbound permit, and a permit is
        # never bound to a presenter this kernel could not verify a
        # proof from at consume time -- such a permit would be
        # unspendable by construction, so it is not minted.
        if presenter is None and self.policy.require_presenter_binding:
            return self._decide("deny", "presenter_binding_required", digest)

        if presenter is not None:
            if not isinstance(presenter, str) or not presenter:
                return self._decide("deny", "presenter_invalid", digest)

            if presenter not in self._presenter_verifiers:
                return self._decide("deny", "presenter_not_registered", digest)

        issued_at_ns = (
            self._clock()
            if timestamp_ns is None
            else timestamp_ns
        )

        expires_at_ns = (
            issued_at_ns
            + self.policy.permit_ttl_ns
        )

        if envelope is not None:
            expires_at_ns = min(
                expires_at_ns,
                envelope.expires_at_ns,
            )

        # Token v3 (Item 4B): the presenter claim -- the SHA-256 of
        # the bound presenter identity, or of the empty string for an
        # unbound (bearer) permit -- is inside the signed payload
        # too, so the binding cannot be stripped or swapped without
        # the kernel secret. Autonomous jumps from v1 straight to
        # v3; the token's signed expiry is authenticated, not
        # re-enforced at this layer -- expiry enforcement stays in
        # the state layer, unchanged.
        presenter_hash = (
            UNBOUND_PRESENTER_HASH if presenter is None else sha256(presenter.encode()).hexdigest()
        )

        nonce = secrets.token_hex(16)

        payload = f"{digest}:{nonce}:{issued_at_ns}:{expires_at_ns}:{presenter_hash}"

        signature = hmac.new(
            self._secret,
            payload.encode(),
            sha256,
        ).hexdigest()

        permit = (
            f"{payload}:{signature}"
        )

        replay = self._state.issue_permit(
            permit,
            digest,
            reason,
            issued_at_ns,
            expires_at_ns,
            approval,
        )

        if replay:
            if envelope is None:
                raise RuntimeError(
                    "state rejected an approval-free permit"
                )

            return self._approval_decide(
                replay,
                digest,
                envelope,
            )

        return Decision(
            "allow",
            reason,
            digest,
            permit,
        )

    def _permit_token_claims(self, permit: object) -> tuple[str, int, int, str] | None:
        """Authenticate a v3 permit token and return its signed claims.

        Tokens are minted in ``_issue_permit`` as
        ``digest:nonce:issued_at_ns:expires_at_ns:presenter_hash:signature``
        with the signature an HMAC of the first five fields under the
        kernel secret. Verification recomputes that HMAC over the token's own
        presented fields and compares in constant time: it proves the
        token was minted under this kernel's secret and is unaltered --
        including its expiry, which therefore cannot be extended by a
        holder, and its presenter claim (Item 4B), which therefore
        cannot be stripped or swapped by a holder. Returns
        ``(intent_digest, issued_at_ns, expires_at_ns, presenter_hash)``
        for an authentic v3 token, else None.

        v1 tokens (``digest:nonce:signature``) fail closed here: this
        is the cutover. An outstanding pre-v3 permit is refused at
        consume, never silently accepted -- the Phase 1 (#355)
        precedent for outstanding tokens at a format change.
        Malformed tokens and tokens minted under any other secret
        fail closed the same way.
        """

        if not isinstance(permit, str):
            return None

        parts = permit.split(":")

        if len(parts) != 6:
            return None

        token_digest, nonce, issued_raw, expires_raw, presenter_hash, signature = parts

        issued_at_ns = _token_time_ns(issued_raw)
        expires_at_ns = _token_time_ns(expires_raw)

        if issued_at_ns is None or expires_at_ns is None:
            return None

        if expires_at_ns <= issued_at_ns:
            return None

        if len(presenter_hash) != 64 or not presenter_hash.isascii() or not all(
            char in "0123456789abcdef" for char in presenter_hash
        ):
            return None

        expected = hmac.new(
            self._secret,
            f"{token_digest}:{nonce}:{issued_raw}:{expires_raw}:{presenter_hash}".encode(),
            sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature.encode(), expected.encode()):
            return None

        return token_digest, issued_at_ns, expires_at_ns, presenter_hash

    @staticmethod
    def presenter_proof_payload(permit: str, intent_digest: str, presenter: str) -> bytes:
        """The exact bytes a presenter signs to prove a consumption.

        One canonical construction, shared by presenters and the
        kernel: the proof binds the presenter identity to the exact
        permit token and the exact intent digest, so a proof captured
        for one permit or intent verifies for no other. The permit's
        own single-use semantics bound replay of a valid proof.
        """

        return _canonical(
            {
                "schema": PRESENTER_PROOF_SCHEMA,
                "permit": permit,
                "intent_hash": intent_digest,
                "presenter": presenter,
            }
        )

    def _presenter_refusal(
        self,
        claims: tuple[str, int, int, str],
        digest: str,
        permit: str,
        presenter: str | None,
        presenter_proof: str | None,
    ) -> str | None:
        """The Item 4B consume gate: a refusal reason, or None to proceed.

        Runs after the token is authenticated, before the store is
        consulted -- so a refusal here never burns the permit, and the
        bound presenter can still spend it. An unbound permit proceeds
        exactly as a bearer <redacted> unless the pinned policy requires
        binding. A bound permit requires the named presenter's valid
        proof under the verifier registered for that identity; every
        failure mode is a distinct recorded reason.
        """

        presenter_hash = claims[3]

        if presenter_hash == UNBOUND_PRESENTER_HASH:
            if self.policy.require_presenter_binding:
                return "permit_presenter_unbound"
            return None

        if presenter is None or presenter_proof is None:
            return "permit_presenter_proof_required"

        if not isinstance(presenter, str) or not isinstance(presenter_proof, str):
            return "permit_presenter_mismatch"

        if not hmac.compare_digest(sha256(presenter.encode()).hexdigest(), presenter_hash):
            return "permit_presenter_mismatch"

        verifier = self._presenter_verifiers.get(presenter)

        if verifier is None:
            return "permit_presenter_unverifiable"

        payload = self.presenter_proof_payload(permit, digest, presenter)

        try:
            verified = verifier.verify(payload, presenter_proof)
        except Exception:
            verified = False

        if not verified:
            return "permit_presenter_mismatch"

        return None

    def _permit_token_valid(self, permit: object) -> bool:
        """Whether ``permit`` is an authentic v3 token (see _permit_token_claims).

        On its own this authenticates provenance only; ``consume``
        enforces the presenter binding on top of it, and the store
        enforces expiry, intent binding, and single-use.
        """

        return self._permit_token_claims(permit) is not None

    def _approval_decide(
        self,
        reason: str,
        digest: str,
        envelope: ApprovalEnvelope,
        *,
        timestamp_ns: int | None = None,
    ) -> Decision:
        if timestamp_ns is None:
            trusted_time = self._trusted_now()

            rejection_time = (
                0
                if trusted_time is None
                else trusted_time
            )

        else:
            rejection_time = timestamp_ns

        rejection_payload = {
            "approval_id": envelope.approval_id,
            "authority_id": envelope.authority_id,
            "verifier_id": envelope.verifier_id,
            "key_id": envelope.key_id,
            "deployment_id": envelope.deployment_id,
            "trust_hash": envelope.trust_hash,
            "envelope_hash": envelope.envelope_hash,
            "signing_payload_hash": (
                envelope.signing_payload_hash
            ),
            "intent_hash": digest,
            "policy_hash": self.policy_hash,
            "reason": reason,
        }

        decision = Decision(
            "deny",
            reason,
            digest,
        )

        self._state.append_many(
            [
                (
                    "approval_rejected",
                    rejection_payload,
                    rejection_time,
                ),
                (
                    "decision",
                    {
                        "outcome": "deny",
                        "reason": reason,
                        "intent_hash": digest,
                    },
                    rejection_time,
                ),
            ]
        )

        return decision

    def consume(
        self,
        permit: str,
        intent: Intent,
        *,
        presenter: str | None = None,
        presenter_proof: str | None = None,
    ) -> bool:
        self._require_pinned_policy()

        digest = self.intent_hash(
            intent
        )

        # Presenter binding (Phase 3, Item 4B): authenticate the token
        # and enforce its presenter claim HERE, before the store is
        # consulted -- so a failed presenter attempt never burns the
        # permit. The claim lives in the signed token, not in any store
        # row a writer could edit. Only a kernel constructed with an
        # explicit secret can authenticate a token. A default-secret
        # kernel falls through to the pre-existing state-only path
        # for tokens it cannot authenticate (see _explicit_secret);
        # the gate runs only for tokens that do authenticate.
        # Binding is only meaningful with an explicitly configured
        # secret.
        claims = self._permit_token_claims(permit)

        if claims is None:
            if self._explicit_secret:
                self._state.append(
                    "permit_rejected",
                    {"intent_hash": digest, "reason": "permit_signature_invalid"},
                    self._clock(),
                )

                return False

        else:
            # Writer custody, Fix A (upstream #355, layering change
            # 2026-11-13): the token's own authenticated digest is
            # compared against the presented intent HERE, before the
            # store is consulted. The store's check against the permit
            # row's stored intent hash remains as the second layer —
            # but that row is writer-controlled and outside the audit
            # chain, so a state-file writer holding a genuine token
            # could rewrite its row (new intent hash, spent reset) and
            # spend the token for an intent the kernel never
            # authorized. The token's digest cannot be rewritten
            # without the kernel secret, so this comparison is the
            # layer that stops the retarget. A mismatch is refused
            # with permit_rejected / permit_intent_mismatch and never
            # burns the permit, exactly like a presenter refusal.
            if claims[0] != digest:
                self._state.append(
                    "permit_rejected",
                    {"intent_hash": digest, "reason": "permit_intent_mismatch"},
                    self._clock(),
                )

                return False

            refusal = self._presenter_refusal(claims, digest, permit, presenter, presenter_proof)

            if refusal is not None:
                self._state.append(
                    "permit_rejected",
                    {"intent_hash": digest, "reason": refusal},
                    self._clock(),
                )

                return False

        return self._state.consume_permit(
            permit,
            digest,
            self._clock(),
        )

    def _audit_integrity_token(
        self,
    ) -> object | None:
        token_reader = getattr(
            self._state,
            "audit_integrity_token",
            None,
        )

        if token_reader is None:
            return None

        return token_reader()

    def _require_audit_integrity(
        self,
    ) -> None:
        current_token = (
            self._audit_integrity_token()
        )

        if (
            current_token is not None
            and current_token
            == self._verified_audit_token
        ):
            return

        if not self.verify_audit():
            raise StateIntegrityError(
                "kernel state audit chain is invalid"
            )

    def verify_audit_report(self) -> dict[str, Any]:
        """Verify the audit chain and report its signing coverage.

        Returns ``ok`` plus, for every record, whether it was accepted
        as signed or as legacy. The signature field is excluded from
        the hashed body (it is a sibling of ``hash``, not part of it),
        so the unkeyed chain math is identical to before signing
        existed. When the state carries no signer, every record
        verifies legacy-style and ``signing_enabled`` is False — the
        exact pre-signing behavior. When a signer is configured,
        every record at or after the legacy prefix must carry a valid
        signature: a missing one fails as ``audit_signature_missing``,
        a present-but-wrong one as ``audit_signature_invalid``. When
        no signer is configured, a present signature is an opaque
        field the chain verifies past legacy-style and counts as
        unsigned — disabling signing is a deployment decision and must
        not brick a chain signed under an earlier config. Malformed
        records fail as ``audit_record_malformed``
        instead of raising, so callers that treat verification as a
        boolean (boot included) fail closed the same way.

        The check mirrors ``verify_audit`` exactly, including the
        delta chain: a record's hash covers its delta fields,
        ``previous_delta_root`` must chain, and ``delta_root`` must
        recompute — a record whose delta was rebuilt without the chain
        fails here even if its hash was recomputed to match.
        """

        signer = getattr(self._state, "audit_signer", None)

        try:
            legacy_records = int(getattr(self._state, "legacy_audit_records", 0) or 0)
        except (TypeError, ValueError):
            legacy_records = 0

        report: dict[str, Any] = {
            "ok": True,
            "reason": None,
            "total_records": 0,
            "signed_records": 0,
            "unsigned_records": 0,
            "legacy_records": legacy_records,
            "signing_enabled": signer is not None,
            "failed_record": None,
        }

        previous = "0" * 64
        previous_delta_root = "0" * 64

        # The report streams the trail through ``iter_audit`` rather
        # than materializing ``self.audit``: kernel bootstrap must not
        # load the whole chain into memory (pinned by
        # test_delta_audit_performance's streaming test), and the old
        # ``verify_audit`` streamed the same way.
        try:
            records = self._state.iter_audit()
        except Exception:
            report.update({"ok": False, "reason": "audit_record_malformed"})
            return report

        for index, record in enumerate(records):
            report["total_records"] = index + 1
            try:
                body = {key: value for key, value in record.items() if key not in ("hash", "signature")}
                if body["previous_hash"] != previous:
                    report.update({"ok": False, "reason": "audit_previous_hash_mismatch", "failed_record": index})
                    return report
                expected = sha256(_canonical(body)).hexdigest()
                if not hmac.compare_digest(str(record["hash"]), expected):
                    report.update({"ok": False, "reason": "audit_hash_mismatch", "failed_record": index})
                    return report
            except (AttributeError, KeyError, TypeError, ValueError):
                report.update({"ok": False, "reason": "audit_record_malformed", "failed_record": index})
                return report

            signature = record.get("signature") if isinstance(record, dict) else None

            if signer is not None:
                if signature is not None:
                    if not signer.verify(record["hash"], signature):
                        report.update({"ok": False, "reason": "audit_signature_invalid", "failed_record": index})
                        return report

                    report["signed_records"] += 1

                elif index >= legacy_records:
                    report.update({"ok": False, "reason": "audit_signature_missing", "failed_record": index})
                    return report

                else:
                    report["unsigned_records"] += 1

            else:
                # No signer configured: a present signature is an
                # opaque field — the chain verifies legacy-style and
                # the record counts as unsigned (see docstring).
                report["unsigned_records"] += 1

            delta = body.get("delta")
            if delta is not None:
                if body.get("previous_delta_root") != previous_delta_root:
                    report.update({"ok": False, "reason": "audit_previous_delta_root_mismatch", "failed_record": index})
                    return report
                expected_delta_root = sha256(
                    _canonical(
                        {
                            "previous_delta_root": previous_delta_root,
                            "delta": delta,
                        }
                    )
                ).hexdigest()
                if not hmac.compare_digest(body.get("delta_root", ""), expected_delta_root):
                    report.update({"ok": False, "reason": "audit_delta_root_mismatch", "failed_record": index})
                    return report
                previous_delta_root = expected_delta_root
            else:
                # Legacy records predate canonical delta logging.
                # Their audit hash remains authoritative, and the
                # first delta record after legacy history binds
                # forward from the legacy audit head.
                previous_delta_root = record["hash"]

            previous = record["hash"]

        return report

    def verify_audit(
        self,
    ) -> bool:
        token_before = (
            self._audit_integrity_token()
        )

        # The chain verdict (hash, delta, and signature checks) lives
        # in verify_audit_report; this wrapper keeps only the
        # audit-integrity-token logic, which must observe the state
        # before and after the verification read.
        if not self.verify_audit_report()["ok"]:
            self._verified_audit_token = None
            return False

        token_after = (
            self._audit_integrity_token()
        )

        if (
            token_before is not None
            and token_before != token_after
        ):
            self._verified_audit_token = None
            return False

        self._verified_audit_token = (
            token_after
        )

        return True

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        """Facade read: the recorded status of one exact directive version."""

        return self._state.directive_status(directive_id, version, directive_hash)

    def directive_hash_status(self, directive_hash: str) -> str:
        """Facade read: the recorded status of a directive by its hash."""

        return self._state.directive_hash_status(directive_hash)

    def activate_directive(
        self,
        directive: Any,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        """Facade verb: record a verified directive activation.

        The only production caller is ``DirectiveAuthorityController``,
        after envelope verification and the one-use authority-permit
        consume. The state layer requires the typed evidence and
        cross-checks its binding, so the fabricated-bare-dict
        activation from design repro 3 (part B) fails at this surface.
        """

        self._state.activate_directive(
            directive,
            authority_evidence,
            timestamp_ns,
        )

    def revoke_directive(
        self,
        directive_id: str,
        version: int,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        """Facade verb: record a verified directive revocation."""

        self._state.revoke_directive(
            directive_id,
            version,
            authority_evidence,
            timestamp_ns,
        )

    def bind_permit_to_directive(
        self,
        permit: str,
        intent_hash: str,
        binding: DirectivePermitBinding,
        timestamp_ns: int,
    ) -> None:
        """Facade verb: bind an issued permit to its live directive."""

        self._state.bind_permit_to_directive(permit, intent_hash, binding, timestamp_ns)

    def record_target_completion(
        self,
        *,
        target_id: str,
        version: int,
        target_hash: str,
        intent_hash: str,
        artifact_path: str | Path,
        timestamp_ns: int,
    ) -> dict[str, Any]:
        """Facade verb: observe an artifact and append its completion record.

        Fixed schema, verified at the append surface (Codex P1 fix on
        PR #359): the verb takes an artifact *path*, never a
        caller-supplied completion dict or hash. It resolves the
        locked target, cross-checks the exact target and intent
        hashes, and observes the file itself through
        ``_observe_artifact_file`` — the same descriptor-bound stable
        observation the governed projection performs — so evidence
        naming a nonexistent or unobserved file cannot be recorded.

        Returns the completion dict exactly as recorded.
        """

        target = self.get_locked_target(target_id, version=version)

        if target is None:
            raise ValueError("target_not_locked")

        if not isinstance(target_hash, str):
            raise ValueError("target_hash_mismatch")

        if not hmac.compare_digest(target.target_hash, target_hash):
            raise ValueError("target_hash_mismatch")

        expected_intent_hash = self.intent_hash(target.intent)

        if not isinstance(intent_hash, str):
            raise ValueError("target_intent_mismatch")

        if not hmac.compare_digest(expected_intent_hash, intent_hash):
            raise ValueError("target_intent_mismatch")

        if timestamp_ns < target.created_at_ns:
            raise RuntimeError("artifact_observed_before_target")

        resolved_path, artifact_sha256, size_bytes = _observe_artifact_file(artifact_path)

        completion: dict[str, Any] = {
            "target_id": target.target_id,
            "version": target.version,
            "target_hash": target.target_hash,
            "intent_hash": expected_intent_hash,
            "artifact_path": resolved_path,
            "artifact_sha256": artifact_sha256,
            "size_bytes": size_bytes,
            "observed_at_ns": timestamp_ns,
            "schema": "pulpo.target-artifact-completion.v0",
        }

        completion_hash = sha256(_canonical(completion)).hexdigest()

        self._state.append(
            "target_completed",
            {
                "target_id": target.target_id,
                "version": target.version,
                "target_hash": target.target_hash,
                "intent_hash": expected_intent_hash,
                "completion": completion,
                "completion_hash": completion_hash,
                "authority_effect": "none",
            },
            timestamp_ns,
        )

        return completion

    def record_domain_outcome_memory(
        self,
        *,
        reconciliation_transition_hash: str,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        """Facade verb: verify, then append-once, a domain outcome-memory record.

        Fixed schema: the ``domain_outcome_memory`` event, unique on
        ``reconciliation_transition_hash``. Returns the existing
        payload when a record with that identity already exists (the
        state layer's ``append_unique`` contract), else None.

        Verified at the append surface (Codex P1 fix on PR #359): a
        self-asserted payload is refused — with a distinct
        ``outcome_memory_*`` ``ValueError`` and nothing appended —
        unless its identity hash recomputes, its policy hash is this
        kernel's, exactly one projected custody-transition evidence
        record backs its transition hash with a receipt bound to its
        order hash and epoch, its classification is consistent with
        that receipt's transition type, and exactly one locked target
        in the audit carries its target and intent hashes. The kernel
        cannot re-derive the custody layer's observation/budget
        checks; those remain the projection's authority (see the
        change record).
        """

        if not isinstance(payload, dict):
            raise ValueError("outcome_memory_payload_invalid")

        if payload.get("reconciliation_transition_hash") != reconciliation_transition_hash:
            raise ValueError("outcome_memory_transition_hash_mismatch")

        if payload.get("schema") != "pulpo.domain-outcome-memory.v0":
            raise ValueError("outcome_memory_schema_mismatch")

        if payload.get("authority_effect") != "none":
            raise ValueError("outcome_memory_authority_effect_mismatch")

        if payload.get("governed_effect") != "canonical_outcome_memory":
            raise ValueError("outcome_memory_governed_effect_mismatch")

        identity = {
            "schema": "pulpo.domain-outcome-memory.v0",
            "attempt_id": payload.get("attempt_id"),
            "order_hash": payload.get("order_hash"),
            "target_hash": payload.get("target_hash"),
            "intent_hash": payload.get("intent_hash"),
            "policy_hash": payload.get("policy_hash"),
            "observation_hash": payload.get("observation_hash"),
            "reconciliation_transition_hash": payload.get("reconciliation_transition_hash"),
            "reconciliation_epoch": payload.get("reconciliation_epoch"),
            "reconciliation_outcome": payload.get("reconciliation_outcome"),
            "classification": payload.get("classification"),
            "reason": payload.get("reason"),
            "reusable": payload.get("reusable"),
            "authority_effect": "none",
            "governed_effect": "canonical_outcome_memory",
        }

        expected_memory_id = sha256(_canonical(identity)).hexdigest()

        memory_id = payload.get("memory_id")

        if not isinstance(memory_id, str):
            raise ValueError("outcome_memory_memory_id_mismatch")

        if not hmac.compare_digest(expected_memory_id, memory_id):
            raise ValueError("outcome_memory_memory_id_mismatch")

        if payload.get("policy_hash") != self.policy_hash:
            raise ValueError("outcome_memory_policy_hash_mismatch")

        custody_matches: list[dict[str, Any]] = []

        for record in self.audit:
            if record.get("event") != "custody_transition":
                continue

            record_payload = record.get("payload")

            if not isinstance(record_payload, dict):
                continue

            if record_payload.get("transition_hash") == reconciliation_transition_hash:
                custody_matches.append(record_payload)

        if len(custody_matches) != 1:
            if not custody_matches:
                raise ValueError("outcome_memory_custody_evidence_missing")
            raise ValueError("outcome_memory_custody_evidence_ambiguous")

        evidence = custody_matches[0]

        receipt = evidence.get("receipt")

        if (
            evidence.get("schema") != "pulpo.custody-evidence-projection.v0"
            or not isinstance(receipt, dict)
            or receipt.get("transition_hash") != reconciliation_transition_hash
            or receipt.get("object_hash") != payload.get("order_hash")
            or receipt.get("epoch") != payload.get("reconciliation_epoch")
        ):
            raise ValueError("outcome_memory_custody_evidence_mismatch")

        transition_type = receipt.get("transition_type")
        outcome = payload.get("reconciliation_outcome")
        classification = payload.get("classification")
        reusable = payload.get("reusable")

        if transition_type == "reconciled_success":
            consistent = (
                outcome == "success"
                and classification == "SUCCESS_VERIFIED"
                and reusable is True
            )
        elif transition_type == "reconciled_failure":
            consistent = (
                outcome == "failure"
                and classification in {"RECONCILIATION_FAILURE", "RECONCILIATION_MISMATCH"}
                and reusable is False
            )
        elif transition_type == "unresolved":
            consistent = (
                outcome == "unresolved"
                and classification == "EVIDENCE_FAILURE"
                and reusable is False
            )
        else:
            raise ValueError("outcome_memory_custody_transition_type_invalid")

        if not consistent:
            raise ValueError("outcome_memory_classification_mismatch")

        target_matches: list[dict[str, Any]] = []

        for record in self.audit:
            if record.get("event") != "target_locked":
                continue

            record_payload = record.get("payload")

            if not isinstance(record_payload, dict):
                continue

            if record_payload.get("target_hash") == payload.get("target_hash"):
                target_matches.append(record_payload)

        if len(target_matches) != 1:
            if not target_matches:
                raise ValueError("outcome_memory_target_missing")
            raise ValueError("outcome_memory_target_ambiguous")

        if target_matches[0].get("intent_hash") != payload.get("intent_hash"):
            raise ValueError("outcome_memory_target_intent_mismatch")

        return self._state.append_unique(
            "domain_outcome_memory",
            "reconciliation_transition_hash",
            reconciliation_transition_hash,
            payload,
            timestamp_ns,
        )

    def state_source_id(self) -> str:
        """Opaque process-scoped identifier for this kernel's backend.

        Read-only identification for evidence derivation (the incident
        channel stamps its reports with which backend instance they
        were derived from). Exposing an identifier is not exposing the
        handle: callers learn a stable name for the backend in this
        process, never the object. A SQLite backend whose connection
        carries an ``activity_id`` reports that id, as before.
        """

        backend = self._state

        source_id = sha256(f"{os.getpid()}:{id(backend)}".encode()).hexdigest()[:32]

        if type(backend) is SQLiteKernelState:
            activity_id = getattr(backend._connection, "activity_id", None)

            if type(activity_id) is str and activity_id:
                source_id = activity_id

        return source_id

    def _decide(
        self,
        outcome: str,
        reason: str,
        digest: str,
        permit: str | None = None,
    ) -> Decision:
        decision = Decision(
            outcome,
            reason,
            digest,
            permit,
        )

        self._append(
            "decision",
            {
                "outcome": outcome,
                "reason": reason,
                "intent_hash": digest,
            },
        )

        return decision

    def record_directive_denial(
        self,
        intent: Intent,
        *,
        directive_id: str,
        version: int,
        directive_hash: str,
        reason: str,
    ) -> None:
        """Facade verb: record a directive-scope denial in the audit.

        Port of upstream Ironnember/Pulpo1.0 PR #372 (kernel build item
        #2): the directive projection returns its directive-scope
        denials (directive not active, parent not active, mandate
        failure) without a kernel evaluation, so before this verb those
        denials appended nothing - a refused attempt was invisible to
        the canonical audit and to reconciliation, unlike
        kernel-reached denials (``decision``) and consume denials
        (``permit_rejected``), which append exactly one record each.
        The projection reports each of its denials through this verb
        instead. The schema is fixed: the caller supplies the intent,
        the directive's identity, and the reason it already computed;
        the kernel derives the intent hash and appends exactly one
        ``directive_denial`` record with ``authority_effect=none``.
        Recording a denial grants nothing, spends nothing, and
        changes no directive state.

        Fork note: upstream's fourth path - the aggregate-budget early
        check from build item #1 (PR #369) - has no Autonomous
        counterpart (Autonomous ``Directive`` carries no aggregate
        budget), so the projection routes its three existing denial
        paths through this verb.
        """

        self._append(
            "directive_denial",
            {
                "schema": "pulpo.directive-denial.v0",
                "directive_id": directive_id,
                "version": version,
                "directive_hash": directive_hash,
                "intent_hash": self.intent_hash(intent),
                "principal": intent.principal,
                "action": intent.action,
                "resource": intent.resource,
                "cost": intent.cost,
                "session_id": intent.session_id,
                "reason": reason,
                "authority_effect": "none",
            },
        )

    def _append(
        self,
        event: str,
        payload: dict[str, Any],
    ) -> None:
        self._state.append(
            event,
            payload,
            self._clock(),
        )
