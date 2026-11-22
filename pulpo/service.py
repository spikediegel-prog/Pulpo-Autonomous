"""Phase 3, Item 3B: the service boundary.

Item 3A (the capability facade) made every production write flow
through one governed verb set on the kernel, but it priced its own
residual honestly (design ruling Q5): Python privacy is convention,
so a determined in-process caller who constructs a state backend
directly can still spend, append, or activate against *that* backend.
3A's answer was that fabrication at least requires a deliberate,
greppable construction. 3B is the design the 3A record named as the
only one where gating is enforced by a process boundary:

    One process holds the state; every other component gets
    authenticated client verbs, never the handle.

This module is that boundary. ``KernelService`` owns exactly one
``GovernanceKernel`` (and, through it, the only handle to the
canonical state) plus the directive controller and projection built
on it. It accepts serialized, HMAC-authenticated request envelopes
and returns serialized, HMAC-authenticated responses. The verb set
is exactly the governed facade surface — evaluate, consume, target
locking/resolution, directive activation/revocation (through the
server-side controller, after server-side envelope verification),
permit binding, the two reconciliation record verbs, and the facade
reads. There is deliberately:

- no verb that appends a caller-shaped record (repro C);
- no verb that accepts authority evidence — evidence is constructed
  server-side by the controller from a verified envelope, exactly as
  in-process (repro B3's fabricated-evidence activation has no field
  to land in);
- no response that carries a kernel, state, or permit-store handle —
  results are plain data (decisions, targets, records) only.

A caller in another process who constructs its own state backend
(repro A) governs that backend and nothing else: its spends never
touch the canonical store, which is the property a process boundary
can actually prove, and the one the tests assert.

Authentication is a dedicated service secret, injected at
construction and never defaulted, domain-separated from the kernel,
audit, and anchor secrets (the Item 1/2 pattern). Requests are
freshness-bounded and nonce-replay-checked server-side; a replayed,
expired, malformed, or wrongly authenticated request fails closed
with no state change. The transport is any bytes-to-bytes callable:
a loopback transport for in-process embedding and tests, and a
length-prefixed Unix-socket transport for a real second process.

Control Center design §5.2: the service may also be constructed
with a separate read-only secret. Requests authenticated under it
hold the read-only role and may call only ``READ_ONLY_VERBS``
(the reads the §5.1 observer snapshot needs, plus ``health``);
every other verb is refused server-side before it runs, with the
refusal counted in process-local diagnostics — never appended to
the canonical audit, so a read-only credential cannot buy a write
into canonical state by being refused. The CC must never hold the
full service secret.
"""

from __future__ import annotations

# Autonomous port of upstream Ironnember/Pulpo1.0 #371 (head 6ab6012a),
# via Preview #147. Adaptations, all confined to this file: the
# Autonomous Intent carries no provenance_hash, so it does not cross
# the boundary; the Autonomous Directive and DirectivePermitBinding
# carry no aggregate-budget fields, so the budget branches are
# dropped (a budgeted directive still fails closed on the hash
# check); the budget_spent verb is omitted because Autonomous has no
# cumulative-budget ledger (the unported 3A / build-item-#1 surface).
# Everything else verbatim from Preview #147.

import hmac
import json
import os
import secrets
import socket
import threading
import time
from hashlib import sha256
from typing import Any, Callable

from .authority import ApprovalEnvelope
from .directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from .kernel import Decision, GovernanceKernel, Intent, LockedTarget, TargetResolution
from .state import DirectivePermitBinding

REQUEST_SCHEMA = "pulpo.service.request.v1"
RESPONSE_SCHEMA = "pulpo.service.response.v1"
_REQUEST_MAC_DOMAIN = b"pulpo.service.request.v1\n"
_RESPONSE_MAC_DOMAIN = b"pulpo.service.response.v1\n"
# Control Center design §5.2: the read-only role uses its own MAC
# domains, so a request MAC'd for one role never verifies as the
# other. The credential is the role claim — the server derives the
# role from which secret verified, never from a client-asserted
# field — and the response is MAC'd under the same role's domain.
_READ_ONLY_REQUEST_MAC_DOMAIN = b"pulpo.service.request.read-only.v1\n"
_READ_ONLY_RESPONSE_MAC_DOMAIN = b"pulpo.service.response.read-only.v1\n"

# Control Center design §5.2: the verbs a read-only credential may
# call — exactly the reads the §5.1 observer snapshot needs, plus
# health. Deliberately excluded: the unbounded `audit` verb (§5.6 is
# a separate build item) and `get_locked_target` (a read, but not one
# the snapshot needs). Everything not in this set is refused for the
# read-only role before it runs, whatever the verb's own shape is.
READ_ONLY_VERBS = frozenset(
    {
        "health",
        "verify_audit",
        "verify_audit_report",
        "state_source_id",
        "policy_hash",
        "directive_status",
        "directive_hash_status",
    }
)

DEFAULT_MAX_REQUEST_TTL_NS = 300_000_000_000  # five minutes
_MAX_FRAME_BYTES = 16 * 1024 * 1024
_NONCE_CACHE_LIMIT = 16_384


class ServiceRefusal(RuntimeError):
    """A service-boundary refusal; the message is a reason token."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _mac(secret: bytes, domain: bytes, body: dict[str, Any]) -> str:
    return hmac.new(secret, domain + _canonical(body), sha256).hexdigest()


def _require_str(args: dict[str, Any], field: str) -> str:
    value = args.get(field)
    if not isinstance(value, str):
        raise ValueError("service_args_invalid")
    return value


def _require_int(args: dict[str, Any], field: str) -> int:
    value = args.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("service_args_invalid")
    return value


def _optional_str(args: dict[str, Any], field: str) -> str | None:
    value = args.get(field)
    if value is not None and not isinstance(value, str):
        raise ValueError("service_args_invalid")
    return value


# --- Data serialization -------------------------------------------------
# Only plain data crosses the boundary. Every ``*_from_dict`` validates
# shape strictly and lets the dataclass constructors re-validate the
# governance fields themselves, so a malformed request fails closed at
# reconstruction with the constructor's own refusal.


def intent_to_dict(intent: Intent) -> dict[str, Any]:
    return {
        "principal": intent.principal,
        "action": intent.action,
        "resource": intent.resource,
        "cost": intent.cost,
        "session_id": intent.session_id,
    }


def intent_from_dict(data: Any) -> Intent:
    if not isinstance(data, dict):
        raise ValueError("service_args_invalid")
    return Intent(
        principal=_require_str(data, "principal"),
        action=_require_str(data, "action"),
        resource=_require_str(data, "resource"),
        cost=_require_int(data, "cost"),
        session_id=_require_str(data, "session_id"),
    )


def decision_to_dict(decision: Decision) -> dict[str, Any]:
    return {
        "outcome": decision.outcome,
        "reason": decision.reason,
        "intent_hash": decision.intent_hash,
        "permit": decision.permit,
    }


def decision_from_dict(data: Any) -> Decision:
    if not isinstance(data, dict):
        raise ValueError("service_args_invalid")
    return Decision(
        outcome=_require_str(data, "outcome"),
        reason=_require_str(data, "reason"),
        intent_hash=_require_str(data, "intent_hash"),
        permit=_optional_str(data, "permit"),
    )


def locked_target_to_dict(target: LockedTarget) -> dict[str, Any]:
    return {
        "target_id": target.target_id,
        "version": target.version,
        "intent": intent_to_dict(target.intent),
        "created_at_ns": target.created_at_ns,
        "schema": target.schema,
    }


def locked_target_from_dict(data: Any) -> LockedTarget:
    if not isinstance(data, dict):
        raise ValueError("service_args_invalid")
    return LockedTarget(
        target_id=_require_str(data, "target_id"),
        version=_require_int(data, "version"),
        intent=intent_from_dict(data.get("intent")),
        created_at_ns=_require_int(data, "created_at_ns"),
        schema=_require_str(data, "schema"),
    )


def resolution_to_dict(resolution: TargetResolution) -> dict[str, Any]:
    return {
        "outcome": resolution.outcome,
        "reason": resolution.reason,
        "target_id": resolution.target_id,
        "version": resolution.version,
        "expected_target_hash": resolution.expected_target_hash,
        "target": locked_target_to_dict(resolution.target) if resolution.target is not None else None,
    }


def resolution_from_dict(data: Any) -> TargetResolution:
    if not isinstance(data, dict):
        raise ValueError("service_args_invalid")
    target = data.get("target")
    return TargetResolution(
        outcome=_require_str(data, "outcome"),
        reason=_require_str(data, "reason"),
        target_id=_require_str(data, "target_id"),
        version=_require_int(data, "version"),
        expected_target_hash=_require_str(data, "expected_target_hash"),
        target=locked_target_from_dict(target) if target is not None else None,
    )


def directive_to_dict(directive: Directive) -> dict[str, Any]:
    # Preview port: the fork's Directive has no aggregate-budget
    # fields, so this mirrors the fork's directive-hash payload shape
    # exactly, with no budget branch.
    data: dict[str, Any] = {
        "directive_id": directive.directive_id,
        "version": directive.version,
        "issuer_authority_id": directive.issuer_authority_id,
        "principal": directive.principal,
        "allowed_actions": sorted(directive.allowed_actions),
        "resource_prefixes": list(directive.resource_prefixes),
        "max_cost": directive.max_cost,
        "issued_at_ns": directive.issued_at_ns,
        "expires_at_ns": directive.expires_at_ns,
        "parent_directive_hash": directive.parent_directive_hash,
        "schema": directive.schema,
        "directive_hash": directive.directive_hash,
    }
    return data


def directive_from_dict(data: Any) -> Directive:
    if not isinstance(data, dict):
        raise ValueError("service_args_invalid")
    allowed = data.get("allowed_actions")
    prefixes = data.get("resource_prefixes")
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        raise ValueError("service_args_invalid")
    if not isinstance(prefixes, list) or not all(isinstance(item, str) for item in prefixes):
        raise ValueError("service_args_invalid")
    fields: dict[str, Any] = {
        "directive_id": _require_str(data, "directive_id"),
        "version": _require_int(data, "version"),
        "issuer_authority_id": _require_str(data, "issuer_authority_id"),
        "principal": _require_str(data, "principal"),
        "allowed_actions": frozenset(allowed),
        "resource_prefixes": tuple(prefixes),
        "max_cost": _require_int(data, "max_cost"),
        "issued_at_ns": _require_int(data, "issued_at_ns"),
        "expires_at_ns": _require_int(data, "expires_at_ns"),
        "parent_directive_hash": _optional_str(data, "parent_directive_hash"),
        "schema": _require_str(data, "schema"),
    }
    # Preview port: no aggregate-budget fields on the fork's
    # Directive. A dict carrying a budgeted directive_hash still fails
    # closed below: the recomputed fork hash cannot match it.
    directive = Directive(**fields)
    claimed = data.get("directive_hash")
    if claimed is not None:
        if not isinstance(claimed, str) or not hmac.compare_digest(claimed, directive.directive_hash):
            raise ValueError("service_directive_hash_mismatch")
    return directive


_ENVELOPE_FIELDS = (
    "approval_id",
    "authority_id",
    "verifier_id",
    "key_id",
    "deployment_id",
    "trust_hash",
    "session_id",
    "principal",
    "intent_hash",
    "policy_hash",
    "nonce",
    "signature",
    "schema",
)


def envelope_to_dict(envelope: ApprovalEnvelope) -> dict[str, Any]:
    data = {field: getattr(envelope, field) for field in _ENVELOPE_FIELDS}
    data["issued_at_ns"] = envelope.issued_at_ns
    data["expires_at_ns"] = envelope.expires_at_ns
    return data


def envelope_from_dict(data: Any) -> ApprovalEnvelope:
    if not isinstance(data, dict):
        raise ValueError("service_args_invalid")
    fields = {field: _require_str(data, field) for field in _ENVELOPE_FIELDS}
    fields["issued_at_ns"] = _require_int(data, "issued_at_ns")
    fields["expires_at_ns"] = _require_int(data, "expires_at_ns")
    return ApprovalEnvelope(**fields)


def binding_to_dict(binding: DirectivePermitBinding) -> dict[str, Any]:
    return {
        "directive_id": binding.directive_id,
        "version": binding.version,
        "directive_hash": binding.directive_hash,
        "issued_at_ns": binding.issued_at_ns,
        "expires_at_ns": binding.expires_at_ns,
        "parent_directive_hash": binding.parent_directive_hash,
    }


def binding_from_dict(data: Any) -> DirectivePermitBinding:
    if not isinstance(data, dict):
        raise ValueError("service_args_invalid")
    return DirectivePermitBinding(
        directive_id=_require_str(data, "directive_id"),
        version=_require_int(data, "version"),
        directive_hash=_require_str(data, "directive_hash"),
        issued_at_ns=_require_int(data, "issued_at_ns"),
        expires_at_ns=_require_int(data, "expires_at_ns"),
        parent_directive_hash=_optional_str(data, "parent_directive_hash"),
    )


# --- The service --------------------------------------------------------


class KernelService:
    """Owns the one kernel; serves authenticated facade verbs.

    The service is the only component in its process that holds the
    kernel and therefore the state handle. Construction requires the
    dedicated service secret; there is no default and no ambient
    fallback, so a service that was never given its secret cannot be
    constructed at all.

    Control Center design §5.2: construction may also take a
    separate read-only secret. A request that authenticates under
    that secret (and only that secret) holds the read-only role and
    may call only ``READ_ONLY_VERBS``; every other verb is refused
    before it runs. The read-only secret must differ from the full
    secret — if the two were equal the role distinction would
    collapse, so equal secrets are refused at construction. Without
    a read-only secret there is no read-only role at all, and the
    service behaves exactly as before.
    """

    def __init__(
        self,
        kernel: GovernanceKernel,
        secret: str | bytes,
        *,
        read_only_secret: str | bytes | None = None,
        clock: Callable[[], int] | None = None,
        max_request_ttl_ns: int = DEFAULT_MAX_REQUEST_TTL_NS,
    ) -> None:
        if isinstance(secret, str):
            secret = secret.encode()
        if not secret:
            raise ValueError("service secret must be non-empty")
        if read_only_secret is not None:
            if isinstance(read_only_secret, str):
                read_only_secret = read_only_secret.encode()
            if not read_only_secret:
                raise ValueError("read-only service secret must be non-empty")
            if hmac.compare_digest(read_only_secret, secret):
                raise ValueError("read-only service secret must differ from the service secret")
        if max_request_ttl_ns <= 0:
            raise ValueError("max_request_ttl_ns must be positive")
        self._kernel = kernel
        self._controller = DirectiveAuthorityController(kernel)
        self._projection = GovernedDirectiveProjection(kernel)
        self._secret = secret
        self._read_only_secret = read_only_secret
        self._clock = clock or time.time_ns
        self._max_request_ttl_ns = max_request_ttl_ns
        self._seen_nonces: dict[str, int] = {}
        # Bounded, process-local evidence of read-only refusals:
        # counts per refused verb plus the last refusal time. This is
        # deliberately NOT a canonical audit record (see
        # _record_read_only_refusal): a read-only credential must not
        # be able to cause a canonical state mutation by being
        # refused, or the refusal path itself would be a write route.
        self._read_only_refusals: dict[str, int] = {}
        self._last_read_only_refusal_ns: int | None = None
        self._lock = threading.Lock()
        self._verbs: dict[str, Callable[[dict[str, Any]], Any]] = {
            "evaluate": self._verb_evaluate,
            "evaluate_with_approval": self._verb_evaluate_with_approval,
            "consume": self._verb_consume,
            "lock_target": self._verb_lock_target,
            "get_locked_target": self._verb_get_locked_target,
            "resolve_locked_target": self._verb_resolve_locked_target,
            "evaluate_locked_target": self._verb_evaluate_locked_target,
            "projection_evaluate": self._verb_projection_evaluate,
            "activate_directive": self._verb_activate_directive,
            "revoke_directive": self._verb_revoke_directive,
            "bind_permit_to_directive": self._verb_bind_permit_to_directive,
            "record_target_completion": self._verb_record_target_completion,
            "record_domain_outcome_memory": self._verb_record_domain_outcome_memory,
            "directive_status": self._verb_directive_status,
            "directive_hash_status": self._verb_directive_hash_status,
            # Preview port: no "budget_spent" verb — Preview has no
            # cumulative-budget ledger (unported 3A surface), so there
            # is no spent figure this verb could honestly report.
            "audit": self._verb_audit,
            "verify_audit": self._verb_verify_audit,
            "verify_audit_report": self._verb_verify_audit_report,
            "state_source_id": self._verb_state_source_id,
            "policy_hash": self._verb_policy_hash,
            "health": self._verb_health,
        }

    # -- protocol --

    def handle(self, raw: bytes) -> bytes:
        """Serve one request frame; always returns a response frame.

        Every failure is a refusal response, never an exception and
        never a state change: authentication, freshness, and replay
        are all checked before any verb runs. A read-only credential
        that reaches a verb outside ``READ_ONLY_VERBS`` is refused
        the same way — before the verb runs, with no state change —
        and the refusal is counted, not silently dropped.
        """
        nonce: str | None = None
        role = "full"
        try:
            request = json.loads(raw.decode("utf-8"))
            if not isinstance(request, dict):
                raise ServiceRefusal("request_malformed")
            claimed_nonce = request.get("nonce")
            if isinstance(claimed_nonce, str) and claimed_nonce:
                nonce = claimed_nonce
            claimed_mac = request.get("mac")
            body = {key: value for key, value in request.items() if key != "mac"}
            expected = _mac(self._secret, _REQUEST_MAC_DOMAIN, body)
            if not isinstance(claimed_mac, str) or not hmac.compare_digest(claimed_mac, expected):
                if not self._authenticate_read_only(claimed_mac, body):
                    raise ServiceRefusal("request_mac_invalid")
                role = "read_only"
            if request.get("schema") != REQUEST_SCHEMA:
                raise ServiceRefusal("request_schema_invalid")
            if nonce is None:
                raise ServiceRefusal("request_nonce_invalid")
            issued = request.get("issued_at_ns")
            expires = request.get("expires_at_ns")
            if (
                isinstance(issued, bool)
                or isinstance(expires, bool)
                or not isinstance(issued, int)
                or not isinstance(expires, int)
            ):
                raise ServiceRefusal("request_freshness_invalid")
            now_ns = self._clock()
            if issued > now_ns:
                raise ServiceRefusal("request_not_yet_valid")
            if expires <= now_ns:
                raise ServiceRefusal("request_expired")
            if expires - issued <= 0 or expires - issued > self._max_request_ttl_ns:
                raise ServiceRefusal("request_ttl_invalid")
            verb = request.get("verb")
            if not isinstance(verb, str) or verb not in self._verbs:
                raise ServiceRefusal("unknown_verb")
            args = request.get("args")
            if not isinstance(args, dict):
                raise ServiceRefusal("request_args_invalid")
            with self._lock:
                self._prune_nonces(now_ns)
                if nonce in self._seen_nonces:
                    raise ServiceRefusal("request_replayed")
                self._seen_nonces[nonce] = expires
                if role == "read_only" and verb not in READ_ONLY_VERBS:
                    self._record_read_only_refusal(verb, now_ns)
                    raise ServiceRefusal("read_only_role_forbidden")
                result = self._verbs[verb](args)
            return self._respond(nonce, True, role=role, result=result)
        except ServiceRefusal as refusal:
            return self._respond(nonce, False, role=role, error=str(refusal))
        except ValueError as exc:
            # Kernel and constructor refusals already speak in reason
            # tokens; they are refusals, not service failures.
            return self._respond(nonce, False, role=role, error=str(exc))
        except Exception:
            return self._respond(nonce, False, role=role, error="service_internal_error")

    def _authenticate_read_only(self, claimed_mac: Any, body: dict[str, Any]) -> bool:
        """True when the request MAC verifies under the read-only secret.

        The read-only credential uses its own MAC domain, so a request
        MAC'd for one role never verifies as the other, and a request
        MAC'd with the read-only secret under the full domain (or vice
        versa) verifies as neither. There is no role field to forge:
        the role is whichever secret verified.
        """
        if self._read_only_secret is None or not isinstance(claimed_mac, str):
            return False
        expected = _mac(self._read_only_secret, _READ_ONLY_REQUEST_MAC_DOMAIN, body)
        return hmac.compare_digest(claimed_mac, expected)

    def _record_read_only_refusal(self, verb: str, now_ns: int) -> None:
        """Count a read-only role refusal in process-local diagnostics.

        Deliberately NOT a canonical audit record: the refusal is
        evidence production about an attempt that the kernel never
        evaluated, and appending it to the audit chain would hand a
        read-only credential a write primitive into canonical state —
        anyone holding the read-only secret could bloat the audit by
        spamming mutating verbs (AGENTS.md: NO_WRITE_ROUTE !=
        NO_WRITE_CAPABILITY). The refusal is evidenced three other
        ways instead: the typed, server-MAC'd refusal response the
        caller retains; these bounded per-verb counts, visible
        through the health verb; and the caller's own records. The
        counts are bounded by the verb set — no per-attempt log is
        kept, so repeated refusals cannot grow this state.
        """
        self._read_only_refusals[verb] = self._read_only_refusals.get(verb, 0) + 1
        self._last_read_only_refusal_ns = now_ns

    def _prune_nonces(self, now_ns: int) -> None:
        expired = [nonce for nonce, expiry in self._seen_nonces.items() if expiry <= now_ns]
        for nonce in expired:
            del self._seen_nonces[nonce]
        if len(self._seen_nonces) > _NONCE_CACHE_LIMIT:
            # Oldest-expiring first; a nonce dropped early can only be
            # replayed inside its own freshness window, which the TTL
            # cap keeps short.
            by_expiry = sorted(self._seen_nonces.items(), key=lambda item: item[1])
            for nonce, _ in by_expiry[: len(self._seen_nonces) - _NONCE_CACHE_LIMIT]:
                del self._seen_nonces[nonce]

    def _respond(
        self,
        nonce: str | None,
        ok: bool,
        *,
        role: str = "full",
        result: Any = None,
        error: str | None = None,
    ) -> bytes:
        body: dict[str, Any] = {"schema": RESPONSE_SCHEMA, "nonce": nonce, "ok": ok}
        if ok:
            body["result"] = result
        else:
            body["error"] = error
        if role == "read_only" and self._read_only_secret is not None:
            body["mac"] = _mac(self._read_only_secret, _READ_ONLY_RESPONSE_MAC_DOMAIN, body)
        else:
            body["mac"] = _mac(self._secret, _RESPONSE_MAC_DOMAIN, body)
        return _canonical(body)

    # -- verbs: authority decisions --

    def _verb_evaluate(self, args: dict[str, Any]) -> Any:
        return decision_to_dict(self._kernel.evaluate(intent_from_dict(args.get("intent"))))

    def _verb_evaluate_with_approval(self, args: dict[str, Any]) -> Any:
        decision = self._kernel.evaluate_with_approval(
            intent_from_dict(args.get("intent")),
            envelope_from_dict(args.get("envelope")),
        )
        return decision_to_dict(decision)

    def _verb_consume(self, args: dict[str, Any]) -> Any:
        consumed = self._kernel.consume(
            _require_str(args, "permit"),
            intent_from_dict(args.get("intent")),
        )
        return {"consumed": consumed}

    def _verb_projection_evaluate(self, args: dict[str, Any]) -> Any:
        decision = self._projection.evaluate(
            intent_from_dict(args.get("intent")),
            directive_from_dict(args.get("directive")),
        )
        return decision_to_dict(decision)

    # -- verbs: locked targets --

    def _verb_lock_target(self, args: dict[str, Any]) -> Any:
        target = self._kernel.lock_target(
            _require_str(args, "target_id"),
            intent_from_dict(args.get("intent")),
            version=_require_int(args, "version"),
        )
        return locked_target_to_dict(target)

    def _verb_get_locked_target(self, args: dict[str, Any]) -> Any:
        target = self._kernel.get_locked_target(
            _require_str(args, "target_id"),
            version=_require_int(args, "version"),
        )
        return locked_target_to_dict(target) if target is not None else None

    def _verb_resolve_locked_target(self, args: dict[str, Any]) -> Any:
        resolution = self._kernel.resolve_locked_target(
            _require_str(args, "target_id"),
            _require_str(args, "expected_target_hash"),
            version=_require_int(args, "version"),
        )
        return resolution_to_dict(resolution)

    def _verb_evaluate_locked_target(self, args: dict[str, Any]) -> Any:
        resolution, decision = self._kernel.evaluate_locked_target(
            _require_str(args, "target_id"),
            _require_str(args, "expected_target_hash"),
            version=_require_int(args, "version"),
        )
        return {
            "resolution": resolution_to_dict(resolution),
            "decision": decision_to_dict(decision) if decision is not None else None,
        }

    # -- verbs: directive lifecycle (server-side controller only) --

    def _verb_activate_directive(self, args: dict[str, Any]) -> Any:
        parent = args.get("parent_directive")
        decision = self._controller.activate(
            directive_from_dict(args.get("directive")),
            envelope_from_dict(args.get("envelope")),
            operator_principal=_require_str(args, "operator_principal"),
            session_id=_require_str(args, "session_id"),
            parent_directive=directive_from_dict(parent) if parent is not None else None,
        )
        return decision_to_dict(decision)

    def _verb_revoke_directive(self, args: dict[str, Any]) -> Any:
        decision = self._controller.revoke(
            directive_from_dict(args.get("directive")),
            envelope_from_dict(args.get("envelope")),
            operator_principal=_require_str(args, "operator_principal"),
            session_id=_require_str(args, "session_id"),
        )
        return decision_to_dict(decision)

    def _verb_bind_permit_to_directive(self, args: dict[str, Any]) -> Any:
        self._kernel.bind_permit_to_directive(
            _require_str(args, "permit"),
            _require_str(args, "intent_hash"),
            binding_from_dict(args.get("binding")),
            _require_int(args, "timestamp_ns"),
        )
        return None

    # -- verbs: reconciliation records --

    def _verb_record_target_completion(self, args: dict[str, Any]) -> Any:
        # The artifact path is observed in the service's own
        # filesystem domain, by the kernel verb itself; the client
        # supplies the reference, never the observation.
        return self._kernel.record_target_completion(
            target_id=_require_str(args, "target_id"),
            version=_require_int(args, "version"),
            target_hash=_require_str(args, "target_hash"),
            intent_hash=_require_str(args, "intent_hash"),
            artifact_path=_require_str(args, "artifact_path"),
            timestamp_ns=_require_int(args, "timestamp_ns"),
        )

    def _verb_record_domain_outcome_memory(self, args: dict[str, Any]) -> Any:
        payload = args.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("service_args_invalid")
        return self._kernel.record_domain_outcome_memory(
            reconciliation_transition_hash=_require_str(args, "reconciliation_transition_hash"),
            payload=payload,
            timestamp_ns=_require_int(args, "timestamp_ns"),
        )

    # -- verbs: facade reads --

    def _verb_directive_status(self, args: dict[str, Any]) -> Any:
        return {
            "status": self._kernel.directive_status(
                _require_str(args, "directive_id"),
                _require_int(args, "version"),
                _require_str(args, "directive_hash"),
            )
        }

    def _verb_directive_hash_status(self, args: dict[str, Any]) -> Any:
        return {"status": self._kernel.directive_hash_status(_require_str(args, "directive_hash"))}

    def _verb_audit(self, args: dict[str, Any]) -> Any:
        return {"records": self._kernel.audit}

    def _verb_verify_audit(self, args: dict[str, Any]) -> Any:
        return {"valid": self._kernel.verify_audit()}

    def _verb_verify_audit_report(self, args: dict[str, Any]) -> Any:
        return self._kernel.verify_audit_report()

    def _verb_state_source_id(self, args: dict[str, Any]) -> Any:
        return {"state_source_id": self._kernel.state_source_id()}

    def _verb_policy_hash(self, args: dict[str, Any]) -> Any:
        return {"policy_hash": self._kernel.policy_hash}

    def _verb_health(self, args: dict[str, Any]) -> Any:
        # Control Center design §5.2: reachability + kernel liveness,
        # no authority content. The CC calls this to distinguish
        # "kernel down" (no response at all — a transport failure, never
        # a fabricated value) from "snapshot stale" (a response whose
        # data is old). The refusal counts are the process-local
        # diagnostics from _record_read_only_refusal, bounded by the
        # verb set; they are not canonical state.
        return {
            "status": "ok",
            "state_source_id": self._kernel.state_source_id(),
            "now_ns": self._clock(),
            "read_only_refusals": dict(self._read_only_refusals),
            "last_read_only_refusal_ns": self._last_read_only_refusal_ns,
        }


# --- The client ---------------------------------------------------------


class KernelServiceClient:
    """The only surface another component receives: authenticated verbs.

    The client holds a transport callable and the service secret —
    never a kernel, a state backend, or any other canonical writer
    (AGENTS.md: a transport surface must not retain a canonical
    writer merely because its declared API is read-only). Every
    method returns plain data reconstructed from the response.
    """

    def __init__(
        self,
        transport: Callable[[bytes], bytes],
        secret: str | bytes,
        *,
        clock: Callable[[], int] | None = None,
        request_ttl_ns: int = DEFAULT_MAX_REQUEST_TTL_NS,
    ) -> None:
        if isinstance(secret, str):
            secret = secret.encode()
        if not secret:
            raise ValueError("service secret must be non-empty")
        if request_ttl_ns <= 0:
            raise ValueError("request_ttl_ns must be positive")
        self._transport = transport
        self._secret = secret
        self._clock = clock or time.time_ns
        self._request_ttl_ns = request_ttl_ns
        self._request_mac_domain = _REQUEST_MAC_DOMAIN
        self._response_mac_domain = _RESPONSE_MAC_DOMAIN

    def _call(self, verb: str, args: dict[str, Any]) -> Any:
        issued = self._clock()
        body: dict[str, Any] = {
            "schema": REQUEST_SCHEMA,
            "verb": verb,
            "nonce": secrets.token_hex(16),
            "issued_at_ns": issued,
            "expires_at_ns": issued + self._request_ttl_ns,
            "args": args,
        }
        body["mac"] = _mac(self._secret, self._request_mac_domain, body)
        raw = self._transport(_canonical(body))
        try:
            response = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ServiceRefusal("response_malformed") from exc
        if not isinstance(response, dict):
            raise ServiceRefusal("response_malformed")
        claimed_mac = response.get("mac")
        response_body = {key: value for key, value in response.items() if key != "mac"}
        expected = _mac(self._secret, self._response_mac_domain, response_body)
        if not isinstance(claimed_mac, str) or not hmac.compare_digest(claimed_mac, expected):
            raise ServiceRefusal("response_mac_invalid")
        if response.get("schema") != RESPONSE_SCHEMA or response.get("nonce") != body["nonce"]:
            raise ServiceRefusal("response_nonce_mismatch")
        if not response.get("ok"):
            raise ServiceRefusal(str(response.get("error") or "service_refused"))
        return response.get("result")

    # -- authority decisions --

    def evaluate(self, intent: Intent) -> Decision:
        return decision_from_dict(self._call("evaluate", {"intent": intent_to_dict(intent)}))

    def evaluate_with_approval(self, intent: Intent, envelope: ApprovalEnvelope) -> Decision:
        return decision_from_dict(
            self._call(
                "evaluate_with_approval",
                {"intent": intent_to_dict(intent), "envelope": envelope_to_dict(envelope)},
            )
        )

    def consume(self, permit: str, intent: Intent) -> bool:
        result = self._call("consume", {"permit": permit, "intent": intent_to_dict(intent)})
        return bool(result["consumed"])

    def projection_evaluate(self, intent: Intent, directive: Directive) -> Decision:
        return decision_from_dict(
            self._call(
                "projection_evaluate",
                {"intent": intent_to_dict(intent), "directive": directive_to_dict(directive)},
            )
        )

    # -- locked targets --

    def lock_target(self, target_id: str, intent: Intent, *, version: int = 1) -> LockedTarget:
        return locked_target_from_dict(
            self._call(
                "lock_target",
                {"target_id": target_id, "intent": intent_to_dict(intent), "version": version},
            )
        )

    def get_locked_target(self, target_id: str, *, version: int = 1) -> LockedTarget | None:
        result = self._call("get_locked_target", {"target_id": target_id, "version": version})
        return locked_target_from_dict(result) if result is not None else None

    def resolve_locked_target(
        self, target_id: str, expected_target_hash: str, *, version: int = 1
    ) -> TargetResolution:
        return resolution_from_dict(
            self._call(
                "resolve_locked_target",
                {
                    "target_id": target_id,
                    "expected_target_hash": expected_target_hash,
                    "version": version,
                },
            )
        )

    def evaluate_locked_target(
        self, target_id: str, expected_target_hash: str, *, version: int = 1
    ) -> tuple[TargetResolution, Decision | None]:
        result = self._call(
            "evaluate_locked_target",
            {"target_id": target_id, "expected_target_hash": expected_target_hash, "version": version},
        )
        decision = result.get("decision")
        return resolution_from_dict(result["resolution"]), (
            decision_from_dict(decision) if decision is not None else None
        )

    # -- directive lifecycle --

    def activate_directive(
        self,
        directive: Directive,
        envelope: ApprovalEnvelope,
        *,
        operator_principal: str,
        session_id: str = "default",
        parent_directive: Directive | None = None,
    ) -> Decision:
        return decision_from_dict(
            self._call(
                "activate_directive",
                {
                    "directive": directive_to_dict(directive),
                    "envelope": envelope_to_dict(envelope),
                    "operator_principal": operator_principal,
                    "session_id": session_id,
                    "parent_directive": directive_to_dict(parent_directive)
                    if parent_directive is not None
                    else None,
                },
            )
        )

    def revoke_directive(
        self,
        directive: Directive,
        envelope: ApprovalEnvelope,
        *,
        operator_principal: str,
        session_id: str = "default",
    ) -> Decision:
        return decision_from_dict(
            self._call(
                "revoke_directive",
                {
                    "directive": directive_to_dict(directive),
                    "envelope": envelope_to_dict(envelope),
                    "operator_principal": operator_principal,
                    "session_id": session_id,
                },
            )
        )

    def bind_permit_to_directive(
        self, permit: str, intent_hash: str, binding: DirectivePermitBinding, timestamp_ns: int
    ) -> None:
        self._call(
            "bind_permit_to_directive",
            {
                "permit": permit,
                "intent_hash": intent_hash,
                "binding": binding_to_dict(binding),
                "timestamp_ns": timestamp_ns,
            },
        )

    # -- reconciliation records --

    def record_target_completion(
        self,
        *,
        target_id: str,
        version: int,
        target_hash: str,
        intent_hash: str,
        artifact_path: str,
        timestamp_ns: int,
    ) -> dict[str, Any]:
        return self._call(
            "record_target_completion",
            {
                "target_id": target_id,
                "version": version,
                "target_hash": target_hash,
                "intent_hash": intent_hash,
                "artifact_path": artifact_path,
                "timestamp_ns": timestamp_ns,
            },
        )

    def record_domain_outcome_memory(
        self,
        *,
        reconciliation_transition_hash: str,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        return self._call(
            "record_domain_outcome_memory",
            {
                "reconciliation_transition_hash": reconciliation_transition_hash,
                "payload": payload,
                "timestamp_ns": timestamp_ns,
            },
        )

    # -- facade reads --

    def directive_status(self, directive_id: str, version: int, directive_hash: str) -> str:
        return self._call(
            "directive_status",
            {"directive_id": directive_id, "version": version, "directive_hash": directive_hash},
        )["status"]

    def directive_hash_status(self, directive_hash: str) -> str:
        return self._call("directive_hash_status", {"directive_hash": directive_hash})["status"]

    def audit(self) -> list[dict[str, Any]]:
        return self._call("audit", {})["records"]

    def verify_audit(self) -> bool:
        return bool(self._call("verify_audit", {})["valid"])

    def verify_audit_report(self) -> dict[str, Any]:
        return self._call("verify_audit_report", {})

    def state_source_id(self) -> str:
        return self._call("state_source_id", {})["state_source_id"]

    def policy_hash(self) -> str:
        return self._call("policy_hash", {})["policy_hash"]

    def health(self) -> dict[str, Any]:
        return self._call("health", {})


class ReadOnlyKernelServiceClient(KernelServiceClient):
    """The observer client: the read-only role, nothing else.

    Control Center design §5.2: this client holds the read-only
    secret under the read-only MAC domains, so the server derives the
    read-only role from its requests. The mutating methods exist on
    this class only by inheritance, and every one of them fails
    closed server-side with ``read_only_role_forbidden`` — the
    server is the single enforcement point, and no client-side
    method absence is load-bearing. Do not call them: the honest
    surface of this client is ``health`` plus the ``READ_ONLY_VERBS``
    reads below. A read-only client holds no kernel, no state
    backend, and no full service secret.
    """

    def __init__(
        self,
        transport: Callable[[bytes], bytes],
        read_only_secret: str | bytes,
        *,
        clock: Callable[[], int] | None = None,
        request_ttl_ns: int = DEFAULT_MAX_REQUEST_TTL_NS,
    ) -> None:
        super().__init__(transport, read_only_secret, clock=clock, request_ttl_ns=request_ttl_ns)
        self._request_mac_domain = _READ_ONLY_REQUEST_MAC_DOMAIN
        self._response_mac_domain = _READ_ONLY_RESPONSE_MAC_DOMAIN


# --- Transports ---------------------------------------------------------


def loopback_transport(service: KernelService) -> Callable[[bytes], bytes]:
    """In-process transport: bytes cross the same protocol, no handle does."""

    return service.handle


def _send_frame(sock: socket.socket, data: bytes) -> None:
    if len(data) > _MAX_FRAME_BYTES:
        raise ServiceRefusal("frame_too_large")
    sock.sendall(len(data).to_bytes(8, "big") + data)


def _recv_frame(sock: socket.socket) -> bytes:
    header = b""
    while len(header) < 8:
        chunk = sock.recv(8 - len(header))
        if not chunk:
            raise ServiceRefusal("transport_closed")
        header += chunk
    length = int.from_bytes(header, "big")
    if length > _MAX_FRAME_BYTES:
        raise ServiceRefusal("frame_too_large")
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise ServiceRefusal("transport_closed")
        payload += chunk
    return payload


class UnixSocketTransport:
    """Client transport over a Unix domain socket, one request per connection."""

    def __init__(self, path: str) -> None:
        self._path = path

    def __call__(self, raw: bytes) -> bytes:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self._path)
            _send_frame(sock, raw)
            return _recv_frame(sock)


def serve_unix_socket(service: KernelService, path: str) -> None:
    """Serve ``service`` on a Unix domain socket until interrupted.

    One request per connection, handled sequentially: the kernel's
    own consume-time atomicity lives in the state backend, and the
    service lock keeps dispatch deterministic.
    """
    if os.path.exists(path):
        os.unlink(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        server.listen(16)
        while True:
            connection, _ = server.accept()
            with connection:
                try:
                    request = _recv_frame(connection)
                    _send_frame(connection, service.handle(request))
                except (ServiceRefusal, ConnectionError, OSError):
                    continue
