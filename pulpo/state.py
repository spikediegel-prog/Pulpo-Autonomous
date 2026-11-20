"""Canonical kernel state backends.

The state backend persists replay guards, one-use permits, directives, and the
audit chain for the existing governance kernel. It is storage for that kernel,
not another router, policy engine, or evidence ledger.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from os import PathLike
import sqlite3
from threading import RLock
from typing import Any, Iterator, Protocol
from urllib.parse import quote as _url_quote


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _delta_for(
    event: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Compact, non-authoritative state-change projection bound into the canonical audit record."""
    keys = (
        "outcome",
        "reason",
        "intent_hash",
        "approval_id",
        "directive_id",
        "version",
        "directive_version",
        "directive_hash",
        "target_id",
        "attempt_id",
        "transition_hash",
        "reconciliation_outcome",
    )

    delta = {
        "event": event,
        "payload_hash": sha256(
            _canonical(payload)
        ).hexdigest(),
    }

    for key in keys:
        if key in payload:
            delta[key] = payload[key]

    return delta


def _delta_state_root(
    previous_delta_root: str,
    delta: dict[str, Any],
) -> str:
    return sha256(
        _canonical(
            {
                "previous_delta_root": previous_delta_root,
                "delta": delta,
            }
        )
    ).hexdigest()


class AuditSigner:
    """HMAC-SHA256 signer/verifier for audit records (Phase 2, Item 1).

    One signer per deployment, keyed by a dedicated ``audit-secret``
    that is deliberately NOT the kernel secret: a single theft must
    not yield both permit minting and undetectable history forgery.
    The signature covers the record's own ``hash`` and is stored as a
    sibling field, excluded from the hashed body — the exact pattern
    ``AuditAnchor`` uses (``signing_payload()`` excludes
    ``signature``). The field is algorithm-agile: a future Ed25519
    signer can replace this class behind the same record shape
    without changing the chain math. Verification is constant-time;
    a missing, non-string, or malformed signature never verifies.
    """

    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ValueError("audit secret must be non-empty")
        self._secret = secret

    def sign(self, record_hash: str) -> str:
        if not isinstance(record_hash, str):
            raise TypeError("record hash must be a string")
        return hmac.new(self._secret, record_hash.encode("utf-8"), sha256).hexdigest()

    def verify(self, record_hash: str, signature: Any) -> bool:
        if not isinstance(signature, str) or not signature:
            return False
        try:
            expected = self.sign(record_hash)
        except (AttributeError, TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, signature)


def _audit_record(
    previous_hash: str,
    event: str,
    payload: dict[str, Any],
    timestamp_ns: int,
    signer: AuditSigner | None = None,
) -> dict[str, Any]:
    body = {
        "event": event,
        "payload": payload,
        "previous_hash": previous_hash,
        "timestamp_ns": timestamp_ns,
    }

    record = {
        **body,
        "hash": sha256(
            _canonical(body)
        ).hexdigest(),
    }

    if signer is not None:
        # The signature is computed over the record hash and stored
        # as a sibling field: it is NOT part of the hashed body, so
        # the unkeyed chain math is unchanged and old verifiers
        # recomputing the body still agree on the hash. Verification
        # of the signature is the kernel's job (verify_audit), not
        # this constructor's. Callers that re-hash the record
        # afterwards (notably _attach_delta, which binds the delta
        # projection into the hash) must re-sign the final hash;
        # append paths sign after _attach_delta, never here.
        record["signature"] = signer.sign(record["hash"])

    return record


def _attach_signature(
    record: dict[str, Any],
    signer: AuditSigner | None,
) -> dict[str, Any]:
    """Sign a finished record over its final hash, if a signer is given.

    The signing point for every append path: called after
    _attach_delta, so the signature covers the hash the kernel
    verifies (which binds the delta fields). With no signer the
    record is returned unchanged (legacy mode).
    """

    if signer is not None:
        record["signature"] = signer.sign(record["hash"])

    return record


def _attach_delta(
    record: dict[str, Any],
    previous_delta_root: str,
) -> dict[str, Any]:
    body = {
        key: value
        for key, value in record.items()
        if key != "hash"
    }

    delta = _delta_for(
        str(body["event"]),
        body["payload"],
    )

    body["delta"] = delta
    body["previous_delta_root"] = previous_delta_root
    body["delta_root"] = _delta_state_root(
        previous_delta_root,
        delta,
    )

    return {
        **body,
        "hash": sha256(
            _canonical(body)
        ).hexdigest(),
    }


@dataclass(frozen=True)
class ApprovalUse:
    approval_id: str
    nonce: str
    audit_payload: dict[str, Any]


@dataclass(frozen=True)
class DirectivePermitBinding:
    directive_id: str
    version: int
    directive_hash: str
    issued_at_ns: int
    expires_at_ns: int
    parent_directive_hash: str | None = None

    def audit_payload(self) -> dict[str, Any]:
        payload = {
            "directive_id": self.directive_id,
            "directive_version": self.version,
            "directive_hash": self.directive_hash,
            "directive_issued_at_ns": self.issued_at_ns,
            "directive_expires_at_ns": self.expires_at_ns,
        }

        if self.parent_directive_hash is not None:
            payload["parent_directive_hash"] = (
                self.parent_directive_hash
            )

        return payload


@dataclass(frozen=True)
class VerifiedAuthorityEvidence:
    """Typed record that directive authority was verified (Phase 2, Item 3A).

    Before Item 3A, ``activate_directive``/``revoke_directive`` accepted
    ``authority_evidence`` as an opaque dict, verified against nothing:
    any holder of the state handle could activate a directive with
    ``{"approver": "no-one", "evidence": "invented"}`` and the invented
    directive then gated real kernel spends (design repro 3, part B).
    The state layer now requires this exact type and cross-checks its
    binding fields against the directive being activated or revoked, so
    a bare dict — or a wrapper naming a different directive — is
    refused at the storage surface itself.

    In practice the only production construction site is
    ``DirectiveAuthorityController``, which builds this value only after
    the kernel has verified the approval envelope and consumed the
    one-use authority permit (the same discipline ``ApprovalUse``
    carries for permit issuance). Honest boundary: this is a library
    type, not a capability — a determined in-process caller can
    construct one with fabricated fields, exactly as it can construct
    a state backend directly. Item 3A makes fabrication a deliberate,
    greppable construction of a named type instead of an anonymous
    dict; process-boundary enforcement is Item 3B (Phase 3).
    """

    operation: str
    directive_id: str
    directive_version: int
    directive_hash: str
    parent_directive_hash: str | None
    authority_id: str
    approval_id: str
    envelope_hash: str
    intent_hash: str
    policy_hash: str

    def __post_init__(self) -> None:
        if self.operation not in (
            "activate_directive",
            "revoke_directive",
        ):
            raise ValueError(
                "authority evidence operation is unsupported"
            )

        if (
            not self.directive_id
            or self.directive_version <= 0
        ):
            raise ValueError(
                "authority evidence directive identity is invalid"
            )

        for value in (
            self.directive_hash,
            self.authority_id,
            self.approval_id,
            self.envelope_hash,
            self.intent_hash,
            self.policy_hash,
        ):
            if (
                not isinstance(value, str)
                or not value
            ):
                raise ValueError(
                    "authority evidence fields must be non-empty"
                )

    def audit_payload(self) -> dict[str, Any]:
        """The exact dict shape recorded in the audit chain.

        Byte-identical to the pre-3A evidence dict the controller
        built, so existing chains and their readers see no format
        change — only the surface that accepts it changed.
        """

        return {
            "operation": self.operation,
            "directive_id": self.directive_id,
            "directive_version": self.directive_version,
            "directive_hash": self.directive_hash,
            "parent_directive_hash": self.parent_directive_hash,
            "authority_id": self.authority_id,
            "approval_id": self.approval_id,
            "envelope_hash": self.envelope_hash,
            "intent_hash": self.intent_hash,
            "policy_hash": self.policy_hash,
        }


def _require_verified_evidence(
    authority_evidence: object,
    *,
    operation: str,
    directive_id: str,
    version: int,
    directive_hash: str,
    parent_directive_hash: str | None = None,
    check_parent: bool = False,
) -> VerifiedAuthorityEvidence:
    """Fail closed unless ``authority_evidence`` is verified-typed and bound.

    The type requirement is exact (``type(...) is``), following the
    repo's canonical-type precedent: a dict, a subclass, or any other
    mapping-shaped value is refused. The binding cross-checks are the
    ones the state layer can perform itself — the evidence must name
    the operation and the exact directive the call is mutating.
    """

    if type(authority_evidence) is not VerifiedAuthorityEvidence:
        raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")
    evidence = authority_evidence
    if (
        evidence.operation != operation
        or evidence.directive_id != directive_id
        or evidence.directive_version != version
        or evidence.directive_hash != directive_hash
        or (check_parent and evidence.parent_directive_hash != parent_directive_hash)
    ):
        raise ValueError("authority evidence does not match the directive")
    return evidence


class KernelState(Protocol):
    @property
    def audit(self) -> list[dict[str, Any]]:
        ...

    def iter_audit(
        self,
        *,
        event: str | None = None,
        reverse: bool = False,
    ) -> Iterator[dict[str, Any]]:
        ...

    def audit_integrity_token(
        self,
    ) -> object | None:
        ...

    def approval_replay_reason(
        self,
        approval_id: str,
        nonce: str,
    ) -> str | None:
        ...

    def issue_permit(
        self,
        permit: str,
        intent_hash: str,
        decision_reason: str,
        timestamp_ns: int,
        expires_at_ns: int,
        approval: ApprovalUse | None = None,
    ) -> str | None:
        ...

    def bind_permit_to_directive(
        self,
        permit: str,
        intent_hash: str,
        binding: DirectivePermitBinding,
        timestamp_ns: int,
    ) -> None:
        ...

    def consume_permit(
        self,
        permit: str,
        intent_hash: str,
        timestamp_ns: int,
    ) -> bool:
        ...

    def activate_directive(
        self,
        directive: Any,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        ...

    def revoke_directive(
        self,
        directive_id: str,
        version: int,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        ...

    def directive_status(
        self,
        directive_id: str,
        version: int,
        directive_hash: str,
    ) -> str:
        ...

    def directive_hash_status(
        self,
        directive_hash: str,
    ) -> str:
        ...

    def append(
        self,
        event: str,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> None:
        ...

    def append_many(
        self,
        entries: list[
            tuple[
                str,
                dict[str, Any],
                int,
            ]
        ],
    ) -> None:
        ...

    def append_unique(
        self,
        event: str,
        identity_field: str,
        identity_value: Any,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        ...


class InMemoryKernelState:
    def __init__(self, audit_signer: AuditSigner | None = None, legacy_audit_records: int = 0) -> None:
        # Audit signing (Phase 2, Item 1): when a signer is supplied,
        # every appended record carries an HMAC over its hash. When no
        # signer is supplied the backend stays in legacy mode — records
        # are unsigned and verification is the unkeyed chain alone — so
        # direct construction keeps its exact pre-signing behavior.
        # ``legacy_audit_records`` is the count of leading records that
        # predate enablement: they verify legacy-style and are reported
        # as an unsigned prefix. The enablement itself is recorded in
        # deployment config outside the state file (ops), never here.
        self.audit_signer = audit_signer
        self.legacy_audit_records = legacy_audit_records

        self._issued: dict[
            str,
            tuple[str, int],
        ] = {}

        self._spent: set[str] = set()

        self._approval_ids: set[str] = set()
        self._approval_nonces: set[str] = set()

        self._directives: dict[
            tuple[str, int],
            tuple[str, bool],
        ] = {}

        self._permit_directives: dict[
            str,
            DirectivePermitBinding,
        ] = {}

        self._audit: list[
            dict[str, Any]
        ] = []

        self._audit_lock = RLock()

        self._unique_audit: dict[
            tuple[str, str, str],
            dict[str, Any],
        ] = {}

    @property
    def audit(self) -> list[dict[str, Any]]:
        # Return detached deep copies, copied under the audit lock, matching
        # the SQLite backend (which rebuilds fresh records from rows on every
        # read). Returning the live list let any holder of the kernel delete
        # records, append forged ones, or rewrite a record's payload in the
        # stored trail through the read path alone.
        # Regression: tests/test_inmemory_audit_detached_copies.py.
        with self._audit_lock:
            return deepcopy(self._audit)

    def iter_audit(
        self,
        *,
        event: str | None = None,
        reverse: bool = False,
    ) -> Iterator[dict[str, Any]]:
        records = (
            reversed(self._audit)
            if reverse
            else iter(self._audit)
        )

        for record in records:
            if (
                event is None
                or record.get("event") == event
            ):
                yield record

    def audit_integrity_token(
        self,
    ) -> object | None:
        # In-memory audit is deliberately mutable in tamper tests.
        # Always force full verification.
        return None

    def approval_replay_reason(
        self,
        approval_id: str,
        nonce: str,
    ) -> str | None:
        if approval_id in self._approval_ids:
            return "approval_id_replayed"

        if nonce in self._approval_nonces:
            return "approval_nonce_replayed"

        return None

    def issue_permit(
        self,
        permit: str,
        intent_hash: str,
        decision_reason: str,
        timestamp_ns: int,
        expires_at_ns: int,
        approval: ApprovalUse | None = None,
    ) -> str | None:
        # Serialize the whole check-and-record transition under the audit lock (an RLock; append()
        # re-enters it), mirroring the SQLite backend's BEGIN IMMEDIATE transaction. Upstream #345 already
        # had issue_permit locked; this vendored copy did not, so it is locked here too.
        with self._audit_lock:
            if approval is not None:
                replay = self.approval_replay_reason(
                    approval.approval_id,
                    approval.nonce,
                )

                if replay:
                    return replay

                self._approval_ids.add(
                    approval.approval_id
                )
                self._approval_nonces.add(
                    approval.nonce
                )

                self.append(
                    "approval_verified",
                    approval.audit_payload,
                    timestamp_ns,
                )

            if expires_at_ns <= timestamp_ns:
                raise ValueError(
                    "permit expiry must be after issue time"
                )

            self._issued[permit] = (
                intent_hash,
                expires_at_ns,
            )

            self.append(
                "decision",
                {
                    "outcome": "allow",
                    "reason": decision_reason,
                    "intent_hash": intent_hash,
                    "permit_expires_at_ns": expires_at_ns,
                },
                timestamp_ns,
            )

            return None

    def bind_permit_to_directive(
        self,
        permit: str,
        intent_hash: str,
        binding: DirectivePermitBinding,
        timestamp_ns: int,
    ) -> None:
        # Serialized under the same lock as issue_permit/consume_permit: the availability and
        # directive-status checks must hold against the same state the binding is recorded into.
        with self._audit_lock:
            issued = self._issued.get(
                permit
            )

            if (
                issued is None
                or issued[0] != intent_hash
                or permit in self._spent
                or timestamp_ns >= issued[1]
            ):
                raise ValueError(
                    "permit unavailable for directive binding"
                )

            if permit in self._permit_directives:
                raise ValueError(
                    "permit directive binding is immutable"
                )

            if (
                self.directive_status(
                    binding.directive_id,
                    binding.version,
                    binding.directive_hash,
                )
                != "active"
            ):
                raise ValueError(
                    "directive is not active for permit binding"
                )

            if (
                binding.parent_directive_hash is not None
                and self.directive_hash_status(
                    binding.parent_directive_hash
                )
                != "active"
            ):
                raise ValueError(
                    "parent directive is not active for permit binding"
                )

            self._permit_directives[
                permit
            ] = binding

            self.append(
                "permit_bound_to_directive",
                {
                    "intent_hash": intent_hash,
                    **binding.audit_payload(),
                },
                timestamp_ns,
            )

    def consume_permit(
        self,
        permit: str,
        intent_hash: str,
        timestamp_ns: int,
    ) -> bool:
        # Serialize the whole check-and-record transition under the audit lock (an RLock; append()
        # re-enters it), mirroring the SQLite backend's BEGIN IMMEDIATE transaction. Without it, a
        # revoke_directive completing mid-consume still admitted against the pre-revocation status, and
        # two concurrent consumptions of one permit could both observe it unspent before either recorded
        # the spend, voiding single-use.
        with self._audit_lock:
            issued = self._issued.get(
                permit
            )

            expires_at_ns = (
                issued[1]
                if issued is not None
                else None
            )

            valid = (
                issued is not None
                and issued[0] == intent_hash
                and permit not in self._spent
                and expires_at_ns is not None
                and timestamp_ns < expires_at_ns
            )

            binding = self._permit_directives.get(
                permit
            )

            payload: dict[str, Any] = {
                "intent_hash": intent_hash,
                "permit_expires_at_ns": expires_at_ns,
            }

            if binding is not None:
                status = self.directive_status(
                    binding.directive_id,
                    binding.version,
                    binding.directive_hash,
                )

                if (
                    status == "active"
                    and binding.parent_directive_hash is not None
                ):
                    status = self.directive_hash_status(
                        binding.parent_directive_hash
                    )

                if (
                    status == "active"
                    and not (
                        binding.issued_at_ns
                        <= timestamp_ns
                        < binding.expires_at_ns
                    )
                ):
                    status = "directive_inactive"

                valid = (
                    valid
                    and status == "active"
                )

                payload.update(
                    binding.audit_payload()
                )

                payload[
                    "directive_status"
                ] = status

            if valid:
                self._spent.add(
                    permit
                )

            self.append(
                (
                    "permit_consumed"
                    if valid
                    else "permit_rejected"
                ),
                payload,
                timestamp_ns,
            )

            return valid

    def activate_directive(
        self,
        directive,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        # Item 3A: the evidence gate runs before any mutation — a bare
        # dict or a wrapper bound to another directive never reaches
        # the immutability/parent checks, let alone the audit append.
        evidence = _require_verified_evidence(
            authority_evidence,
            operation="activate_directive",
            directive_id=directive.directive_id,
            version=directive.version,
            directive_hash=directive.directive_hash,
            parent_directive_hash=getattr(
                directive,
                "parent_directive_hash",
                None,
            ),
            check_parent=True,
        )

        # Serialized under the same lock: the immutability and parent checks must hold against the state
        # the activation records into.
        with self._audit_lock:
            key = (
                directive.directive_id,
                directive.version,
            )

            if key in self._directives:
                raise ValueError(
                    "directive version is immutable"
                )

            parent_hash = getattr(
                directive,
                "parent_directive_hash",
                None,
            )

            if (
                parent_hash is not None
                and self.directive_hash_status(
                    parent_hash
                )
                != "active"
            ):
                raise ValueError(
                    "parent directive is not active for activation"
                )

            self._directives[key] = (
                directive.directive_hash,
                False,
            )

            self.append(
                "directive_activated",
                {
                    "directive_id": directive.directive_id,
                    "version": directive.version,
                    "directive_hash": directive.directive_hash,
                    "authority_evidence": evidence.audit_payload(),
                },
                timestamp_ns,
            )

    def revoke_directive(
        self,
        directive_id: str,
        version: int,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        # Item 3A: the type gate runs before any lookup or mutation.
        if type(authority_evidence) is not VerifiedAuthorityEvidence:
            raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")

        # Serialized under the same lock: the revocation mutation and its audit append are one transition,
        # atomic against consume_permit's status read -- a revocation fully precedes or fully follows any
        # consumption, and never lands inside one.
        with self._audit_lock:
            key = (
                directive_id,
                version,
            )

            if key not in self._directives:
                raise ValueError(
                    "directive version not found"
                )

            digest, _ = self._directives[
                key
            ]

            # The stored hash is known only after the lookup, so the
            # binding cross-check completes here, before the mutation.
            evidence = _require_verified_evidence(
                authority_evidence,
                operation="revoke_directive",
                directive_id=directive_id,
                version=version,
                directive_hash=digest,
            )

            self._directives[key] = (
                digest,
                True,
            )

            self.append(
                "directive_revoked",
                {
                    "directive_id": directive_id,
                    "version": version,
                    "directive_hash": digest,
                    "authority_evidence": evidence.audit_payload(),
                },
                timestamp_ns,
            )

    def directive_status(
        self,
        directive_id: str,
        version: int,
        directive_hash: str,
    ) -> str:
        value = self._directives.get(
            (
                directive_id,
                version,
            )
        )

        if value is None:
            return "directive_not_authorized"

        digest, revoked = value

        if digest != directive_hash:
            return "directive_version_mismatch"

        return (
            "directive_revoked"
            if revoked
            else "active"
        )

    def directive_hash_status(
        self,
        directive_hash: str,
    ) -> str:
        for (
            digest,
            revoked,
        ) in self._directives.values():
            if digest == directive_hash:
                return (
                    "directive_parent_revoked"
                    if revoked
                    else "active"
                )

        return "directive_parent_not_authorized"

    def append(
        self,
        event: str,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> None:
        # Payload detachment (upstream #355, Repro C): the record must
        # hold a copy of the caller's payload, not the caller's dict
        # itself — mutating the dict after append rewrote the stored
        # in-memory record in place. SQLite serializes at write and
        # is detached by construction; this is the in-memory half.
        payload = deepcopy(payload)

        with self._audit_lock:
            previous = (
                self._audit[-1]["hash"]
                if self._audit
                else "0" * 64
            )

            previous_root = (
                self._audit[-1].get(
                    "delta_root",
                    previous,
                )
                if self._audit
                else "0" * 64
            )

            record = _audit_record(
                previous,
                event,
                payload,
                timestamp_ns,
            )

            self._audit.append(
                _attach_signature(
                    _attach_delta(
                        record,
                        previous_root,
                    ),
                    self.audit_signer,
                )
            )

    def append_many(
        self,
        entries: list[
            tuple[
                str,
                dict[str, Any],
                int,
            ]
        ],
    ) -> None:
        if any(
            not event
            or not isinstance(
                payload,
                dict,
            )
            for event, payload, _ in entries
        ):
            raise ValueError(
                "audit batch entry invalid"
            )

        with self._audit_lock:
            start = len(
                self._audit
            )

            try:
                for (
                    event,
                    payload,
                    timestamp_ns,
                ) in entries:
                    # Payload detachment (upstream #355, Repro C —
                    # Autonomous-only extension: upstream touched
                    # append/append_unique only, but append_many holds
                    # the same caller reference in the same backend).
                    payload = deepcopy(payload)

                    previous = (
                        self._audit[-1]["hash"]
                        if self._audit
                        else "0" * 64
                    )

                    previous_root = (
                        self._audit[-1].get(
                            "delta_root",
                            previous,
                        )
                        if self._audit
                        else "0" * 64
                    )

                    record = _audit_record(
                        previous,
                        event,
                        payload,
                        timestamp_ns,
                    )

                    self._audit.append(
                        _attach_signature(
                            _attach_delta(
                                record,
                                previous_root,
                            ),
                            self.audit_signer,
                        )
                    )

            except Exception:
                del self._audit[start:]
                raise

    def append_unique(
        self,
        event: str,
        identity_field: str,
        identity_value: Any,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        # Payload detachment (upstream #355, Repro C): see append.
        payload = deepcopy(payload)

        if (
            not event
            or not identity_field
            or payload.get(
                identity_field
            )
            != identity_value
        ):
            raise ValueError(
                "unique audit identity invalid"
            )

        with self._audit_lock:
            identity_key = (
                event,
                identity_field,
                _canonical(
                    identity_value
                ).decode(),
            )

            indexed = (
                self._unique_audit.get(
                    identity_key
                )
            )

            if indexed is not None:
                # Detached copy: the index holds the stored payload object
                # (a fork addition upstream does not have), so returning it
                # directly would hand out a live reference to the store.
                return deepcopy(indexed)

            matches = [
                record["payload"]
                for record in self._audit
                if record.get("event")
                == event
                and isinstance(
                    record.get("payload"),
                    dict,
                )
                and record[
                    "payload"
                ].get(
                    identity_field
                )
                == identity_value
            ]

            if len(matches) > 1:
                raise ValueError(
                    "unique audit identity ambiguous"
                )

            if matches:
                self._unique_audit[
                    identity_key
                ] = matches[0]

                # Detached copy, as on the SQLite backend (which returns a
                # freshly decoded payload): the caller must not be able to
                # rewrite the stored record through the returned payload.
                return deepcopy(matches[0])

            previous = (
                self._audit[-1]["hash"]
                if self._audit
                else "0" * 64
            )

            previous_root = (
                self._audit[-1].get(
                    "delta_root",
                    previous,
                )
                if self._audit
                else "0" * 64
            )

            record = _audit_record(
                previous,
                event,
                payload,
                timestamp_ns,
            )

            self._audit.append(
                _attach_signature(
                    _attach_delta(
                        record,
                        previous_root,
                    ),
                    self.audit_signer,
                )
            )

            self._unique_audit[
                identity_key
            ] = payload

            return None


class SQLiteKernelState:
    def __init__(
        self,
        path: str | PathLike[str],
        audit_signer: AuditSigner | None = None,
        legacy_audit_records: int = 0,
        migrate_schema: bool = True,
    ) -> None:
        # Audit signing (Phase 2, Item 1): same contract as the
        # in-memory backend — a signer signs every appended record, no
        # signer means legacy unsigned mode. ``legacy_audit_records``
        # counts the leading pre-enablement records (see above).
        #
        # ``migrate_schema`` gates the schema migrations below. Mutating
        # opens take the default (True): a deployment created before a
        # column existed gains it on first mutating open. Read-only
        # projections MUST pass False: with it the state is opened
        # through a read-only connection and no DDL runs at all, so
        # inspecting a deployment can neither silently rewrite its
        # canonical state nor fail outright on a read-only mount (Codex
        # P1 on PR #357). The read path tolerates a missing signature
        # column (see ``audit``); ``append``/``append_unique``/``_append``
        # fail loudly rather than silently appending unsigned when a
        # signer is configured but the column is absent.
        self.audit_signer = audit_signer
        self.legacy_audit_records = legacy_audit_records
        self._migrate_schema = migrate_schema

        if migrate_schema:
            self._connection = sqlite3.connect(
                path
            )
        else:
            # mode=ro: the open itself must not require write access,
            # or a read-only mount fails before any statement runs.
            # The URI is quoted so deployment paths carrying "?" or "#"
            # cannot change the query string. A missing state file
            # fails to open here (fail closed) instead of being
            # silently created as an empty chain.
            self._connection = sqlite3.connect(
                f"file:{_url_quote(str(path), safe='/')}?mode=ro", uri=True
            )

        self._connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        self._connection.execute(
            "PRAGMA synchronous = FULL"
        )

        if migrate_schema:
            self._connection.executescript(
                """
            CREATE TABLE IF NOT EXISTS permits (
                permit TEXT PRIMARY KEY,
                intent_hash TEXT NOT NULL,
                spent INTEGER NOT NULL DEFAULT 0
                    CHECK (spent IN (0, 1)),
                expires_at_ns INTEGER
            );

            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS directives (
                directive_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                directive_hash TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
                    CHECK (revoked IN (0, 1)),
                PRIMARY KEY (
                    directive_id,
                    version
                )
            );

            CREATE INDEX IF NOT EXISTS idx_directives_hash
                ON directives(directive_hash);

            CREATE TABLE IF NOT EXISTS permit_directives (
                permit TEXT PRIMARY KEY
                    REFERENCES permits(permit)
                    ON DELETE CASCADE,
                directive_id TEXT NOT NULL,
                directive_version INTEGER NOT NULL,
                directive_hash TEXT NOT NULL,
                directive_issued_at_ns INTEGER NOT NULL,
                directive_expires_at_ns INTEGER NOT NULL,
                parent_directive_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS audit (
                sequence INTEGER PRIMARY KEY,
                event TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                hash TEXT NOT NULL,
                delta_json TEXT,
                previous_delta_root TEXT,
                delta_root TEXT,
                signature TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_audit_event
                ON audit(event);

            CREATE TABLE IF NOT EXISTS audit_unique (
                event TEXT NOT NULL,
                identity_field TEXT NOT NULL,
                identity_value_json TEXT NOT NULL,
                sequence INTEGER NOT NULL UNIQUE
                    REFERENCES audit(sequence)
                    ON DELETE CASCADE,
                PRIMARY KEY (
                    event,
                    identity_field,
                    identity_value_json
                )
            );
            """
        )

        if migrate_schema:
            permit_directive_columns = {
                row[1]
                for row
                in self._connection.execute(
                    "PRAGMA table_info(permit_directives)"
                ).fetchall()
            }

            if (
                "parent_directive_hash"
                not in permit_directive_columns
            ):
                self._connection.execute(
                    "ALTER TABLE permit_directives "
                    "ADD COLUMN parent_directive_hash TEXT"
                )

            permit_columns = {
                row[1]
                for row
                in self._connection.execute(
                    "PRAGMA table_info(permits)"
                ).fetchall()
            }

            if (
                "expires_at_ns"
                not in permit_columns
            ):
                self._connection.execute(
                    "ALTER TABLE permits "
                    "ADD COLUMN expires_at_ns INTEGER"
                )

            audit_columns = {
                row[1]
                for row
                in self._connection.execute(
                    "PRAGMA table_info(audit)"
                ).fetchall()
            }

            for column in (
                "delta_json",
                "previous_delta_root",
                "delta_root",
                "signature",
            ):
                if column not in audit_columns:
                    self._connection.execute(
                        f"ALTER TABLE audit "
                        f"ADD COLUMN {column} TEXT"
                    )

            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS "
                "idx_directives_hash "
                "ON directives(directive_hash)"
            )

            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS "
                "idx_audit_event "
                "ON audit(event)"
            )

        # Whether the audit table carries a signature column, read once
        # at open: with migration it is always present; without it, a
        # legacy database reports False and the read/append paths below
        # adapt instead of assuming the column exists.
        audit_columns = {
            row[1]
            for row
            in self._connection.execute(
                "PRAGMA table_info(audit)"
            ).fetchall()
        }

        self._audit_has_signature = "signature" in audit_columns

    @staticmethod
    def _decode_audit_row(
        row: tuple[Any, ...],
    ) -> dict[str, Any]:
        # A legacy database opened without migration has no signature
        # column: the row carries 8 values and the record reads as
        # unsigned rather than failing the projection with "no such
        # column".
        signature = row[8] if len(row) > 8 else None

        (
            event,
            payload_json,
            previous_hash,
            timestamp_ns,
            digest,
            delta_json,
            previous_delta_root,
            delta_root,
        ) = row[:8]

        record = {
            "event": event,
            "payload": json.loads(
                payload_json
            ),
            "previous_hash": previous_hash,
            "timestamp_ns": timestamp_ns,
            "hash": digest,
        }

        if signature is not None:
            record["signature"] = signature

        if delta_json is not None:
            record["delta"] = json.loads(
                delta_json
            )

            record[
                "previous_delta_root"
            ] = previous_delta_root

            record[
                "delta_root"
            ] = delta_root

        return record

    def iter_audit(
        self,
        *,
        event: str | None = None,
        reverse: bool = False,
    ) -> Iterator[dict[str, Any]]:
        # A legacy database opened without migration has no signature
        # column: read the records without it (signature None) rather
        # than failing the projection with "no such column".
        if self._audit_has_signature:
            columns = (
                "event, payload_json, previous_hash, "
                "timestamp_ns, hash, delta_json, "
                "previous_delta_root, delta_root, signature"
            )
        else:
            columns = (
                "event, payload_json, previous_hash, "
                "timestamp_ns, hash, delta_json, "
                "previous_delta_root, delta_root"
            )

        order = (
            "DESC"
            if reverse
            else "ASC"
        )

        if event is None:
            cursor = self._connection.execute(
                f"SELECT {columns} "
                f"FROM audit "
                f"ORDER BY sequence {order}"
            )

        else:
            cursor = self._connection.execute(
                f"SELECT {columns} "
                f"FROM audit "
                f"WHERE event = ? "
                f"ORDER BY sequence {order}",
                (event,),
            )

        for row in cursor:
            yield self._decode_audit_row(
                row
            )

    @property
    def audit(
        self,
    ) -> list[dict[str, Any]]:
        return list(
            self.iter_audit()
        )

    def audit_integrity_token(
        self,
    ) -> object | None:
        # SQLite changes data_version when another
        # connection commits to the database.
        row = self._connection.execute(
            "PRAGMA data_version"
        ).fetchone()

        if row is None:
            raise RuntimeError(
                "SQLite audit data version is unavailable"
            )

        return (
            "sqlite-data-version",
            int(row[0]),
        )

    def approval_replay_reason(
        self,
        approval_id: str,
        nonce: str,
    ) -> str | None:
        return self._approval_replay_reason(
            approval_id,
            nonce,
        )

    def _approval_replay_reason(
        self,
        approval_id: str,
        nonce: str,
    ) -> str | None:
        row = self._connection.execute(
            """
            SELECT CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM approvals
                    WHERE approval_id = ?
                )
                THEN 'approval_id_replayed'

                WHEN EXISTS (
                    SELECT 1
                    FROM approvals
                    WHERE nonce = ?
                )
                THEN 'approval_nonce_replayed'

                ELSE NULL
            END
            """,
            (
                approval_id,
                nonce,
            ),
        ).fetchone()

        return (
            row[0]
            if row is not None
            else None
        )

    def issue_permit(
        self,
        permit: str,
        intent_hash: str,
        decision_reason: str,
        timestamp_ns: int,
        expires_at_ns: int,
        approval: ApprovalUse | None = None,
    ) -> str | None:
        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            if approval is not None:
                replay = (
                    self._approval_replay_reason(
                        approval.approval_id,
                        approval.nonce,
                    )
                )

                if replay:
                    return replay

                self._connection.execute(
                    """
                    INSERT INTO approvals (
                        approval_id,
                        nonce
                    )
                    VALUES (?, ?)
                    """,
                    (
                        approval.approval_id,
                        approval.nonce,
                    ),
                )

            if expires_at_ns <= timestamp_ns:
                raise ValueError(
                    "permit expiry must be after issue time"
                )

            self._connection.execute(
                """
                INSERT INTO permits (
                    permit,
                    intent_hash,
                    expires_at_ns
                )
                VALUES (?, ?, ?)
                """,
                (
                    permit,
                    intent_hash,
                    expires_at_ns,
                ),
            )

            if approval is not None:
                self._append(
                    "approval_verified",
                    approval.audit_payload,
                    timestamp_ns,
                )

            self._append(
                "decision",
                {
                    "outcome": "allow",
                    "reason": decision_reason,
                    "intent_hash": intent_hash,
                    "permit_expires_at_ns": expires_at_ns,
                },
                timestamp_ns,
            )

        return None

    def bind_permit_to_directive(
        self,
        permit: str,
        intent_hash: str,
        binding: DirectivePermitBinding,
        timestamp_ns: int,
    ) -> None:
        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            row = self._connection.execute(
                """
                SELECT
                    intent_hash,
                    spent,
                    expires_at_ns
                FROM permits
                WHERE permit = ?
                """,
                (permit,),
            ).fetchone()

            if (
                row is None
                or row[0] != intent_hash
                or row[1] != 0
                or row[2] is None
                or timestamp_ns >= row[2]
            ):
                raise ValueError(
                    "permit unavailable for directive binding"
                )

            existing = (
                self._connection.execute(
                    """
                    SELECT 1
                    FROM permit_directives
                    WHERE permit = ?
                    """,
                    (permit,),
                ).fetchone()
            )

            if existing:
                raise ValueError(
                    "permit directive binding is immutable"
                )

            directive = (
                self._connection.execute(
                    """
                    SELECT
                        directive_hash,
                        revoked
                    FROM directives
                    WHERE directive_id = ?
                      AND version = ?
                    """,
                    (
                        binding.directive_id,
                        binding.version,
                    ),
                ).fetchone()
            )

            if (
                directive is None
                or directive[0]
                != binding.directive_hash
                or directive[1] != 0
            ):
                raise ValueError(
                    "directive is not active for permit binding"
                )

            if (
                binding.parent_directive_hash
                is not None
                and self.directive_hash_status(
                    binding.parent_directive_hash
                )
                != "active"
            ):
                raise ValueError(
                    "parent directive is not active for permit binding"
                )

            self._connection.execute(
                """
                INSERT INTO permit_directives (
                    permit,
                    directive_id,
                    directive_version,
                    directive_hash,
                    directive_issued_at_ns,
                    directive_expires_at_ns,
                    parent_directive_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    permit,
                    binding.directive_id,
                    binding.version,
                    binding.directive_hash,
                    binding.issued_at_ns,
                    binding.expires_at_ns,
                    binding.parent_directive_hash,
                ),
            )

            self._append(
                "permit_bound_to_directive",
                {
                    "intent_hash": intent_hash,
                    **binding.audit_payload(),
                },
                timestamp_ns,
            )

    def consume_permit(
        self,
        permit: str,
        intent_hash: str,
        timestamp_ns: int,
    ) -> bool:
        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            permit_row = (
                self._connection.execute(
                    """
                    SELECT
                        intent_hash,
                        spent,
                        expires_at_ns
                    FROM permits
                    WHERE permit = ?
                    """,
                    (permit,),
                ).fetchone()
            )

            expires_at_ns = (
                permit_row[2]
                if permit_row is not None
                else None
            )

            valid = (
                permit_row is not None
                and permit_row[0] == intent_hash
                and permit_row[1] == 0
                and expires_at_ns is not None
                and timestamp_ns < expires_at_ns
            )

            payload: dict[str, Any] = {
                "intent_hash": intent_hash,
                "permit_expires_at_ns": expires_at_ns,
            }

            row = self._connection.execute(
                """
                SELECT
                    directive_id,
                    directive_version,
                    directive_hash,
                    directive_issued_at_ns,
                    directive_expires_at_ns,
                    parent_directive_hash
                FROM permit_directives
                WHERE permit = ?
                """,
                (permit,),
            ).fetchone()

            if row is not None:
                binding = DirectivePermitBinding(
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                )

                directive = (
                    self._connection.execute(
                        """
                        SELECT
                            directive_hash,
                            revoked
                        FROM directives
                        WHERE directive_id = ?
                          AND version = ?
                        """,
                        (
                            binding.directive_id,
                            binding.version,
                        ),
                    ).fetchone()
                )

                if directive is None:
                    status = (
                        "directive_not_authorized"
                    )

                elif (
                    directive[0]
                    != binding.directive_hash
                ):
                    status = (
                        "directive_version_mismatch"
                    )

                elif directive[1] != 0:
                    status = "directive_revoked"

                elif (
                    binding.parent_directive_hash
                    is not None
                ):
                    status = (
                        self.directive_hash_status(
                            binding.parent_directive_hash
                        )
                    )

                else:
                    status = "active"

                if (
                    status == "active"
                    and not (
                        binding.issued_at_ns
                        <= timestamp_ns
                        < binding.expires_at_ns
                    )
                ):
                    status = "directive_inactive"

                valid = (
                    valid
                    and status == "active"
                )

                payload.update(
                    binding.audit_payload()
                )

                payload[
                    "directive_status"
                ] = status

            if valid:
                cursor = (
                    self._connection.execute(
                        """
                        UPDATE permits
                        SET spent = 1
                        WHERE permit = ?
                          AND intent_hash = ?
                          AND spent = 0
                        """,
                        (
                            permit,
                            intent_hash,
                        ),
                    )
                )

                valid = (
                    cursor.rowcount == 1
                )

            self._append(
                (
                    "permit_consumed"
                    if valid
                    else "permit_rejected"
                ),
                payload,
                timestamp_ns,
            )

        return valid

    def activate_directive(
        self,
        directive,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        # Item 3A: same evidence gate as the in-memory backend, before
        # the transaction opens — a refused activation writes nothing.
        evidence = _require_verified_evidence(
            authority_evidence,
            operation="activate_directive",
            directive_id=directive.directive_id,
            version=directive.version,
            directive_hash=directive.directive_hash,
            parent_directive_hash=getattr(
                directive,
                "parent_directive_hash",
                None,
            ),
            check_parent=True,
        )

        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            existing = (
                self._connection.execute(
                    """
                    SELECT 1
                    FROM directives
                    WHERE directive_id = ?
                      AND version = ?
                    """,
                    (
                        directive.directive_id,
                        directive.version,
                    ),
                ).fetchone()
            )

            if existing:
                raise ValueError(
                    "directive version is immutable"
                )

            parent_hash = getattr(
                directive,
                "parent_directive_hash",
                None,
            )

            if parent_hash is not None:
                parent = (
                    self._connection.execute(
                        """
                        SELECT revoked
                        FROM directives
                        WHERE directive_hash = ?
                        """,
                        (parent_hash,),
                    ).fetchone()
                )

                if (
                    parent is None
                    or parent[0] != 0
                ):
                    raise ValueError(
                        "parent directive is not active for activation"
                    )

            self._connection.execute(
                """
                INSERT INTO directives (
                    directive_id,
                    version,
                    directive_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    directive.directive_id,
                    directive.version,
                    directive.directive_hash,
                ),
            )

            self._append(
                "directive_activated",
                {
                    "directive_id": directive.directive_id,
                    "version": directive.version,
                    "directive_hash": directive.directive_hash,
                    "authority_evidence": evidence.audit_payload(),
                },
                timestamp_ns,
            )

    def revoke_directive(
        self,
        directive_id: str,
        version: int,
        authority_evidence: VerifiedAuthorityEvidence,
        timestamp_ns: int,
    ) -> None:
        # Item 3A: the type gate runs before the transaction opens.
        if type(authority_evidence) is not VerifiedAuthorityEvidence:
            raise TypeError("authority_evidence must be VerifiedAuthorityEvidence")

        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            row = self._connection.execute(
                """
                SELECT directive_hash
                FROM directives
                WHERE directive_id = ?
                  AND version = ?
                """,
                (
                    directive_id,
                    version,
                ),
            ).fetchone()

            if row is None:
                raise ValueError(
                    "directive version not found"
                )

            # Binding cross-check against the stored hash, before the
            # mutation (mirrors the in-memory backend).
            evidence = _require_verified_evidence(
                authority_evidence,
                operation="revoke_directive",
                directive_id=directive_id,
                version=version,
                directive_hash=row[0],
            )

            self._connection.execute(
                """
                UPDATE directives
                SET revoked = 1
                WHERE directive_id = ?
                  AND version = ?
                """,
                (
                    directive_id,
                    version,
                ),
            )

            self._append(
                "directive_revoked",
                {
                    "directive_id": directive_id,
                    "version": version,
                    "directive_hash": row[0],
                    "authority_evidence": evidence.audit_payload(),
                },
                timestamp_ns,
            )

    def directive_status(
        self,
        directive_id: str,
        version: int,
        directive_hash: str,
    ) -> str:
        row = self._connection.execute(
            """
            SELECT
                directive_hash,
                revoked
            FROM directives
            WHERE directive_id = ?
              AND version = ?
            """,
            (
                directive_id,
                version,
            ),
        ).fetchone()

        if row is None:
            return "directive_not_authorized"

        if row[0] != directive_hash:
            return "directive_version_mismatch"

        return (
            "directive_revoked"
            if row[1]
            else "active"
        )

    def directive_hash_status(
        self,
        directive_hash: str,
    ) -> str:
        row = self._connection.execute(
            """
            SELECT revoked
            FROM directives
            WHERE directive_hash = ?
            """,
            (directive_hash,),
        ).fetchone()

        if row is None:
            return (
                "directive_parent_not_authorized"
            )

        return (
            "directive_parent_revoked"
            if row[0]
            else "active"
        )

    def append(
        self,
        event: str,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> None:
        # A signer configured over a database without a signature column
        # (a read-only open over a legacy database) must never silently
        # append unsigned: fail loudly before the write is attempted.
        # See _append for the same guard on the direct path.
        if self.audit_signer is not None and not self._audit_has_signature:
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")

        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            self._append(
                event,
                payload,
                timestamp_ns,
            )

    def append_many(
        self,
        entries: list[
            tuple[
                str,
                dict[str, Any],
                int,
            ]
        ],
    ) -> None:
        if any(
            not event
            or not isinstance(
                payload,
                dict,
            )
            for event, payload, _ in entries
        ):
            raise ValueError(
                "audit batch entry invalid"
            )

        if not entries:
            return

        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            for (
                event,
                payload,
                timestamp_ns,
            ) in entries:
                self._append(
                    event,
                    payload,
                    timestamp_ns,
                )

    def append_unique(
        self,
        event: str,
        identity_field: str,
        identity_value: Any,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> dict[str, Any] | None:
        if (
            not event
            or not identity_field
            or payload.get(
                identity_field
            )
            != identity_value
        ):
            raise ValueError(
                "unique audit identity invalid"
            )

        # Same loud failure as append(): a signer over a database
        # without a signature column never appends unsigned.
        if self.audit_signer is not None and not self._audit_has_signature:
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")

        identity_json = _canonical(
            identity_value
        ).decode()

        with self._connection:
            self._connection.execute(
                "BEGIN IMMEDIATE"
            )

            indexed = (
                self._connection.execute(
                    """
                    SELECT a.payload_json
                    FROM audit_unique u
                    JOIN audit a
                      ON a.sequence = u.sequence
                    WHERE u.event = ?
                      AND u.identity_field = ?
                      AND u.identity_value_json = ?
                    """,
                    (
                        event,
                        identity_field,
                        identity_json,
                    ),
                ).fetchone()
            )

            if indexed is not None:
                return json.loads(
                    str(indexed[0])
                )

            rows = self._connection.execute(
                """
                SELECT
                    sequence,
                    payload_json
                FROM audit
                WHERE event = ?
                ORDER BY sequence
                """,
                (event,),
            ).fetchall()

            matches: list[
                tuple[
                    int,
                    dict[str, Any],
                ]
            ] = []

            for (
                sequence,
                encoded,
            ) in rows:
                candidate = json.loads(
                    str(encoded)
                )

                if (
                    isinstance(
                        candidate,
                        dict,
                    )
                    and candidate.get(
                        identity_field
                    )
                    == identity_value
                ):
                    matches.append(
                        (
                            sequence,
                            candidate,
                        )
                    )

            if len(matches) > 1:
                raise ValueError(
                    "unique audit identity ambiguous"
                )

            if matches:
                (
                    sequence,
                    candidate,
                ) = matches[0]

                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO audit_unique (
                        event,
                        identity_field,
                        identity_value_json,
                        sequence
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        event,
                        identity_field,
                        identity_json,
                        sequence,
                    ),
                )

                return candidate

            sequence = self._append(
                event,
                payload,
                timestamp_ns,
            )

            self._connection.execute(
                """
                INSERT INTO audit_unique (
                    event,
                    identity_field,
                    identity_value_json,
                    sequence
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    event,
                    identity_field,
                    identity_json,
                    sequence,
                ),
            )

            return None

    def _append(
        self,
        event: str,
        payload: dict[str, Any],
        timestamp_ns: int,
    ) -> int:
        row = self._connection.execute(
            """
            SELECT
                hash,
                delta_root
            FROM audit
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()

        previous = (
            row[0]
            if row
            else "0" * 64
        )

        previous_root = (
            (
                row[1]
                or row[0]
            )
            if row
            else "0" * 64
        )

        record = _attach_signature(
            _attach_delta(
                _audit_record(
                    previous,
                    event,
                    payload,
                    timestamp_ns,
                ),
                previous_root,
            ),
            self.audit_signer,
        )

        if not self._audit_has_signature and self.audit_signer is not None:
            # Opened without migration over a legacy database: a signer
            # configured here must never silently append unsigned — the
            # record would be refused at the next boot, bricking the
            # deployment (Codex P1 on PR #357). Fail loudly instead; the
            # caller re-opens with migration to add the column first.
            # (The same guard sits in append()/append_unique() so the
            # precise error fires before the connection's own write
            # refusal; this one covers direct _append callers.)
            raise RuntimeError("audit signing is configured but the state database has no signature column; open the state with schema migration enabled")

        cursor = self._connection.execute(
            """
            INSERT INTO audit (
                event,
                payload_json,
                previous_hash,
                timestamp_ns,
                hash,
                delta_json,
                previous_delta_root,
                delta_root,
                signature
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["event"],
                _canonical(
                    record["payload"]
                ).decode(),
                record["previous_hash"],
                record["timestamp_ns"],
                record["hash"],
                _canonical(
                    record["delta"]
                ).decode(),
                record[
                    "previous_delta_root"
                ],
                record["delta_root"],
                record.get("signature"),
            ),
        )

        return int(
            cursor.lastrowid
        )

    def close(self) -> None:
        self._connection.close()
