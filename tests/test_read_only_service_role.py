"""Control Center design §5.2 — the read-only service role.

The read-only role is a separate credential, not a client-side
convention: a request that authenticates under the read-only secret
(and only that secret) may call exactly ``READ_ONLY_VERBS`` — the
reads the §5.1 observer snapshot needs, plus ``health``. Every other
verb is refused server-side before it runs, with the refusal counted
in process-local diagnostics, never appended to the canonical audit
(a read-only credential must not be able to buy a write into
canonical state by being refused).

The server is the single enforcement point. The read-only client
inherits the mutating methods, and every one of them fails closed
server-side; these tests pin that through the client a confused
caller would actually use, and through raw request frames.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from hashlib import sha256
import tempfile
import threading
import time
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive, DirectiveAuthorityController
from pulpo.kernel import GovernanceKernel as KernelClass
from pulpo.service import (
    READ_ONLY_VERBS,
    REQUEST_SCHEMA,
    KernelService,
    KernelServiceClient,
    ReadOnlyKernelServiceClient,
    ServiceRefusal,
    UnixSocketTransport,
    _READ_ONLY_REQUEST_MAC_DOMAIN,
    _READ_ONLY_RESPONSE_MAC_DOMAIN,
    _REQUEST_MAC_DOMAIN,
    loopback_transport,
    serve_unix_socket,
)
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"
SERVICE_SECRET = "service-secret-test-only".encode("utf-8")
READ_ONLY_SECRET = "read-only-secret-test-only".encode("utf-8")
KERNEL_SECRET = "kernel-secret".encode("utf-8")

# Verbs outside the read-only allow-list. The first twelve mutate;
# `audit` is the unbounded read (§5.6 is a separate build item) and
# `get_locked_target` is a read the snapshot does not need — both
# are refused for the read-only role exactly like the mutating verbs.
FORBIDDEN_VERBS = (
    "evaluate",
    "evaluate_with_approval",
    "consume",
    "lock_target",
    "resolve_locked_target",
    "evaluate_locked_target",
    "projection_evaluate",
    "activate_directive",
    "revoke_directive",
    "bind_permit_to_directive",
    "record_target_completion",
    "record_domain_outcome_memory",
    "audit",
    "get_locked_target",
)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


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


class ReadOnlyFixture:
    """A service with both secrets, plus a full and a read-only client."""

    def __init__(self, *, read_only_secret=READ_ONLY_SECRET):
        self.clock_cell = [NOW]
        self.clock = lambda: self.clock_cell[0]
        self.verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            policy,
            KERNEL_SECRET,
            approval_verifier=self.verifier,
            clock=self.clock,
            state=InMemoryKernelState(),
        )
        kwargs: dict = {"clock": self.clock, "max_request_ttl_ns": 500_000}
        if read_only_secret is not None:
            kwargs["read_only_secret"] = read_only_secret
        self.service = KernelService(self.kernel, SERVICE_SECRET, **kwargs)
        self.client = KernelServiceClient(
            loopback_transport(self.service),
            SERVICE_SECRET,
            clock=self.clock,
            request_ttl_ns=400_000,
        )
        self.read_only = ReadOnlyKernelServiceClient(
            loopback_transport(self.service),
            READ_ONLY_SECRET,
            clock=self.clock,
            request_ttl_ns=400_000,
        )
        self.controller = DirectiveAuthorityController(self.kernel)

    def envelope_for(self, operation, d, approval_id):
        intent = self.controller.authority_intent(operation, d, operator_principal=OPERATOR)
        return signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=self.clock_cell[0] - 10,
            approval_id=approval_id,
            nonce=f"{approval_id}-nonce",
        )

    def audit(self):
        return list(self.kernel.audit)

    def raw_request(self, verb, args, *, secret=READ_ONLY_SECRET, domain=_READ_ONLY_REQUEST_MAC_DOMAIN,
                    nonce="ro-raw-1", issued=NOW, ttl=400_000):
        """One request frame MAC'd under the given secret and domain."""
        body = {
            "schema": REQUEST_SCHEMA,
            "verb": verb,
            "nonce": nonce,
            "issued_at_ns": issued,
            "expires_at_ns": issued + ttl,
            "args": args,
        }
        body["mac"] = hmac.new(secret, domain + _canonical(body), sha256).hexdigest()
        return json.loads(self.service.handle(_canonical(body)).decode("utf-8"))

    def raw_refusal(self, verb, args, **kwargs):
        response = self.raw_request(verb, args, **kwargs)
        assert not response["ok"], response
        return response["error"]


class ReadOnlyRoleTests(unittest.TestCase):
    def test_read_only_verb_set_is_exactly_the_snapshot_reads(self):
        self.assertEqual(
            READ_ONLY_VERBS,
            frozenset(
                {
                    "health",
                    "verify_audit",
                    "verify_audit_report",
                    "state_source_id",
                    "policy_hash",
                    "directive_status",
                    "directive_hash_status",
                }
            ),
        )

    def test_read_only_client_reads_and_health_succeed(self):
        fx = ReadOnlyFixture()
        d = directive()
        activation = fx.client.activate_directive(
            d, fx.envelope_for("activate_directive", d, "act-1"), operator_principal=OPERATOR
        )
        self.assertEqual(activation.outcome, "allow")
        self.assertTrue(fx.read_only.verify_audit())
        report = fx.read_only.verify_audit_report()
        self.assertTrue(report["ok"])
        self.assertEqual(report["total_records"], len(fx.audit()))
        self.assertEqual(fx.read_only.state_source_id(), fx.client.state_source_id())
        self.assertEqual(fx.read_only.policy_hash(), fx.client.policy_hash())
        self.assertEqual(
            fx.read_only.directive_status(d.directive_id, d.version, d.directive_hash),
            "active",
        )
        self.assertEqual(
            fx.read_only.directive_hash_status(d.directive_hash), "active"
        )
        health = fx.read_only.health()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["state_source_id"], fx.client.state_source_id())
        self.assertEqual(health["now_ns"], NOW)
        self.assertEqual(health["read_only_refusals"], {})
        self.assertIsNone(health["last_read_only_refusal_ns"])

    def test_full_secret_still_works_including_health(self):
        fx = ReadOnlyFixture()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        decision = fx.client.evaluate(intent)
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.permit)
        self.assertTrue(fx.client.consume(decision.permit, intent))
        self.assertTrue(fx.client.verify_audit())
        self.assertEqual(fx.client.health()["status"], "ok")
        self.assertEqual(fx.client.health()["state_source_id"], fx.client.state_source_id())

    def test_every_mutating_verb_refused_for_read_only_credential(self):
        fx = ReadOnlyFixture()
        before = fx.audit()
        for index, verb in enumerate(FORBIDDEN_VERBS):
            error = fx.raw_refusal(verb, {}, nonce=f"ro-sweep-{index}")
            self.assertEqual(error, "read_only_role_forbidden", verb)
        # Refusals are not state changes: the canonical audit is
        # byte-identical after fourteen refused mutating verbs.
        self.assertEqual(fx.audit(), before)

    def test_refusal_is_evidenced_not_silent(self):
        fx = ReadOnlyFixture()
        before = fx.audit()
        # The refusal response itself is server-MAC'd evidence the
        # caller retains: verify the frame MAC under the read-only
        # secret and the read-only response domain.
        body = {
            "schema": REQUEST_SCHEMA,
            "verb": "consume",
            "nonce": "ro-evidence-1",
            "issued_at_ns": NOW,
            "expires_at_ns": NOW + 400_000,
            "args": {},
        }
        body["mac"] = hmac.new(
            READ_ONLY_SECRET, _READ_ONLY_REQUEST_MAC_DOMAIN + _canonical(body), sha256
        ).hexdigest()
        raw = fx.service.handle(_canonical(body))
        response = json.loads(raw.decode("utf-8"))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "read_only_role_forbidden")
        response_body = {key: value for key, value in response.items() if key != "mac"}
        expected_mac = hmac.new(
            READ_ONLY_SECRET, _READ_ONLY_RESPONSE_MAC_DOMAIN + _canonical(response_body), sha256
        ).hexdigest()
        self.assertTrue(hmac.compare_digest(response["mac"], expected_mac))
        # And the service counts the refusal where the operator can
        # see it, through health — without touching canonical state.
        health = fx.read_only.health()
        self.assertEqual(health["read_only_refusals"], {"consume": 1})
        self.assertEqual(health["last_read_only_refusal_ns"], NOW)
        self.assertEqual(fx.audit(), before)

    def test_repeated_refusals_cannot_bloat_the_audit(self):
        fx = ReadOnlyFixture()
        before = fx.audit()
        for index in range(5):
            error = fx.raw_refusal("consume", {}, nonce=f"ro-spam-{index}")
            self.assertEqual(error, "read_only_role_forbidden")
        self.assertEqual(fx.audit(), before)
        self.assertEqual(fx.read_only.health()["read_only_refusals"], {"consume": 5})

    def test_read_only_credential_cannot_mint_or_spend(self):
        fx = ReadOnlyFixture()
        intent = Intent("agent:builder", "write", "repo:core", 3, "s1")
        with self.assertRaises(ServiceRefusal) as caught:
            fx.read_only.evaluate(intent)
        self.assertEqual(str(caught.exception), "read_only_role_forbidden")
        with self.assertRaises(ServiceRefusal) as caught:
            fx.read_only.consume("permit-x", intent)
        self.assertEqual(str(caught.exception), "read_only_role_forbidden")
        # The same permit flow works for the full secret — and the
        # read-only credential cannot spend the permit it mints.
        decision = fx.client.evaluate(intent)
        self.assertEqual(decision.outcome, "allow")
        with self.assertRaises(ServiceRefusal) as caught:
            fx.read_only.consume(decision.permit, intent)
        self.assertEqual(str(caught.exception), "read_only_role_forbidden")
        self.assertTrue(fx.client.consume(decision.permit, intent))

    def test_read_only_client_audit_and_locked_target_refused(self):
        # `audit` is unbounded and `get_locked_target` is not a
        # snapshot read: both are refused even though both are reads.
        fx = ReadOnlyFixture()
        with self.assertRaises(ServiceRefusal) as caught:
            fx.read_only.audit()
        self.assertEqual(str(caught.exception), "read_only_role_forbidden")
        with self.assertRaises(ServiceRefusal) as caught:
            fx.read_only.get_locked_target("deploy-1", version=1)
        self.assertEqual(str(caught.exception), "read_only_role_forbidden")

    def test_tampered_replayed_and_expired_read_only_requests_refused(self):
        fx = ReadOnlyFixture()
        before = fx.audit()
        # Wrong read-only secret.
        error = fx.raw_refusal(
            "verify_audit", {}, secret="the-wrong-secret".encode("utf-8"), nonce="ro-wrong-1"
        )
        self.assertEqual(error, "request_mac_invalid")
        # Tampered args: the MAC no longer matches the body.
        body = {
            "schema": REQUEST_SCHEMA,
            "verb": "verify_audit",
            "nonce": "ro-tamper-1",
            "issued_at_ns": NOW,
            "expires_at_ns": NOW + 400_000,
            "args": {},
        }
        body["mac"] = hmac.new(
            READ_ONLY_SECRET, _READ_ONLY_REQUEST_MAC_DOMAIN + _canonical(body), sha256
        ).hexdigest()
        body["args"] = {"forged": True}
        response = json.loads(fx.service.handle(_canonical(body)).decode("utf-8"))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "request_mac_invalid")
        # Cross-domain confusion: read-only secret under the full
        # domain, and full secret under the read-only domain — each
        # verifies as neither role.
        error = fx.raw_refusal(
            "verify_audit", {}, secret=READ_ONLY_SECRET, domain=_REQUEST_MAC_DOMAIN,
            nonce="ro-cross-1",
        )
        self.assertEqual(error, "request_mac_invalid")
        error = fx.raw_refusal(
            "verify_audit", {}, secret=SERVICE_SECRET, domain=_READ_ONLY_REQUEST_MAC_DOMAIN,
            nonce="ro-cross-2",
        )
        self.assertEqual(error, "request_mac_invalid")
        # Replayed read-only request: the first succeeds, the replay
        # is refused, and the audit does not move.
        first = fx.raw_request("verify_audit", {}, nonce="ro-replay-1")
        self.assertTrue(first["ok"])
        error = fx.raw_refusal("verify_audit", {}, nonce="ro-replay-1")
        self.assertEqual(error, "request_replayed")
        # Expired read-only request.
        error = fx.raw_refusal(
            "verify_audit", {}, nonce="ro-expired-1", issued=NOW - 600_000, ttl=400_000
        )
        self.assertEqual(error, "request_expired")
        self.assertEqual(fx.audit(), before)

    def test_read_only_reads_are_non_mutating(self):
        fx = ReadOnlyFixture()
        d = directive()
        fx.client.activate_directive(
            d, fx.envelope_for("activate_directive", d, "act-1"), operator_principal=OPERATOR
        )
        before = fx.audit()
        self.assertTrue(fx.read_only.verify_audit())
        # Repeated, malformed, and refused read-only calls leave the
        # canonical audit byte-identical — the read-only surface is
        # non-mutating under every call shape the boundary accepts.
        for _ in range(3):
            self.assertTrue(fx.read_only.verify_audit())
            self.assertEqual(fx.read_only.health()["status"], "ok")
            self.assertEqual(
                fx.read_only.directive_status(d.directive_id, d.version, d.directive_hash),
                "active",
            )
        for index, verb in enumerate(FORBIDDEN_VERBS):
            fx.raw_refusal(verb, {}, nonce=f"ro-nonmut-{index}")
        self.assertEqual(fx.audit(), before)
        self.assertTrue(fx.read_only.verify_audit())

    def test_service_without_read_only_secret_has_no_read_only_role(self):
        fx = ReadOnlyFixture(read_only_secret=None)
        error = fx.raw_refusal("verify_audit", {}, nonce="ro-absent-1")
        self.assertEqual(error, "request_mac_invalid")
        self.assertTrue(fx.client.verify_audit())
        self.assertEqual(fx.client.health()["status"], "ok")

    def test_read_only_secret_must_differ_and_be_non_empty(self):
        fx = ReadOnlyFixture()
        with self.assertRaises(ValueError):
            KernelService(fx.kernel, SERVICE_SECRET, read_only_secret=SERVICE_SECRET)
        with self.assertRaises(ValueError):
            KernelService(fx.kernel, SERVICE_SECRET, read_only_secret="".encode("utf-8"))

    def test_health_distinguishes_down_from_stale(self):
        fx = ReadOnlyFixture()
        self.assertEqual(fx.read_only.health()["status"], "ok")

        def dead_transport(raw):
            raise ConnectionRefusedError("kernel down")

        dead = ReadOnlyKernelServiceClient(
            dead_transport, READ_ONLY_SECRET, clock=fx.clock, request_ttl_ns=400_000
        )
        # A dead kernel raises the transport failure — it is never
        # papered over with a fabricated healthy value.
        with self.assertRaises(ConnectionRefusedError):
            dead.health()

    def test_read_only_role_over_unix_socket(self):
        fx = ReadOnlyFixture()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "service.sock")
            thread = threading.Thread(
                target=serve_unix_socket, args=(fx.service, path), daemon=True
            )
            thread.start()
            for _ in range(200):
                if os.path.exists(path):
                    break
                time.sleep(0.01)
            ro = ReadOnlyKernelServiceClient(
                UnixSocketTransport(path),
                READ_ONLY_SECRET,
                clock=fx.clock,
                request_ttl_ns=400_000,
            )
            self.assertEqual(ro.health()["status"], "ok")
            self.assertTrue(ro.verify_audit())
            with self.assertRaises(ServiceRefusal) as caught:
                ro.consume("permit-x", Intent("agent:builder", "write", "repo:core", 3, "s1"))
            self.assertEqual(str(caught.exception), "read_only_role_forbidden")


if __name__ == "__main__":
    unittest.main()
