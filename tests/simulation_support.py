"""Test-only composition of canonical governance and a disposable motion sink.

Never expose this fixture, its synthetic signer, or its sink to a robot.
There is no runtime router, executor, authority service, or evidence ledger here.
"""
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
import math
import time

from domains.safety import (CommandFreshness, GeoFence, ResourceAvailability,
                            ResourceBudget, SensorHealth, SharedSafetyGate,
                            DegradedMode)
from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


@dataclass(frozen=True)
class Motion:
    speed: float = 0.2
    seconds: float = 0.5

    def __post_init__(self):
        if (not all(math.isfinite(v) for v in (self.speed, self.seconds))
                or not 0 < self.speed <= 0.2 or not 0 < self.seconds <= 0.5):
            raise ValueError("simulation_motion_out_of_bounds")

    @property
    def resource(self):
        # Exact parameters and endpoint are bound by the existing intent hash.
        return f"sim:disposable:cmd_vel:{self.speed.hex()}:{self.seconds.hex()}"


class DeterministicWorld:
    """Kinematic test double, not Gazebo or a safety controller."""
    def __init__(self):
        self.x = 0.0
        self.local_stop = False

    def observe(self):
        return self.x

    def send(self, motion):
        if not self.local_stop:
            self.x += motion.speed * motion.seconds

    def settle(self):
        pass


def reconcile(before, after, consumed, *, minimum=0.01, tolerance=0.005):
    """Observation is evidence, never permission or an automatic retry trigger."""
    if before is None or after is None or not all(math.isfinite(x) for x in (before, after)):
        return "unknown"
    distance = abs(after - before)
    if not consumed:
        return "unexpected_effect" if distance > tolerance else "no_observed_effect"
    return "observed_motion" if distance >= minimum else "no_observed_motion"


class SimulationFixture:
    def __init__(self, world, state=None):
        self.world = world
        self.now = 2_000_000
        verifier = HmacTestVerifier()
        self.kernel = GovernanceKernel(
            Policy(frozenset({"move", "activate_directive", "revoke_directive"}), 0,
                   frozenset({"activate_directive", "revoke_directive"}),
                   permit_ttl_ns=100, authority_trust=trust_for(verifier)),
            secret=b"disposable-simulation-only", approval_verifier=verifier,
            clock=lambda: self.now, state=state)
        self.verifier = verifier
        self.directive = Directive("sim-motion", 1, verifier.authority_id, "agent:sim",
                                   frozenset({"move"}), ("sim:disposable:",), 0,
                                   self.now - 100, self.now + 10_000)
        self.controller = DirectiveAuthorityController(self.kernel)
        self.projection = GovernedDirectiveProjection(self.kernel)
        self.change_directive(self.controller.ACTIVATE)
        self.gate = SharedSafetyGate(GeoFence(-1, 1, -1, 1), ResourceBudget(battery_minimum=20))
        self.sequence = 0

    def change_directive(self, operation):
        intent = self.controller.authority_intent(operation, self.directive,
                                                 operator_principal="operator:fixture")
        envelope = signed_envelope(self.kernel, intent, self.verifier, now_ns=self.now - 1,
                                   approval_id=operation, nonce=operation)
        method = self.controller.activate if operation == self.controller.ACTIVATE else self.controller.revoke
        decision = method(self.directive, envelope, operator_principal="operator:fixture")
        if decision.outcome != "allow":
            raise AssertionError(decision.reason)

    def intent(self, motion):
        return Intent("agent:sim", "move", motion.resource, 0, "simulation-only")

    def attempt(self, motion, intent, permit, *, human=False, stale_sensor=False,
                outside_geofence=False, low_resource=False):
        """A test driver, deliberately outside the installed runtime API."""
        if intent != self.intent(motion):
            return False, "motion_binding_mismatch"
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.sequence += 1
        try:
            self.gate.admit(
                CommandFreshness(str(self.sequence), now, now + timedelta(seconds=1),
                                 self.sequence, "sim:disposable"), now=now,
                latitude=2 if outside_geofence else 0, longitude=0, altitude=None,
                sensor=SensorHealth(now - timedelta(seconds=2 if stale_sensor else 0), 1, True, 1),
                available=ResourceAvailability(10 if low_resource else 100, 100, 100, 100, 100),
                human_present=human)
        except PermissionError as exc:
            return False, str(exc)
        if not self.kernel.consume(permit or "", intent):
            return False, "canonical_permit_rejected"
        # A failed/ambiguous send is never retried; the permit remains spent.
        self.world.send(motion)
        return True, "canonical_permit_consumed"


SCENARIOS = ("permitted", "denied", "replay", "expiry", "revocation", "substitution",
             "human_presence", "stale_sensor", "geofence", "resource_budget",
             "degraded_mode", "emergency_stop", "local_interlock",
             "raw_cmd_vel_bypass", "remapped_cmd_vel_bypass")


def run_case(name, world):
    if name not in SCENARIOS:
        raise ValueError("unknown_scenario")
    fixture = SimulationFixture(world)
    motion = Motion()
    intent = fixture.intent(motion)
    if name == "denied":
        intent = replace(intent, action="unapproved_move")
    decision = fixture.projection.evaluate(intent, fixture.directive)
    permit = decision.permit
    if name == "replay":
        if not fixture.attempt(motion, intent, permit)[0]:
            raise AssertionError("replay_setup_did_not_execute")
        world.settle()
    elif name == "expiry":
        fixture.now += 100  # Exact expiry, not just beyond it.
    elif name == "revocation":
        fixture.change_directive(fixture.controller.REVOKE)
    elif name == "substitution":
        motion = Motion(0.1)
    elif name == "emergency_stop":
        fixture.gate.state.enter(DegradedMode.EMERGENCY_STOP)
    elif name == "degraded_mode":
        fixture.gate.state.enter(DegradedMode.SAFE)
    elif name == "local_interlock":
        world.local_stop = True
    before = world.observe()
    start = time.perf_counter_ns()
    if name.endswith("bypass"):
        # Positive attack control: same actuator through a raw/remapped publisher.
        # This MUST be reported as a hole, never as governance containment.
        world.send(motion)
        consumed, reason = False, "direct_actuator_path"
    elif decision.outcome != "allow":
        consumed, reason = False, decision.reason
    else:
        consumed, reason = fixture.attempt(motion, intent, permit,
                                           human=name == "human_presence",
                                           stale_sensor=name == "stale_sensor",
                                           outside_geofence=name == "geofence",
                                           low_resource=name == "resource_budget")
    elapsed = time.perf_counter_ns() - start
    world.settle()
    after = world.observe()
    outcome = reconcile(before, after, consumed)
    expected = ("unexpected_effect" if name.endswith("bypass") else
                "no_observed_motion" if name == "local_interlock" else
                "observed_motion" if name == "permitted" else "no_observed_effect")
    audit = fixture.kernel.audit
    audit_valid = fixture.kernel.verify_audit()
    return {"scenario": name, "classification": "Unknown" if outcome == "unknown" else "Verified",
            "passed": outcome == expected and audit_valid,
            "decision": decision.outcome, "reason": reason, "permit_consumed": consumed,
            "before_x": before, "after_x": after, "reconciliation": outcome,
            "expected": expected, "attempt_ns": elapsed, "audit_valid": audit_valid,
            "policy_hash": fixture.kernel.policy_hash, "intent_hash": fixture.kernel.intent_hash(intent),
            "audit": audit, "authority_effect": "none",
            "containment_proven": False if name.endswith("bypass") else None}
