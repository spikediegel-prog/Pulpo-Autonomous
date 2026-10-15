import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from domains.safety import DegradedMode
from pulpo.state import SQLiteKernelState

from tests.simulation_support import (DeterministicWorld, Motion, SCENARIOS,
                                      SimulationFixture, reconcile, run_case)


class SimulationTesterTests(unittest.TestCase):
    def test_scenario_matrix(self):
        for name in SCENARIOS:
            with self.subTest(name=name):
                result = run_case(name, DeterministicWorld())
                self.assertTrue(result["passed"], result)
                if name.endswith("bypass"):
                    self.assertFalse(result["containment_proven"])

    def test_unknown_is_not_success(self):
        for before, after in ((None, 1), (0, None), (0, float("nan")), (float("inf"), 1)):
            self.assertEqual("unknown", reconcile(before, after, True))
        self.assertEqual("no_observed_motion", reconcile(0, 0, True))
        self.assertEqual("unexpected_effect", reconcile(0, 1, False))
        class MissingWorld(DeterministicWorld):
            def observe(self):
                return None
        result = run_case("permitted", MissingWorld())
        self.assertFalse(result["passed"])
        self.assertEqual("Unknown", result["classification"])

    def test_bounds(self):
        for speed, seconds in ((float("nan"), .1), (.3, .1), (.1, 1), (0, .1)):
            with self.assertRaises(ValueError):
                Motion(speed, seconds)

    def test_send_failure_spends_permit_without_retry(self):
        class FailedWorld(DeterministicWorld):
            calls = 0

            def send(self, motion):
                self.calls += 1
                raise TimeoutError("ambiguous_transport")

        world = FailedWorld()
        fixture = SimulationFixture(world)
        motion = Motion()
        intent = fixture.intent(motion)
        permit = fixture.projection.evaluate(intent, fixture.directive).permit
        with self.assertRaises(TimeoutError):
            fixture.attempt(motion, intent, permit)
        self.assertFalse(fixture.attempt(motion, intent, permit)[0])
        self.assertEqual(1, world.calls)

    def test_evidence_tampering_detected(self):
        fixture = SimulationFixture(DeterministicWorld())
        fixture.kernel.audit[0]["payload"]["reason"] = "tampered"
        self.assertFalse(fixture.kernel.verify_audit())

    def test_sqlite_canonical_consumption_is_one_use_after_reopen(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.sqlite3"
            state = SQLiteKernelState(path)
            fixture = SimulationFixture(DeterministicWorld(), state)
            intent = fixture.intent(Motion())
            permit = fixture.projection.evaluate(intent, fixture.directive).permit
            self.assertTrue(fixture.attempt(Motion(), intent, permit)[0])
            state.close()
            state = SQLiteKernelState(path)
            try:
                # No new fixture activation: reopen exactly the canonical state.
                from pulpo import GovernanceKernel
                kernel = GovernanceKernel(fixture.kernel.policy, state=state,
                                          clock=lambda: fixture.now,
                                          secret=b"disposable-simulation-only")
                self.assertFalse(kernel.consume(permit, intent))
                self.assertTrue(kernel.verify_audit())
            finally:
                state.close()

    def test_permit_does_not_reset_emergency_stop(self):
        fixture = SimulationFixture(DeterministicWorld())
        motion = Motion()
        intent = fixture.intent(motion)
        permit = fixture.projection.evaluate(intent, fixture.directive).permit
        fixture.gate.state.enter(DegradedMode.EMERGENCY_STOP)
        self.assertFalse(fixture.attempt(motion, intent, permit)[0])
        self.assertTrue(fixture.gate.state.emergency_stop_latched)
        self.assertEqual(0, fixture.world.observe())
