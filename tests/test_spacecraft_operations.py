from datetime import datetime, timedelta, timezone
import math
import unittest

from domains.spacecraft import (
    CommandSequenceGuard,
    ContactWindow,
    MissionClockGuard,
    MissionTimeEvidence,
    ResourceMinimums,
    ResourceState,
    SensorState,
    SpacecraftAction,
    SpacecraftCommand,
    SpacecraftSafetyGate,
)


NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


class SpacecraftOperationsTests(unittest.TestCase):
    def test_mission_clock_rejects_uncertainty_and_rollback(self):
        guard = MissionClockGuard(max_uncertainty=timedelta(seconds=2))
        guard.accept(MissionTimeEvidence(NOW, 1, timedelta(seconds=1)))
        with self.assertRaisesRegex(PermissionError, "uncertainty"):
            guard.accept(MissionTimeEvidence(NOW + timedelta(seconds=1), 2, timedelta(seconds=3)))
        with self.assertRaisesRegex(PermissionError, "rollback"):
            guard.accept(MissionTimeEvidence(NOW, 1, timedelta(seconds=1)))

    def test_command_sequence_requires_order_phase_window_and_freshness(self):
        window = ContactWindow("ground:1", NOW, NOW + timedelta(minutes=5))
        guard = CommandSequenceGuard()
        first = SpacecraftCommand(
            "sequence:1", 0, SpacecraftAction.ATTITUDE, "sc:1",
            NOW, NOW + timedelta(minutes=1), "station-keeping", window,
        )
        guard.admit(first, now=NOW, expected_phase="station-keeping", ground_station_id="ground:1")
        with self.assertRaisesRegex(PermissionError, "gap"):
            guard.admit(
                SpacecraftCommand(
                    "sequence:1", 2, SpacecraftAction.THRUSTER, "sc:1",
                    NOW, NOW + timedelta(minutes=1), "station-keeping", window,
                ),
                now=NOW,
                expected_phase="station-keeping",
                ground_station_id="ground:1",
            )
        with self.assertRaisesRegex(PermissionError, "stale"):
            guard.admit(
                SpacecraftCommand(
                    "sequence:1", 1, SpacecraftAction.THRUSTER, "sc:1",
                    NOW - timedelta(minutes=2), NOW - timedelta(seconds=1),
                    "station-keeping", window,
                ),
                now=NOW,
                expected_phase="station-keeping",
                ground_station_id="ground:1",
            )

    def test_safety_gate_vetoes_faults_resources_and_sensor_disagreement(self):
        gate = SpacecraftSafetyGate(
            "orbit-insertion",
            {SpacecraftAction.THRUSTER: ResourceMinimums(propellant_margin=0.5)},
        )
        resources = ResourceState(1.0, 1.0, 0.4, 1.0)
        sensors = SensorState(0.99, True, True)
        with self.assertRaisesRegex(PermissionError, "resource"):
            gate.veto(SpacecraftAction.THRUSTER, resources=resources, sensors=sensors)
        resources = ResourceState(1.0, 1.0, 0.8, 1.0)
        with self.assertRaisesRegex(PermissionError, "sensor"):
            gate.veto(
                SpacecraftAction.THRUSTER,
                resources=resources,
                sensors=SensorState(0.99, False, True),
            )
        gate.enter_fault()
        with self.assertRaisesRegex(PermissionError, "faulted"):
            gate.veto(SpacecraftAction.THRUSTER, resources=resources, sensors=sensors)
        gate.recover(fresh_attestation=True, reconciled=True)
        gate.veto(SpacecraftAction.THRUSTER, resources=resources, sensors=sensors)

    def test_non_finite_spacecraft_measurements_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "finite"):
            ResourceState(math.nan, 1.0, 1.0, 1.0)
        with self.assertRaisesRegex(ValueError, "finite"):
            ResourceMinimums(propellant_margin=math.inf)
        with self.assertRaisesRegex(ValueError, "finite"):
            SensorState(math.nan, True, True)


if __name__ == "__main__":
    unittest.main()
