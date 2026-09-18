from datetime import datetime, timedelta, timezone
import math
import unittest

from domains.safety import (
    CommandFreshness,
    DegradedMode,
    GeoFence,
    ResourceAvailability,
    ResourceBudget,
    SafetyState,
    SensorHealth,
    SharedSafetyGate,
)


NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


class SharedSafetyTests(unittest.TestCase):
    def setUp(self):
        self.gate = SharedSafetyGate(
            GeoFence(10, 20, 30, 40, 0, 100),
            ResourceBudget(battery_minimum=20, compute_minimum=1),
        )
        self.command = CommandFreshness(
            "command:1", NOW, NOW + timedelta(minutes=1), 0, "unit:1"
        )
        self.sensor = SensorHealth(NOW, 0.95, True, 10)
        self.available = ResourceAvailability(50, 10, 10, 2, 10)

    def admit(self, **overrides):
        values = {
            "now": NOW,
            "latitude": 15,
            "longitude": 35,
            "altitude": 50,
            "sensor": self.sensor,
            "available": self.available,
        }
        values.update(overrides)
        self.gate.admit(self.command, **values)

    def test_admission_requires_geofence_sensor_resources_and_fresh_sequence(self):
        self.admit()
        with self.assertRaisesRegex(PermissionError, "replayed"):
            self.admit()
        for kwargs, message in (
            ({"latitude": 25}, "geofence"),
            ({"sensor": SensorHealth(NOW - timedelta(seconds=1), 0.95, True, 0)}, "sensor"),
            ({"available": ResourceAvailability(10, 10, 10, 2, 10)}, "resource"),
            ({"human_present": True}, "human"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(PermissionError, message):
                fresh = CommandFreshness(
                    f"command:{message}", NOW, NOW + timedelta(minutes=1), 1, "unit:1"
                )
                values = {
                    "now": NOW,
                    "latitude": 15,
                    "longitude": 35,
                    "altitude": 50,
                    "sensor": self.sensor,
                    "available": self.available,
                }
                values.update(kwargs)
                self.gate.admit(fresh, **values)

    def test_emergency_stop_requires_local_attested_reconciliation_reset(self):
        state = SafetyState()
        state.enter(DegradedMode.EMERGENCY_STOP)
        with self.assertRaises(PermissionError):
            state.reset_emergency_stop(local_reset=False, attested=True, reconciled=True)
        self.assertFalse(state.allows_motion())
        state.reset_emergency_stop(local_reset=True, attested=True, reconciled=True)
        self.assertFalse(state.allows_motion())

    def test_non_finite_resource_values_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "finite"):
            ResourceAvailability(math.nan, 1, 1, 1, 1)


if __name__ == "__main__":
    unittest.main()
