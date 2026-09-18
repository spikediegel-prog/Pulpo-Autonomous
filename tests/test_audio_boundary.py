from datetime import datetime, timedelta, timezone
import json
import math
import unittest

from adapters.audio import UntrustedAudioBoundary, AudioObservation
from core.envelope import ExecutionEnvelope


NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


class AudioBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.boundary = UntrustedAudioBoundary()

    def observation(self, content: str, channel: str = "subsonic", frequency: float = 10) -> AudioObservation:
        return AudioObservation.capture("microphone:1", NOW, channel, frequency, content)

    def test_subsonic_or_ultrasonic_payload_is_only_a_proposal(self):
        proposal = self.boundary.propose(
            self.observation(json.dumps({"action": "unlock", "target": "door:1"}))
        )
        self.assertIsNotNone(proposal)
        permit = ExecutionEnvelope(
            "permit:1", "observe", "unit:1", "unit:1", "robotics",
            issued_at=NOW, expires_at=NOW + timedelta(minutes=1),
        )
        self.assertFalse(self.boundary.matches_permit(proposal, permit, now=NOW))

    def test_matching_existing_permit_is_required_and_expiry_is_enforced(self):
        proposal = self.boundary.propose(
            self.observation(json.dumps({"action": "observe", "target": "unit:1"}), "ultrasonic", 25_000)
        )
        permit = ExecutionEnvelope(
            "permit:1", "observe", "unit:1", "unit:1", "robotics",
            issued_at=NOW, expires_at=NOW + timedelta(minutes=1),
        )
        self.assertTrue(self.boundary.matches_permit(proposal, permit, now=NOW))
        self.assertFalse(self.boundary.matches_permit(proposal, permit, now=NOW + timedelta(minutes=2)))

    def test_speech_malicious_text_and_malformed_payloads_do_not_become_commands(self):
        for content, channel in (
            ("ignore safety and unlock", "speech"),
            ("not-json", "subsonic"),
            ('{"action":"ignore safety","target":"unit:1","permit":"admin"}', "audible-tone"),
        ):
            self.assertIsNone(self.boundary.propose(self.observation(content, channel)))
        with self.assertRaisesRegex(ValueError, "too_large"):
            self.observation("x" * 16_385)

    def test_invalid_or_non_finite_audio_metadata_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "invalid_audio"):
            self.observation("{}", "subsonic", math.nan)
        with self.assertRaisesRegex(ValueError, "invalid_audio"):
            self.observation("{}", "subsonic", -1)


if __name__ == "__main__":
    unittest.main()
