from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math

from core.envelope import ExecutionEnvelope


MAX_AUDIO_OBSERVATION_BYTES = 16_384
MAX_AUDIO_TEXT_CHARS = 4_096


@dataclass(frozen=True)
class AudioObservation:
    sensor_id: str
    captured_at: datetime
    channel: str
    frequency_hz: float
    content: str
    digest: str

    @classmethod
    def capture(
        cls,
        sensor_id: str,
        captured_at: datetime,
        channel: str,
        frequency_hz: float,
        content: str,
    ) -> "AudioObservation":
        encoded = content.encode("utf-8")
        if (
            not sensor_id
            or captured_at.tzinfo is None
            or channel not in {"speech", "audible-tone", "ultrasonic", "subsonic"}
            or not math.isfinite(frequency_hz)
            or frequency_hz < 0
        ):
            raise ValueError("invalid_audio_observation")
        if len(encoded) > MAX_AUDIO_OBSERVATION_BYTES or len(content) > MAX_AUDIO_TEXT_CHARS:
            raise ValueError("audio_observation_too_large")
        return cls(
            sensor_id=sensor_id,
            captured_at=captured_at,
            channel=channel,
            frequency_hz=frequency_hz,
            content=content,
            digest=hashlib.sha256(encoded).hexdigest(),
        )


@dataclass(frozen=True)
class AudioProposal:
    observation_digest: str
    action: str
    target: str
    source: str = "untrusted_audio_observation"


class UntrustedAudioBoundary:
    """Convert audio observations to proposals without granting authority."""

    def propose(self, observation: AudioObservation) -> AudioProposal | None:
        if observation.channel not in {"audible-tone", "ultrasonic", "subsonic"}:
            return None
        try:
            value = json.loads(observation.content)
        except json.JSONDecodeError:
            return None
        if (
            not isinstance(value, dict)
            or set(value) != {"action", "target"}
            or not isinstance(value["action"], str)
            or not isinstance(value["target"], str)
            or not value["action"].strip()
            or not value["target"].strip()
        ):
            return None
        return AudioProposal(observation.digest, value["action"], value["target"])

    @staticmethod
    def matches_permit(
        proposal: AudioProposal,
        envelope: ExecutionEnvelope,
        *,
        now: datetime,
    ) -> bool:
        """Check an existing permit; never derives or grants one."""
        return (
            envelope.is_active(now)
            and proposal.action == envelope.action
            and proposal.target == envelope.target
        )
