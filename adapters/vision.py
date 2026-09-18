from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from core.envelope import ExecutionEnvelope


MAX_OBSERVATION_BYTES = 16_384
MAX_TEXT_CHARS = 4_096


@dataclass(frozen=True)
class VisualObservation:
    sensor_id: str
    captured_at: datetime
    media_type: str
    content: str
    digest: str

    @classmethod
    def capture(
        cls,
        sensor_id: str,
        captured_at: datetime,
        media_type: str,
        content: str,
    ) -> "VisualObservation":
        encoded = content.encode("utf-8")
        if not sensor_id or captured_at.tzinfo is None:
            raise ValueError("invalid_visual_observation")
        if media_type not in {"ocr", "qr", "image-text"}:
            raise ValueError("unsupported_visual_media_type")
        if len(encoded) > MAX_OBSERVATION_BYTES or len(content) > MAX_TEXT_CHARS:
            raise ValueError("visual_observation_too_large")
        return cls(
            sensor_id=sensor_id,
            captured_at=captured_at,
            media_type=media_type,
            content=content,
            digest=hashlib.sha256(encoded).hexdigest(),
        )


@dataclass(frozen=True)
class VisualProposal:
    observation_digest: str
    action: str
    target: str
    source: str = "untrusted_visual_observation"


class UntrustedVisionBoundary:
    """Convert visual data to proposals without creating authority or execution."""

    def propose(self, observation: VisualObservation) -> VisualProposal | None:
        if observation.media_type == "qr":
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
            return VisualProposal(
                observation.digest,
                value["action"],
                value["target"],
            )
        return None

    @staticmethod
    def matches_permit(
        proposal: VisualProposal,
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
