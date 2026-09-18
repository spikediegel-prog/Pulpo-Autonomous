from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .journal import DurableJournal


class HardwareKeyProvider(Protocol):
    """Hardware boundary: Pulpo may request use, never read, a private key."""

    def sign_digest(self, digest: bytes, *, key_id: str) -> bytes:
        ...


@dataclass(frozen=True)
class BootEvidence:
    machine_id: str
    deployment_id: str
    firmware_measurement: str
    boot_counter: int
    trusted: bool


@dataclass(frozen=True)
class KeyUseRequest:
    key_id: str
    machine_id: str
    deployment_id: str
    firmware_measurement: str
    purpose: str


@dataclass
class ColdBootGuard:
    """Software gate for hardware-backed key use and reset recovery.

    This does not provide cold-boot resistance by itself. It ensures Pulpo will
    not use authority material until the external hardware trust boundary has
    approved the current boot.
    """

    machine_id: str
    deployment_id: str
    expected_firmware_measurement: str
    journal: DurableJournal
    last_boot_counter: int = 0
    boot_valid: bool = False
    volatile_state_valid: bool = False

    def attest_boot(self, evidence: BootEvidence) -> None:
        if (
            not evidence.trusted
            or evidence.machine_id != self.machine_id
            or evidence.deployment_id != self.deployment_id
            or evidence.firmware_measurement != self.expected_firmware_measurement
            or evidence.boot_counter <= self.last_boot_counter
        ):
            self.invalidate("boot_attestation_rejected")
            raise PermissionError("boot_attestation_rejected")
        self.last_boot_counter = evidence.boot_counter
        self.boot_valid = True
        self.volatile_state_valid = True
        self.journal.append(
            "boot_attested",
            {
                "machine_id": evidence.machine_id,
                "deployment_id": evidence.deployment_id,
                "firmware_measurement": evidence.firmware_measurement,
                "boot_counter": evidence.boot_counter,
            },
        )

    def invalidate(self, reason: str = "unexpected_reset") -> None:
        self.boot_valid = False
        self.volatile_state_valid = False
        self.journal.append("security_invalidated", {"reason": reason})

    def authorize_key_use(self, request: KeyUseRequest) -> None:
        if not self.boot_valid or not self.volatile_state_valid:
            raise PermissionError("key_release_requires_verified_boot")
        if (
            request.machine_id != self.machine_id
            or request.deployment_id != self.deployment_id
            or request.firmware_measurement != self.expected_firmware_measurement
            or not request.key_id
            or not request.purpose
        ):
            raise PermissionError("key_release_binding_mismatch")
        self.journal.append(
            "key_use_authorized",
            {
                "key_id": request.key_id,
                "machine_id": request.machine_id,
                "deployment_id": request.deployment_id,
                "firmware_measurement": request.firmware_measurement,
                "purpose": request.purpose,
            },
        )

    def can_execute(self) -> bool:
        return self.boot_valid and self.volatile_state_valid

    def reset(self) -> None:
        self.invalidate("unexpected_reset")
