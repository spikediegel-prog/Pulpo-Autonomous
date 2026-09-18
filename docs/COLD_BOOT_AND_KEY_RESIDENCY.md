# Cold-boot and key-residency requirements

Pulpo Autonomous cannot make a general-purpose host resistant to physical RAM
extraction by software alone. It can, however, prevent the canonical authority
path from using recovered or unverified volatile state and require an external
hardware trust boundary before key use.

## Requirements

- Long-term private keys remain in a TPM, HSM, secure element, or flight
  computer security module. Pulpo receives a cryptographic result, not the
  private key.
- Key release or use is gated by machine identity, deployment, approved
  firmware measurement, verified boot, and purpose.
- Unexpected reset invalidates volatile execution state, command sessions, and
  any in-memory authority cache.
- Recovery requires a fresh, strictly increasing boot counter and verified boot
  evidence. Replayed or rolled-back boot evidence fails closed.
- Secure boot, measured boot, hardware-backed key storage, memory protection,
  DMA isolation, encrypted memory, and rollback prevention are required where
  the platform supports them.
- Temporary plaintext key and command material must be minimized and
  zeroized by the hardware or cryptographic implementation that owns it.
- Recovery and reset events must be durably recorded without restoring or
  expanding authority.
- An update must not weaken key residency, boot attestation, lease bounds,
  replay protection, journal integrity, or safe fallback behavior.

## Software boundary implemented here

`core/cold_boot.py` provides:

- `HardwareKeyProvider`, an interface that permits key use without exposing a
  private key to Pulpo;
- `BootEvidence`, binding the unit, deployment, firmware measurement, trust
  result, and monotonic boot counter;
- `ColdBootGuard`, which rejects untrusted, substituted, stale, or rolled-back
  boot evidence and blocks execution until the current boot is attested;
- `KeyUseRequest`, which binds a key operation to its machine, deployment,
  firmware measurement, and purpose.

`ExecutionTracker` can receive a `ColdBootGuard` and fails closed after reset
or before verified boot. The guard is a software gate, not a hardware security
module and not proof of cold-boot resistance.

## Required hardware evidence

The following remain outside this repository's software-only proof:

- RAM remanence resistance after power loss;
- encrypted memory behavior;
- DMA isolation;
- secure-element or HSM key non-exportability;
- secure-boot implementation and firmware measurement correctness;
- physical tamper response;
- zeroization during abrupt power removal;
- representative flight-computer or vehicle security behavior.

Those claims are **Unknown** until tested on representative hardware.
Simulator tests of the guard are **Verified** only for the software boundary.
