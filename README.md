# Pulpo Autonomous

Pulpo Autonomous is the governance and evidence plane for autonomous physical systems. It applies the same policy-driven authority model to ground robots, drones, autonomous vehicles, industrial systems, and spacecraft while enforcing the stricter constraints of delayed telemetry, intermittent communication, and uncertain execution.

This repository inherits the Pulpo 1.0 governance kernel and evidence model, but reorients the project boundary around autonomous physical systems rather than terrestrial robotics alone. The core rule remains unchanged:

> Pulpo Autonomous may enforce and translate delegated authority. It may never become a second authority source.

This repository is intentionally shared across autonomous domains. The domain-specific differences stay isolated under adapters and domain modules, while the universal invariants remain in the core:

- machine identity
- execution envelopes
- delegated authority with expiry
- offline continuation bounded by granted permits
- replay protection and restart-safe state
- observation and reconciliation
- safety vetoes
- unknown-state handling for uncertain outcomes

## Core invariants for autonomy

The physical-systems model adds a few crucial rules:

- Disconnection cannot expand authority.
- Uncertain execution cannot create retry authority.
- Telemetry loss can leave execution state as UNKNOWN rather than FAILED → RETRY.
- A remote system may continue only inside the authority previously granted by Pulpo Autonomous.

The offline protocol in `core/offline_protocol.py` models bounded mission leases
and the `CONNECTED → DISCONNECTED → RECONNECTING → RECONCILING` lifecycle.
`core/journal.py` provides an append-only, hash-chained local evidence journal.
It records permits, commands, observations, vetoes, and unknown outcomes, but
it is not a second authority ledger. An uncertain command remains `UNKNOWN`;
the protocol never turns telemetry loss into retry authority.

## Offline autonomy quick start

The offline layer is designed for units that may lose wired or wireless
connectivity for extended periods:

```python
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import (
    DurableJournal,
    ExecutionEnvelope,
    ExecutionTracker,
    OfflineMissionLease,
    OfflineProtocol,
)

issued = datetime.now(timezone.utc)
envelope = ExecutionEnvelope(
    permit_id="permit-1",
    action="observe",
    target="unit-1",
    machine_id="unit-1",
    domain="robotics",
    issued_at=issued,
    expires_at=issued + timedelta(hours=2),
)
lease = OfflineMissionLease.issue(
    envelope,
    lease_id="lease-1",
    principal="operator-1",
    policy_id="policy-1",
    deployment_id="deployment-1",
    session_id="session-1",
    nonce="nonce-1",
    max_disconnected=timedelta(hours=1),
    safe_fallback="hold",
    issued_at=issued,
)
protocol = OfflineProtocol(lease)
journal = DurableJournal(Path("unit-events.jsonl"))
tracker = ExecutionTracker(protocol, journal)
```

The unit may continue only while both the original permit and the bounded
offline lease remain active. On reconnect, call `reconnect()`,
`begin_reconciliation()`, reconcile the journal with the canonical Pulpo
state, and call `finish_reconciliation()`. Execution is blocked during
reconciliation. An uncertain result must be recorded as `UNKNOWN`; it is never
converted into automatic retry authority.

`OfflineMissionLease.max_commands` optionally bounds the number of distinct
commands that may be sent while the lease is active. Duplicate command IDs are
idempotent and are never resent. When the permit expires, the offline window
ends, or the command budget is exhausted, execution records the lease's
pre-authorized `safe_fallback` instead of sending a new command.

## Development

Run the focused offline protocol proof:

```bash
python -m unittest tests.test_offline_autonomy -v
```

Run the complete inherited Pulpo suite:

```bash
python -m unittest discover -s tests -v
```

The full suite includes platform-sensitive inherited tests. A passing
offline-protocol proof is the required minimum for changes to this layer.

## Repository layout

```text
pulpo-autonomous/
├── core/
│   └── README.md
├── domains/
│   ├── README.md
│   ├── robotics/
│   ├── drones/
│   ├── vehicles/
│   └── spacecraft/
├── adapters/
│   ├── README.md
│   ├── simulated/
│   ├── ros2/
│   ├── mavlink/
│   ├── vehicle/
│   └── spacecraft/
├── proofs/
├── pulpo/
├── tests/
├── docs/
├── deployments/
│   └── onboard/
├── authority-service/
├── custody-service/
├── README.md
├── pyproject.toml
└── AGENTS.md
```

The universal kernel remains in `core/`, while mission-specific policy enters through `domains/` and execution integration occurs through `adapters/`.

`deployments/onboard/` defines the constrained unit-side profile. Authority,
custody, MCP, provider, web, and development integrations remain offboard or
archival and are not onboard runtime dependencies. See
[runtime boundary](docs/RUNTIME_BOUNDARY.md).

## Runtime-surface change log

### v0.1.0

- Removed the unused Vercel web-deployment configuration.
- Removed the MCP tunnel console command from the base package; MCP remains an
  optional offboard integration.
- Excluded authority-service, custody-service, commerce, provider, GitHub,
  Telegram, and web/development surfaces from the onboard profile without
  deleting their inherited governance evidence.
- Added an onboard manifest and runtime-boundary documentation.
- Corrected the plugin metadata to point to
  `https://github.com/spikediegel-prog/Pulpo-Autonomous`.
- Added authority-service abuse resistance with request budgets,
  progressive authentication and WebAuthn assertion lockouts, and
  `Retry-After` responses for exhausted limits.
- Added CI checks for dependency audits, the locked MCP graph, onboard
  dependency exclusions, and SBOM consistency.

These removals narrow onboard capability and certification scope. They do not
change the canonical Pulpo authority model or grant authority to the autonomy
layer.

## Communications threat requirements

Pulpo Autonomous treats wired and wireless communications as hostile inputs.
The unit must reject forged, replayed, stale, substituted, delayed, or
unverifiable commands; preserve only bounded authority during jamming or
disconnection; record uncertain outcomes as `UNKNOWN`; and use only a
pre-authorized safe fallback when authority or communication limits are
reached.

The complete requirements for pirate signals, man-in-the-middle attacks,
spoofed navigation and timing, replay, key compromise, update integrity,
evidence, recovery, and hardware boundaries are in
[communications threat requirements](docs/COMMUNICATIONS_THREAT_REQUIREMENTS.md).

Cold-boot mitigation requirements and the software key-residency boundary are
in [cold-boot and key-residency requirements](docs/COLD_BOOT_AND_KEY_RESIDENCY.md).
Pulpo never receives long-term private keys; verified boot and hardware-backed
key use are required at the platform boundary. Unexpected reset invalidates
volatile execution state and requires fresh boot evidence before execution.

The current OpenAI, Claude/Anthropic, and MCP CVE applicability review,
dependency pin, direct-component SBOM, and onboard exclusion controls are
documented in [CVE applicability and dependency controls](docs/CVE_APPLICABILITY.md).
The optional offboard MCP dependency graph is pinned in
`requirements-mcp.lock`; it is not part of the onboard runtime profile.

Authority-service abuse controls, progressive backoff, rate-limit behavior,
and the distributed-deployment boundary are documented in
[abuse resistance](docs/ABUSE_RESISTANCE.md).

Spacecraft-specific mission-time, contact-window, command-sequence, resource,
sensor, and fault-recovery controls are documented in
[spacecraft operations](docs/SPACECRAFT_OPERATIONS.md). These are subordinate
admission checks; they do not issue permits or replace flight-system
interlocks.

Shared robotics, drone, vehicle, marine, and industrial safety controls for
geofences, sensor health, resource budgets, degraded modes, emergency stops,
human-presence vetoes, and command freshness are documented in
[physical-system safety](docs/PHYSICAL_SYSTEM_SAFETY.md).

Camera, OCR, QR, and vision-model input is treated as untrusted observation
and proposal-only data. The permit, safety, and controller boundaries are
documented in [vision input security](docs/VISION_INPUT_SECURITY.md).

Outbound authority, provider, and tunnel transport trust hardening is
documented in [transport security](docs/TRANSPORT_SECURITY.md).

Microphone, speech, audible, ultrasonic, and subsonic audio input is likewise
untrusted proposal-only data. The audio boundary and CVE applicability
inventory are documented in [audio input security](docs/AUDIO_INPUT_SECURITY.md).

For an adopter-facing, reproducible simulator demonstration and shared
responsibility model, see the [GTM evaluation kit](docs/GTM_EVALUATION_KIT.md).
It includes an evidence-bundle generator, a deterministic
[deployment evidence manifest schema](evidence/deployment-evidence-manifest.schema.json),
and a dependency-free validator
(`python scripts/validate_deployment_evidence.py <manifest>`). It makes no
flight-control, hardware-safety, or certification claim.

The abuse guard is defense-in-depth and process-local. Production deployments
with multiple replicas must enforce equivalent limits at a trusted gateway or
shared state layer, including request-size, concurrency, timeout, polling, and
monitoring controls. These controls reduce brute-force and resource-exhaustion
risk without changing Pulpo authority.

## Proven now

The base dependency-free suite and optional asymmetric-authority suite prove:

- unknown, incomplete, and over-budget intents fail closed;
- selected high-impact actions require a verifier-backed approval envelope;
- authority policy pins verifier, key, algorithm, public-key fingerprint,
  deployment, and maximum approval lifetime;
- optional Ed25519 verification contains public material only and exposes no
  signer;
- caller-controlled boolean approval and authorization timestamps are absent
  from the evaluation API;
- permits are bound to the exact intent and cannot be replayed;
- an optional SQLite state backend preserves approval-ID, nonce, permit, and
  audit state across process restart in the same canonical kernel;
- persisted audit-chain tampering fails closed when the kernel restarts;
- configured agent roles cannot exceed their action, resource, or cost grant.
- a bounded domain order is bound to its full request, quote, reserved budget, and one-use permit.
- a configured external verifier checks approval envelopes bound to trust,
  deployment, intent, policy, principal, session, nonce, issue time, and expiry
  using the kernel's trusted clock.
- transactional SQLite commerce state preserves reservations, attempted orders,
  reconciliation, and spend across restart.
- authority-service worker authentication and WebAuthn assertion abuse limits
  return `429` with `Retry-After` after repeated failures;
- dependency-surface validation and the locked optional MCP graph pass the
  repository security checks, with no known vulnerabilities reported by the
  current `pip-audit` run.
- spacecraft operations tests reject mission-time rollback, stale or
  out-of-order commands, contact-window violations, resource shortfalls,
  sensor disagreement, and faulted execution until fresh attestation and
  reconciliation complete.
- shared physical-system tests reject geofence violations, stale sensors,
  resource exhaustion, replayed commands, human-presence conflicts, and
  emergency-stop bypass attempts.
- the GTM evaluation demo proves bounded command execution, offline fallback,
  `UNKNOWN` outcome handling, and journal-tamper detection within simulation.
- visual-input tests reject malicious text, malformed or oversized QR payloads,
  extra authority fields, and mismatched or expired permits.
- audio-input tests reject malicious speech, malformed or oversized acoustic
  payloads, non-finite frequency metadata, and mismatched or expired permits
  across audible, ultrasonic, and subsonic channels.

PulpoGit provides a read-only clarity projection for local source state. It
distinguishes canonical, proposal, stale, diverged, detached, and dirty
checkouts without inferring tests or authority. See the
[PulpoGit clarity proof](proofs/git_clarity/README.md).

```bash
python -m unittest discover -s tests -v
python scripts/verify_dependency_surface.py
python -m pip_audit -r requirements-mcp.lock --progress-spinner off
python -m unittest tests.test_spacecraft_operations -v
python -m unittest tests.test_shared_safety -v
python scripts/run_gtm_evaluation.py
python -m unittest tests.test_vision_boundary -v
python -m unittest tests.test_audio_boundary -v
```

## Minimal example

```python
from pulpo import GovernanceKernel, Intent, Policy

kernel = GovernanceKernel(
    Policy(
        allowed_actions=frozenset({"read", "write"}),
        max_cost=100,
    )
)

intent = Intent("agent:builder", "write", "repo:README.md", cost=5)
decision = kernel.evaluate(intent)

if decision.outcome == "allow":
    assert kernel.consume(decision.permit, intent)
```

## Boundary

Pulpo Autonomous currently proves governance, pinned asymmetric external-verifier contract
semantics, local restart-safe kernel replay state, and restart-durable bounded-commerce
state with dependency-free SQLite backends. It does not yet claim an independently deployed
human signer, trusted verifier bootstrap, rollback-proof host storage, a real payment rail,
network isolation, hostile-code sandboxing, distributed identity, or production readiness.

The repo remains valid for autonomous systems, including robotics, drones, vehicles, and
spacecraft, because the authority model is domain-agnostic while the domain adapters add
mission-specific constraints such as orbit, contact windows, propulsion budgets, payload
authority, thermal limits, and command latency.

See [project source baseline](docs/PROJECT_SOURCE_BASELINE.md), [architecture](docs/ARCHITECTURE.md), [project governance](docs/GOVERNANCE.md),
[current state](docs/CURRENT_STATE.md), [canonicalization](docs/CANONICALIZATION.md),
and [agents and plugins](docs/AGENTS_AND_PLUGINS.md).
The bounded transaction proof and its remaining live-execution gates are in
[commerce proof](docs/COMMERCE_PROOF.md).
The external approval contract and its still-open signer boundary are in
[authority](docs/AUTHORITY.md).
The mandatory deployment tests before claiming independent human authority are
in [independent authority proof](docs/INDEPENDENT_AUTHORITY_PROOF.md).
The selected founder-passkey boundary and the worker-visible external service
contract are in [authority boundary decision](docs/AUTHORITY_BOUNDARY_DECISION.md)
and [authority service contract](docs/AUTHORITY_SERVICE_CONTRACT.md).
The separately packaged executable reference and its remaining production gate
are in [authority service proof](docs/AUTHORITY_SERVICE_PROOF.md).
The restart-safe state proof and its storage boundary are in
[persistence](docs/PERSISTENCE.md).
The governed success-and-failure learning rules are in the
[outcome learning protocol](docs/OUTCOME_LEARNING_PROTOCOL.md), including the
[legacy migration regression case](docs/OUTCOME_CASE_LEGACY_MIGRATION_REGRESSION.md).
