# Communications threat requirements

Pulpo Autonomous must assume that wired and wireless communications can be
intercepted, modified, replayed, delayed, spoofed, jammed, or replaced by an
unauthorized transmitter. A stronger or apparently valid signal must never
become an authority source.

These requirements apply to robots, drones, vehicles, spacecraft, ground
stations, and reconciliation services. Hardware and transport adapters must
implement them without creating a second authority path.

## Authority and command requirements

1. Every command must be mutually authenticated between the unit and an
   authorized control-plane identity.
2. Commands and sensitive telemetry must use authenticated encryption. A valid
   signature without confidentiality or freshness is insufficient for a
   communications channel.
3. Each command must bind the exact machine identity, mission, policy,
   deployment, verifier, principal, session, nonce, issue time, expiry, target,
   and command sequence.
4. The unit must reject unknown, malformed, expired, duplicated, substituted,
   or unverifiable messages.
5. A command received from an unknown transmitter must not be converted into a
   proposal, permit, retry, or safe-mode override.
6. Replay protection must survive process restart and must not rely only on
   volatile memory.
7. A command sequence, nonce, or lease must never be accepted twice with
   different payloads.
8. The unit must not accept a control-plane identity solely because it is
   reachable, has a stronger signal, or presents a familiar network address.

## Disconnection, jamming, and delayed communication

9. Loss of the authorized signal must not create, extend, or enlarge authority.
10. During jamming or suspected signal substitution, the unit may continue only
    within its existing bounded offline mission lease.
11. The offline lease must have an absolute permit expiry and a maximum
    disconnected duration.
12. Reconnection must enter `RECONNECTING` and then `RECONCILING`; execution is
    blocked while reconciliation is active.
13. Delayed, duplicated, reordered, or conflicting messages must remain
    distinguishable in the evidence record.
14. A missing acknowledgement or lost telemetry must produce `UNKNOWN`, not
    `FAILED`, and must not create automatic retry authority.
15. When the permit, offline window, or resource budget ends, the unit may only
    execute the already-authorized safe fallback.

## Spoofed navigation, timing, and telemetry

16. Position, time, attitude, and health observations used for consequential
    actions must identify their source, freshness, and confidence.
17. Conflicting navigation or timing sources must fail closed or enter an
    explicitly bounded degraded mode; they must not silently reset lease time.
18. A telemetry message must not be treated as proof of physical success unless
    it satisfies the required observation and reconciliation contract.
19. The unit must detect and record relevant signal, clock, navigation, and
    sensor anomalies before allowing a consequential transition.
20. A degraded-mode transition must be pre-authorized by policy. The unit must
    not invent new authority in response to spoofing or sensor disagreement.

## Keys, updates, and identity

21. Each unit and authorized control station must have a distinct identity.
22. Private signing and encryption keys must remain outside governed agent,
    plugin, adapter, test-fixture, and evidence paths.
23. Key rotation, revocation, bootstrap, and recovery must be explicit governed
    transitions with durable evidence.
24. The unit must fail closed when its trust configuration is missing,
    substituted, expired, or inconsistent with the approved deployment.
25. Secure boot, hardware-backed key storage, protected update verification, and
    rollback prevention are required where the hardware supports them.
26. An update must not weaken command authentication, replay protection, lease
    bounds, journal integrity, or safe fallback behavior.

## Evidence and recovery

27. The unit must append durable evidence for authentication failures, replay
    attempts, source conflicts, jamming indicators, clock anomalies, rejected
    commands, unknown outcomes, fallback entry, and reconciliation.
28. Evidence storage must be append-only or tamper-evident and must fail closed
    when integrity verification fails.
29. Recovery procedures must distinguish communication denial, identity
    compromise, key compromise, sensor spoofing, and flight-computer compromise.
30. Recovery must not restore authority from an untrusted snapshot or permit
    rollback.

## Hardware boundary

Pulpo cannot by itself prevent antenna replacement, physical destruction,
compromise of the flight computer, extraction of hardware keys, persistent
radio-frequency denial, or deception below the software observation boundary.
Those risks require secure boot, hardware-backed key storage, independent
navigation and sensor checks, redundant communications, key-management
operations, and recovery procedures.

An adapter is not considered secure merely because it can encode a command.
Hardware integration requires an authorized interface contract and tests proving
that the adapter cannot mint permits, bypass the canonical kernel, extend an
offline lease, or convert uncertain execution into retry authority.

## Required adversarial evidence

Before connecting representative hardware, the simulator and adapter tests
must cover:

- forged commands from an unknown transmitter;
- modified commands with otherwise valid authentication;
- replayed commands and leases after restart;
- reordered and duplicated messages;
- stale, conflicting, or substituted vehicle identities;
- delayed telemetry and missing acknowledgements;
- signal jamming followed by a pirate transmitter;
- clock rollback and false time synchronization;
- spoofed position, attitude, or health observations;
- key revocation and trust-configuration substitution;
- journal restoration, truncation, and tampering;
- resource exhaustion during degraded communication;
- recovery while an outcome remains `UNKNOWN`.

Evidence is **Proposed** until executable tests pass at the exact commit.
Passing simulator tests is **Verified** only for the simulated boundary; it
does not prove radio resilience, hardware security, or physical safety.
