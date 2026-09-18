# Pulpo Autonomous evaluation kit

Pulpo Autonomous is a governance and evidence layer for teams that already
operate autonomous physical systems. It bounds authority across connected and
disconnected execution, rejects hostile or stale inputs, records uncertain
outcomes, and supports reconciliation.

Pulpo does **not** replace navigation, stabilization, collision avoidance,
propulsion, braking, flight control, emergency-stop hardware, or local
controller safety logic.

## Reproducible evaluation

Run the dependency-free simulator demo from the repository root:

```bash
python scripts/run_gtm_evaluation.py --output evidence/gtm-evaluation.json
```

The demo proves, within the simulated boundary:

- an exact permitted command can execute;
- an offline command budget ends in the pre-authorized safe fallback;
- an uncertain result is recorded as `UNKNOWN` rather than retried;
- tampering with the append-only evidence journal is detected.

The output records the exact Git commit, scenario results, authority effect,
and limitations. It is an evaluation artifact, not a production-certificate
or mission-safety claim.

## Evaluation path

1. Select a domain profile: robotics, drones, vehicles, industrial systems, or
   spacecraft.
2. Identify the existing controller and local safety mechanisms. Pulpo must
   remain subordinate to them.
3. Bind the exact machine, deployment, policy, session, nonce, target, action,
   expiry, and resource/safety conditions.
4. Run the simulator and adversarial tests.
5. Integrate the adapter only after canonical permit checks, domain safety
   gates, and local interlocks are all explicit.
6. Produce a deployment evidence bundle containing the exact commit, dependency
   and platform hashes, hardware identity, test results, and unresolved
   limitations.

## Suggested proof scenarios

Run the evaluation with:

- communication loss and bounded offline continuation;
- forged, replayed, stale, delayed, and out-of-order commands;
- sensor disagreement, navigation spoofing, geofence violation, and resource
  exhaustion;
- emergency-stop, watchdog reset, brownout, and controller failover;
- uncertain actuator outcome followed by delayed telemetry;
- permit revocation and reconciliation conflict.

## Shared responsibility

| Pulpo governs | Existing platform must govern |
|---|---|
| permit binding and expiry | stabilization and navigation |
| offline authority bounds | collision avoidance and braking |
| replay and sequence checks | actuator and propulsion interlocks |
| evidence and reconciliation | emergency-stop wiring |
| safety admission vetoes | secure boot and hardware isolation |

Claims in evaluation artifacts must be labeled **Verified**, **Recorded**,
**Inferred**, **Proposed**, or **Unknown**. A successful simulator run does not
transfer hardware, firmware, network, or mission-level safety claims.
