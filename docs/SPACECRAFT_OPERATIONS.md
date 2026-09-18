# Spacecraft operations boundary

Pulpo Autonomous supports spacecraft execution without becoming a flight
computer, navigation system, propulsion controller, or second authority plane.
The canonical `pulpo` kernel still decides whether a governed action is
authorized. `domains.spacecraft.operations` only applies additional
fail-closed admission checks before an adapter attempts execution.

## Implemented checks

- Mission-time evidence requires timezone-aware time, bounded uncertainty, and
  strictly increasing monotonic counters. Rollback or excessive uncertainty is
  rejected.
- Commands carry mission phase, expiry, target, and optional ground-station
  contact-window bindings.
- Commands in a sequence must begin at ordinal zero and advance without gaps or
  replay. A late command, wrong phase, wrong station, or out-of-window command
  is rejected.
- Resource margins cover power, thermal, propellant, and storage. Each action
  can define minimum margins; non-finite measurements are rejected.
- Navigation confidence, independent sensor agreement, and attitude validity
  are required by the safety gate.
- Fault entry blocks actions. Recovery requires fresh platform attestation and
  completed reconciliation.

## Required integration

Adapters must evaluate the canonical permit first, then these checks, then
independent flight-system interlocks. A failed spacecraft check must not create,
extend, or substitute authority. An uncertain maneuver remains `UNKNOWN` in the
core execution protocol and must not be retried automatically.

Mission profiles should define separate limits for launch, orbit insertion,
station-keeping, docking, landing, payload deployment, safe mode, and
end-of-life. The profile must state valid phases, contact windows, resource
minimums, sensor thresholds, fallback behavior, and reconciliation evidence.

The command and safety checks are **Verified** by focused unit tests at the
implementation commit. They do not prove radiation tolerance, actuator
interlock correctness, secure-element behavior, navigation authenticity,
hardware fault containment, or mission safety. Those remain **Unknown** until
representative hardware and mission simulations provide evidence.
