# Shared physical-system safety boundary

Pulpo Autonomous now provides shared admission checks for robotics, drones,
vehicles, marine systems, and industrial physical systems. These checks are
not a second authority system. The canonical `pulpo` kernel must approve an
action first; the domain safety layer may only reject execution.

## Implemented controls

- Rectangular geographic and altitude geofences with non-finite coordinate
  rejection.
- Fresh sensor evidence with confidence, independent agreement, and age limits.
- Battery, fuel, thermal, compute, and storage minimums.
- Degraded modes and a latched emergency-stop state.
- Local, attested, reconciled emergency-stop reset requirements.
- Human-presence vetoes for motion-capable actions.
- Strict command expiry, target presence, and monotonic sequence checks.

## Required domain integration

Robotics, vehicle, drone, and industrial adapters must add domain-specific
collision, braking, actuator, altitude, proximity, and local-maintenance
interlocks. The shared layer does not perform stabilization, navigation,
collision avoidance, or actuator control.

Safety state, emergency-stop latches, revoked permits, and fault transitions
must be persisted in tamper-evident restart-safe storage by the deployment.
The in-memory reference state is not sufficient for production recovery.

If sensor evidence is stale or contradictory, a resource budget is exceeded,
the unit leaves its geofence, a human is present, or a command is replayed or
expired, the adapter must fail closed. An uncertain outcome remains `UNKNOWN`
and does not create retry authority.

The shared checks and adversarial tests are **Verified** at the implementation
commit. Hardware interlocks, braking distance, collision avoidance, GNSS
authenticity, emergency-stop wiring, and physical safety remain **Unknown**
until tested on representative hardware.
