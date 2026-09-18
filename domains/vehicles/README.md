# Vehicles domain

The vehicles domain covers autonomous land and mobile systems.

Typical concerns:

- path authority and maneuver boundedness
- route-specific permits and approvals
- state reconciliation under outage
- safety gating around uncertain control outcomes

Vehicle adapters should add the shared geofence and command-freshness checks
alongside local braking-distance, proximity, occupant, maintenance-mode, and
emergency-stop interlocks. Pulpo does not replace the vehicle controller.
