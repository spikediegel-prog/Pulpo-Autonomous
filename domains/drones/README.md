# Drones domain

The drones domain handles airborne autonomy, timing sensitivity, and continuity of authority during disconnected operation.

Typical concerns:

- geofencing and altitude bounds
- mission windows and flight phases
- delayed telemetry and lost-link behavior
- hazard vetoes for retry and re-entry

Drone adapters should combine the shared checks with flight-specific altitude,
airspace, return-to-home, lost-link, battery, and propulsion interlocks.
