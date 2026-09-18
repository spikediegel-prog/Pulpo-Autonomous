# Robotics domain

The robotics domain models terrestrial autonomous systems operating under bounded permits.

Typical concerns:

- task execution envelopes
- local autonomy windows
- sensor and actuator safety constraints
- human operator override boundaries
- mission-phase state transitions

Robotics adapters should also use the shared geofence, sensor-health,
resource-budget, degraded-mode, emergency-stop, human-presence, and command
freshness checks before motion. Real-time collision avoidance and actuator
interlocks remain local controller responsibilities.
