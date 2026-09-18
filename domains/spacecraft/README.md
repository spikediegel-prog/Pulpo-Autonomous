# Spacecraft domain

The spacecraft domain applies the same Pulpo governance model to orbital and deep-space autonomy under harsher latency and consequence constraints.

Typical concerns:

- command windows and contact-time authority
- delayed observation and long-latency response
- orbital maneuver safety envelopes
- thermal, power, and propellant budgets
- no-retry policy for uncertain orbital actions

`operations.py` provides subordinate admission checks for spacecraft adapters:
mission-time uncertainty and rollback, contact windows, ordered command
sequences, resource margins, navigation/sensor agreement, and fault recovery.
These checks do not issue permits or extend authority. High-consequence actions
remain subject to the canonical Pulpo kernel, exact permits, and independent
flight-system interlocks.

The safety gate must enter a faulted state after watchdog/radiation-reset,
failover, navigation disagreement, or other mission-defined safety faults.
Recovery requires fresh platform attestation and completed reconciliation.
