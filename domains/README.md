# Autonomous domains

Pulpo Autonomous uses a common authority model across multiple physical-system domains.

Each domain adds constraints specific to its execution environment while preserving the same governance invariants:

- Disconnection cannot expand authority.
- Uncertain execution cannot create retry authority.
- An unknown outcome remains unknown until reconciliation proves otherwise.

The shared kernel remains domain-agnostic; domain modules enrich mission constraints.

Shared physical-system safety checks live in `domains/safety.py`. They reject
out-of-bounds, stale, sensor-unsafe, resource-exhausting, human-presence, and
emergency-stop-blocked motion before an adapter executes. They never issue or
extend Pulpo permits. See `docs/PHYSICAL_SYSTEM_SAFETY.md`.
