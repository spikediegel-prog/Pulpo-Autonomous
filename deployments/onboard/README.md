# Onboard runtime profile

This profile defines the smallest intended Pulpo Autonomous deployment for a
robot, vehicle, drone, or spacecraft unit operating at the edge.

## Included

- `pulpo/` canonical governance kernel;
- `core/` bounded autonomy models and offline execution controls;
- one selected domain package under `domains/`;
- one selected hardware or simulation adapter under `adapters/`;
- durable local journal storage;
- machine-specific configuration supplied by the deployment authority.

## Excluded

The onboard image must not include:

- MCP servers, plugin hosts, or AI/operator transport bridges;
- GitHub, Telegram, Name.com, commerce, or web deployment integrations;
- `authority-service/` or `custody-service/` servers;
- CI scripts, experiments, proof runners, and development-only fixtures.

Those components belong to the offboard control plane, development environment,
or evidence archive. A unit may upload journal evidence through a separately
governed reconciliation client; it must not receive a second authority source.

The profile is a packaging boundary, not a claim that any hardware adapter is
flight-ready. Hardware integration remains subject to its own verification,
security review, and authorized interface contract.
