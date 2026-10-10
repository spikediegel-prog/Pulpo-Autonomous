# Core autonomy kernel

This directory holds the shared Pulpo Autonomous authority model for physical systems.

The policy boundary remains the same across robot and spacecraft deployments:

- machine identity
- delegated authority with expiry
- permit enforcement
- offline authority bounds
- observation capture
- reconciliation and unknown-state handling
- safety vetoes

Pulpo Autonomous may enforce authority and translate it into machine-executable operations, but it never becomes a second authority source.


Optional `CommandTrafficSettings` places passive bounded transport inspection
at the existing `ExecutionTracker.execute()` boundary. Default callers remain
unchanged. The intake retains no governed writer, and fallback/observation paths
remain outside it. See [the integration proof and limits](../docs/AUTONOMOUS_TRAFFIC_ROUTER.md).
