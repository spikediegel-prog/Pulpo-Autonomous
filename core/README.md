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
