# Runtime boundary

Pulpo Autonomous has two deployment classes:

1. **Onboard runtime**: the constrained unit-side process that evaluates
   already-governed execution envelopes, applies offline limits, executes
   through one selected adapter, and records durable evidence.
2. **Offboard control plane**: operator, authority, custody, MCP, GitHub, and
   reconciliation services that prepare or review work and receive evidence.

The onboard runtime must not include an authority service, custody service,
MCP transport, AI provider bridge, commerce provider, Telegram transport,
GitHub client, Name.com client, web deployment configuration, or development
experiment. These are removed from the onboard profile rather than treated as
trusted runtime dependencies.

The canonical `pulpo/` kernel remains the sole authority source. `core/`
contains subordinate autonomy models; adapters translate an already-governed
envelope and cannot mint permits, extend leases, or create retry authority.

## Release change log

### v0.1.0 runtime-surface correction

- Removed the unused `vercel.json` web-deployment artifact from the repository.
- Removed the `pulpo-mcp-tunnel` console entry point from the base package so
  MCP transport is not installed as an onboard command.
- Kept MCP, authority, custody, commerce, and provider code available only as
  explicitly offboard or inherited evidence surfaces; they are excluded by the
  onboard manifest rather than silently becoming runtime dependencies.
- Added `deployments/onboard/manifest.json` and its deployment guidance.
- Corrected the plugin repository URL to the actual GitHub repository.

This change narrows the runtime capability surface. It does not delete
historical governance evidence or grant new authority. The removed web and
onboard command surfaces have no relevant temporal-transfer proof; no temporal
claim is made.

## Communications boundary

The runtime must treat every external message as untrusted until it passes the
identity, cryptographic, freshness, exact-intent, and mission-state checks in
[communications threat requirements](COMMUNICATIONS_THREAT_REQUIREMENTS.md).
Jamming, spoofing, or a pirate transmitter can deny service but cannot become a
new authority source. Hardware-level protections and radio-resilience claims
remain outside this software boundary.
