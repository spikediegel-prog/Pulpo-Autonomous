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

## Cold-boot boundary

`core/cold_boot.py` provides a fail-closed software gate around verified boot,
monotonic boot evidence, key-use binding, and reset invalidation. It does not
read, store, or export long-term private keys. RAM remanence resistance,
encrypted memory, DMA isolation, secure-element non-exportability, and abrupt
power-loss zeroization require representative hardware evidence and remain
**Unknown** until tested.

## Host bound and Pulpo bound
Pulpo is only as secure as the host it is running on. The kernel, permit store, and evidence journal assume that host is still the host that was installed and that it is still enforcing process, file, and boot policy. Pulpo does not own the boot chain, firmware, NVRAM, unused or hidden partitions, storage-controller firmware, the management controller, service-account privileges, or the decision to keep operating a machine that can no longer be measured. An OS reimage, snapshot, or rollback does not restore those layers. A compromised host can skip the process, replace local state, or omit a record. That is an operator incident, not a Pulpo control failure.
Pulpo is accountable for the contract it states, on a host that is still enforcing it: unknown, incomplete, and over-budget intents fail closed; a permit is bound to one exact intent and cannot be replayed; loss of contact does not widen a grant; uncertain execution remains unknown and does not become retry authority; a visible broken audit chain fails closed. A defect in that contract is a Pulpo failure. Survival of host compromise, rollback-proof storage, trusted verifier bootstrap, network isolation, and hostile-code sandboxing are not part of that contract.
