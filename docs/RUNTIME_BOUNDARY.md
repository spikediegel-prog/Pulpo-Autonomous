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

**Recorded — contract and deployment boundary; host integrity remains Unknown
without independent deployment evidence.**

Pulpo's security guarantees depend on the stated contract and deployment
assumptions, including host enforcement of process, file, and boot policy. The
operator and integrator are responsible for establishing and maintaining those
platform assumptions: boot chain, firmware, NVRAM, unused or hidden partitions,
storage-controller firmware, management controller, service-account privileges,
and decisions about continuing operation when the host can no longer be
measured. An OS reimage, snapshot, or rollback alone does not establish the
integrity of those layers.

A compromised host can bypass the Pulpo process, replace local state, or omit
records. Evidence integrity does not establish host integrity or prove that all
governed effects were observed. Host compromise may make governance outcomes
unverifiable; those outcomes remain **Unknown** unless independent evidence
establishes them. A valid local audit chain alone cannot rule out omissions,
bypass, or replacement with an internally consistent history.

Responsibility for such an incident depends on the stated contract, deployment
assumptions, and evidence, and may be shared across Pulpo, the operator, and the
integrator. Host compromise is not a categorical exemption from a Pulpo control
failure. Pulpo remains accountable for enforcing its specified controls and
detecting specified tampering under their stated assumptions, including
failing closed on a visible broken audit chain. Failure of a specified control
while its assumptions hold is a Pulpo failure; failure to establish or maintain
required platform protections is an operator or integration failure. When those
assumptions or the relevant evidence cannot be verified, attribution also
remains **Unknown** rather than defaulting to an operator-only incident.

Pulpo's bounded contract includes failing closed on unknown, incomplete, and
over-budget intents; binding one-use permits to exact intents; preserving grant
limits during loss of contact; and keeping uncertain execution unknown without
creating retry authority. These properties are bounded to the tested topology.
They do not establish survival of arbitrary host compromise, rollback-proof
storage, trusted verifier bootstrap, universal network isolation, or universal
hostile-code containment. Each deployment must identify which protections are
Pulpo controls and which require operator or integration enforcement, with
assumptions and evidence for each.
