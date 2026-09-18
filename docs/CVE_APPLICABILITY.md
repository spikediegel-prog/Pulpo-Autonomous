# CVE applicability and dependency controls

This document records the current review of OpenAI, Claude/Anthropic, and MCP
security advisories against Pulpo Autonomous. It is a deployment applicability
record, not a claim that vendor software is secure.

## Repository exposure

Pulpo Autonomous does not bundle an OpenAI SDK, Anthropic SDK, Claude Code,
Codex, Claude Desktop, model runtime, `mcp-remote`, MCP Inspector, or a tunnel
binary. The Python MCP SDK is optional and offboard only. It is pinned to
`mcp[cli]==2.2.0`; the onboard manifest explicitly excludes MCP and external
AI/operator tooling.

The OpenAI Secure MCP Tunnel integration invokes an operator-installed
`tunnel-client` binary. The binary is not part of this repository and must be
inventoried by deployment with its version, provenance, checksum, signature,
configuration, and vendor advisories.

## Reviewed records

| Record | Affected component | Pulpo status |
|---|---|---|
| CVE-2025-49596 | MCP Inspector before 0.14.1 | Not bundled; applicable only if an operator runs the affected Inspector |
| CVE-2025-6514 | `mcp-remote` 0.0.5-0.1.15 | Not bundled; block from onboard and review any operator installation |
| CVE-2026-0621 | Anthropic TypeScript MCP SDK through 1.25.1 | Not the Python `mcp` package used by this repository |
| CVE-2025-66479 | Anthropic `sandbox-runtime` before 0.0.16 | Not bundled; applicable only to a separate deployment |
| CVE-2025-54558, CVE-2025-59532 | OpenAI Codex CLI | Operator-tooling risk, not an onboard dependency |
| CVE-2026-19591, CVE-2026-19592 | OpenAI Codex CLI/Desktop | Operator-tooling risk, not an onboard dependency |
| CVE-2025-52882, CVE-2025-54794, CVE-2025-54795, CVE-2025-55284 | Claude Code | Operator-tooling risk, not an onboard dependency |
| CVE-2026-21852, CVE-2026-55607, CVE-2026-54316 | Claude Code | Operator-tooling risk, not an onboard dependency |
| CVE-2026-44467, CVE-2026-44470 | Claude Desktop | Operator-tooling risk, not an onboard dependency |

Primary references:

- [NVD CVE-2025-49596](https://nvd.nist.gov/vuln/detail/CVE-2025-49596)
- [NVD CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)
- [NVD CVE-2026-0621](https://nvd.nist.gov/vuln/detail/CVE-2026-0621)
- [NVD CVE-2025-66479](https://nvd.nist.gov/vuln/detail/CVE-2025-66479)
- [NVD CVE-2025-59532](https://nvd.nist.gov/vuln/detail/CVE-2025-59532)
- [NVD CVE-2026-19591](https://nvd.nist.gov/vuln/detail/CVE-2026-19591)
- [NVD CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)
- [NVD CVE-2026-55607](https://nvd.nist.gov/vuln/detail/CVE-2026-55607)

## Controls implemented

- The optional Python MCP dependency is pinned to an exact version.
- `requirements-mcp.lock` records the resolved optional MCP dependency graph
  for reproducible offboard installation review.
- A CycloneDX SBOM records the direct optional dependencies and their scopes.
- The onboard manifest excludes MCP, OpenAI, Anthropic, Claude, Codex,
  `mcp-remote`, MCP Inspector, and `tunnel-client`.
- `scripts/verify_dependency_surface.py` fails if the pin, SBOM, or onboard
  exclusions drift.
- No external tunnel binary is bundled or trusted by repository presence.

Run the control:

```bash
python scripts/verify_dependency_surface.py
```

## Limitations and claim classification

The dependency pin, resolved lock, direct-component SBOM, and repository-surface
checks are **Verified** at the implementation commit. The checked-in lock
records versions but not every platform-specific artifact hash; deployments
must generate and retain a final environment SBOM including hashes. External
tunnel binaries and operator tools remain **Unknown** until their exact
versions are supplied. No CVE absence claim is made for unlisted transitive
dependencies or future advisories.
