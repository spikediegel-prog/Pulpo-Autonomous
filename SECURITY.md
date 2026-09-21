# Security Policy

Pulpo Autonomous is a governance and evidence system for autonomous physical systems. Security reports should be handled privately until maintainers have had a reasonable opportunity to investigate and remediate them.

## Reporting a vulnerability

Please do **not** disclose suspected vulnerabilities in a public issue, discussion, pull request, or social post.

Preferred reporting path:

1. Use GitHub's **Security** tab for this repository.
2. Select **Report a vulnerability** / private vulnerability reporting when available.
3. Include the affected commit or release, reproduction steps, expected versus observed behavior, and the smallest safe proof that demonstrates the issue.
4. Do not include live credentials, production secrets, private keys, or unrelated provider data.

If private vulnerability reporting is not available, contact the repository owner through GitHub before publishing technical details.

## Scope

Reports are especially useful when they demonstrate a failure of a documented governance or security invariant, including:

- authority or policy bypass;
- permit replay, reuse, or expiry failure;
- approval, identity, target, policy, or session binding mismatch;
- audit-chain or persisted-state integrity failure;
- fail-open behavior after restart or partial persistence failure;
- unauthorized network exposure or capability activation;
- custody or secret-boundary escape;
- unsafe handling of untrusted model, vision, audio, provider, or transport input;
- evidence substitution, tampering, or reconciliation mismatch.

## Evidence standard

A security claim should distinguish:

- **Verified** — reproduced against a specific commit or release;
- **Recorded** — present in durable evidence but not reproduced in the current report;
- **Inferred** — reasoned from evidence but not directly demonstrated;
- **Proposed** — remediation or design change not yet proven;
- **Unknown** — insufficient evidence.

Where possible, provide a minimal executable reproduction that fails closed and does not touch production resources.

## Boundaries

Pulpo Autonomous does not claim universal production readiness, certified physical safety, trusted hardware, universal hostile-code containment, or secure deployment outside the tested topology. A report should state the environment and trust boundaries actually exercised.

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**
