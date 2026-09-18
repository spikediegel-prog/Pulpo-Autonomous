# Data transport security boundary

Pulpo's authority and safety checks do not make an untrusted network path
safe. Offboard/provider transports must use explicit HTTPS trust configuration
and must not inherit arbitrary proxy or CA settings from the host environment.

## Implemented controls

- Authority-client HTTPS uses a no-proxy opener, explicit redirect rejection,
  HTTPS origin validation, response-size limits, and standard certificate
  validation.
- Name.com provider HTTPS uses the same no-proxy and certificate policy.
- Telegram provider HTTPS uses the same explicit transport policy while
  preserving `EXTERNAL_REALITY_UNKNOWN` behavior for ambiguous writes.
- MCP tunnel child environments remove proxy variables, ambient CA variables,
  alternate control-plane variables, and operator-tool overrides.
- An optional `PULPO_CA_BUNDLE` may select one explicit absolute CA bundle.
  Ambient `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, and
  `CURL_CA_BUNDLE` settings are rejected unless the deployment supplies the
  explicit Pulpo bundle consistently.

This is a trust-store and proxy hardening control, not certificate pinning.
Deployments requiring stronger identity assurance should use mTLS, gateway
allowlists, pinned service identities, egress controls, and certificate
rotation procedures independently of the application.

## Required deployment controls

- Restrict authority ingress with workload identity or mTLS.
- Do not expose service replicas directly behind an untrusted proxy.
- Allowlist authority, provider, tunnel, and update endpoints.
- Pin exact external binary versions and hashes.
- Test proxy bypass, malicious CA, DNS changes, redirect attempts, TLS
  expiration, certificate rotation, timeout, truncation, duplication, and
  ambiguous write outcomes.

The repository transport policy and tests are **Verified** at the
implementation commit. Host, gateway, DNS, CA-store, mTLS, external binary,
provider, and hardware-radio behavior remain **Unknown** until verified in the
deployment environment.
