# Abuse resistance and service availability

Pulpo's governance invariants are not replaced by availability controls.
Rate limits, backoff, and quotas can reject or delay requests, but they never
grant, extend, or revoke authority. The canonical `pulpo` kernel remains the
only authority source.

## Implemented controls

The authority HTTP service now applies:

- a bounded request budget per client address for worker request/poll traffic;
- a bounded challenge request budget per approval and client address;
- progressive failure tracking for worker authentication;
- progressive failure tracking for WebAuthn assertions;
- temporary lockout after repeated failed authentication or assertion attempts;
- `429` responses with `Retry-After` for exhausted budgets and lockouts;
- fail-closed behavior when the guard or authenticator rejects a request.

The default guard is intentionally conservative but process-local. It is a
defense-in-depth control, not an identity system and not a replacement for
gateway policy.

## Production deployment requirements

For multiple replicas, the same limits must be enforced before traffic reaches
individual replicas using a trusted API gateway or shared, strongly protected
state. The deployment must bind quotas to authenticated worker identity where
available and to an untrusted client-network key before authentication. Do not
trust arbitrary `X-Forwarded-For` values without a configured trusted proxy
chain.

The deployment must additionally provide:

- maximum request body and decompression sizes;
- connection, concurrency, and polling limits;
- timeouts and queue bounds;
- alerting for distributed challenge failures, authentication failures, and
  repeated requests for nonexistent IDs;
- operator-visible lockout and recovery procedures;
- protection against gateway bypass and direct replica exposure.

The in-memory guard does not survive process restart. Restart recovery must
fail closed for authority state, while abuse counters may be restored or
allowed to decay according to the deployment incident policy. A lockout must
never be treated as evidence of approval or permit validity.

## Evidence and boundaries

The API guard and focused tests are **Verified** at the implementation commit.
Distributed rate limiting, gateway configuration, DDoS resistance, upstream
identity-provider throttling, TPM/HSM PIN lockout, and hardware/firmware
availability remain **Unknown** until tested in the target deployment.
