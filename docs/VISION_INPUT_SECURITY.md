# Vision input security boundary

Cameras, OCR, QR decoders, and vision models are **untrusted observation
sources**. A paper, photograph, QR code, screen, or environmental sign may
contain malicious instructions or replayed data, but it must not grant,
extend, substitute, or revoke Pulpo authority.

The reference boundary is:

```text
camera/OCR/QR -> untrusted observation -> proposal
              -> existing canonical permit check
              -> domain safety gates
              -> local controller/interlocks
              -> execution
```

`adapters.vision.UntrustedVisionBoundary` only creates bounded proposals from
strict QR data and checks whether a proposal matches an already-issued,
unexpired `ExecutionEnvelope`. It does not parse signatures as authority,
issue permits, execute actions, or accept extra fields such as `authority` or
`signature` from visual content.

## Required deployment controls

- Keep OCR and vision-model output outside the authority and permit stores.
- Bind any accepted proposal to the observation digest, sensor identity,
  capture time, machine identity, target, action, policy, session, nonce, and
  expiry.
- Require an independently issued canonical permit; a printed or displayed
  permit is not proof of current authority.
- Apply the shared safety gate and local controller interlocks after permit
  validation.
- Reject malformed, oversized, stale, replayed, out-of-context, or
  contradictory visual input.
- Rate-limit visual processing and bound queues, memory, and downstream model
  calls.
- Never allow visual text to reset emergency stops, alter geofences, enroll
  credentials, change policies, or approve a command.

The parser and adversarial tests are **Verified** at the implementation
commit. Resistance to camera spoofing, adversarial patches, sensor compromise,
model-specific prompt injection, physical QR replacement, and hardware
tampering remains **Unknown** until tested on representative sensors and
deployed pipelines.
