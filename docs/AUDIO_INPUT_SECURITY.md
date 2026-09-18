# Audio input security boundary

Microphones, speech recognition, audible tones, ultrasonic signals, and
subsonic signals are **untrusted observation sources**. A nearby speaker,
radio, actuator, or hidden transmitter may emit commands intended to influence
an autonomy pipeline. Frequency, loudness, or apparent urgency does not grant
authority.

The required path is:

```text
microphone/audio DSP/speech -> untrusted observation -> proposal
                              -> existing canonical permit check
                              -> domain safety gates
                              -> local controller/interlocks
                              -> execution
```

`adapters.audio.UntrustedAudioBoundary` accepts bounded metadata and creates
strict proposals only for structured tone payloads. Speech is never parsed as
an executable command by the reference boundary. Subsonic and ultrasonic
payloads remain untrusted proposals and cannot override Pulpo, reset safety
state, alter policy, enroll credentials, or bypass local interlocks.

## CVE applicability inventory

Audio is an attack modality, not a CVE identifier. Review CVEs and advisories
for the exact deployed component in these categories:

| Component category | Review for |
|---|---|
| Microphone, codec, DSP, and audio firmware | memory corruption, parser bugs, DMA, privilege escalation |
| Speech-recognition and audio ML runtimes | unsafe deserialization, model loading, prompt/command injection |
| Audio drivers and kernel interfaces | device escape, privilege escalation, malformed-frame handling |
| QR/radio/acoustic modem decoders | parser overflow, replay, unauthenticated command acceptance |
| ROS 2, MAVLink, vehicle, and spacecraft audio adapters | injection, unsafe defaults, authorization bypass |
| External operator tools and gateways | dependency, browser, API, and authentication vulnerabilities |

No CVE should be marked applicable merely because it mentions audio. Record the
exact product, version, platform, affected range, fix, deployment exposure,
and evidence. If no exact component is present, classify the record as
**Not applicable** or **Unknown**, not as a Pulpo vulnerability.

## Required controls

- Keep speech transcripts and acoustic payloads outside authority state.
- Bind accepted proposals to sensor identity, capture time, observation digest,
  machine, target, action, policy, session, nonce, and expiry.
- Require an independently issued canonical permit and local safety gates.
- Reject malformed, oversized, stale, replayed, contradictory, and
  out-of-band audio input.
- Rate-limit decoding and bound buffers, queues, CPU, memory, and model calls.
- Test loud, quiet, subsonic, ultrasonic, replayed, delayed, and overlapping
  signals, including false emergency or maintenance instructions.

The proposal parser and adversarial tests are **Verified** at the
implementation commit. Resistance to microphone hardware compromise,
acoustic injection at range, sensor fusion attacks, DSP/firmware CVEs, and
model-specific speech attacks remains **Unknown** until tested on the target
platform.
