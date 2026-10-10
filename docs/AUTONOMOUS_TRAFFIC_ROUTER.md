# Opt-in Autonomous command traffic intake

Frozen base: `9a354938d5a59e30d638ca0ab078c26dcdaf8e39`.
Authority delta: unchanged. No canonical mutation capability is introduced or
exposed. Existing tracker operations and their durable journal remain the only
command lifecycle path modified by this integration.

## Insertion point and configuration

`ExecutionTracker.execute()` inspects traffic before running its unchanged
original method body. The passive intake holds only settings, a lock and the
existing opaque-byte `sentry_traffic.TrafficRouter`. It never retains a tracker,
protocol, envelope, lease, journal, credential, callback, kernel or executor.
It creates no second routing algorithm, authority ledger or command executor.
The trusted owner proceeds with its original arguments exactly once; routed
bytes cannot substitute another command or grant authority.

Install the existing local scheduling package in your chosen environment:

```powershell
python -m pip install -e C:\Users\spike\SENTRY
```

Then opt in where your host already constructs the tracker:

```python
from core import CommandTrafficSettings, ExecutionTracker

tracker = ExecutionTracker(
    protocol,
    journal,
    traffic_settings=CommandTrafficSettings(),
)
```

Existing callers remain off by default and need no router dependency. Opt-in
fails explicitly if the package is missing; it does not silently bypass intake.
The existing simulation adapter uses the same tracker method without changes.
No service, hardware adapter or mission was launched by this change.

Settings are frozen, positive host-only integer budgets: 128 items, 1 MiB queued
bytes, 64 KiB per command and 30 seconds transport TTL by default. Encoded bytes
and input allocation are bounded. FIFO and batch size one are fixed; priority,
fan-out, deduplication and automatic retries are disabled for physical commands.
There is no recirculation. Busy intake, exhausted item/byte budgets, malformed
input, missing/faulty transport or substituted bytes terminate with
`CommandTrafficRejected(status="REJECT", reason=...)`; expired transport work
terminates with `status="DROP"`. These are transport outcomes, not execution
states or new permission to retry. Waiting for intake is nonblocking.

The synchronous integration admits and drains one command immediately. It does
not introduce a background worker, persistent command queue, delayed execution,
multi-host scheduler or hardware delivery guarantee. The buffer's volatile
state is never used for durable idempotency: duplicates still reach the existing
journal/replay checks. Restart loses pending transport state; it does not clear
or reconstruct command authority or recorded UNKNOWN outcomes.

Safety fallback, observation capture and emergency-stop mechanisms stay outside
transport intake so overload does not suppress their existing guarded paths.
The router does not implement physical safety: existing boot, lease, expiry,
offline-window, command-budget and reconciliation checks remain in the owner.
The shared geofence/sensor/resource and spacecraft guards are not moved into the
router. Their existing tests continue to pass.

## Verification

```powershell
python -W error scripts\test_command_router.py --router-source C:\Users\spike\SENTRY
```

The runner uses an explicitly supplied local source, not a production path hack.
It fails if the router is unavailable or any focused tests skip. Without the
optional dependency, normal root discovery still tests default-off behavior and
skips integration-specific cases; that is not proof of the enabled path.

Verified: 18 baseline autonomy/boot/safety/spacecraft tests passed before edits.
The final focused suite passes 31 tests on Windows Python 3.12.10 and WSL Python
3.14.4. Full WSL root discovery passes 429 tests with one skipped historical
proof because its source commits are absent from this fork. Existing Python
3.14 SQLite finalization warnings remain outside this integration's JSONL path;
no repository-wide warning-cleanup claim is made. Source compilation and
whitespace checks pass. Logs remain local: `router-baseline.log`,
`router-focused-windows.log`, `router-focused-wsl.log`, `router-root-wsl.log`.

AST comparison confirms that original tracker method bodies after the single
intake check, the journal, lease protocol, canonical Pulpo kernel and state are
unchanged. Tests compare exact journal bytes and governed lease/envelope hashes;
exercise FIFO budgets, nonblocking contention, terminal TTL, malformed/Unicode
input, transport faults, substituted bytes, action denial, expired authority,
reconciliation, verified-boot denial, and fallback/observation availability.
The stacked boss round combines disconnection, UNKNOWN observation, tracker and
router restart, duplicate replay and journal tamper. UNKNOWN is preserved and
tamper fails closed without another send.

Reused router SHA-256:
`935717819dc2e57698eb2aaa52e22523da068f1e96f328386c383559c786a55a`.
The source is the existing non-authoritative scheduling package only; no
proprietary SENTRY/PASI decisions, thresholds, deception or topology were copied.

## Gladiator review

| Transformation | Result and boundary |
| --- | --- |
| Flip | SURVIVES: forged command types/settings cannot supply host configuration or authority. |
| Reverse | SURVIVES: transport READY alone cannot create a send; original boot/lease/reconciliation checks still govern. |
| Invert | SURVIVES: transport acceptance is not SENT or observed success; UNKNOWN replay stays UNKNOWN. |
| Inside-Out | SURVIVES: intake retains no governed owner/callback and writes no journal/permit state. |
| Darken | SURVIVES in tests: overflow, contention, expiry, missing transport and byte substitution reject/drop before mutation. |
| Lighten | SURVIVES: valid bytes and journal results match baseline, with no performance claim. |
| Amplify | SURVIVES for tested capacity/replay bounds; multiwriter command races, fleet aggregation and realtime deadlines remain UNKNOWN. |
| Negate | SURVIVES: default-off uses the original owner without another executor; fallback/observation remain outside scheduling. |

Physical permit provenance and live kernel-to-adapter containment are properties
of the existing modeled offline layer, not newly proved by this router. The
inherited tracker/journal is not proven safe for concurrent canonical writes;
nonblocking transport inspection does not serialize the original execution
body. Hardware stop latency, real providers, throughput/CPU/memory improvements,
enterprise/fleet scale and historical transfer remain Unknown. No performance
benchmark was run; earlier Pulpo 1.0 measurements are Recorded and do not prove
transfer to autonomous physical systems. Missing historical commits are not
replaced or invented to manufacture temporal proof.
