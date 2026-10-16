# Disposable ROS 2 / Gazebo simulation tester

This is an opt-in, owner-run test fixture. It exercises the existing kernel,
directive controller/projection, permit consumption, and shared safety gate.
It adds no installed ROS executor, router, service, authority plane, or ledger.
The original `adapters.ros2.ROS2Adapter` remains a translation stub. Do not treat
this experiment as a production robotics adapter or hardware commissioning.

## Run and review

From the repository root, Python 3.11 or newer:

```sh
python -W error -m unittest tests.test_simulation_tester -v
python scripts/test_simulation.py --output /tmp/pulpo-sim/deterministic.json
```

For actual ROS 2 Jazzy / Gazebo Harmonic, use a disposable container, with no
host networking, devices, Docker socket, credentials, or live robot endpoints:

```sh
docker build -f experiments/ros2-gazebo/Dockerfile -t pulpo-disposable-sim .
mkdir -p simulation-results
docker image inspect pulpo-disposable-sim > simulation-results/image.json
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -e GZ_PARTITION=pulpo-disposable-review \
  -v "$PWD:/fixture:ro" -v "$PWD/simulation-results:/results" \
  pulpo-disposable-sim --output /results/gazebo.json
```

The base image is pinned by digest. Apt packages remain repository-versioned,
not hermetically pinned; the report records installed ROS package versions.
`simulation-results/` is an operator-selected report directory, not canonical
state. Reports include the exact source commit, dirty status, source hashes,
backend, Python/platform, observations, expected outcomes, audit records and
verification results. Existing CI remains intact; the new workflow runs the
deterministic proof on PRs and allows a manual isolated Gazebo job. No image
push, deployment, release, merge, or hardware communication is performed.

## Scenario contract

| Scenario | Required result |
| --- | --- |
| Permitted move | Exact bound motion, canonical permit consumed, observed motion |
| Denied action | Canonical directive denial, no observed motion |
| Replay | First send succeeds; reuse rejects with no additional observed motion |
| Exact expiry | Already-issued permit rejects at its expiry timestamp |
| Revocation | Canonically approved fixture revocation invalidates a preissued permit |
| Motion substitution | Changed speed rejects before consumption or send |
| Human / stale sensor / geofence / resource | Existing shared safety gate vetoes |
| Safe degraded mode / emergency stop | Existing safety state vetoes; latch is not reset |
| Local interlock | Valid permit remains subordinate to the simulated sink veto |
| Raw command / remapped command | Deliberate bypass produces unexpected effect and reports containment false |

Each matrix case requires the specific control outcome as well as the observed
effect and audit integrity. The replay control must first execute. ROS readiness
requires odometry and subscribers for both publishers; startup is bounded to
30 seconds. A new odometry sample is required for each observation. Missing or
nonfinite observations reconcile to `unknown` and fail the proof. Timeout or
transport failure exits nonzero; partial results and the error remain in the
report. Unit tests cover ambiguous send without retry, missing observations,
evidence tampering, bounded motion, latch preservation, and canonical SQLite
one-use consumption after reopening.

Commands are at most 0.2 m/s for 0.5 seconds on hardcoded disposable endpoints.
Parameters, endpoint, principal and session are bound through the existing
`Intent` hash. No parallel permit format or replay/revocation store is added.
Governance uses a synthetic clock so exact expiry can be tested without
scheduler-dependent sleeps; ROS publication and observation use monotonic wall
time. Reconciliation classifies displacement over 1 cm as observed motion and
over 5 mm without consumption as unexpected effect. It never grants authority,
rewrites canonical outcomes, or retries an uncertain effect.

## Safety and bypass evidence boundary

**Verified in the named fixture:** allow/deny and adversarial outcomes, canonical
audit integrity, and observations described by the result files.

**Recorded limitation:** the raw and remapped publishers reach the DiffDrive
actuator without consuming a Pulpo permit. Their expected detection makes the
test pass, but `containment_proven=false` remains explicit. These are positive
attack controls, not a claim that ordinary ROS topics enforce governance. A
deployment must separately enumerate and restrict controller topics, bridges,
services, actions, remaps, direct Gazebo transport and hardware interfaces. This
fixture tests two command-topic paths, not that entire graph. It does not
implement SROS2 permissions, actuator custody, or isolation from a hostile host.

**Unknown:** production bypass closure, hostile ROS participants, physical
motion, collision avoidance, sensor spoofing, hardware interlock behavior,
network faults, real-world stopping distance, long-run resource use, or safety
certification. Gazebo odometry is simulated wheel-based feedback, not an
independent ground-truth measurement. Sensor health and local-interlock flags
are test doubles. The local-interlock case proves test composition preserves a
sink veto; it does not establish an independently implemented safety controller.

Independent emergency stops, collision avoidance, watchdogs, human overrides,
and actuator interlocks remain controller/hardware responsibilities and retain
their veto. The tester neither disables nor resets deployed safety systems.

## Measurement scope

The report retains per-case attempt wall time, plus a separate deterministic
benchmark with 100 raw samples by default (bounded to 1–1000), median, nearest-
rank p95 and maximum latency, process CPU, and a separate untimed Python
allocation pass. Linux additionally reports peak process RSS including imports
and setup. Latency times canonical evaluate, shared safety, consumption and
kinematic send; setup and final audit verification are excluded. CPU explicitly
includes setup and validation. Gazebo case wall time includes command duration
and ROS spinning; it is not isolated kernel latency. Gazebo and bridge child
process CPU/RSS are not measured. No deadline, throughput, energy, GPU, fleet-
capacity, hardware-performance or performance-improvement claim follows.

## Governance change record

1. Failure addressed: governance decisions alone do not establish motion or
   absence of motion; alternative actuator routes can bypass that path.
2. Deployed authority is unchanged. Fixture setup activates synthetic bounded
   directives; the revocation case narrows synthetic authority using the
   existing independently-approved-transition contract and test-only signer.
   That signer is the repository's existing HMAC test double and proves no
   independent production authority. No human credential is used or introduced.
3. Canonical mutations are confined to disposable fixture state: existing
   approval consumption, permit issue/bind/consume/reject, directive activation
   and revocation, and their existing audit events. The current kernel and
   directive controller control them. JSON reports are projections and
   observations, not a second canonical audit source. No runtime writer is
   exposed to a transport or added to a read-only projection.
4. Exact outcomes and source SHAs are recorded in `simulation-evidence/` and the
   validation record. Existing production governance files are unchanged.
5. Evidence does not establish deployed authority independence, physical safety,
   production adapter completeness, or bypass containment.
6. Claims are classified above; measured timings are Recorded observations.
7. Legacy sources are the canonical Autonomous kernel/directives/shared safety
   and Preview benchmark methodology. No Preview control path is copied.
8. Historical baseline is reconstructed at exact Autonomous commit
   `de2f9e9c9e2a9256d07aaef056519e2733db8324`, with its original policy, authority
   and tests. The original ROS adapter is a stub; there is no relevant historical
   ROS/Gazebo tester checkpoint to claim temporal transfer against. Baseline
   regression evidence establishes existing behavior only. Preview measurement
   conventions are adapted as reporting, not a verified reusable scheduling or
   authority lesson; no future approval, credential or permission travels back
   to a historical state. General temporal transfer remains Unknown.
