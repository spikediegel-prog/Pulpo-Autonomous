# Simulation validation record — 2026-10-15

**Tested source commit:** `9e8a73cdfef1475ccb88459ce4b4a3a5b17df22c`.
**Autonomous base:** `de2f9e9c9e2a9256d07aaef056519e2733db8324`.
**Preview inspected main:** `12d07e37a34c979fc054872299191bb26c8ad387`.
Later commits add this record, branch review detail and evidence only; they do
not change the tested executable sources. Each JSON report also carries source
hashes, dirty status, environment, canonical audit projections and raw samples.
The dirty status in some runs reflects evidence files being collected, not a
claim that the checkout was clean. SHA plus recorded hashes identify the tested
behavior; recorded results do not authenticate the host.

## Outcomes

| Check | Recorded result |
| --- | --- |
| Exact untouched base, Ubuntu Python 3.14.4 | 429 tests, OK, 12 skipped |
| Candidate, Ubuntu Python 3.14.4 | 436 tests, OK, 12 skipped |
| Candidate, ROS image Python 3.12 | 436 tests, OK, 12 skipped |
| New focused unit suite, Windows bundled Python | 7 tests, OK; matrix covers 15 scenarios |
| Deterministic matrix, Ubuntu and Windows | 15/15 in each report |
| Live ROS 2 Jazzy / Gazebo Harmonic matrix | 15/15, repeated twice with recorded image identities |
| Compilation and whitespace | Passed for new Python sources and committed diff |
| Windows exact base full suite | 429 tests; 12 failures, 118 errors, 13 skipped |
| Windows candidate full suite | 436 tests; 14 failures, 118 errors, 13 skipped |

The Linux base and candidate both emit existing Python 3.14 database finalizer
ResourceWarnings. Windows failures include open SQLite cleanup handles,
platform-dependent snapshot behavior, and Git report expectations. The candidate
Windows run has two additional Git report failures; earlier run counts also
vary. A clean Windows regression result is **Unknown**, and this feature does
not repair those existing subsystems. `regression-summary.json` records exact
failure/error identities, aggregate outcomes, and raw local-log hashes. The
initial Windows run had 434 tests while two additional feature tests were being
added; it is retained as an initial observation, not final validation.

The optional independent Ed25519 tests remain skipped in the zero-dependency
full-suite environments. Synthetic HMAC test authority is not evidence of a
deployed independent authority service. Existing authority CI remains unchanged.

Final live run: permitted motion displaced simulated odometry by 0.107800 m.
Raw command bypass displaced 0.100099 m, and the separate remapped publisher
displaced 0.103995 m. Both bypasses reconciled as `unexpected_effect` with
`containment_proven=false`. Denial/replay/expiry/revocation/substitution and
safety veto cases produced no additional observed motion within the declared
5 mm tolerance. A valid consumed permit with the simulated local interlock
engaged produced `no_observed_motion`, preserving the sink's veto.

The final build uses image
`sha256:c92d2425d993aba4082ff221b85d3600c06f45ff52f6055f0bc6c9ed815f0923`.
The earlier successful live run and full Python 3.12 suite used image
`sha256:7f5c9e7fe49316fcb7b0a66227039a9915e7d602ad7a28714dd02bcc6d7bc004`,
with `GZ_IP=127.0.0.1` supplied at run time for the live run. The final image
sets that value in its Dockerfile and pins the same resolved ROS base digest;
the installed package layer is identical. Both runs used `--network none`,
dropped capabilities, no-new-privileges, read-only source, a disposable ROS
domain/Gazebo partition, and no devices or credentials. Image metadata and
installed ROS package versions are retained.

**Recorded benchmark, final container run:** 100 deterministic samples;
median 172,262 ns, p95 227,033 ns, max and individual samples in
`gazebo-final.json`; process CPU including fixture setup/validation 74,557,615 ns;
separate allocation-pass peak 6,705 Python bytes. Full runner peak RSS 75,884 KiB
includes imports, ROS setup, reports and benchmark, and excludes Gazebo/bridge
children. These are local measurements, not deadlines, real-time proof, or a
Preview performance comparison. See the measurement scope in the tester guide.

## Files and review scope

- `tests/simulation_support.py`: bounded test-only composition of the existing
  kernel, directive authority controller/projection and shared safety gate;
  deterministic world and read-only effect reconciliation.
- `tests/test_simulation_tester.py`: matrix, unknown evidence, malformed motion,
  latch preservation, ambiguous-send non-retry, audit tampering and SQLite replay.
- `scripts/test_simulation.py`: bounded CLI, report/source provenance, benchmark,
  nonzero failure exit and optional live backend selection.
- `scripts/ros2_simulation_world.py`: hardcoded disposable topics, fresh odometry,
  separate remapped attack publisher, bounded startup and owned process cleanup.
- `experiments/ros2-gazebo/{Dockerfile,world.sdf}`: local test image and robot/world.
- `.github/workflows/simulation.yml`: PR deterministic proof and manual live job.
- `adapters/ros2/README.md`: discovery link and explicit adapter maturity boundary.
- `docs/SIMULATION_TESTER.md`, `docs/SIMULATION_PREVIEW_REVIEW.md`, this record and
  `docs/simulation-evidence/`: contracts, source review, exact results and limits.

No production Python source, policy, canonical state schema, authority/custody
service, router, executor, ledger, or original CI admission gate changes.
The source tree and executable review scope remain additive test tooling.
The owner-run fixture's existing canonical mutations are enumerated in the
tester guide; all are confined to disposable test state.

## Claim boundary

**Verified:** executable scenario outcomes at the recorded source/hashes and
backends, exact expected denial reasons, canonical audit integrity checks,
one-use persistence test, and unchanged production file scope.

**Recorded:** timings, source/branch inventories, package/image identities and
platform-specific regression outcomes. All fetched branches were inventoried;
recent applicable improvements were reviewed, not every historical branch.

**Proposed:** review and eventual integration of this test harness. No merge,
deployment, release, image publication, or safety-system replacement is included.

**Unknown:** production bypass containment, independent physical safety,
full Windows compatibility, sustained resource behavior, and general temporal
transfer. No historical ROS tester checkpoint exists to claim a transferable
ROS testing lesson; exact-base regression evidence does not manufacture one.
