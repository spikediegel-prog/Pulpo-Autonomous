# Preview applicability review — 2026-10-15

Autonomous base: `de2f9e9c9e2a9256d07aaef056519e2733db8324` (`main`, v0.3.0).
Preview inspected main: `12d07e37a34c979fc054872299191bb26c8ad387`.
Preview alternate `preview`: `e29e46c494d4f00a00bc2b4206b2d64974ee74c6`.
Exact fetched remote branch tips for both repositories are in
`simulation-evidence/repository-inventory.json`. Branch names are evidence of
available work, not authority to merge it. No open Autonomous PR existed when
this work began.

| Preview source | Applicability and decision |
| --- | --- |
| `08a688e1fcec2202b2d7e834f8caa70433c4c165`, `experiments/mixed-workload-20261014/` | Adapt explicit source/evidence/scope reporting and separation of test fixture from runtime. SQL/API worker scheduling is unrelated to robotics control and is not ported. |
| `2fb11f9cd0c591935a1e3f53d0c001643b6b657b`, `scripts/benchmark_unique_audit_scan.py` | Selectively adapt reporting methodology: setup excluded, separate allocation pass, retained raw samples, exact SHA/source hashes, explicit CPU/platform scope. Verified by running the new benchmark and correctness matrix; no speedup is asserted. The canonical audit streaming change itself is not copied. |
| `bb16c8ad24b0aa615eb80c30e61ab4be712c4de6`, `pulpo/kernel.py` and related canonical JSON paths | Encoder reuse could reduce allocation, but byte compatibility and concurrency/history replay deserve a separate canonical audit change. Not necessary for simulation; deferred. |
| `824020d36562befdcf12753a0ef74ae06f49a8ef`, `pulpo/traffic.py` | Bounded SQL/API queues and expiry use a different intake than Autonomous's existing command traffic path. Do not introduce another router or change command timing under this feature. Deferred. |
| `af5ce1a730c0a07a8331fbb9214290ae2b9a5561`, `pulpo/resources.py`, lifecycle and traffic changes | Deterministic cleanup is relevant. New simulation code uses bounded waits, stop-on-exit, process termination and explicit database close; importing Preview's resource owner or idle routing is unnecessary. Existing database cleanup failures are recorded, not silently repaired in this PR. |
| `3972c1e49310451d81fd9639ecc181f07d5cd495`, `pulpo/mcp_plugin.py` and portability tests | Relevant to separate Windows support, including native snapshot handle security. No simulation requirement depends on MCP snapshot loading; do not selectively weaken that boundary to make Windows tests pass. Deferred as a separately reviewed port. |
| `0bd2b96f1f525ff3c820c15c06e3092887343efe`, authenticated restart checkpoint | Canonical restart trust and durability change is unrelated to a new test sink. Deferred. |
| `40fa56d2497b653fcdb1a6fdbfcbc3b509f4a9c2`, PTC prototype; tuning/ledger branches | No second routing, authority, executor, ledger, tuning authority, or control-plane port. Autonomous already has an experimental PTC branch; it is not the implementation base. |

**Verified by file scope:** the port consists of test/reporting conventions,
implemented in new simulation fixture files. No Preview production source is
cherry-picked, and no Autonomous kernel, state backend, executor, orchestrator,
authority service, custody service, or router is modified. The new fixture owns
synthetic test setup only. Preview's experimental results are not relabeled as
Autonomous results or evidence of physical safety.

**Unknown:** whether the deferred optimizations improve Autonomous on its target
hardware without negative transfer. The exact base/candidate regression runs
and measurements here verify the simulation feature's local behavior, not those
deferred changes.

ROS bridge syntax and the differential drive fixture follow the primary
[ROS Jazzy bridge documentation](https://docs.ros.org/en/jazzy/p/ros_gz_bridge/)
and [Gazebo Harmonic moving robot documentation](https://gazebosim.org/docs/harmonic/moving_robot/).
