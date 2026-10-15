"""Run disposable simulation proofs; no hardware endpoints or runtime authority.

Benchmark method adapted from Preview's benchmark_unique_audit_scan.py:
setup excluded, monotonic wall/process CPU, separate allocation pass, raw samples.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.simulation_support import DeterministicWorld, SCENARIOS, SimulationFixture, Motion, run_case


def benchmark(iterations):
    samples = []
    cpu_start = time.process_time_ns()
    for _ in range(iterations):
        fixture = SimulationFixture(DeterministicWorld())
        motion = Motion()
        intent = fixture.intent(motion)
        start = time.perf_counter_ns()
        decision = fixture.projection.evaluate(intent, fixture.directive)
        consumed, _ = fixture.attempt(motion, intent, decision.permit)
        samples.append(time.perf_counter_ns() - start)
        if not consumed or not fixture.kernel.verify_audit():
            raise AssertionError("benchmark_canonical_validation_failed")
    cpu = time.process_time_ns() - cpu_start
    fixture = SimulationFixture(DeterministicWorld())
    intent = fixture.intent(Motion())
    tracemalloc.start()
    try:
        decision = fixture.projection.evaluate(intent, fixture.directive)
        fixture.attempt(Motion(), intent, decision.permit)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return {"iterations": iterations, "samples_ns": samples,
            "median_ns": statistics.median(samples),
            "p95_ns": sorted(samples)[math_ceil_95(iterations) - 1],
            "max_ns": max(samples), "process_cpu_ns_including_setup_and_validation": cpu,
            "separate_pass_peak_python_bytes": peak,
            "scope": "deterministic canonical evaluate + shared safety + consume + kinematic send; "
                     "fixture setup and audit verification excluded from latency; no ROS, Gazebo, "
                     "DDS, I/O, real-time guarantee, native RSS, GPU, or hardware performance claim"}


def math_ceil_95(n):
    return (95 * n + 99) // 100


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("deterministic", "gazebo"), default="deterministic")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 1000:
        parser.error("iterations must be between 1 and 1000")
    report = {"schema": "pulpo.simulation-test.v1", "backend": args.backend,
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "python": sys.version, "platform": platform.platform(), "results": [],
              "source_hashes": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for pattern in ("tests/*simulation*.py", "scripts/*simulation*.py",
                                                "experiments/ros2-gazebo/*", "pulpo/kernel.py",
                                                "pulpo/state.py", "pulpo/directives.py", "domains/safety.py")
                                for p in ROOT.glob(pattern) if p.is_file()},
              "claim": "Scenario results apply only to the named test backend. Synthetic test authority; "
                       "no independent authority or physical safety certification. Bypass detection is not containment."}
    try:
        if args.backend == "gazebo":
            report["installed_packages"] = subprocess.check_output([
                "dpkg-query", "-W", "-f=${Package}=${Version}\n", "ros-jazzy-*"], text=True).splitlines()
            from scripts.ros2_simulation_world import GazeboWorld
            with GazeboWorld() as world:
                for name in SCENARIOS:
                    world.local_stop = False
                    world.remapped = name == "remapped_cmd_vel_bypass"
                    report["results"].append(run_case(name, world))
        else:
            report["results"] = [run_case(name, DeterministicWorld()) for name in SCENARIOS]
        report["benchmark"] = benchmark(args.iterations)
        report["passed"] = all(row["passed"] for row in report["results"])
    except Exception as exc:
        report.update(passed=False, classification="Unknown", error=f"{type(exc).__name__}: {exc}")
    if sys.platform == "linux":
        import resource
        report["peak_process_rss_kib_including_imports_and_setup"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "backend": args.backend,
                      "cases": len(report["results"]), "output": str(args.output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
