#!/usr/bin/env python3
"""Run a dependency-free Pulpo Autonomous evaluation-kit demonstration."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.envelope import ExecutionEnvelope
from core.execution import ExecutionTracker
from core.journal import DurableJournal
from core.offline_protocol import ExecutionState, OfflineMissionLease, OfflineProtocol


ISSUED = datetime(2030, 1, 1, tzinfo=timezone.utc)


def git_revision() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "UNKNOWN"


def make_tracker(path: Path) -> tuple[ExecutionTracker, OfflineProtocol]:
    envelope = ExecutionEnvelope(
        permit_id="permit:demo",
        action="observe",
        target="unit:demo",
        machine_id="unit:demo",
        domain="robotics",
        issued_at=ISSUED,
        expires_at=ISSUED + timedelta(minutes=10),
    )
    lease = OfflineMissionLease.issue(
        envelope,
        lease_id="lease:demo",
        principal="operator:demo",
        policy_id="policy:demo",
        deployment_id="deployment:demo",
        session_id="session:demo",
        nonce="nonce:demo",
        max_disconnected=timedelta(minutes=5),
        max_commands=1,
        safe_fallback="hold",
        issued_at=ISSUED,
    )
    protocol = OfflineProtocol(lease)
    return ExecutionTracker(protocol, DurableJournal(path)), protocol


def run_demo() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="pulpo-gtm-evaluation-") as directory:
        journal_path = Path(directory) / "events.jsonl"
        tracker, protocol = make_tracker(journal_path)
        sent = tracker.execute(
            "command:observe",
            "observe",
            (ISSUED + timedelta(minutes=1)).isoformat(),
        )
        protocol.disconnect(ISSUED + timedelta(minutes=2))
        fallback = tracker.execute(
            "command:second",
            "observe",
            (ISSUED + timedelta(minutes=8)).isoformat(),
        )
        unknown = tracker.observe(
            "command:uncertain",
            ExecutionState.UNKNOWN,
            (ISSUED + timedelta(minutes=3)).isoformat(),
        )
        tamper_detected = False
        with journal_path.open("a", encoding="utf-8") as stream:
            stream.write('{"event":"forged"}\n')
        try:
            tracker.journal.read()
        except (KeyError, ValueError, json.JSONDecodeError):
            tamper_detected = True

        return {
            "schema": "pulpo-autonomous.gtm-evaluation.v1",
            "commit": git_revision(),
            "claim_classification": "Verified",
            "authority_effect": "none",
            "governed_effect": "bounded execution and evidence only",
            "scenarios": {
                "authorized_command": sent.value == "sent",
                "offline_budget_fallback": fallback.value == "safe_fallback",
                "uncertain_result_not_retried": unknown.value == "unknown",
                "journal_tamper_detected": tamper_detected,
            },
            "limitations": [
                "simulation only; no actuator, navigation, or flight-controller claim",
                "does not prove hardware, network, or mission safety",
                "deployment must integrate canonical permits and local interlocks",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="also write the JSON evidence bundle")
    args = parser.parse_args()
    result = run_demo()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if all(result["scenarios"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
