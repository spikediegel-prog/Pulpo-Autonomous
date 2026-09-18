#!/usr/bin/env python3
"""Validate a deterministic, adopter-provided deployment evidence manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "evidence" / "deployment-evidence-manifest.schema.json"
CLASSIFICATIONS = {"Verified", "Recorded", "Inferred", "Proposed", "Unknown"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _error(path: str, message: str) -> ValueError:
    return ValueError(f"{path}: {message}")


def validate_manifest(manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict):
        raise _error("$", "manifest must be an object")
    required = (
        "schema", "commit", "software", "dependencies", "platform", "hardware",
        "tests", "limitations", "claims", "integration_boundaries",
        "authority_effect", "governed_effect",
    )
    missing = [key for key in required if key not in manifest]
    if missing:
        raise _error("$", f"missing required fields: {', '.join(missing)}")
    allowed = set(required)
    unexpected = sorted(set(manifest) - allowed)
    if unexpected:
        raise _error("$", f"unexpected fields: {', '.join(unexpected)}")
    if manifest["schema"] != "pulpo-autonomous.deployment-evidence.v1":
        raise _error("$.schema", "unsupported schema")
    commit = manifest["commit"]
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise _error("$.commit", "must be a lowercase 40-character commit SHA")
    if manifest["authority_effect"] != "none":
        raise _error("$.authority_effect", "must be none; evidence cannot grant authority")
    if not isinstance(manifest["governed_effect"], str) or not manifest["governed_effect"].strip():
        raise _error("$.governed_effect", "must describe the bounded governed effect")

    _validate_object(manifest["software"], "$.software", ("name", "version", "source_tree_sha256"))
    _validate_sha(manifest["software"]["source_tree_sha256"], "$.software.source_tree_sha256")
    for index, dependency in enumerate(_validate_list(manifest["dependencies"], "$.dependencies")):
        _validate_object(dependency, f"$.dependencies[{index}]", ("name", "version", "source"))
        if "sha256" in dependency:
            _validate_sha(dependency["sha256"], f"$.dependencies[{index}].sha256")
    _validate_object(manifest["platform"], "$.platform", ("os", "architecture", "python"))
    _validate_object(manifest["hardware"], "$.hardware", ("manufacturer", "model", "identity", "identity_source"))
    tests = _validate_list(manifest["tests"], "$.tests")
    for index, test in enumerate(tests):
        path = f"$.tests[{index}]"
        _validate_object(test, path, ("name", "command", "result", "output_sha256"))
        if test["result"] not in {"pass", "not_run"}:
            raise _error(f"{path}.result", "must be pass or not_run; failed evidence cannot be accepted")
        if test["result"] == "not_run" and not str(test.get("notes", "")).strip():
            raise _error(f"{path}.notes", "must explain why an unrun test is a limitation")
        _validate_sha(test["output_sha256"], f"{path}.output_sha256")
    _validate_strings(manifest["limitations"], "$.limitations")
    for index, claim in enumerate(_validate_list(manifest["claims"], "$.claims")):
        path = f"$.claims[{index}]"
        _validate_object(claim, path, ("claim", "classification", "evidence"))
        if claim["classification"] not in CLASSIFICATIONS:
            raise _error(f"{path}.classification", "invalid claim classification")
    for index, boundary in enumerate(_validate_list(manifest["integration_boundaries"], "$.integration_boundaries")):
        _validate_object(boundary, f"$.integration_boundaries[{index}]", ("boundary", "owner", "required_control"))
    return manifest


def _validate_list(value: object, path: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise _error(path, "must be a non-empty array")
    if not all(isinstance(item, dict) for item in value):
        raise _error(path, "items must be objects")
    return value


def _validate_object(value: object, path: str, fields: tuple[str, ...]) -> None:
    if not isinstance(value, dict):
        raise _error(path, "must be an object")
    missing = [field for field in fields if field not in value]
    if missing:
        raise _error(path, f"missing required fields: {', '.join(missing)}")
    allowed = set(fields)
    optional = {
        "$.dependencies": {"sha256"},
        "$.platform": {"kernel"},
        "$.tests": {"notes"},
    }
    allowed.update(next((extras for prefix, extras in optional.items() if path.startswith(prefix)), set()))
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise _error(path, f"unexpected fields: {', '.join(unexpected)}")
    for field in fields:
        if not isinstance(value[field], str) or not value[field].strip():
            raise _error(f"{path}.{field}", "must be a non-empty string")


def _validate_strings(value: object, path: str) -> None:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
        raise _error(path, "must be a non-empty array of non-empty strings")


def _validate_sha(value: object, path: str) -> None:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise _error(path, "must be a lowercase 64-character SHA-256")


def validate_file(path: Path) -> dict[str, object]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot read JSON: {exc}") from exc
    return validate_manifest(manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        validate_file(args.manifest)
    except ValueError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"VALID: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
