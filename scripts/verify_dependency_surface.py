from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    manifest = json.loads(
        (ROOT / "deployments" / "onboard" / "manifest.json").read_text(encoding="utf-8")
    )
    sbom = json.loads(
        (ROOT / "sbom" / "pulpo-autonomous.cdx.json").read_text(encoding="utf-8")
    )
    lock = (ROOT / "requirements-mcp.lock").read_text(encoding="utf-8")

    if not re.search(r'mcp\s*=\s*\["mcp\[cli\]==2\.2\.0"\]', pyproject):
        raise SystemExit("mcp_dependency_must_be_pinned_to_2.2.0")
    excluded = set(manifest["excluded_surfaces"])
    required = {
        "mcp",
        "openai",
        "anthropic",
        "claude",
        "codex",
        "mcp-remote",
        "mcp-inspector",
        "tunnel-client",
    }
    if not required.issubset(excluded):
        raise SystemExit("onboard_manifest_missing_external_tool_exclusion")
    components = {
        (component["name"], component["version"])
        for component in sbom["components"]
    }
    if ("mcp", "2.2.0") not in components:
        raise SystemExit("sbom_missing_pinned_mcp_component")
    if "mcp==2.2.0" not in lock:
        raise SystemExit("mcp_lock_missing_pinned_version")
    print("dependency-surface-validation-ok")


if __name__ == "__main__":
    main()
