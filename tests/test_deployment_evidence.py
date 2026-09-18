from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_deployment_evidence.py"
SPEC = importlib.util.spec_from_file_location("validate_deployment_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def manifest() -> dict[str, object]:
    sha = "a" * 64
    return {
        "schema": "pulpo-autonomous.deployment-evidence.v1",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "software": {"name": "pulpo-autonomous", "version": "0.1.0", "source_tree_sha256": sha},
        "dependencies": [{"name": "python", "version": "3.11.9", "source": "runtime", "sha256": sha}],
        "platform": {"os": "Linux 6.8", "architecture": "x86_64", "python": "3.11.9"},
        "hardware": {"manufacturer": "Example", "model": "simulator", "identity": "sim-001", "identity_source": "operator inventory"},
        "tests": [{"name": "GTM simulator", "command": "python scripts/run_gtm_evaluation.py", "result": "pass", "output_sha256": sha}],
        "limitations": ["simulation only"],
        "claims": [{"claim": "bounded execution demo passes", "classification": "Verified", "evidence": "GTM simulator output"}],
        "integration_boundaries": [{"boundary": "local controller interlock", "owner": "adopter", "required_control": "must remain authoritative"}],
        "authority_effect": "none",
        "governed_effect": "evidence and bounded execution evaluation only",
    }


class DeploymentEvidenceTests(unittest.TestCase):
    def test_valid_manifest_is_accepted(self):
        self.assertEqual(validator.validate_manifest(manifest())["schema"], "pulpo-autonomous.deployment-evidence.v1")

    def test_missing_identity_and_test_hash_fail_closed(self):
        invalid = manifest()
        del invalid["hardware"]["identity"]
        with self.assertRaisesRegex(ValueError, "hardware.*identity"):
            validator.validate_manifest(invalid)
        invalid = manifest()
        invalid["tests"][0]["output_sha256"] = "not-a-hash"
        with self.assertRaisesRegex(ValueError, "output_sha256"):
            validator.validate_manifest(invalid)

    def test_authority_expansion_and_invalid_claim_are_rejected(self):
        invalid = manifest()
        invalid["authority_effect"] = "grant"
        with self.assertRaisesRegex(ValueError, "authority_effect"):
            validator.validate_manifest(invalid)
        invalid = manifest()
        invalid["claims"][0]["classification"] = "Marketing"
        with self.assertRaisesRegex(ValueError, "classification"):
            validator.validate_manifest(invalid)
        invalid = manifest()
        invalid["tests"][0]["result"] = "fail"
        with self.assertRaisesRegex(ValueError, "failed evidence"):
            validator.validate_manifest(invalid)
        invalid = manifest()
        invalid["tests"][0]["result"] = "not_run"
        with self.assertRaisesRegex(ValueError, "notes"):
            validator.validate_manifest(invalid)


if __name__ == "__main__":
    unittest.main()
