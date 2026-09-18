# Evaluation evidence

This directory is reserved for deployment-specific evidence bundles. Generate
the reproducible evaluation artifact with:

```bash
python scripts/run_gtm_evaluation.py --output evidence/gtm-evaluation.json
```

Generated evidence should be reviewed before distribution and must include the
exact commit, dependency/platform hashes, test output, environment, and
limitations. Do not commit credentials, private keys, telemetry secrets, or
unredacted mission data.

For adopter pilots, use the
[deployment evidence manifest schema](deployment-evidence-manifest.schema.json)
and validate each completed manifest with:

```bash
python scripts/validate_deployment_evidence.py path/to/deployment-evidence.json
```

The validator is dependency-free and fail-closed. It checks exact commit and
software/dependency/platform/hardware identity, test-result hashes, limitations,
claim classifications, and required integration boundaries. It records
evidence only; it cannot issue permits, mutate canonical state, or expand
authority.
