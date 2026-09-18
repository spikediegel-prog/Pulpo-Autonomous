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
