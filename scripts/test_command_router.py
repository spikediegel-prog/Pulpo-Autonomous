"""Run the non-authoritative Autonomous router proof with explicit local source."""
import argparse
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--router-source", type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    if args.router_source is not None:
        source = args.router_source.resolve()
        if not (source / "sentry_traffic" / "router.py").is_file():
            parser.error("router source must contain the existing sentry_traffic package")
        sys.path.insert(0, str(source))
    import sentry_traffic  # No skipped integration proof when explicitly invoked.
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        "tests.test_command_traffic", "tests.test_offline_autonomy",
        "tests.test_cold_boot", "tests.test_shared_safety", "tests.test_spacecraft_operations",
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and not result.skipped else 1

if __name__ == "__main__":
    raise SystemExit(main())
