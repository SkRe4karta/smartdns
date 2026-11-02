"""Short, bounded release checks; no production load generation."""

import argparse
import subprocess
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=["backend", "integration"])
    group = parser.parse_args().group
    files = (
        ["tests/test_accounts_api.py", "tests/test_catalog_pool.py"]
        if group == "backend"
        else ["tests/test_gateway.py", "tests/test_agent_migration.py"]
    )
    raise SystemExit(subprocess.run([sys.executable, "-m", "pytest", "-q", *files], timeout=110).returncode)
