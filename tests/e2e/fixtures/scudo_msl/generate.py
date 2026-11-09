#!/usr/bin/env python3
"""Generate the committed Android Scudo MSL runs for the pipeline-scudo e2e spec.

Run from the repo root (or anywhere):

    python tests/e2e/fixtures/scudo_msl/generate.py
"""

import json
import sys
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(OUT_DIR.parents[3]))

from tests.fixtures.generate_scudo_msl_fixtures import (  # noqa: E402
    SECRET_SIZE,
    secret_value,
    write_scudo_msl_fixtures,
)

N_RUNS = 3


def main() -> None:
    written = write_scudo_msl_fixtures(OUT_DIR, N_RUNS)
    expected = {"key_size": SECRET_SIZE, "secret_hex": secret_value(0).hex()}
    (OUT_DIR / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(f"wrote {len(written)} runs and expected.json to {OUT_DIR}")


if __name__ == "__main__":
    main()
