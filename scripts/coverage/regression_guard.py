"""Guard against unintended coverage regressions.

Compare a "current" coverage JSON report with a previous baseline and fail when
the drop exceeds the configured threshold. Designed for CI pipelines where the
previous report is supplied via downloaded artifact or repository snapshot.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", required=True, type=pathlib.Path)
    parser.add_argument("--previous", required=True, type=pathlib.Path)
    parser.add_argument("--threshold", type=float, default=2.0, help="Allowed coverage drop in percentage points")
    return parser.parse_args()


def load(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def total_percent(data: dict) -> float:
    totals = data.get("totals", {})
    return float(totals.get("percent_covered", 0.0))


def main() -> int:
    args = parse_args()

    if not args.previous.exists():
        print(f"[regression_guard] Previous coverage report '{args.previous}' not found; skipping comparison.")
        return 0

    current = total_percent(load(args.current))
    previous = total_percent(load(args.previous))
    delta = previous - current

    print(f"[regression_guard] previous={previous:.2f}% current={current:.2f}% delta={delta:.2f}pp")

    if delta > args.threshold:
        print(
            f"::error ::Coverage regression detected ({delta:.2f}pp drop exceeds {args.threshold:.2f}pp threshold)."
        )
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


