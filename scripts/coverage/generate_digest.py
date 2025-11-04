"""Produce a markdown digest summarising coverage reports.

The digest is intended for weekly status updates and can be run either on a
schedule or manually. Provide one or more coverage JSON files and optionally an
output path.
"""

from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timezone
from typing import Iterable, List, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=pathlib.Path, help="Coverage JSON report(s) to summarise")
    parser.add_argument("--output", type=pathlib.Path, help="Optional markdown file to write")
    return parser.parse_args()


def read_report(path: pathlib.Path) -> Tuple[str, float, str]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    totals = data.get("totals", {})
    percent = float(totals.get("percent_covered", 0.0))
    meta = data.get("meta", {})
    timestamp = meta.get("timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    suite = path.stem
    return suite, percent, timestamp


def render_table(rows: Iterable[Tuple[str, float, str]]) -> str:
    header = "| Suite | Coverage % | Timestamp |"
    separator = "|-------|------------|-----------|"
    lines: List[str] = [header, separator]

    for suite, percent, timestamp in rows:
        lines.append(f"| {suite} | {percent:.2f}% | {timestamp} |")

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    summaries = [read_report(path) for path in args.inputs]
    markdown = "# Coverage Digest\n\n" + render_table(summaries)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown, encoding="utf-8")
    else:
        print(markdown)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


