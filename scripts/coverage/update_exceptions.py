"""Automate updates to the coverage exceptions register.

This script inspects a coverage JSON report (as produced by
``coverage json``) and ensures the markdown table in
``tests/docs/test_framework_upgrades/coverage_exceptions.md`` reflects
modules that fall below the configured threshold. It is intentionally
lightweight so it can run in CI or locally with ``--dry-run``.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import date
from typing import Iterable, List, Tuple


DEFAULT_THRESHOLDS = {
    "api": 90.0,
    "auth": 90.0,
    "logging": 90.0,
}

SUITE_PREFIXES = {
    "api": ("apps/api/",),
    "auth": ("apps/auth_service/",),
    "logging": ("logging_lib/",),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage-json", required=True, type=pathlib.Path)
    parser.add_argument(
        "--markdown",
        default=pathlib.Path("tests/docs/test_framework_upgrades/coverage_exceptions.md"),
        type=pathlib.Path,
    )
    parser.add_argument("--suite", choices=("api", "auth", "logging"), required=True)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--owner", default="QA")
    parser.add_argument("--exception-type", default="coverage")
    parser.add_argument("--mitigation", default="Add tests or document rationale")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def load_coverage(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def collect_exceptions(data: dict, suite: str, threshold: float) -> List[Tuple[str, float]]:
    prefixes: Iterable[str] = SUITE_PREFIXES.get(suite, ())
    files = data.get("files", {})
    results: List[Tuple[str, float]] = []

    for path, meta in files.items():
        if prefixes and not any(path.startswith(prefix) for prefix in prefixes):
            continue
        summary = meta.get("summary", {})
        percent = float(summary.get("percent_covered", 0.0))
        if percent < threshold:
            results.append((path, percent))

    results.sort(key=lambda item: item[1])
    return results


def build_table(entries: List[Tuple[str, float]], owner: str, exception_type: str, mitigation: str, threshold: float) -> List[str]:
    header = "| Module / Path | Current Coverage | Exception Type | Owner | Rationale | Mitigation Plan | Next Review |"
    separator = "|---------------|------------------|----------------|-------|-----------|-----------------|-------------|"

    if not entries:
        rows = ["| _None (baseline)_ | n/a | n/a | n/a | At or above threshold | Monitor trends | n/a |"]
    else:
        today = date.today().isoformat()
        rows = []
        for path, percent in entries:
            sanitized = path.replace("|", "\\|")
            rows.append(
                "| `{}` | {:.2f}% | {} | {} | Below fail-under {:.0f}% | {} | {} |".format(
                    sanitized, percent, exception_type, owner, threshold, mitigation, today
                )
            )

    return [header, separator, *rows]


def replace_table(markdown: pathlib.Path, table_lines: List[str]) -> str:
    text = markdown.read_text(encoding="utf-8")
    lines = text.splitlines()
    start = None
    end = None

    for idx, line in enumerate(lines):
        if line.strip().startswith("| Module / Path"):
            start = idx
            break

    if start is None:
        raise RuntimeError("Unable to locate coverage exception table header")

    end = start + 1
    while end < len(lines) and lines[end].strip().startswith("|"):
        end += 1

    new_lines = lines[:start] + table_lines + lines[end:]
    return "\n".join(new_lines) + "\n"


def main() -> int:
    args = parse_args()
    threshold = args.threshold or DEFAULT_THRESHOLDS.get(args.suite, 90.0)

    coverage = load_coverage(args.coverage_json)
    exceptions = collect_exceptions(coverage, args.suite, threshold)
    table = build_table(exceptions, args.owner, args.exception_type, args.mitigation, threshold)

    if args.dry_run:
        print("\n".join(table))
        return 0

    updated = replace_table(args.markdown, table)
    args.markdown.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


