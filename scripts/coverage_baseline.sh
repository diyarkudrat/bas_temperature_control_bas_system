#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

COVERAGE_CMD=${COVERAGE_CMD:-python3 -m coverage}
read -r -a coverage_cmd <<< "${COVERAGE_CMD}"

if ! command -v "${coverage_cmd[0]}" >/dev/null 2>&1; then
  echo "[error] Coverage command '${COVERAGE_CMD}' is not available. Set COVERAGE_CMD to a valid executable." >&2
  exit 127
fi

export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/coverage_baseline.sh [--suite <suite>] [--] [additional pytest args]

Runs the unit test suites under multiple roadmap contexts (architecture, reliability, security)
and emits HTML + JSON coverage artifacts into the coverage/ directory.

Options:
  --suite <suite>   Limit execution to a logical suite (all | api | auth | logging). Default: all.
  -h, --help        Show this message and exit.

Environment overrides:
  PYTEST_TARGETS             Space-delimited list of test paths/expressions to execute.
  PYTEST_MARKER_ARCHITECTURE Pytest expression appended for the architecture context run.
  PYTEST_MARKER_RELIABILITY  Pytest expression appended for the reliability context run.
  PYTEST_MARKER_SECURITY     Pytest expression appended for the security context run.

Any arguments following `--` are forwarded directly to pytest.
USAGE
}

suite="all"
pytest_passthrough=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)
      suite="${2:-}"
      if [[ -z "${suite}" ]]; then
        echo "[error] --suite requires a value" >&2
        exit 1
      fi
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      pytest_passthrough+=("$@")
      break
      ;;
    *)
      pytest_passthrough+=("$1")
      shift
      ;;
  esac
done

declare -a pytest_targets
if [[ -n "${PYTEST_TARGETS:-}" ]]; then
  # shellcheck disable=SC2206
  pytest_targets=(${PYTEST_TARGETS})
else
  case "${suite}" in
    all)
      pytest_targets=(tests/unit)
      ;;
    api)
      pytest_targets=(tests/unit/api tests/unit/http)
      ;;
    auth)
      pytest_targets=(tests/unit/auth)
      ;;
    logging)
      pytest_targets=(tests/unit/logging)
      ;;
    *)
      if [[ -d "${suite}" || -f "${suite}" ]]; then
        pytest_targets=("${suite}")
      else
        echo "[error] Unknown suite '${suite}'." >&2
        exit 1
      fi
      ;;
  esac
fi

mkdir -p coverage/html
mkdir -p coverage/xml
mkdir -p coverage/json

report_basename="${suite}"
if [[ "${report_basename}" == "" || "${report_basename}" == "all" ]]; then
  report_basename="combined"
fi
report_basename="${report_basename//[^a-zA-Z0-9_-]/-}"

echo "[coverage] Erasing previous data..."
"${coverage_cmd[@]}" erase

themes=(architecture reliability security)

for theme in "${themes[@]}"; do
  marker_suffix=$(printf '%s' "${theme}" | tr '[:lower:]' '[:upper:]')
  marker_var="PYTEST_MARKER_${marker_suffix}"
  marker_value="${!marker_var:-}"
  if [[ -n "${marker_value}" ]]; then
    marker_args=(-m "${marker_value}")
  else
    marker_args=()
  fi

  echo "[coverage] Running theme '${theme}' on targets: ${pytest_targets[*]}" >&2
  cmd=("${coverage_cmd[@]}" run --parallel-mode --context="${theme}" -m pytest "${pytest_targets[@]}")
  if [[ ${#marker_args[@]} -gt 0 ]]; then
    cmd+=("${marker_args[@]}")
  fi
  if [[ ${#pytest_passthrough[@]} -gt 0 ]]; then
    cmd+=("${pytest_passthrough[@]}")
  fi
  "${cmd[@]}"
done

echo "[coverage] Combining data files..."
"${coverage_cmd[@]}" combine

echo "[coverage] Generating reports..."

fail_under="${COVERAGE_FAIL_UNDER:-}"
report_args=(-m)
if [[ -n "${fail_under}" ]]; then
  report_args+=("--fail-under=${fail_under}")
fi

"${coverage_cmd[@]}" report "${report_args[@]}"
"${coverage_cmd[@]}" html -d coverage/html/${report_basename}
"${coverage_cmd[@]}" xml -o coverage/xml/${report_basename}.xml
"${coverage_cmd[@]}" json -o coverage/json/${report_basename}.json

cp coverage/json/${report_basename}.json coverage/baseline.json 2>/dev/null || true

cat <<'SUMMARY'

Coverage artifacts generated:
  - coverage/html/${report_basename}/index.html
  - coverage/xml/${report_basename}.xml
  - coverage/json/${report_basename}.json

Each coverage run is tagged via --context (architecture, reliability, security). Downstream
analysis tools can consume the JSON report for theme-specific slices.
SUMMARY


