# ADR 2025-12 — Coverage Exception Governance

## Status
Accepted — Phase R6

## Context
- Phase R5 introduced automated coverage enforcement (CI matrix with
  `COVERAGE_FAIL_UNDER`, JSON/XML artifacts, regression guard).
- We require a lightweight governance model for modules that temporarily fall
  below the 90% baseline while ensuring visibility and remediation plans.

## Decision
1. **Exception Register:** Maintain `tests/docs/test_framework_upgrades/coverage_exceptions.md`
   as the single source of truth. The Phase R5 workflow runs
   `scripts/coverage/update_exceptions.py` per suite to synchronise the table.
2. **Approval:** Any entry requires an owner, rationale, mitigation plan, and
   review date. Owners must confirm exceptions during PR reviews and quarterly
   audits.
3. **Thresholds:** Default fail-under remains 90% per component. Critical
   security modules (Auth service token flows) target ≥92%; lower thresholds may
   only be granted with Architecture Council approval.
4. **Regression Guard:** `scripts/coverage/regression_guard.py` compares current
   coverage against baselines (`coverage/baselines/*.json`) with a maximum
   tolerated drop of 2 percentage points. Exceeding the threshold blocks the CI
   job until addressed or baseline updated by maintainers.
5. **Cadence:** Review coverage exceptions monthly during coverage digest sync
   and quarterly during portfolio refresh. Update `alignment_checklist.md` with
   next review dates.

## Consequences
- Exceptions remain visible to stakeholders (hiring managers, QA) via the
  register and weekly digest artifacts.
- Developers must document remediation steps when introducing new exceptions.
- The ADR provides a reference point for future tooling (e.g., mutation testing
  pilots) to integrate with governance policy.


