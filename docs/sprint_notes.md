# CyberMail cybersecurity sprint notes

## Sprint goal

Build the first access-control tests and scanner reports for CyberMail.

## In scope

- incident reports and vulnerability reports
- Bandit scan of this repository
- A timestamped security report

## This week

| Intern | Task | Status |
| --- | --- | --- |
|  | Implement login in `tests/conftest.py` | Not started |
|  | Add the access-control cases in `tests/access_control/test_report_access.py` | Not started |
|  | Add `pip-audit` and `detect-secrets` runners | Not started |

## Decisions

- Secrets stay in `.env` and are never committed.
- Generated files in `reports/` are local output, not source.

## Blockers

-
