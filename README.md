# CyberMail Cybersecurity Lab

This repository is the cybersecurity workspace for **CyberMail**. It is separate from the application repositories. Interns use it to write access-control tests, security scanning scripts, and security reports.

CyberMail is the central security-operations platform. Teams track threats, vulnerabilities, incidents, and compliance reports.

The work in this repository is defensive. Run tests and scanners only against environments the team is allowed to test, such as a local or shared development API. Do not point these tools at production or at systems you do not own.

## What you will practise

- Automated access-control tests with pytest
- Repeatable scanner scripts with clear exit codes
- Timestamped Markdown reports
- Keeping secrets out of source code

You are expected to write most of the logic. The Python files here show structure and standards. Look for comments that start with `Interns: implement this part`.

## Repository layout

```text
.
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── scanners/          Scanner entry points (Bandit, pip-audit, detect-secrets)
├── tests/
│   ├── access_control/
│   ├── api_security/
│   └── conftest.py
├── automation/        Report generation and repeatable security tasks
├── configs/           Non-secret scanner and test settings
├── reports/           Generated output (not committed)
└── docs/              Vulnerability log and sprint notes
```

## Coding standards

- Use clear names for functions, classes, and variables.
- Write a docstring for every module and function.
- Never hard-code secrets, tokens, or passwords. Load them from environment variables.
- Use `pathlib` for filesystem paths.
- Handle errors and return a message a teammate can act on.
- Make scripts runnable with `if __name__ == "__main__"`.
- Write pytest tests whose names describe the allowed or denied behaviour.
- Keep each function focused on one responsibility.
- Comment only to explain why, or to mark work an intern still has to write.
- Timestamp every generated report.

## Setup

1. Use Python 3.11 or newer.
2. Create a virtual environment and install the pinned libraries.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

macOS or Linux:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

3. Copy the environment template and fill in local values.

```bash
copy .env.example .env
```

On macOS or Linux, use `cp .env.example .env`.

Leave `.env` untracked. The `.gitignore` file already excludes it.

## Run the tests

From the repository root, with the application API running at `API_BASE_URL`:

```bash
pytest
```

Run only the access-control examples:

```bash
pytest tests/access_control
```

The sample tests skip, with a reason, when the required environment variables are missing. That is intentional. Implement login and add the cases described in `tests/access_control/test_report_access.py` before treating the suite as complete.

## Run a scanner

Bandit checks this repository's Python for common security issues. The example runner writes a timestamped file under `reports/`.

```bash
python scanners/bandit_runner.py
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Bandit finished and reported no issues |
| 1 | Bandit finished and reported issues |
| 2 | The scanner could not run |

Add further runners in `scanners/` for `pip-audit` and `detect-secrets`, following the same pattern.

## Generate a report

```bash
python automation/generate_security_report.py
```

The command writes `reports/security-report-<timestamp>.md`. The generator lists scanner outputs it can see. Summarising severity is left for you to implement.

## Where to add your work

| Location | What belongs there |
| --- | --- |
| `tests/access_control/` | Who may read or change incident reports and vulnerability reports |
| `tests/api_security/` | Input validation, authentication, and security headers |
| `scanners/` | One script per scanner, with timestamped output |
| `configs/` | Shared settings that are safe to commit |
| `automation/` | Report assembly and other repeatable tasks |
| `docs/vulnerability_log.md` | Findings your team has confirmed |
| `docs/sprint_notes.md` | What the cybersecurity team did this sprint |

## Safety rules

- Test only the CyberMail environments your lead has approved.
- Do not commit `.env`, tokens, passwords, or raw customer data.
- Do not copy secrets out of scanner output into reports or git.
- Record confirmed findings in `docs/vulnerability_log.md` with the date, impact, and status.
