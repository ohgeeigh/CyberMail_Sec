"""Run pip-audit against requirements.txt and write a timestamped report.

Exit codes: 0 = no known vulnerabilities, 1 = vulnerabilities found,
2 = the scanner could not run.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS_FILE = REPO_ROOT / "requirements.txt"
REPORTS_DIR = REPO_ROOT / "reports"


def run_pip_audit() -> dict:
    """Run pip-audit and return its parsed JSON output."""
    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", "-r", str(REQUIREMENTS_FILE), "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"pip-audit gave no readable output. It may be missing or offline. "
            f"Details: {result.stderr.strip() or error}"
        ) from error


def write_report(findings: list[str]) -> Path:
    """Write the findings to a timestamped file under reports/."""
    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = REPORTS_DIR / f"pip-audit-{stamp}.txt"
    body = "\n".join(findings) if findings else "No known vulnerabilities found."
    report_path.write_text(body + "\n", encoding="utf-8")
    return report_path


def main() -> int:
    """Run the audit and return the exit code."""
    if not REQUIREMENTS_FILE.exists():
        print(f"requirements.txt not found at {REQUIREMENTS_FILE}")
        return 2
    try:
        data = run_pip_audit()
    except (RuntimeError, OSError) as error:
        print(f"Scanner could not run: {error}")
        return 2

    findings = []
    for dependency in data.get("dependencies", []):
        for vuln in dependency.get("vulns", []):
            fixes = ", ".join(vuln.get("fix_versions", [])) or "none listed"
            findings.append(
                f"{dependency['name']} {dependency['version']}: "
                f"{vuln['id']} (fixed in: {fixes})"
            )
    report_path = write_report(findings)
    print(f"{len(findings)} issue(s) found. Report: {report_path}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())