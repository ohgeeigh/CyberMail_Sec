"""Run detect-secrets and write a timestamped report without secret values.

The report lists file, line number, and secret type only. Never copy real
secrets into reports or git.

Exit codes: 0 = no secrets found, 1 = possible secrets found,
2 = the scanner could not run.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
EXCLUDE_PATTERN = r"(\.venv|reports|\.git)/"


def run_detect_secrets() -> dict:
    """Run detect-secrets and return its parsed JSON output."""
    result = subprocess.run(
        [
            sys.executable, "-m", "detect_secrets", "scan",
            "--exclude-files", EXCLUDE_PATTERN,
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"detect-secrets gave no readable output. Details: "
            f"{result.stderr.strip() or error}"
        ) from error


def write_report(findings: list[str]) -> Path:
    """Write the findings to a timestamped file under reports/."""
    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = REPORTS_DIR / f"detect-secrets-{stamp}.txt"
    body = "\n".join(findings) if findings else "No possible secrets found."
    report_path.write_text(body + "\n", encoding="utf-8")
    return report_path


def main() -> int:
    """Run the scan and return the exit code."""
    try:
        data = run_detect_secrets()
    except (RuntimeError, OSError) as error:
        print(f"Scanner could not run: {error}")
        return 2

    findings = [
        f"{file_name}:{item['line_number']} {item['type']}"
        for file_name, items in data.get("results", {}).items()
        for item in items
    ]
    report_path = write_report(findings)
    print(f"{len(findings)} possible secret(s) found. Report: {report_path}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())