"""Run Bandit and write a timestamped report for the CyberMail cybersecurity lab.

The script is a pattern for other scanners. Deciding which application
directories are in scope is left to the team.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_NAME = "CyberMail"
REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
# Third-party and generated trees create noise and can hide issues in our code.
EXCLUDED_DIRECTORIES = ".venv,venv,.git,reports"


def select_scan_target() -> Path:
    """Return the directory Bandit should scan.

    Interns: implement this part.
    The default is this repository so the script runs before an application
    checkout is configured. Point the target at the agreed source tree when
    the team names one.
    """
    return REPO_ROOT


def build_report_path() -> Path:
    """Return a new UTC-timestamped report path."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return REPORTS_DIR / f"bandit-{timestamp}.md"


def run_bandit(target: Path) -> subprocess.CompletedProcess[str]:
    """Run Bandit against `target` and capture its text output."""
    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(target),
        "-x",
        EXCLUDED_DIRECTORIES,
        "-f",
        "txt",
    ]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def write_report(report_path: Path, target: Path, result: subprocess.CompletedProcess[str]) -> None:
    """Write a Markdown summary plus the raw Bandit output."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output = ((result.stdout or "") + (result.stderr or "")).rstrip()
    lines = [
        f"# Bandit scan — {PROJECT_NAME}",
        "",
        f"- Generated at: {generated_at}",
        f"- Target: `{target}`",
        f"- Exit code: {result.returncode}",
        "",
        "## Raw output",
        "",
        "```text",
        output,
        "```",
        "",
        "## Summary",
        "",
        "Interns: implement this part.",
        "Group the findings by severity. Do not copy secrets from the raw output.",
        "",
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")


def map_exit_code(return_code: int) -> int:
    """Map a Bandit exit code to this script's exit code.

    Bandit returns 0 when it finds nothing and 1 when it finds issues.
    Any other code means the tool did not complete a scan.
    """
    if return_code in {0, 1}:
        return return_code
    return 2


def main() -> int:
    """Scan the selected target and write a report."""
    target = select_scan_target()
    if not target.exists():
        print(f"Scan target does not exist: {target}", file=sys.stderr)
        return 2

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        result = run_bandit(target)
    except OSError as exc:
        print(f"Could not start Bandit: {exc}", file=sys.stderr)
        return 2

    report_path = build_report_path()
    try:
        write_report(report_path, target, result)
    except OSError as exc:
        print(f"Could not write the report: {exc}", file=sys.stderr)
        return 2

    exit_code = map_exit_code(result.returncode)
    print(f"Wrote {report_path}")
    if exit_code == 2:
        print("Bandit did not complete. Install dependencies with pip install -r requirements.txt.", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
