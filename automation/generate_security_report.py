"""Build a timestamped Markdown security report for CyberMail.

The file lists scanner reports that already exist. Turning those files into a
severity summary is intern work.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

PROJECT_NAME = "CyberMail"
PROTECTED_RESOURCE = "incident reports and vulnerability reports"
REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
CONSOLE = Console()


def build_report_path(generated_at: datetime) -> Path:
    """Return the output path for one report run."""
    timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    return REPORTS_DIR / f"security-report-{timestamp}.md"


def collect_scanner_reports(reports_dir: Path) -> list[Path]:
    """Return scanner Markdown files, newest first.

    The security report this command is about to write is not an input.
    """
    if not reports_dir.exists():
        return []
    reports = [
        path
        for path in reports_dir.glob("*.md")
        if not path.name.startswith("security-report-")
    ]
    return sorted(reports, key=lambda path: path.stat().st_mtime, reverse=True)


def summarise_findings(report_paths: list[Path]) -> str:
    """Describe findings from scanner output.

    Interns: implement this part.
    Read each report and group results by severity. Never copy tokens,
    passwords, or other secrets into the summary.
    """
    if not report_paths:
        return "_No scanner reports found. Run a scanner, then generate this report again._"

    lines = [
        "Scanner reports found. Interns: replace this list with a severity summary.",
        "",
    ]
    lines.extend(f"- `{path.name}`" for path in report_paths)
    return "\n".join(lines)


def render_report(generated_at: datetime, findings: str) -> str:
    """Render the Markdown body. `generated_at` must be timezone-aware."""
    stamp = generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"# {PROJECT_NAME} security report",
        "",
        f"- Generated at: {stamp}",
        "- Scope: local cybersecurity lab and the authorised test environment",
        "",
        "## Access control",
        "",
        f"Focus: {PROTECTED_RESOURCE}.",
        "",
        "Interns: implement this part.",
        "Record which roles were tested and whether each case passed.",
        "",
        "## Scanner findings",
        "",
        findings,
        "",
        "## Open actions",
        "",
        "- [ ] Confirm the report route used by the access-control tests",
        "- [ ] Add the negative cases marked in `tests/access_control/`",
        "- [ ] File confirmed issues in `docs/vulnerability_log.md`",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    """Write the security report and print its path."""
    generated_at = datetime.now(timezone.utc)
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        findings = summarise_findings(collect_scanner_reports(REPORTS_DIR))
        report_path = build_report_path(generated_at)
        report_path.write_text(render_report(generated_at, findings), encoding="utf-8")
    except OSError as exc:
        CONSOLE.print(f"[red]Could not write the security report:[/red] {exc}")
        return 1

    CONSOLE.print(f"[green]Wrote[/green] {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
