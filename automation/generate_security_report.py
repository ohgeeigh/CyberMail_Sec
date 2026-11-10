"""Build a timestamped Markdown security report for CyberMail.

The file lists scanner reports that already exist. Turning those files into a
severity summary is intern work.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

PROJECT_NAME = "CyberMail"
PROTECTED_RESOURCE = "incident reports and vulnerability reports"
REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
CONSOLE = Console()
SCANNER_PREFIXES = {
    "bandit": "Bandit",
    "pip-audit": "pip-audit",
    "detect-secrets": "detect-secrets",
}
BANDIT_SEVERITIES = ("High", "Medium", "Low")
PIP_AUDIT_FINDING = r"^\S+ \S+: \S+ \(fixed in:"
SECRET_FINDING = r"^.+:\d+ \S.*$"


def build_report_path(generated_at: datetime) -> Path:
    """Return the output path for one report run."""
    timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    return REPORTS_DIR / f"security-report-{timestamp}.md"


def collect_scanner_reports(reports_dir: Path) -> list[Path]:
    """Return scanner reports (.md or .txt), newest first.

    The security report this command is about to write is not an input.
    """
    if not reports_dir.exists():
        return []
    reports = [
        path
        for path in reports_dir.iterdir()
        if path.suffix in {".md", ".txt"}
        and not path.name.startswith("security-report-")
    ]
    return sorted(reports, key=lambda path: path.stat().st_mtime, reverse=True)


def summarise_findings(report_paths: list[Path]) -> str:
    """Summarise the newest report from each scanner as a Markdown table.

    Only counts are reported. Secret values are never copied.
    """
    if not report_paths:
        return "_No scanner reports found. Run a scanner, then generate this report again._"

    rows = [
        "| Scanner | Report | Findings | High / Medium / Low |",
        "|---|---|---|---|",
    ]
    for prefix, label in SCANNER_PREFIXES.items():
        path = latest_report_for(prefix, report_paths)
        if path is None:
            rows.append(f"| {label} | _not run_ | - | - |")
            continue
        try:
            if prefix == "bandit":
                counts = count_bandit_severities(path)
                total = sum(counts.values())
                breakdown = " / ".join(str(counts[name]) for name in BANDIT_SEVERITIES)
            elif prefix == "pip-audit":
                total = count_matching_lines(path, PIP_AUDIT_FINDING)
                breakdown = "not graded by pip-audit"
            else:
                total = count_matching_lines(path, SECRET_FINDING)
                breakdown = "not graded"
        except (OSError, ValueError) as exc:
            rows.append(f"| {label} | `{path.name}` | could not read ({exc}) | - |")
            continue
        rows.append(f"| {label} | `{path.name}` | {total} | {breakdown} |")

    rows.extend(["", "Details stay in the scanner reports. Counts only, no secret values."])
    return "\n".join(rows)


def latest_report_for(prefix: str, report_paths: list[Path]) -> Path | None:
    """Return the newest report whose name starts with the scanner prefix."""
    for path in report_paths:
        if path.name.startswith(f"{prefix}-"):
            return path
    return None

def count_bandit_severities(path: Path) -> dict[str, int]:
    """Return Bandit issue counts by severity from one report."""
    text = path.read_text(encoding="utf-8")
    block = re.search(
        r"Total issues \(by severity\):(.*?)Total issues \(by confidence\)",
        text,
        re.DOTALL,
    )
    if block is None:
        raise ValueError("no severity totals; re-run scanners/bandit_runner.py")
    counts = {name: 0 for name in BANDIT_SEVERITIES}
    for name, number in re.findall(r"(High|Medium|Low):\s*(\d+)", block.group(1)):
        counts[name] = int(number)
    return counts

def count_matching_lines(path: Path, pattern: str) -> int:
    """Count lines in a report that match a finding pattern."""
    text = path.read_text(encoding="utf-8")
    return len(re.findall(pattern, text, re.MULTILINE))



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
