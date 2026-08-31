from __future__ import annotations

from rich.console import Console
from rich.table import Table

from kspm.models import Finding, Severity
from kspm.scanner import compute_posture_score, summarize_by_severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SCORE_STYLE_THRESHOLDS = (
    (90, "bold green"),
    (70, "bold yellow"),
    (0, "bold red"),
)


def _score_style(score: int) -> str:
    for threshold, style in _SCORE_STYLE_THRESHOLDS:
        if score >= threshold:
            return style
    return "bold red"


def render_console(findings: list[Finding], scanned_count: int, console: Console | None = None) -> None:
    console = console or Console()
    score = compute_posture_score(findings)
    counts = summarize_by_severity(findings)

    console.print()
    console.print(f"[bold]KSPM Scanner[/bold] — scanned {scanned_count} workload(s)")

    if not findings:
        console.print("[bold green]No security posture issues found.[/bold green]")
        console.print("Posture score: [bold green]100[/bold green]/100\n")
        return

    table = Table(show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Workload")
    table.add_column("Container", no_wrap=True)
    table.add_column("Finding")

    for f in findings:
        table.add_row(
            f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
            f.rule_id,
            f.workload.locator,
            f.container or "-",
            f.message,
        )

    console.print(table)
    console.print()

    summary_parts = [
        f"[{_SEVERITY_STYLE[Severity(sev)]}]{sev}: {count}[/]"
        for sev, count in counts.items()
        if count
    ]
    console.print("Findings — " + "  ".join(summary_parts))
    console.print(
        f"Posture score: [{_score_style(score)}]{score}[/]/100\n"
    )
