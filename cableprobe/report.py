# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Report writing, loading and console rendering."""

from __future__ import annotations

import json
from pathlib import Path

from cableprobe.advice import build_advice
from cableprobe.fsutil import PRIVATE_FILE_MODE, atomic_write, read_text_nofollow
from cableprobe.models import Delta, Finding, SessionReport

try:  # rich ships with Typer, but keep rendering optional
    from rich.console import Console
    from rich.markup import escape as _rich_escape
    from rich.panel import Panel
    from rich.table import Table

    _RICH = True
except ImportError:  # pragma: no cover
    _RICH = False

    def _rich_escape(value: str) -> str:  # type: ignore[misc]
        return value


#: Reports can contain host details, MAC addresses and process command lines;
#: keep them owner-readable only.
REPORT_FILE_MODE = PRIVATE_FILE_MODE

#: Refuse to load a report file larger than this. A well-formed report is a few
#: hundred KB; anything past this is corrupt or hostile and would only OOM us.
MAX_REPORT_BYTES = 50 * 1024 * 1024

#: Sidecar in the output directory: ``{filename: card}`` so the report picker
#: does not have to parse every saved report just to show a one-line summary.
REPORT_INDEX_NAME = ".cableprobe-index.json"


def _read_json_capped(path: Path) -> object:
    """``json.loads`` a report file: size-capped, and never through a symlink."""

    return json.loads(read_text_nofollow(path, max_bytes=MAX_REPORT_BYTES))


def report_card(report: SessionReport) -> dict:
    """The handful of fields the report picker shows for each saved session."""

    return {
        "session_name": report.metadata.session_name,
        "started_at": report.metadata.started_at.isoformat(),
        "highest_severity": report.summary.get("highest_severity"),
        "finding_count": report.summary.get("finding_count"),
    }


def read_report_index(output_dir: Path) -> dict:
    """Load the sidecar index, or ``{}`` if it is missing or unreadable."""

    try:
        data = json.loads(read_text_nofollow(Path(output_dir) / REPORT_INDEX_NAME))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_report_index_entry(output_dir: Path, filename: str, card: dict) -> None:
    """Best-effort: fold one card into the sidecar index. Never raises."""

    index_path = Path(output_dir) / REPORT_INDEX_NAME
    index = read_report_index(output_dir)
    index[filename] = card
    try:
        atomic_write(index_path, json.dumps(index))
    except OSError:  # pragma: no cover - non-POSIX / unusual filesystems
        pass


def report_card_for(path: Path, index: dict | None = None) -> dict:
    """Return the summary card for a saved report: from the index if present,
    otherwise by parsing the file (size-capped). Missing/broken -> ``{}``."""

    path = Path(path)
    if index is not None:
        card = index.get(path.name)
        if isinstance(card, dict):
            return card
    try:
        data = _read_json_capped(path)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    meta = data.get("metadata") or {}
    summary = data.get("summary") or {}
    return {
        "session_name": meta.get("session_name"),
        "started_at": meta.get("started_at"),
        "highest_severity": summary.get("highest_severity"),
        "finding_count": summary.get("finding_count"),
    }


_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def write_report(report: SessionReport, output_dir: Path, *, filename: str | None = None) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if filename is None:
        stamp = report.metadata.started_at.strftime("%Y%m%dT%H%M%SZ")
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "-" for c in report.metadata.session_name
        )
        filename = f"{stamp}-{safe_name}.cableprobe.json"
    path = output_dir / filename
    atomic_write(path, report.to_json())
    _write_report_index_entry(output_dir, filename, report_card(report))
    return path


def load_report(path: Path | str) -> SessionReport:
    data = _read_json_capped(Path(path))
    return SessionReport.model_validate(data)


# --------------------------------------------------------------------------
# console rendering
# --------------------------------------------------------------------------


def render_summary(report: SessionReport, *, plain: bool = False) -> str:
    lines = _plain_summary(report)
    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    meta = report.metadata
    host_model = meta.host.get("hardware_model", meta.host.get("machine", "?"))
    console.print(
        Panel.fit(
            f"[bold]{_rich_escape(str(meta.session_name))}[/bold]\n"
            f"host: {_rich_escape(str(meta.host.get('node', '?')))} "
            f"({_rich_escape(str(host_model))})\n"
            f"started: {meta.started_at.isoformat()}\n"
            f"probes: {_rich_escape(', '.join(meta.probes_used)) or '(none)'}",
            title="CableProbe session",
        )
    )

    if meta.probes_unavailable:
        names = ", ".join(w.split(":", 1)[0] for w in meta.probes_unavailable)
        console.print(
            f"[dim]Probes skipped (interface not present on this host): {names}[/dim]"
        )

    if meta.probe_warnings:
        console.print("[yellow]Probe warnings:[/yellow]")
        for warning in meta.probe_warnings:
            console.print(f"  - {_rich_escape(str(warning))}")

    _render_delta_table(console, report.deltas)
    _render_findings(console, report.findings)
    _render_advice(console, report)

    summary = report.summary
    console.print(
        f"\n[bold]Overall:[/bold] {summary.get('finding_count', 0)} finding(s), "
        f"highest severity: "
        f"[{_SEVERITY_STYLE.get(summary.get('highest_severity') or 'info', 'dim')}]"
        f"{summary.get('highest_severity') or 'none'}[/]"
    )
    return text


_ADVICE_BORDER = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "cyan",
    "none": "green",
}


def _render_advice(console, report: SessionReport) -> None:
    advice = build_advice(report)
    style = _SEVERITY_STYLE.get(advice.severity, "dim")
    lines = [f"[{style}][bold]{_rich_escape(advice.headline)}[/bold][/]"]
    for line in advice.body:
        lines.append(_rich_escape(line) if line else "")
    console.print(
        Panel(
            "\n".join(lines),
            title="What this means",
            border_style=_ADVICE_BORDER.get(advice.severity, "cyan"),
        )
    )


def _render_delta_table(console, deltas: list[Delta]) -> None:
    if not deltas:
        console.print("\n[green]No differences between phases.[/green]")
        return
    table = Table(title=f"\nPhase differences ({len(deltas)})", show_lines=False)
    table.add_column("change")
    table.add_column("kind")
    table.add_column("label", overflow="fold")
    table.add_column("first seen")
    table.add_column("reverted?")
    for delta in deltas:
        reverted = (
            "-"
            if delta.reverted_after_disconnect is None
            else ("yes" if delta.reverted_after_disconnect else "[red]no[/red]")
        )
        table.add_row(
            delta.change + (" (transient)" if delta.transient else ""),
            _rich_escape(delta.kind),
            _rich_escape(delta.label),
            delta.first_seen_phase or "-",
            reverted,
        )
    console.print(table)


def _render_findings(console, findings: list[Finding]) -> None:
    if not findings:
        console.print("\n[green]No rule findings.[/green]")
        return
    console.print(f"\n[bold]Findings ({len(findings)})[/bold]")
    for finding in findings:
        style = _SEVERITY_STYLE.get(finding.severity, "dim")
        console.print(
            f"\n  [{style}]{finding.severity.upper()}[/] "
            f"{_rich_escape(finding.title)}  "
            f"[dim]({_rich_escape(finding.rule_id)})[/dim]"
        )
        if finding.rationale:
            console.print(f"    {_rich_escape(finding.rationale.strip())}")
        for line in finding.evidence:
            console.print(f"      • {_rich_escape(line)}")


def _plain_summary(report: SessionReport) -> list[str]:
    meta = report.metadata
    lines = [
        "CableProbe session report",
        f"  session:  {meta.session_name}",
        f"  host:     {meta.host.get('node', '?')}",
        f"  started:  {meta.started_at.isoformat()}",
        f"  ended:    {meta.ended_at.isoformat()}",
        f"  probes:   {', '.join(meta.probes_used) or '(none)'}",
    ]
    if meta.probes_unavailable:
        names = ", ".join(w.split(":", 1)[0] for w in meta.probes_unavailable)
        lines.append(f"  skipped:  {names} (interface not present on this host)")
    for warning in meta.probe_warnings:
        lines.append(f"  warning:  {warning}")

    lines.append("")
    lines.append(f"Phase differences: {len(report.deltas)}")
    for delta in report.deltas:
        reverted = (
            ""
            if delta.reverted_after_disconnect is None
            else (" [reverted]" if delta.reverted_after_disconnect else " [DID NOT REVERT]")
        )
        lines.append(
            f"  - {delta.change:<11} {delta.kind:<18} {delta.label}"
            f" (first seen: {delta.first_seen_phase or '-'}){reverted}"
        )

    lines.append("")
    lines.append(f"Findings: {len(report.findings)}")
    for finding in report.findings:
        lines.append(f"  [{finding.severity.upper()}] {finding.title} ({finding.rule_id})")
        for ev in finding.evidence:
            lines.append(f"      - {ev}")

    advice = build_advice(report)
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"WHAT THIS MEANS — {advice.headline}")
    lines.append("=" * 70)
    for line in advice.body:
        lines.append(line)
    lines.append("=" * 70)

    lines.append("")
    lines.append(f"Highest severity: {report.summary.get('highest_severity') or 'none'}")
    return lines


SEVERITY_EXIT_CODES = {
    None: 0,
    "info": 0,
    "low": 0,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


def exit_code_for(report: SessionReport) -> int:
    return SEVERITY_EXIT_CODES.get(report.summary.get("highest_severity"), 0)
