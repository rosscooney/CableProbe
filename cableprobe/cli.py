# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""CableProbe command-line interface (Typer)."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Optional

import typer

from cableprobe import __version__
from cableprobe.config import Config
from cableprobe.logging_config import setup_logging
from cableprobe.probes import PROBE_REGISTRY
from cableprobe.report import (
    exit_code_for,
    load_report,
    render_summary,
    write_report,
)
from cableprobe.rules import RuleSet
from cableprobe.session import run_session
from cableprobe.system_info import collect_host_info

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "CableProbe - defensive USB cable analysis (USB-C or USB-A).\n\n"
        "Runs a controlled baseline / test / post-test session and reports "
        "anything that changed in correlation with an unknown cable being "
        "connected. Observation only; CableProbe never modifies the system."
    ),
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cableprobe {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


def _load_config(config_path: Optional[Path]) -> Config:
    try:
        return Config.load(config_path)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"error: could not load config: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


#: Directories on root's default ``secure_path`` (see ``sudo -V``). If the
#: launcher lives here, a bare ``sudo cableprobe`` works; otherwise (pipx /
#: ``pip install --user`` put it in ``~/.local/bin``) it does not.
_ROOT_SECURE_PATH = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/snap/bin",
)


def _launcher_path() -> Path | None:
    """Absolute path to the installed ``cableprobe`` launcher script, if any.

    Ignores ``sys.argv[0]`` when it is not actually the ``cableprobe`` console
    script (e.g. ``python -m cableprobe.cli`` during development).
    """

    argv0 = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    candidates = []
    if argv0 is not None and argv0.name == "cableprobe":
        candidates.append(argv0)
    candidates.append(Path(shutil.which("cableprobe")) if shutil.which("cableprobe") else None)
    for path in candidates:
        if path is not None and path.is_absolute() and path.exists():
            return path
    return None


def _sudo_hints(subcommand: str) -> list[str]:
    """Copy-pasteable ways to re-run ``subcommand`` as root, best first.

    ``sudo`` resets ``PATH`` to a fixed ``secure_path``, so a bare
    ``sudo cableprobe`` fails with "command not found" for the common pipx /
    ``pip install --user`` layout. Detect that and offer commands that work.
    """

    extra = " …" if subcommand == "run" else ""
    launcher = _launcher_path()
    on_root_path = launcher is not None and str(launcher.parent) in _ROOT_SECURE_PATH

    if on_root_path or launcher is None:
        return [f"sudo cableprobe {subcommand}{extra}"]

    return [
        f"sudo {shlex.quote(str(launcher))} {subcommand}{extra}",
        f'sudo env "PATH=$PATH" cableprobe {subcommand}{extra}',
        "# permanent: put it on root's PATH once with  sudo ./scripts/install.sh",
    ]


def _advise_root(subcommand: str, *, interactive: bool) -> None:
    """If not running as root, tell the operator and let them bail out.

    Several probes (kernel log, udev attributes, USB descriptors, keystroke
    timing, raw sockets) see much less without privileges, and some are skipped
    entirely, so running under ``sudo`` is strongly recommended.
    """

    if _is_root():
        return

    hint = "\n    ".join(_sudo_hints(subcommand))
    typer.secho("\n" + "=" * 70, fg="bright_black")
    typer.secho(
        "CableProbe is NOT running as root.\n"
        "Without privileges the kernel-log, udev-attribute, USB-descriptor,\n"
        "keystroke-timing and raw-socket probes see much less detail, and some\n"
        "are skipped entirely. Running under sudo is strongly recommended.\n\n"
        "You can exit now and re-run as:\n\n"
        f"    {hint}",
        fg="yellow",
        bold=True,
    )
    typer.secho("=" * 70, fg="bright_black")

    if not interactive:
        typer.secho("(--auto: continuing without root)", fg="bright_black")
        return
    try:
        if not typer.confirm("Continue without sudo?", default=True):
            typer.secho("aborted - re-run with sudo.", fg="red")
            raise typer.Exit(code=1)
    except typer.Abort:  # Ctrl-C / Ctrl-D at the prompt
        raise typer.Exit(code=1) from None


def _operator_prompt(phase: str, message: str) -> None:
    typer.secho("\n" + "=" * 70, fg="bright_black")
    typer.secho(message, fg="yellow", bold=True)
    typer.secho("=" * 70, fg="bright_black")
    try:
        input("Press ENTER when ready to begin this phase... ")
    except EOFError:  # non-interactive stdin
        typer.secho("(no TTY - continuing automatically)", fg="bright_black")


def _auto_prompt_factory(grace: int):
    def _auto_prompt(phase: str, message: str) -> None:
        typer.secho("\n" + message, fg="yellow", bold=True)
        for remaining in range(grace, 0, -1):
            typer.secho(f"  starting {phase} in {remaining}s ...", fg="bright_black")
            time.sleep(1)

    return _auto_prompt


def _tick_line(phase: str, elapsed: float, duration: float) -> None:
    pct = int(100 * elapsed / duration) if duration else 100
    typer.secho(
        f"  [{phase}] {elapsed:5.1f}/{duration:.0f}s ({pct:3d}%)", fg="bright_black"
    )


class _PhaseProgress:
    """Render a progress bar for each observation phase, driven from ``on_tick``.

    One bar per phase (``baseline`` / ``test`` / ``post_test``); each fills to
    100% and stays on screen, so the finished session shows all three. Falls
    back to plain text lines when ``plain`` is set (e.g. under ``-v``, so the bar
    does not fight with log output) or when ``rich`` is unavailable.
    """

    def __init__(self, *, plain: bool = False) -> None:
        self._phase: str | None = None
        self._progress = None
        self._task = None
        self._factory = None
        if plain:
            return
        try:  # rich ships with typer, but stay defensive
            from rich.progress import (
                BarColumn,
                Progress,
                TaskProgressColumn,
                TextColumn,
                TimeRemainingColumn,
            )

            self._factory = lambda: Progress(
                TextColumn("  [bold]{task.description:<9}[/bold]"),
                BarColumn(bar_width=36),
                TaskProgressColumn(),
                TextColumn("{task.completed:>3.0f}/{task.total:.0f}s"),
                TimeRemainingColumn(),
            )
        except Exception:  # pragma: no cover - rich missing
            self._factory = None

    def tick(self, phase: str, elapsed: float, duration: float) -> None:
        if self._factory is None:
            _tick_line(phase, elapsed, duration)
            return
        if phase != self._phase:
            self.close()
            self._phase = phase
            self._progress = self._factory()
            self._progress.start()
            self._task = self._progress.add_task(phase, total=duration)
        self._progress.update(self._task, completed=min(elapsed, duration))
        if elapsed >= duration:
            self.close()

    def close(self) -> None:
        if self._progress is not None:
            try:
                if self._task is not None:
                    total = self._progress.tasks[self._task].total
                    self._progress.update(self._task, completed=total)
                self._progress.stop()
            except Exception:  # pragma: no cover - best effort teardown
                pass
        self._phase = None
        self._progress = None
        self._task = None


@app.command()
def run(
    baseline: Optional[int] = typer.Option(None, help="Baseline phase duration (seconds)."),
    test: Optional[int] = typer.Option(None, help="Test phase duration (seconds)."),
    post_test: Optional[int] = typer.Option(None, "--post-test", help="Post-test duration (seconds)."),
    interval: Optional[float] = typer.Option(None, help="Sampling interval (seconds)."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    rules: Optional[Path] = typer.Option(None, "--rules", "-r", help="YAML rules file (default: built-in)."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Where to write the report."),
    session_name: Optional[str] = typer.Option(None, "--name", "-n", help="Human name for this session."),
    auto: bool = typer.Option(
        False, "--auto", help="Do not wait for operator input; advance phases on a timer."
    ),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help="Exit non-zero when medium+ findings are present."
    ),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True,
        help="-v info logs (plain progress lines), -vv debug.",
    ),
) -> None:
    """Run a full three-phase cable analysis session."""

    logger = setup_logging(verbose)
    cfg = _load_config(config)

    if baseline is not None:
        cfg.session.baseline_seconds = baseline
    if test is not None:
        cfg.session.test_seconds = test
    if post_test is not None:
        cfg.session.post_test_seconds = post_test
    if interval is not None:
        cfg.session.sample_interval_seconds = interval
    if output_dir is not None:
        cfg.output_dir = output_dir
    if auto:
        cfg.session.interactive = False

    # re-validate after overrides
    cfg = Config.model_validate(cfg.model_dump())

    rules_path = rules or cfg.rules_file
    try:
        ruleset = RuleSet.resolve(rules_path)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"error: could not load rules: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    name = session_name or f"cableprobe-{time.strftime('%Y%m%dT%H%M%S')}"
    prompt_fn = (
        _auto_prompt_factory(cfg.session.auto_advance_grace_seconds)
        if not cfg.session.interactive
        else _operator_prompt
    )

    typer.secho(f"CableProbe {__version__} - session {name!r}", fg="green", bold=True)
    typer.echo(
        f"phases: baseline={cfg.session.baseline_seconds}s "
        f"test={cfg.session.test_seconds}s post-test={cfg.session.post_test_seconds}s "
        f"(sample every {cfg.session.sample_interval_seconds}s)"
    )

    _advise_root("run", interactive=cfg.session.interactive)

    progress = _PhaseProgress(plain=verbose > 0)
    try:
        report = asyncio.run(
            run_session(
                cfg,
                ruleset,
                session_name=name,
                prompt_fn=prompt_fn,
                on_tick=progress.tick,
            )
        )
    except KeyboardInterrupt:  # pragma: no cover
        typer.secho("\naborted by operator", fg="red", err=True)
        raise typer.Exit(code=130)
    except Exception as exc:  # noqa: BLE001
        logger.exception("session failed")
        typer.secho(f"error: session failed: {exc}", fg="red", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        progress.close()

    path = write_report(report, cfg.output_dir)
    typer.echo("")
    render_summary(report)
    typer.secho(f"\nreport written to {path}", fg="green")

    if fail_on_findings:
        raise typer.Exit(code=exit_code_for(report))


@app.command()
def check(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True),
) -> None:
    """Check that this host can run CableProbe (probes, tools, permissions)."""

    setup_logging(verbose)
    cfg = _load_config(config)
    host = collect_host_info()

    typer.secho("Host", fg="cyan", bold=True)
    typer.echo(f"  node:        {host.get('node')}")
    typer.echo(f"  model:       {host.get('hardware_model', host.get('machine'))}")
    typer.echo(f"  kernel:      {host.get('release')}")
    typer.echo(f"  python:      {host.get('python_version')}")
    typer.echo(f"  root:        {host.get('running_as_root')}")

    typer.secho("\nExternal tools", fg="cyan", bold=True)
    for tool in (
        "lsusb", "lsblk", "journalctl", "dmesg", "udevadm", "ss", "lspci", "iw", "nmcli"
    ):
        present = shutil.which(tool) is not None
        mark = "ok " if present else "MISSING"
        typer.secho(f"  {mark:8}{tool}", fg="green" if present else "yellow")

    typer.secho("\nProbes", fg="cyan", bold=True)
    all_ok = True
    session_start = time.time()
    for name in cfg.probes.enabled:
        probe_cls = PROBE_REGISTRY.get(name)
        if probe_cls is None:
            typer.secho(f"  UNKNOWN  {name}", fg="red")
            all_ok = False
            continue
        probe = probe_cls(config=cfg, session_start=session_start)
        availability = probe.availability()
        mark = "ok " if availability.ok else "FAIL"
        colour = "green" if availability.ok else "yellow"
        detail = f" - {availability.detail}" if availability.detail else ""
        typer.secho(f"  {mark:8}{name}{detail}", fg=colour)
        all_ok = all_ok and availability.ok

    try:
        cfg.output_dir.mkdir(parents=True, exist_ok=True)
        probe_file = cfg.output_dir / ".cableprobe-write-test"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink()
        typer.secho(f"\noutput dir writable: {cfg.output_dir}", fg="green")
    except OSError as exc:
        typer.secho(f"\noutput dir NOT writable: {cfg.output_dir} ({exc})", fg="red")
        all_ok = False

    if not _is_root():
        typer.secho(
            "\nnot running as root: kernel-log, udev-attribute, USB-descriptor, "
            "keystroke-timing and raw-socket probes will see less or be skipped.",
            fg="yellow",
        )
        typer.secho("  for a full check, re-run as:", fg="bright_black")
        for hint in _sudo_hints("check"):
            typer.secho(f"    {hint}", fg="bright_black")

    raise typer.Exit(code=0 if all_ok else 1)


@app.command()
def probes() -> None:
    """List available probes."""

    for name, probe_cls in PROBE_REGISTRY.items():
        typer.secho(name, fg="cyan", bold=True)
        typer.echo(f"  {probe_cls.description}")


@app.command()
def rules(
    path: Optional[Path] = typer.Argument(None, help="Rules YAML file (default: built-in)."),
) -> None:
    """Show the detection rules that would be used."""

    try:
        ruleset = RuleSet.resolve(path)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"ruleset version {ruleset.version}, {len(ruleset.rules)} rule(s)\n")
    for rule in ruleset.rules:
        typer.secho(f"[{rule.severity.upper():8}] {rule.id}", fg="cyan")
        typer.echo(f"           {rule.title}")


_SEVERITY_COLOUR = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "bright_black",
}


def _list_saved_reports(output_dir: Path) -> list[tuple[Path, dict]]:
    """Return (path, {name, when, severity, findings}) newest-first."""

    rows: list[tuple[Path, dict]] = []
    for path in sorted(output_dir.glob("*.cableprobe.json"), reverse=True):
        meta = {"name": path.stem, "when": "", "severity": None, "findings": None}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            meta["name"] = data.get("metadata", {}).get("session_name") or path.stem
            meta["when"] = data.get("metadata", {}).get("started_at", "")[:19].replace(
                "T", " "
            )
            summary = data.get("summary", {})
            meta["severity"] = summary.get("highest_severity")
            meta["findings"] = summary.get("finding_count")
        except (OSError, ValueError):
            pass
        rows.append((path, meta))
    return rows


def _pick_report(output_dir: Path) -> Path:
    if not output_dir.is_dir():
        typer.secho(f"error: no reports directory at {output_dir}", fg="red", err=True)
        raise typer.Exit(code=2)
    rows = _list_saved_reports(output_dir)
    if not rows:
        typer.secho(f"error: no saved reports in {output_dir}", fg="red", err=True)
        raise typer.Exit(code=2)

    typer.secho(f"Saved reports in {output_dir}:\n", fg="cyan", bold=True)
    for i, (_, m) in enumerate(rows, start=1):
        if m["findings"]:
            sev = m["severity"] or "info"
            tag = typer.style(
                f"{sev} ({m['findings']} finding(s))",
                fg=_SEVERITY_COLOUR.get(sev, "white"),
            )
        else:
            tag = typer.style("clean", fg="green")
        typer.echo(f"  {i:>3}. {m['when'] or '?':<19}  {m['name']:<32}  {tag}")
    typer.echo("")
    try:
        choice = typer.prompt("Enter the number of the report to view", type=int)
    except typer.Abort:
        typer.secho("\nno selection - pass a report path instead.", fg="red", err=True)
        raise typer.Exit(code=2) from None
    if not 1 <= choice <= len(rows):
        typer.secho(f"error: {choice} is out of range (1-{len(rows)})", fg="red", err=True)
        raise typer.Exit(code=2)
    return rows[choice - 1][0]


@app.command()
def report(
    path: Optional[Path] = typer.Argument(
        None, help="Path to a .cableprobe.json report (omit to pick from saved ones)."
    ),
    output_format: str = typer.Option("summary", "--format", "-f", help="summary | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir", "-o", help="Where saved reports live (default: from config)."
    ),
) -> None:
    """Re-render a previously saved report.

    With no PATH, lists the reports in the output directory and asks which one.
    """

    if path is None:
        base = output_dir or _load_config(config).output_dir
        path = _pick_report(Path(base))

    if not path.is_file():
        typer.secho(f"error: no such file: {path}", fg="red", err=True)
        raise typer.Exit(code=2)
    try:
        loaded = load_report(path)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"error: could not parse report: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    if output_format == "json":
        typer.echo(loaded.to_json())
    else:
        render_summary(loaded)


def main() -> None:  # pragma: no cover - entry point shim
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
