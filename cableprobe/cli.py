# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""CableProbe command-line interface (Typer)."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import typer

from cableprobe import __version__
from cableprobe.config import Config
from cableprobe.fsutil import probe_dir_writable, unsafe_output_dir_reasons
from cableprobe.knowledge import Allowlist, ImplantList
from cableprobe.logging_config import setup_logging
from cableprobe.probes import PROBE_REGISTRY
from cableprobe.report import (
    exit_code_for,
    load_report,
    read_report_index,
    render_summary,
    report_card_for,
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


def _allowlist_path(cfg: Config) -> Path:
    return cfg.allowlist_file or (cfg.output_dir / "allowlist.yaml")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _sudo_uid() -> int | None:
    """The uid behind ``sudo`` (``$SUDO_UID``), or None."""

    raw = os.environ.get("SUDO_UID")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def _tighten_output_dir(directory: Path, *, interactive: bool) -> None:
    """Offer to remove group/other write from an output dir we own; failing
    that, print the exact command to run."""

    quoted = shlex.quote(str(directory))
    if interactive and sys.stdin.isatty() and typer.confirm(
        f"  Remove group/other write from {directory} now?", default=False
    ):
        try:
            mode = stat.S_IMODE(directory.stat().st_mode)
            directory.chmod(mode & ~(stat.S_IWGRP | stat.S_IWOTH))
            typer.secho(f"  tightened {directory}", fg="green")
            return
        except OSError as exc:
            typer.secho(f"  could not chmod {directory}: {exc}", fg="red", err=True)
    typer.secho(f"    to fix: chmod go-w {quoted}", fg="bright_black")


def _guard_output_dir(
    directory: Path, *, hard_fail_on_symlink: bool, interactive: bool = False
) -> None:
    """Warn (yellow) when a root-run session's output dir looks unsafe to write
    into, offer or explain the fix, and abort if it is a symlink."""

    if not _is_root():
        return
    if directory.is_symlink():
        msg = f"{directory} is a symlink; a root session must not write reports through it"
        if hard_fail_on_symlink:
            typer.secho(f"error: {msg}", fg="red", err=True)
            raise typer.Exit(code=2)
        typer.secho(f"  WARNING: {msg}", fg="yellow")
        return

    reasons = unsafe_output_dir_reasons(directory, invoking_uid=_sudo_uid())
    for reason in reasons:
        typer.secho(
            f"  WARNING: {reason} - a planted file there could expose report "
            "contents; prefer a root-owned --output-dir",
            fg="yellow",
        )
    foreign_owner = any("owned by uid" in r for r in reasons)
    if any("writable by other users" in r for r in reasons) and not foreign_owner:
        _tighten_output_dir(directory, interactive=interactive)
    elif foreign_owner:
        typer.secho(
            f"    to fix: sudo chown -R root: {shlex.quote(str(directory))}",
            fg="bright_black",
        )


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
            # resolve symlinks so callers see (and can vet) the real target
            try:
                return Path(os.path.realpath(path))
            except OSError:
                return path
    return None


def _trusted_to_run_as_root(path: Path) -> bool:
    """True if ``path`` and its directory are writable only by their owner.

    ``_launcher_path()`` can fall back to ``$PATH`` (``shutil.which``), which is
    the *invoking* user's ``PATH``. Before we ask ``sudo`` to run that file as
    root - or symlink it onto root's ``PATH`` - make sure a third party could
    not have swapped it out via a group-/world-writable file or parent dir.
    """

    try:
        for target in (path, path.parent):
            mode = target.stat().st_mode
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
    except OSError:
        return False
    return True


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

    quoted = shlex.quote(str(launcher))
    return [
        f"sudo {quoted} {subcommand}{extra}",
        f'sudo env "PATH=$PATH" cableprobe {subcommand}{extra}',
    ]


def _permanent_link_hint() -> str | None:
    """One-liner that makes ``sudo cableprobe`` work for good, or None if the
    launcher is already on root's PATH."""

    launcher = _launcher_path()
    if launcher is None or str(launcher.parent) in _ROOT_SECURE_PATH:
        return None
    return "cableprobe link          # prompts for your sudo password"


def _advise_root(subcommand: str, *, interactive: bool) -> None:
    """If not running as root, tell the operator and let them bail out.

    Several probes (kernel log, udev attributes, USB descriptors, keystroke
    timing, raw sockets) see much less without privileges, and some are skipped
    entirely, so running under ``sudo`` is strongly recommended.
    """

    if _is_root():
        return

    hint = "\n    ".join(_sudo_hints(subcommand))
    body = (
        "CableProbe is NOT running as root.\n"
        "Without privileges the kernel-log, udev-attribute, USB-descriptor,\n"
        "keystroke-timing and raw-socket probes see much less detail, and some\n"
        "are skipped entirely. Running under sudo is strongly recommended.\n\n"
        "You can exit now and re-run as:\n\n"
        f"    {hint}"
    )
    permanent = _permanent_link_hint()
    if permanent is not None:
        body += (
            "\n\n"
            "Or, so that a bare `sudo cableprobe` works from now on, run once:\n\n"
            f"    {permanent}"
        )
    typer.secho("\n" + "=" * 70, fg="bright_black")
    typer.secho(body, fg="yellow", bold=True)
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
    interval: Optional[float] = typer.Option(None, help="Event-poll / progress-refresh interval (seconds)."),
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

    _guard_output_dir(
        cfg.output_dir,
        hard_fail_on_symlink=True,
        interactive=cfg.session.interactive,
    )

    unknown = [n for n in cfg.probes.enabled if n not in PROBE_REGISTRY]
    if unknown:
        typer.secho(
            f"error: unknown probe(s) in config: {', '.join(sorted(set(unknown)))}\n"
            f"  valid names: {', '.join(sorted(PROBE_REGISTRY))}",
            fg="red",
            err=True,
        )
        raise typer.Exit(code=2)

    rules_path = rules or cfg.rules_file
    try:
        ruleset = RuleSet.resolve(rules_path)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"error: could not load rules: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    implants = ImplantList.load(cfg.implants_file)
    allowlist = Allowlist.load(_allowlist_path(cfg))

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
        f"(poll every {cfg.session.sample_interval_seconds}s)"
    )

    _advise_root("run", interactive=cfg.session.interactive)

    if len(implants):
        typer.echo(f"known-implant list: {len(implants)} entries")
    if len(allowlist):
        typer.echo(f"allowlist: {len(allowlist)} trusted device(s)")

    progress = _PhaseProgress(plain=verbose > 0)
    try:
        report = asyncio.run(
            run_session(
                cfg,
                ruleset,
                session_name=name,
                prompt_fn=prompt_fn,
                on_tick=progress.tick,
                implants=implants,
                allowlist=allowlist,
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
        probe_dir_writable(cfg.output_dir)
        typer.secho(f"\noutput dir writable: {cfg.output_dir}", fg="green")
    except OSError as exc:
        typer.secho(f"\noutput dir NOT writable: {cfg.output_dir} ({exc})", fg="red")
        all_ok = False
    _guard_output_dir(cfg.output_dir, hard_fail_on_symlink=False, interactive=True)

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


def _reexec_with_sudo() -> None:
    """Re-run this exact command under ``sudo`` (which prompts for a password).

    Returns only if that is not possible (no sudo, no TTY, or already elevated);
    otherwise it replaces the current process and never returns.
    """

    if _is_root() or os.environ.get("CABLEPROBE_NO_SUDO_REEXEC"):
        return
    if shutil.which("sudo") is None or not sys.stdin.isatty():
        return
    launcher = _launcher_path()
    if launcher is None:
        return
    if not _trusted_to_run_as_root(launcher):
        typer.secho(
            f"not auto-escalating: {launcher} or its directory is writable by "
            "other users. Re-run as root explicitly if you trust it.",
            fg="yellow",
            err=True,
        )
        return
    argv = ["sudo", str(launcher), *sys.argv[1:]]
    typer.secho(f"re-running with sudo: {shlex.join(argv)}", fg="bright_black")
    try:
        os.execvp("sudo", argv)  # noqa: S606 - deliberate privilege escalation
    except OSError:
        return


@app.command()
def link(
    bin_dir: Path = typer.Option(
        Path("/usr/local/bin"), "--bin-dir",
        help="Directory on root's PATH to link the launcher into.",
    ),
    remove: bool = typer.Option(False, "--remove", help="Remove the link instead of creating it."),
    sudo: bool = typer.Option(
        True, "--sudo/--no-sudo",
        help="Re-run under sudo (prompting for a password) if writing needs root.",
    ),
) -> None:
    """Make `sudo cableprobe` work by symlinking the launcher into root's PATH.

    A pipx / ``pip install --user`` install puts ``cableprobe`` in
    ``~/.local/bin``, which ``sudo`` does not see. Run ``cableprobe link`` once
    (no ``sudo`` needed - it re-runs itself under ``sudo`` and prompts for your
    password) and afterwards ``sudo cableprobe run`` works without a full path.
    ``--no-sudo`` skips the escalation; ``--remove`` deletes the link.
    """

    target = bin_dir / "cableprobe"
    need_root = not os.access(bin_dir if bin_dir.is_dir() else bin_dir.parent, os.W_OK)
    if need_root and not _is_root() and sudo:
        _reexec_with_sudo()  # replaces the process on success

    if remove:
        if target.is_symlink() or target.exists():
            try:
                target.unlink()
            except OSError as exc:
                typer.secho(f"error: could not remove {target}: {exc}", fg="red", err=True)
                raise typer.Exit(code=1) from exc
            typer.secho(f"removed {target}", fg="green")
        else:
            typer.echo(f"nothing to remove at {target}")
        return

    launcher = _launcher_path()
    if launcher is None:
        typer.secho(
            "error: could not locate the cableprobe launcher to link.", fg="red", err=True
        )
        raise typer.Exit(code=2)

    if not _trusted_to_run_as_root(launcher):
        typer.secho(
            f"error: refusing to link {target} -> {launcher}: the launcher or its "
            "directory is writable by other users, so the link would let them run "
            "code as root via `sudo cableprobe`.",
            fg="red",
            err=True,
        )
        raise typer.Exit(code=2)

    if target.is_symlink() and target.resolve() == launcher.resolve():
        typer.secho(f"{target} already points at {launcher}", fg="green")
        return

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.exists():
            target.unlink()
        target.symlink_to(launcher)
    except OSError as exc:
        typer.secho(f"error: could not write {target}: {exc}", fg="red", err=True)
        if not _is_root():
            typer.secho(
                f"  run it as root:  sudo {shlex.quote(str(launcher))} link",
                fg="bright_black",
            )
        raise typer.Exit(code=1) from exc

    typer.secho(f"linked {target} -> {launcher}", fg="green")
    typer.echo("`sudo cableprobe run` now works without a full path.")


_PYPI_JSON_URL = "https://pypi.org/pypi/cableprobe/json"


def _pypi_latest_version(timeout: float = 6.0) -> str | None:
    """The newest cableprobe version on PyPI, queried directly (no pip cache)."""

    req = urllib.request.Request(
        _PYPI_JSON_URL, headers={"User-Agent": f"cableprobe/{__version__}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https literal
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    return (data.get("info") or {}).get("version")


def _version_key(value: str) -> tuple:
    key: list = []
    for part in value.replace("-", ".").replace("+", ".").split("."):
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)


def _is_editable_install() -> bool:
    try:
        from importlib.metadata import distribution

        raw = distribution("cableprobe").read_text("direct_url.json")
        if raw:
            return bool(json.loads(raw).get("dir_info", {}).get("editable"))
    except (ImportError, OSError, ValueError):  # metadata absent / malformed
        pass
    return False


#: Conservative POSIX login-name shape; also bounds what we hand to ``sudo -u``.
_USERNAME_RE = re.compile(r"\A[a-z_][a-z0-9_-]{0,31}\Z")


def _valid_local_user(name: str | None) -> str | None:
    """Return ``name`` (canonicalised) only if it is a well-formed login name
    of a real local account. Guards values passed to ``sudo -u`` - notably
    ``$SUDO_USER``, which is attacker-influenceable if root's environment is
    already tainted."""

    if not name or not _USERNAME_RE.match(name):
        return None
    try:
        import pwd

        return pwd.getpwnam(name).pw_name
    except (KeyError, ImportError):  # not a local account / non-POSIX
        return None


def _path_owner(path: str) -> str | None:
    """Login name that owns ``path`` (pipx venvs are owned by their installer)."""

    try:
        import pwd

        return pwd.getpwuid(Path(path).stat().st_uid).pw_name
    except (OSError, KeyError, ImportError):  # stat failure / unknown uid / non-POSIX
        return None


def _upgrade_command() -> list[str] | None:
    """The command that upgrades *this* install, or None if it can't be guessed."""

    if __version__.endswith("+dev") or _is_editable_install():
        return None  # source checkout - `git pull`
    prefix = str(Path(sys.prefix).resolve())
    launcher = str(_launcher_path() or "")
    is_pipx = (
        "/pipx/" in prefix
        or "/pipx/" in launcher
        or os.path.basename(os.path.dirname(prefix)) == "venvs"
    )
    if is_pipx:
        cmd = ["pipx", "upgrade", "cableprobe", "--pip-args=--no-cache-dir"]
        # `sudo cableprobe upgrade` runs as root, but a pipx install lives in
        # the *user's* home - pipx as root can't see it. Drop back to the
        # invoking user. Both candidate names are validated as real local
        # accounts before they reach `sudo -u`.
        owner = _valid_local_user(os.environ.get("SUDO_USER")) or _valid_local_user(
            _path_owner(prefix)
        )
        if _is_root() and owner and owner != "root":
            return ["sudo", "-u", owner, "-H", *cmd]
        return cmd
    if prefix.startswith("/opt/cableprobe"):
        return None  # managed by scripts/install.sh
    return [
        sys.executable, "-m", "pip", "install", "--upgrade", "--no-cache-dir", "cableprobe"
    ]


@app.command()
def upgrade(
    check: bool = typer.Option(
        False, "--check", help="Only report whether an update is available; do not install."
    ),
) -> None:
    """Check PyPI for a newer cableprobe and (unless --check) install it.

    Queries PyPI directly, so it is not fooled by a stale pip index cache the
    way ``pipx upgrade`` can be.
    """

    typer.echo(f"installed: {__version__}")
    latest = _pypi_latest_version()
    if latest is None:
        typer.secho("could not reach PyPI to check for updates.", fg="red", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"latest on PyPI: {latest}")

    if __version__.endswith("+dev") or _is_editable_install():
        typer.secho(
            "this is a source / editable checkout - `git pull` to update.",
            fg="bright_black",
        )
        raise typer.Exit(code=0)

    if _version_key(latest) <= _version_key(__version__):
        typer.secho("cableprobe is up to date.", fg="green")
        raise typer.Exit(code=0)

    typer.secho(f"\ncableprobe {latest} is available.", fg="yellow", bold=True)
    cmd = _upgrade_command()
    if cmd and cmd[0] == "sudo":
        typer.secho(
            f"(this is a pipx install owned by {cmd[2]}; upgrading as that user)",
            fg="bright_black",
        )
    if check or cmd is None:
        if cmd is None:
            typer.echo(
                "this install is managed elsewhere (scripts/install.sh, a distro"
                " package, ...) - upgrade it the same way you installed it."
            )
        else:
            typer.echo(f"to upgrade:  {shlex.join(cmd)}")
        raise typer.Exit(code=10)

    typer.secho(f"running: {shlex.join(cmd)}\n", fg="bright_black")
    try:
        result = subprocess.run(cmd, check=False)  # noqa: S603 - argv list, no shell
    except FileNotFoundError:
        typer.secho(f"error: {cmd[0]} not found on PATH.", fg="red", err=True)
        raise typer.Exit(code=1) from None
    if result.returncode != 0:
        typer.secho("upgrade command failed - see its output above.", fg="red", err=True)
        raise typer.Exit(code=result.returncode)
    typer.secho(f"\nupgraded. run `cableprobe --version` to confirm.", fg="green")


@app.command()
def allow(
    vid: Optional[str] = typer.Option(None, help="Vendor ID (hex) of a device to trust."),
    pid: Optional[str] = typer.Option(None, help="Product ID (hex) of a device to trust."),
    serial: Optional[str] = typer.Option(
        None, help="Serial number - strongly recommended; otherwise ANY device with "
        "that vendor:product is trusted."
    ),
    name: Optional[str] = typer.Option(None, help="A label for the entry."),
    remove: Optional[int] = typer.Option(
        None, "--remove", help="Remove the allowlist entry with this number."
    ),
    from_report: Optional[Path] = typer.Option(
        None, "--from-report", help="Interactively add the USB devices seen in a saved report."
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir", "-o", help="Where the allowlist lives (default: from config)."
    ),
) -> None:
    """Manage the allowlist of devices you trust.

    Findings about an allowlisted device are downgraded to *info*, so repeat
    tests of your own hardware stop shouting. With no options this lists the
    current entries.
    """

    cfg = _load_config(config)
    if output_dir is not None:
        cfg.output_dir = output_dir
    path = _allowlist_path(cfg)
    al = Allowlist.load(path)
    al.path = path

    if remove is not None:
        if not 1 <= remove <= len(al.entries):
            typer.secho(
                f"error: {remove} is out of range (1-{len(al.entries)})", fg="red", err=True
            )
            raise typer.Exit(code=2)
        gone = al.entries.pop(remove - 1)
        al.save()
        typer.secho(f"removed #{remove}: {gone.name} ({gone.vid}:{gone.pid})", fg="green")
        return

    if from_report is not None:
        if not from_report.is_file():
            typer.secho(f"error: no such file: {from_report}", fg="red", err=True)
            raise typer.Exit(code=2)
        loaded = load_report(from_report)
        seen: set[tuple] = set()
        added = 0
        for delta in loaded.deltas:
            v = delta.attributes.get("vendor_id")
            p = delta.attributes.get("product_id")
            s = delta.attributes.get("serial")
            if not (v and p) or (v, p, s) in seen:
                continue
            seen.add((v, p, s))
            label = f"{delta.label}  ({v}:{p}" + (f" serial {s}" if s else "") + ")"
            if typer.confirm(f"allowlist {label}?", default=False):
                al.add(v, p, s, typer.prompt("  name", default=str(delta.label)))
                added += 1
        if added:
            al.save()
        typer.secho(f"added {added} device(s) to {path}", fg="green")
        return

    if vid and pid:
        entry = al.add(vid, pid, serial, name or f"{vid}:{pid}")
        al.save()
        typer.secho(
            f"added: {entry.name}  {entry.vid}:{entry.pid}"
            + (f" serial {entry.serial}" if entry.serial else "  (any serial)"),
            fg="green",
        )
        if not serial:
            typer.secho(
                "  no serial given - this trusts ANY device presenting that "
                "vendor:product, including a spoofed one. Add --serial when you can.",
                fg="yellow",
            )
        return

    if not al.entries:
        typer.echo(f"allowlist is empty ({path})")
        return
    typer.secho(f"Allowlist ({path}):\n", fg="cyan", bold=True)
    for i, e in enumerate(al.entries, start=1):
        tail = f"serial {e.serial}" if e.serial else "(any serial)"
        typer.echo(f"  {i:>3}. {e.name:<28}  {e.vid}:{e.pid}  {tail}")


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
    """Return (path, {name, when, severity, findings}) newest-first.

    Reads the sidecar index written by ``write_report``; only falls back to
    parsing a report file when it is missing from the index.
    """

    index = read_report_index(output_dir)
    rows: list[tuple[Path, dict]] = []
    for path in sorted(output_dir.glob("*.cableprobe.json"), reverse=True):
        card = report_card_for(path, index)
        rows.append(
            (
                path,
                {
                    "name": card.get("session_name") or path.stem,
                    "when": (card.get("started_at") or "")[:19].replace("T", " "),
                    "severity": card.get("highest_severity"),
                    "findings": card.get("finding_count"),
                },
            )
        )
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
