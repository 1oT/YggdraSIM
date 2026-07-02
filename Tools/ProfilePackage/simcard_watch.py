# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Polling watcher that auto-opens fresh SIMCARD profiles in the SAIP tooling.

Architecture:

1. ``SIMCARD.engine.SimulatedSimCardEngine`` fires a profile-download
   hook whenever a new ICCID appears in the profile store (see
   ``_dispatch_profile_download_hooks``). We mirror that semantics over
   the filesystem for operators who run the simulator and the SAIP
   shell in different processes.
2. :class:`ProfileStoreWatcher` polls the on-disk store directory and
   compares the ICCID set against its last snapshot. New entries get
   surfaced through a user-supplied callback.
3. :func:`watch_and_launch_tui` is the one-stop convenience wrapper
   that runs the watcher and, on each arrival, spawns
   ``saip-diff-tui`` or the transcode TUI at the fresh profile.

Polling (rather than inotify / fsevents) keeps the module dependency
light — no extra wheels, portable to macOS / Windows / Linux. The
default poll interval (2 s) is aligned with the shell REPL ergonomics:
slow enough not to burn CPU, fast enough that a new ES10b download is
visible within a breath.

The watcher is **read-only** with respect to the profile store. It
never deletes, mutates, or rewrites anything inside
``<Workspace>/SIMCARD/.../profile_store/``.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


_LOGGER = logging.getLogger(__name__)


DEFAULT_POLL_INTERVAL_SECONDS: float = 2.0
MANIFEST_FILENAME: str = "profile.json"
PROFILE_IMAGE_FILENAME: str = "profile_image.json"


@dataclass(frozen=True)
class ProfileArrival:
    """Metadata for a newly detected profile inside the store.

    ``manifest_path`` is the ``profile.json`` file that
    ``SIMCARD.profile_store.sync_profiles_to_store`` writes for every
    entry. ``profile_image_path`` is the richer ``profile_image.json``
    when it is present (populated whenever the downloaded BPP contained
    a decoded SAIP profile image). Consumers usually prefer the image
    because the SAIP TUI can read it directly.
    """

    iccid: str
    profile_dir: Path
    manifest_path: Path | None = None
    profile_image_path: Path | None = None

    @property
    def preferred_profile_path(self) -> Path | None:
        if self.profile_image_path is not None:
            return self.profile_image_path
        return self.manifest_path


def _manifest_iccid(manifest_path: Path) -> str | None:
    try:
        payload = json.loads(manifest_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(payload, dict) is False:
        return None
    raw = payload.get("iccid")
    if isinstance(raw, str) is False:
        return None
    normalised = raw.strip()
    if len(normalised) == 0:
        return None
    return normalised


def _scan_store_once(store_root: Path) -> list[ProfileArrival]:
    """Enumerate ``<store_root>/<profile-dir>/`` entries with ICCIDs."""
    if store_root.is_dir() is False:
        return []
    arrivals: list[ProfileArrival] = []
    for child in sorted(store_root.iterdir(), key=lambda p: p.name):
        if child.is_dir() is False:
            continue
        manifest_path = child / MANIFEST_FILENAME
        image_path = child / PROFILE_IMAGE_FILENAME
        iccid: str | None = None
        if manifest_path.is_file() is True:
            iccid = _manifest_iccid(manifest_path)
        if iccid is None and image_path.is_file() is True:
            iccid = _manifest_iccid(image_path)
        if iccid is None:
            continue
        arrivals.append(
            ProfileArrival(
                iccid=iccid,
                profile_dir=child,
                manifest_path=manifest_path if manifest_path.is_file() else None,
                profile_image_path=image_path if image_path.is_file() else None,
            )
        )
    return arrivals


class ProfileStoreWatcher:
    """Poll a SIMCARD profile-store directory and fire callbacks on new ICCIDs.

    The watcher uses an explicit ``seed_on_start`` contract: the first
    poll sets the baseline and does NOT fire callbacks for ICCIDs
    already on disk. This prevents "welcome back" spam when an
    operator restarts the watcher against an existing store.
    """

    def __init__(
        self,
        store_root: Path,
        on_arrival: Callable[[ProfileArrival], None],
        *,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        seed_on_start: bool = True,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if callable(on_arrival) is False:
            raise TypeError("on_arrival must be callable")
        if poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        self._store_root = Path(store_root).expanduser().resolve()
        self._on_arrival = on_arrival
        self._poll_interval_seconds = float(poll_interval_seconds)
        self._seed_on_start = bool(seed_on_start)
        self._clock = clock
        self._sleep = sleep
        self._stop_event = threading.Event()
        self._seen_iccids: set[str] = set()
        self._seeded: bool = False

    @property
    def store_root(self) -> Path:
        return self._store_root

    def poll_once(self) -> list[ProfileArrival]:
        """Poll for card presence once and return the current card state dict."""
        try:
            arrivals = _scan_store_once(self._store_root)
        except OSError as scan_error:
            # A transient filesystem error (permission denied on a stray
            # profile dir, a racing delete) should never take the whole
            # watcher down. Log and return an empty list so the main
            # loop keeps polling on the next tick.
            _LOGGER.warning(
                "simcard_watch scan raised %s: %s (continuing)",
                scan_error.__class__.__name__,
                scan_error,
            )
            return []
        current_iccids = {arrival.iccid for arrival in arrivals}
        if self._seeded is False:
            self._seeded = True
            if self._seed_on_start is True:
                self._seen_iccids = current_iccids
                return []
        fresh = [
            arrival
            for arrival in arrivals
            if arrival.iccid not in self._seen_iccids
        ]
        if len(fresh) > 0:
            for arrival in fresh:
                try:
                    self._on_arrival(arrival)
                except Exception as callback_error:
                    _LOGGER.warning(
                        "simcard_watch callback raised: %s: %s",
                        callback_error.__class__.__name__,
                        callback_error,
                    )
        self._seen_iccids = current_iccids
        return fresh

    def stop(self) -> None:
        self._stop_event.set()

    def run_forever(self) -> None:
        """Run the card-presence polling loop forever until interrupted."""
        while self._stop_event.is_set() is False:
            try:
                self.poll_once()
            except Exception as loop_error:
                # poll_once() is already hardened against scan OSErrors,
                # but a downstream callback or state corruption could
                # still raise. Log and keep the loop alive so a
                # temporary hiccup does not require an operator restart.
                _LOGGER.warning(
                    "simcard_watch poll_once raised %s: %s (continuing)",
                    loop_error.__class__.__name__,
                    loop_error,
                )
            deadline = self._clock() + self._poll_interval_seconds
            while self._clock() < deadline:
                if self._stop_event.is_set() is True:
                    return
                self._sleep(min(0.1, self._poll_interval_seconds))


def default_profile_store_root(workspace_root: Path) -> Path:
    """Resolve the simulator default profile-store root.

    Mirrors ``SIMCARD.config.get_sim_profile_store_path``'s default,
    but resolved relative to the caller-supplied workspace. We do the
    import lazily so ``simcard_watch`` stays importable in contexts
    where the simulator-side packages are unavailable.
    """
    try:
        from SIMCARD.config import get_sim_profile_store_path
        from SIMCARD.euicc_store import default_profile_store_path
        from SIMCARD.config import get_sim_euicc_store_root
    except ImportError:
        return Path(workspace_root) / "Workspace" / "SIMCARD" / "profile_store"
    explicit = str(get_sim_profile_store_path() or "").strip()
    if len(explicit) > 0:
        return Path(explicit).expanduser().resolve()
    euicc_root = str(get_sim_euicc_store_root() or "").strip()
    if len(euicc_root) == 0:
        return Path(workspace_root) / "Workspace" / "SIMCARD" / "profile_store"
    return Path(default_profile_store_path(euicc_root)).expanduser().resolve()


def _build_default_tui_command(arrival: ProfileArrival) -> list[str]:
    target = arrival.preferred_profile_path
    if target is None:
        raise RuntimeError(
            f"Arrival {arrival.iccid} has no usable profile file on disk"
        )
    python_binary = sys.executable or "python3"
    # Previous iterations of this hook invoked the diff TUI with the
    # same profile on both sides, which always produced "no
    # differences" — useless for an operator. Instead drop the new
    # profile into the profile-package shell with a three-command
    # inspect batch so the operator sees profile_name/iccid/imsi plus
    # the TREE of PE sections immediately.
    batch_cmd = (
        f"USE {shlex.quote(str(target))}; INFO; TREE; EXIT"
    )
    return [
        python_binary,
        "-m",
        "Tools.ProfilePackage",
        "--cmd",
        batch_cmd,
    ]


_LAUNCHER_TEMPLATE_VARIABLES: tuple[str, ...] = (
    "iccid",
    "profile",
    "profile_path",
    "profile_dir",
    "manifest",
    "python",
)


def _expand_launcher_template(
    template: str,
    arrival: ProfileArrival,
) -> list[str]:
    """Expand the documented ``{token}`` placeholders inside a launcher template.

    The accepted tokens are:

    * ``{iccid}``         — the newly seen ICCID.
    * ``{profile}``       — the preferred profile file path.
    * ``{profile_path}``  — alias of ``{profile}``; kept for callers that
      still use the original placeholder name.
    * ``{profile_dir}``   — the per-profile directory.
    * ``{manifest}``      — the manifest JSON path (empty string if the
      arrival did not ship a manifest).
    * ``{python}``        — ``sys.executable``.

    Unknown tokens are substituted with empty strings rather than
    raising: a typo in the operator's ``--launcher`` string must not
    crash the watcher mid-run.
    """
    target = arrival.preferred_profile_path
    if target is None:
        return []
    manifest = arrival.manifest_path
    substitutions = {
        "iccid": arrival.iccid,
        "profile": str(target),
        "profile_path": str(target),
        "profile_dir": str(arrival.profile_dir),
        "manifest": str(manifest) if manifest is not None else "",
        "python": sys.executable or "python3",
    }
    # Use a defaultdict-style fallback so unknown placeholders render
    # as empty strings. str.format_map is the right primitive here
    # because we want substitution without argparse-style strictness.

    class _SafeSubs(dict):
        def __missing__(self, key: str) -> str:
            _LOGGER.warning(
                "simcard_watch launcher template referenced unknown placeholder '%s'",
                key,
            )
            return ""

    expanded = template.format_map(_SafeSubs(substitutions))
    # shlex.split respects quoted path segments, which is critical for
    # operators who run the watcher on workspaces with whitespace in
    # the filesystem layout (macOS "~/Library/Application Support/...").
    try:
        argv = shlex.split(expanded, posix=True)
    except ValueError as split_error:
        _LOGGER.warning(
            "simcard_watch launcher template failed shlex parse: %s",
            split_error,
        )
        return []
    if len(argv) == 0:
        return []
    binary = argv[0]
    if shutil.which(binary) is None and Path(binary).is_file() is False:
        _LOGGER.warning(
            "simcard_watch launcher binary '%s' not found on PATH or disk",
            binary,
        )
    return argv


def _spawn_launcher(
    command: Sequence[str],
    *,
    cwd: Path | None,
    env: dict[str, str] | None,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdin=subprocess.DEVNULL,
    )


def watch_and_launch_tui(
    store_root: Path,
    *,
    launcher_command_factory: Callable[[ProfileArrival], Sequence[str]] | None = None,
    workspace_root: Path | None = None,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    max_arrivals: int | None = None,
) -> int:
    """Convenience loop that polls ``store_root`` and spawns a TUI per arrival.

    ``launcher_command_factory`` receives the arrival record and
    returns the argv for the TUI process. The default factory points
    at ``python -m Tools.ProfilePackage.saip_diff_tui --text`` so new
    profiles are dumped to stdout; real operators will typically pass
    a factory that invokes the transcode TUI or the shell with
    ``INSPECT``.

    ``max_arrivals`` caps how many downloads the watcher handles
    before returning. ``None`` means "run until Ctrl+C". The cap is
    useful for automated smoke tests and for single-shot CLI usage.
    """
    store_root = Path(store_root).expanduser().resolve()
    factory = launcher_command_factory or _build_default_tui_command
    seen_count = 0

    def _on_arrival(arrival: ProfileArrival) -> None:
        nonlocal seen_count
        command = list(factory(arrival))
        if len(command) == 0:
            _LOGGER.warning("simcard_watch launcher returned empty command")
            return
        sys.stderr.write(
            f"[yggdrasim-profile-autoload] new profile ICCID={arrival.iccid} "
            f"-> launching {' '.join(command)}\n"
        )
        sys.stderr.flush()
        try:
            process = _spawn_launcher(
                command,
                cwd=workspace_root,
                env=dict(os.environ),
            )
        except FileNotFoundError as exc:
            sys.stderr.write(f"[-] launcher missing: {exc}\n")
            return
        process.wait()
        seen_count += 1

    watcher = ProfileStoreWatcher(
        store_root,
        on_arrival=_on_arrival,
        poll_interval_seconds=poll_interval_seconds,
    )
    try:
        while True:
            watcher.poll_once()
            if max_arrivals is not None and seen_count >= max_arrivals:
                return 0
            time.sleep(poll_interval_seconds)
    except KeyboardInterrupt:
        return 130


def run_cli(argv: Sequence[str] | None = None) -> int:
    """Parse CLI arguments and launch the SIM-card watch loop."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="yggdrasim-profile-autoload",
        description=(
            "Watch a SIMCARD profile-store directory and auto-open new "
            "profiles in the SAIP diff TUI. Exits cleanly on Ctrl+C."
        ),
    )
    parser.add_argument(
        "--store-root",
        default="",
        help="profile-store directory (default: simulator default)",
    )
    parser.add_argument(
        "--workspace-root",
        default="",
        help="workspace root used for default resolution",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help=f"polling interval in seconds (default {DEFAULT_POLL_INTERVAL_SECONDS})",
    )
    parser.add_argument(
        "--max-arrivals",
        type=int,
        default=0,
        help="exit after N arrivals (0 = run forever, default)",
    )
    parser.add_argument(
        "--launcher",
        default="",
        help=(
            "custom launcher command. Supported placeholders: "
            "{iccid}, {profile}, {profile_path}, {profile_dir}, "
            "{manifest}, {python}. If empty, the profile-package "
            "shell is invoked with USE/INFO/TREE/EXIT."
        ),
    )
    args = parser.parse_args(argv)

    workspace_root = (
        Path(args.workspace_root).expanduser().resolve()
        if len(args.workspace_root.strip()) > 0
        else Path.cwd().resolve()
    )
    store_root = (
        Path(args.store_root).expanduser().resolve()
        if len(args.store_root.strip()) > 0
        else default_profile_store_root(workspace_root)
    )
    if store_root.is_dir() is False:
        try:
            store_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            sys.stderr.write(
                f"[-] cannot create store root {store_root}: {exc}\n"
            )
            return 4

    factory: Callable[[ProfileArrival], Sequence[str]]
    if len(args.launcher.strip()) == 0:
        factory = _build_default_tui_command
    else:
        template = args.launcher

        def _custom_factory(arrival: ProfileArrival) -> Sequence[str]:
            return _expand_launcher_template(template, arrival)

        factory = _custom_factory

    max_arrivals = None if args.max_arrivals <= 0 else args.max_arrivals

    sys.stderr.write(
        f"[yggdrasim-profile-autoload] watching {store_root} "
        f"(poll={args.poll_interval}s, max_arrivals={max_arrivals})\n"
    )
    sys.stderr.flush()
    return watch_and_launch_tui(
        store_root,
        launcher_command_factory=factory,
        workspace_root=workspace_root,
        poll_interval_seconds=float(args.poll_interval),
        max_arrivals=max_arrivals,
    )


if __name__ == "__main__":
    raise SystemExit(run_cli())
