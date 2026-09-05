#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Write native desktop launchers that start the YggdraSIM Command Center.

Runs after a ``pipx`` or ``pip`` install and drops one OS-native launcher
per host so the GUI can be started without a terminal:

* Linux -- ``~/.local/share/applications/yggdrasim.desktop`` with
  ``Terminal=false``.
* Windows -- a Start Menu ``.lnk`` built through ``WScript.Shell``,
  pointed at the ``pythonw``-backed ``yggdrasim-desktop.exe`` so no
  console window appears behind the GUI.
* macOS -- an ``osacompile`` applet at ``~/Applications/YggdraSIM.app``,
  or the equivalent instructions when ``osacompile`` is unavailable.

The launcher target is resolved to an absolute path at install time.
Desktop sessions and Explorer do not inherit the shell ``PATH``, so a
launcher that merely names ``yggdrasim-desktop`` fails on exactly the
hosts this script exists for.

Launchers carry the YggdraSIM mark shipped as ``yggdrasim_common``
package data. Linux consumes the SVG through the icon theme, Windows
needs an ``.ico`` container that is written from the shipped PNG here,
and macOS converts the PNG with ``sips``. Every icon step is optional:
a host without the assets, or run with ``--no-icon``, gets a working
launcher with the desktop default icon.

    python scripts/install_shortcuts.py                # install
    python scripts/install_shortcuts.py --dry-run      # show, write nothing
    python scripts/install_shortcuts.py --force        # overwrite existing
    python scripts/install_shortcuts.py --uninstall    # remove
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

APPLICATION_NAME = "YggdraSIM"
DESKTOP_ENTRY_STEM = "yggdrasim"
GENERIC_NAME = "eUICC and SIM toolkit"
LAUNCHER_COMMENT = "Open the YggdraSIM Command Center"

# ``yggdrasim-desktop`` is the ``[project.gui-scripts]`` entry: on Windows
# setuptools backs it with ``pythonw.exe``, which is what makes a
# double-clicked shortcut windowless. ``yggdrasim-gui`` is the console
# entry and is the fallback for installs predating the gui-scripts table.
WINDOWLESS_ENTRY_POINT = "yggdrasim-desktop"
CONSOLE_ENTRY_POINT = "yggdrasim-gui"
FALLBACK_MODULE = "main.gui"

# Icon-theme name written into ``Icon=``; also the installed file stem.
ICON_NAME = "yggdrasim"
SVG_ASSET = "yggdrasim.svg"
PNG_ICO_ASSET = "yggdrasim-256.png"
PNG_LARGE_ASSET = "yggdrasim-512.png"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNSUPPORTED = 2


@dataclass(frozen=True)
class LauncherTarget:
    """A resolved, absolute command that starts the GUI."""

    command: tuple[str, ...]
    origin: str
    windowless: bool

    def display(self) -> str:
        return " ".join(self.command)


class ResolutionError(RuntimeError):
    """No GUI launcher could be resolved on this host."""


def _emit(message: str) -> None:
    print(message)


def _absolute(path: Path) -> str:
    """Absolute path with symlinks left intact.

    ``Path.resolve`` would follow the symlink pipx keeps in
    ``~/.local/bin``, pinning the launcher to the venv's internal layout
    instead of the stable shim the package manager maintains.
    """
    return os.path.abspath(str(path.expanduser()))


def _interpreter_script_dir() -> Path:
    """Directory holding console scripts for the running interpreter.

    For a pipx or venv install this is the environment's ``bin`` /
    ``Scripts`` folder, which holds the generated entry points even when
    the user's ``PATH`` never exposed them.
    """
    return Path(sys.executable).resolve().parent


def _executable_candidates(entry_point: str) -> list[Path]:
    candidates: list[Path] = []
    on_path = shutil.which(entry_point)
    if on_path is not None:
        candidates.append(Path(on_path))
    script_dir = _interpreter_script_dir()
    suffixes = (".exe", ".cmd", "") if os.name == "nt" else ("",)
    for suffix in suffixes:
        candidates.append(script_dir / f"{entry_point}{suffix}")
    return candidates


def _windowless_interpreter() -> Path:
    """The console-free interpreter for the module fallback on Windows."""
    interpreter = Path(sys.executable).resolve()
    if os.name != "nt":
        return interpreter
    windowless = interpreter.with_name("pythonw.exe")
    if windowless.exists():
        return windowless
    return interpreter


def _module_fallback_is_importable(interpreter: Path) -> bool:
    """Check the fallback interpreter can import the GUI shim.

    ``-m main.gui`` only works when the interpreter has YggdraSIM
    installed; resolving to it blindly would write a launcher that fails
    at double-click time rather than here, where the failure is legible.
    """
    probe = interpreter
    if os.name == "nt" and probe.name.lower() == "pythonw.exe":
        console_probe = probe.with_name("python.exe")
        if console_probe.exists():
            probe = console_probe
    try:
        completed = subprocess.run(
            [str(probe), "-c", f"import {FALLBACK_MODULE}"],
            capture_output=True,
            timeout=60,
            check=False,
            # Probe from a neutral directory. Run from a checkout, the
            # current directory is on ``sys.path`` and the import would
            # succeed for an interpreter that has no YggdraSIM installed,
            # producing a launcher that only works from the checkout.
            cwd=tempfile.gettempdir(),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def resolve_target(explicit: str | None = None) -> LauncherTarget:
    """Resolve the absolute command a launcher should run.

    Preference order: the windowless entry point, the console entry
    point, then ``<interpreter> -m main.gui``. Each is looked up on
    ``PATH`` first and next to the running interpreter, which is where a
    pipx venv keeps its scripts.
    """
    if explicit is not None:
        explicit_path = shutil.which(explicit) or explicit
        resolved = Path(explicit_path).expanduser()
        if not resolved.exists():
            raise ResolutionError(f"--target does not exist: {resolved}")
        return LauncherTarget(
            command=(_absolute(resolved),),
            origin="--target",
            windowless=resolved.stem.lower() == WINDOWLESS_ENTRY_POINT,
        )

    for entry_point, windowless in (
        (WINDOWLESS_ENTRY_POINT, True),
        (CONSOLE_ENTRY_POINT, False),
    ):
        for candidate in _executable_candidates(entry_point):
            if candidate.exists():
                return LauncherTarget(
                    command=(_absolute(candidate),),
                    origin=f"{entry_point} entry point",
                    windowless=windowless,
                )

    interpreter = _windowless_interpreter()
    if _module_fallback_is_importable(interpreter):
        return LauncherTarget(
            command=(str(interpreter), "-m", FALLBACK_MODULE),
            origin=f"{interpreter.name} -m {FALLBACK_MODULE}",
            windowless=interpreter.name.lower() == "pythonw.exe",
        )

    raise ResolutionError(
        "no YggdraSIM GUI launcher found. Install the package first, for "
        "example: pipx install '.[gui,saip]' (from a checkout) or "
        "pip install '.[gui]', then re-run this script with the same "
        "interpreter."
    )


def asset_directory() -> Path | None:
    """Locate the shipped icon assets, in a checkout or an installed wheel.

    The checkout is tried first because this script is normally run from
    one, and the interpreter running it need not have YggdraSIM
    installed. ``importlib.resources`` covers the pipx and wheel case,
    where only the installed package exists.
    """
    checkout = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "assets"
    if (checkout / SVG_ASSET).is_file():
        return checkout
    try:
        from importlib.resources import files

        installed = Path(str(files("yggdrasim_common") / "assets"))
    except (ImportError, ModuleNotFoundError, TypeError, OSError):
        return None
    if (installed / SVG_ASSET).is_file():
        return installed
    return None


def _png_dimensions(data: bytes) -> tuple[int, int]:
    """Read width and height straight out of a PNG's IHDR chunk."""
    if data[:8] != PNG_SIGNATURE or data[12:16] != b"IHDR":
        raise ValueError("icon asset is not a PNG")
    width, height = struct.unpack(">II", data[16:24])
    return int(width), int(height)


def build_ico(png_data: bytes) -> bytes:
    """Wrap a PNG in a single-image ICO container.

    Windows accepts PNG-compressed icon entries (Vista and later), so the
    container is a 6-byte ICONDIR plus one 16-byte ICONDIRENTRY in front
    of the PNG bytes -- no image library, and no rasterizer, needed at
    install time. The size fields are one byte each and encode 256 as
    zero, which caps an entry at 256x256.
    """
    width, height = _png_dimensions(png_data)
    if not (0 < width <= 256 and 0 < height <= 256):
        raise ValueError(f"ICO entries cap at 256x256; asset is {width}x{height}")
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack(
        "<BBBBHHII",
        0 if width == 256 else width,
        0 if height == 256 else height,
        0,
        0,
        1,
        32,
        len(png_data),
        len(header) + 16,
    )
    return header + entry + png_data


def _desktop_exec_value(command: tuple[str, ...]) -> str:
    """Quote a command for a desktop entry ``Exec=`` key.

    Desktop entries use their own quoting (freedesktop Desktop Entry
    Specification s. "Exec variables"): double quotes around arguments
    that need them, backslash escapes inside, and a literal percent sign
    written as ``%%``.
    """
    parts: list[str] = []
    for argument in command:
        escaped = argument.replace("\\", "\\\\").replace('"', '\\"')
        escaped = escaped.replace("%", "%%")
        if any(character in argument for character in ' \t"\'\\><~|&;$*?#()`'):
            parts.append(f'"{escaped}"')
        else:
            parts.append(escaped)
    return " ".join(parts)


def render_desktop_entry(
    target: LauncherTarget, icon_name: str | None = None
) -> str:
    """Render the Linux ``.desktop`` body.

    ``Terminal=false`` is the key that keeps no terminal pinned open for
    the GUI's lifetime. ``Categories`` and ``Keywords`` are semicolon
    terminated because the specification treats them as string lists,
    and ``Categories`` names a single main category so the entry cannot
    appear twice in a menu. ``Icon`` names a theme entry rather than a
    path, which is what lets the icon survive a moved install; it is
    omitted when the mark could not be installed, because a dangling
    name shows a broken-image glyph in some menus.
    """
    exec_value = _desktop_exec_value(target.command)
    lines = [
        "[Desktop Entry]",
        "Type=Application",
        "Version=1.0",
        f"Name={APPLICATION_NAME}",
        f"GenericName={GENERIC_NAME}",
        f"Comment={LAUNCHER_COMMENT}",
        f"Exec={exec_value}",
        f"TryExec={target.command[0]}",
        "Terminal=false",
        "StartupNotify=true",
    ]
    if icon_name is not None:
        lines.append(f"Icon={icon_name}")
    lines += [
        f"StartupWMClass={APPLICATION_NAME}",
        "Categories=Development;",
        "Keywords=SIM;eUICC;eSIM;APDU;SmartCard;",
    ]
    return "\n".join(lines) + "\n"


def _linux_applications_dir(install_dir: Path | None) -> Path:
    if install_dir is not None:
        return install_dir
    data_home = os.environ.get("XDG_DATA_HOME", "").strip()
    if len(data_home) > 0:
        return Path(data_home) / "applications"
    return Path.home() / ".local" / "share" / "applications"


def _icon_theme_dir() -> Path:
    data_home = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(data_home) if len(data_home) > 0 else Path.home() / ".local" / "share"
    return base / "icons" / "hicolor"


def _linux_icon_targets() -> tuple[tuple[str, Path], ...]:
    """Assets paired with their icon-theme destinations.

    The scalable SVG is what most menus pick up; the 256x256 PNG covers
    environments whose icon loader has no SVG support.
    """
    theme = _icon_theme_dir()
    return (
        (SVG_ASSET, theme / "scalable" / "apps" / f"{ICON_NAME}.svg"),
        (PNG_ICO_ASSET, theme / "256x256" / "apps" / f"{ICON_NAME}.png"),
    )


def _refresh_icon_cache() -> None:
    """Best-effort icon-cache refresh; absence of the tool is not an error."""
    tool = shutil.which("gtk-update-icon-cache")
    if tool is None:
        return
    try:
        subprocess.run(
            [tool, "--force", "--quiet", str(_icon_theme_dir())],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def install_linux_icons(*, dry_run: bool) -> str | None:
    """Install the mark into the user icon theme.

    Returns the theme name for ``Icon=``, or ``None`` when nothing was
    installed so the caller omits the key.
    """
    assets = asset_directory()
    if assets is None:
        _emit("[!] icon assets not found; using the desktop default icon")
        return None
    installed = False
    for asset_name, destination in _linux_icon_targets():
        source = assets / asset_name
        if not source.is_file():
            continue
        if dry_run:
            _emit(f"[dry-run] would install icon {destination}")
            installed = True
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
        _emit(f"[+] installed icon: {destination}")
        installed = True
    if installed is False:
        return None
    if dry_run is False:
        _refresh_icon_cache()
    return ICON_NAME


def uninstall_linux_icons(*, dry_run: bool) -> None:
    removed = False
    for _asset_name, destination in _linux_icon_targets():
        if not destination.exists():
            continue
        if dry_run:
            _emit(f"[dry-run] would remove icon {destination}")
            continue
        destination.unlink()
        _emit(f"[-] removed icon: {destination}")
        removed = True
    if removed:
        _refresh_icon_cache()


def _refresh_desktop_database(applications_dir: Path) -> None:
    """Best-effort menu refresh; absence of the tool is not an error."""
    tool = shutil.which("update-desktop-database")
    if tool is None:
        return
    try:
        subprocess.run(
            [tool, str(applications_dir)],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def install_linux(
    target: LauncherTarget,
    *,
    install_dir: Path | None,
    dry_run: bool,
    force: bool,
    with_icon: bool = True,
) -> int:
    applications_dir = _linux_applications_dir(install_dir)
    entry_path = applications_dir / f"{DESKTOP_ENTRY_STEM}.desktop"

    if entry_path.exists() and not force and not dry_run:
        _emit(f"[=] desktop entry already present: {entry_path}")
        _emit("    re-run with --force to overwrite it")
        return EXIT_OK

    icon_name = install_linux_icons(dry_run=dry_run) if with_icon else None
    body = render_desktop_entry(target, icon_name)

    if dry_run:
        _emit(f"[dry-run] would write {entry_path}")
        _emit(body.rstrip("\n"))
        return EXIT_OK

    applications_dir.mkdir(parents=True, exist_ok=True)
    entry_path.write_text(body, encoding="utf-8")
    entry_path.chmod(0o644)
    _refresh_desktop_database(applications_dir)
    _emit(f"[+] wrote desktop entry: {entry_path}")
    _emit(f"    Exec={_desktop_exec_value(target.command)}")
    _emit("    Search your application menu for YggdraSIM to launch it.")
    return EXIT_OK


def uninstall_linux(*, install_dir: Path | None, dry_run: bool) -> int:
    applications_dir = _linux_applications_dir(install_dir)
    entry_path = applications_dir / f"{DESKTOP_ENTRY_STEM}.desktop"
    uninstall_linux_icons(dry_run=dry_run)
    if not entry_path.exists():
        _emit(f"[=] no desktop entry at {entry_path}")
        return EXIT_OK
    if dry_run:
        _emit(f"[dry-run] would remove {entry_path}")
        return EXIT_OK
    entry_path.unlink()
    _refresh_desktop_database(applications_dir)
    _emit(f"[-] removed desktop entry: {entry_path}")
    return EXIT_OK


def _powershell_executable() -> str | None:
    for name in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        found = shutil.which(name)
        if found is not None:
            return found
    return None


def _powershell_quote(value: str) -> str:
    """Quote for a PowerShell single-quoted string (doubling embedded quotes)."""
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _windows_icon_dir() -> Path:
    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    base = (
        Path(local_appdata)
        if len(local_appdata) > 0
        else Path.home() / "AppData" / "Local"
    )
    return base / APPLICATION_NAME


def install_windows_icon(*, dry_run: bool) -> Path | None:
    """Write the ``.ico`` a shortcut can point at.

    Windows shortcuts take an icon from an ``.ico``, ``.exe``, or
    ``.dll`` only, so the shipped PNG is wrapped in an ICO container
    next to the install rather than referenced directly.
    """
    assets = asset_directory()
    if assets is None:
        _emit("[!] icon assets not found; using the default shortcut icon")
        return None
    source = assets / PNG_ICO_ASSET
    if not source.is_file():
        _emit(f"[!] icon asset missing: {source}")
        return None
    destination = _windows_icon_dir() / f"{ICON_NAME}.ico"
    if dry_run:
        _emit(f"[dry-run] would write icon {destination}")
        return destination
    try:
        payload = build_ico(source.read_bytes())
    except (OSError, ValueError) as error:
        _emit(f"[!] icon conversion failed: {error}")
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    _emit(f"[+] wrote icon: {destination}")
    return destination


def render_shortcut_script(
    target: LauncherTarget, link_path: Path, icon_path: Path | None = None
) -> str:
    """Render the PowerShell that creates the ``.lnk`` through WScript.Shell.

    ``WindowStyle`` is left at 1 (normal): it controls how the target's
    own window opens, not whether a console appears. The console is
    suppressed by the target itself being a ``pythonw``-backed
    executable, which is why ``resolve_target`` prefers the
    gui-scripts entry point.
    """
    executable = target.command[0]
    arguments = " ".join(target.command[1:])
    working_directory = str(Path(executable).parent)
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "$shell = New-Object -ComObject WScript.Shell",
        f"$link = $shell.CreateShortcut({_powershell_quote(str(link_path))})",
        f"$link.TargetPath = {_powershell_quote(executable)}",
        f"$link.Arguments = {_powershell_quote(arguments)}",
        f"$link.WorkingDirectory = {_powershell_quote(working_directory)}",
        f"$link.Description = {_powershell_quote(LAUNCHER_COMMENT)}",
        "$link.WindowStyle = 1",
    ]
    if icon_path is not None:
        # The trailing ",0" selects the first icon in the file.
        lines.append(
            f"$link.IconLocation = {_powershell_quote(f'{icon_path},0')}"
        )
    lines.append("$link.Save()")
    return "\n".join(lines)


def _windows_start_menu_dir(install_dir: Path | None) -> Path:
    if install_dir is not None:
        return install_dir
    appdata = os.environ.get("APPDATA", "").strip()
    base = Path(appdata) if len(appdata) > 0 else Path.home() / "AppData" / "Roaming"
    return base / "Microsoft" / "Windows" / "Start Menu" / "Programs"


def _manual_windows_instructions(target: LauncherTarget, link_path: Path) -> None:
    _emit("[!] PowerShell was not found, so no .lnk was created.")
    _emit("    Create the shortcut by hand:")
    _emit(f"      1. Right-click in {link_path.parent} -> New -> Shortcut")
    _emit(f"      2. Location: {target.display()}")
    _emit(f"      3. Name: {APPLICATION_NAME}")


def install_windows(
    target: LauncherTarget,
    *,
    install_dir: Path | None,
    dry_run: bool,
    force: bool,
    with_icon: bool = True,
) -> int:
    start_menu = _windows_start_menu_dir(install_dir)
    link_path = start_menu / f"{APPLICATION_NAME}.lnk"
    icon_path = install_windows_icon(dry_run=dry_run) if with_icon else None
    script = render_shortcut_script(target, link_path, icon_path)

    if not target.windowless:
        _emit(
            "[!] resolved a console launcher; the shortcut will show a "
            "console window. Reinstall so the yggdrasim-desktop entry "
            "point exists to avoid it."
        )
    if link_path.exists() and not force and not dry_run:
        _emit(f"[=] shortcut already present: {link_path}")
        _emit("    re-run with --force to overwrite it")
        return EXIT_OK
    if dry_run:
        _emit(f"[dry-run] would write {link_path}")
        _emit(script)
        return EXIT_OK

    powershell = _powershell_executable()
    if powershell is None:
        _manual_windows_instructions(target, link_path)
        return EXIT_FAILED

    start_menu.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        _emit(f"[-] shortcut creation failed: {type(error).__name__}: {error}")
        _manual_windows_instructions(target, link_path)
        return EXIT_FAILED
    if completed.returncode != 0:
        _emit(f"[-] PowerShell exited {completed.returncode}")
        _emit((completed.stderr or "").strip())
        _manual_windows_instructions(target, link_path)
        return EXIT_FAILED

    _emit(f"[+] wrote Start Menu shortcut: {link_path}")
    _emit(f"    Target={target.display()}")
    return EXIT_OK


def uninstall_windows(*, install_dir: Path | None, dry_run: bool) -> int:
    icon_path = _windows_icon_dir() / f"{ICON_NAME}.ico"
    if icon_path.exists():
        if dry_run:
            _emit(f"[dry-run] would remove icon {icon_path}")
        else:
            icon_path.unlink()
            _emit(f"[-] removed icon: {icon_path}")
    link_path = _windows_start_menu_dir(install_dir) / f"{APPLICATION_NAME}.lnk"
    if not link_path.exists():
        _emit(f"[=] no shortcut at {link_path}")
        return EXIT_OK
    if dry_run:
        _emit(f"[dry-run] would remove {link_path}")
        return EXIT_OK
    link_path.unlink()
    _emit(f"[-] removed shortcut: {link_path}")
    return EXIT_OK


def _macos_applications_dir(install_dir: Path | None, system_wide: bool) -> Path:
    if install_dir is not None:
        return install_dir
    if system_wide:
        return Path("/Applications")
    return Path.home() / "Applications"


def render_applescript(target: LauncherTarget) -> str:
    """Render the applet source.

    The shell command is backgrounded and its streams are discarded:
    an applet that waits on the GUI stays "running" in the Dock for the
    session's whole lifetime, which is the behaviour a windowless
    launcher is meant to avoid.
    """
    quoted = " ".join(f"'{part}'" for part in target.command)
    return f'do shell script "{quoted} > /dev/null 2>&1 &"\n'


def apply_macos_icon(app_path: Path, *, dry_run: bool) -> None:
    """Replace the applet icon with the YggdraSIM mark.

    ``sips`` ships with macOS and converts the PNG straight to the
    ``.icns`` the bundle expects. A host without it keeps the default
    AppleScript applet icon, which is cosmetic rather than fatal.
    """
    assets = asset_directory()
    if assets is None:
        _emit("[!] icon assets not found; the applet keeps the default icon")
        return
    source = assets / PNG_LARGE_ASSET
    if not source.is_file():
        _emit(f"[!] icon asset missing: {source}")
        return
    converter = shutil.which("sips")
    if converter is None:
        _emit("[!] sips not found; the applet keeps the default icon")
        return
    destination = app_path / "Contents" / "Resources" / "applet.icns"
    if dry_run:
        _emit(f"[dry-run] would convert {source.name} to {destination}")
        return
    try:
        completed = subprocess.run(
            [converter, "-s", "format", "icns", str(source), "--out", str(destination)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        _emit(f"[!] icon conversion failed: {type(error).__name__}: {error}")
        return
    if completed.returncode != 0:
        _emit(f"[!] sips exited {completed.returncode}; keeping the default icon")
        return
    _emit(f"[+] applied icon: {destination}")


def _macos_manual_instructions(target: LauncherTarget, app_path: Path) -> None:
    _emit("    Build the applet by hand with:")
    _emit(f"      cat > /tmp/{DESKTOP_ENTRY_STEM}.applescript <<'EOF'")
    _emit(render_applescript(target).rstrip("\n"))
    _emit("      EOF")
    _emit(f"      osacompile -o {app_path} /tmp/{DESKTOP_ENTRY_STEM}.applescript")


def install_macos(
    target: LauncherTarget,
    *,
    install_dir: Path | None,
    system_wide: bool,
    dry_run: bool,
    force: bool,
    with_icon: bool = True,
) -> int:
    applications_dir = _macos_applications_dir(install_dir, system_wide)
    app_path = applications_dir / f"{APPLICATION_NAME}.app"
    source = render_applescript(target)

    if app_path.exists() and not force and not dry_run:
        _emit(f"[=] app bundle already present: {app_path}")
        _emit("    re-run with --force to overwrite it")
        return EXIT_OK
    if dry_run:
        _emit(f"[dry-run] would build {app_path} from:")
        _emit(source.rstrip("\n"))
        if with_icon:
            apply_macos_icon(app_path, dry_run=True)
        return EXIT_OK

    compiler = shutil.which("osacompile")
    if compiler is None:
        _emit("[!] osacompile was not found, so no .app was created.")
        _macos_manual_instructions(target, app_path)
        return EXIT_FAILED

    applications_dir.mkdir(parents=True, exist_ok=True)
    if app_path.exists() and force:
        shutil.rmtree(app_path)

    with tempfile.TemporaryDirectory() as work_dir:
        script_path = Path(work_dir) / f"{DESKTOP_ENTRY_STEM}.applescript"
        script_path.write_text(source, encoding="utf-8")
        try:
            completed = subprocess.run(
                [compiler, "-o", str(app_path), str(script_path)],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            _emit(f"[-] osacompile failed: {type(error).__name__}: {error}")
            _macos_manual_instructions(target, app_path)
            return EXIT_FAILED

    if completed.returncode != 0:
        _emit(f"[-] osacompile exited {completed.returncode}")
        _emit((completed.stderr or "").strip())
        _macos_manual_instructions(target, app_path)
        return EXIT_FAILED

    if with_icon:
        apply_macos_icon(app_path, dry_run=False)
    _emit(f"[+] built app bundle: {app_path}")
    _emit(f"    Command={target.display()}")
    _emit("    Launch it from Finder, Spotlight, or the Dock.")
    return EXIT_OK


def uninstall_macos(
    *, install_dir: Path | None, system_wide: bool, dry_run: bool
) -> int:
    app_path = _macos_applications_dir(install_dir, system_wide) / f"{APPLICATION_NAME}.app"
    if not app_path.exists():
        _emit(f"[=] no app bundle at {app_path}")
        return EXIT_OK
    # Guard the recursive delete: only a directory whose name this script
    # owns is removable, never an arbitrary --install-dir argument.
    if not app_path.is_dir() or app_path.suffix != ".app":
        _emit(f"[-] refusing to remove non-bundle path: {app_path}")
        return EXIT_FAILED
    if dry_run:
        _emit(f"[dry-run] would remove {app_path}")
        return EXIT_OK
    shutil.rmtree(app_path)
    _emit(f"[-] removed app bundle: {app_path}")
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install_shortcuts.py",
        description=(
            "Install or remove the native desktop launcher for the "
            "YggdraSIM Command Center."
        ),
    )
    parser.add_argument(
        "--target",
        default=None,
        help=(
            "explicit GUI executable to point the launcher at; defaults to "
            f"{WINDOWLESS_ENTRY_POINT}, then {CONSOLE_ENTRY_POINT}, then "
            f"<interpreter> -m {FALLBACK_MODULE}"
        ),
    )
    parser.add_argument(
        "--install-dir",
        default=None,
        help=(
            "directory to write the launcher into; defaults to the "
            "platform location (XDG applications dir, Start Menu, "
            "~/Applications)"
        ),
    )
    parser.add_argument(
        "--system",
        action="store_true",
        help="macOS only: target /Applications instead of ~/Applications",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing launcher",
    )
    parser.add_argument(
        "--no-icon",
        action="store_true",
        help="skip the YggdraSIM mark and use the desktop default icon",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be written without touching the filesystem",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="remove a previously installed launcher",
    )
    return parser


def run_cli(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    install_dir = Path(args.install_dir).expanduser() if args.install_dir else None
    system = platform.system()

    if args.uninstall:
        if system == "Linux":
            return uninstall_linux(install_dir=install_dir, dry_run=args.dry_run)
        if system == "Windows":
            return uninstall_windows(install_dir=install_dir, dry_run=args.dry_run)
        if system == "Darwin":
            return uninstall_macos(
                install_dir=install_dir,
                system_wide=args.system,
                dry_run=args.dry_run,
            )
        _emit(f"[-] unsupported platform: {system}")
        return EXIT_UNSUPPORTED

    try:
        target = resolve_target(args.target)
    except ResolutionError as error:
        _emit(f"[-] {error}")
        return EXIT_FAILED
    _emit(f"[*] launcher target: {target.display()}  (via {target.origin})")

    with_icon = not args.no_icon
    if system == "Linux":
        return install_linux(
            target,
            install_dir=install_dir,
            dry_run=args.dry_run,
            force=args.force,
            with_icon=with_icon,
        )
    if system == "Windows":
        return install_windows(
            target,
            install_dir=install_dir,
            dry_run=args.dry_run,
            force=args.force,
            with_icon=with_icon,
        )
    if system == "Darwin":
        return install_macos(
            target,
            install_dir=install_dir,
            system_wide=args.system,
            dry_run=args.dry_run,
            force=args.force,
            with_icon=with_icon,
        )
    _emit(f"[-] unsupported platform: {system}")
    return EXIT_UNSUPPORTED


if __name__ == "__main__":
    sys.exit(run_cli())
