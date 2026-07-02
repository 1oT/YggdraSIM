# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP file-open picker: Textual TUI widget for selecting a profile file from the default profile directory."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .saip_tool import SaipToolBridge


_SUPPORTED_PROFILE_SUFFIXES = {
    ".bin",
    ".der",
    ".hex",
    ".txt",
    ".varder",
    ".upp",
}


@dataclass(frozen=True, slots=True)
class SaipOpenPickerEntry:
    path: Path
    label: str
    is_directory: bool


def picker_start_directory(bridge: SaipToolBridge) -> Path:
    """Return the directory path that the file picker TUI should open in."""
    candidate_directories: list[Path] = []
    if getattr(bridge, "last_input_open_directory", None) is not None:
        candidate_directories.append(Path(bridge.last_input_open_directory))
    current_input_file = getattr(bridge, "current_input_file", None)
    if current_input_file is not None:
        candidate_directories.append(Path(current_input_file).expanduser().resolve().parent)
    candidate_directories.append(Path(bridge.default_profile_dir))
    candidate_directories.append(Path(bridge.workspace_root))
    for raw_candidate in candidate_directories:
        candidate = Path(raw_candidate).expanduser().resolve()
        if candidate.exists() is False:
            continue
        if candidate.is_dir() is False:
            continue
        return candidate
    return Path.cwd().resolve()


def picker_entries_for_directory(directory_path: Path) -> list[SaipOpenPickerEntry]:
    """Return a sorted list of file-picker entry dicts for the given directory."""
    normalized_directory = Path(directory_path).expanduser().resolve()
    entries: list[SaipOpenPickerEntry] = []
    parent_directory = normalized_directory.parent
    if parent_directory != normalized_directory:
        entries.append(
            SaipOpenPickerEntry(
                path=parent_directory,
                label="DIR  ../",
                is_directory=True,
            )
        )

    directory_entries: list[SaipOpenPickerEntry] = []
    file_entries: list[SaipOpenPickerEntry] = []
    for child in sorted(normalized_directory.iterdir(), key=lambda item: item.name.lower()):
        if child.name.startswith("."):
            continue
        resolved_child = child.resolve()
        if child.is_dir():
            directory_entries.append(
                SaipOpenPickerEntry(
                    path=resolved_child,
                    label=f"DIR  {child.name}/",
                    is_directory=True,
                )
            )
            continue
        if child.is_file() is False:
            continue
        if child.suffix.lower() not in _SUPPORTED_PROFILE_SUFFIXES:
            continue
        file_entries.append(
            SaipOpenPickerEntry(
                path=resolved_child,
                label=child.name,
                is_directory=False,
            )
        )

    entries.extend(directory_entries)
    entries.extend(file_entries)
    return entries


def _clear_option_list(option_list) -> None:
    clear_options = getattr(option_list, "clear_options", None)
    if callable(clear_options):
        clear_options()
        return
    clear = getattr(option_list, "clear", None)
    if callable(clear):
        clear()
        return
    remove_option_at_index = getattr(option_list, "remove_option_at_index", None)
    option_count = getattr(option_list, "option_count", None)
    if callable(remove_option_at_index) is False:
        return
    try:
        count_value = int(option_count)
    except (TypeError, ValueError):
        count_value = 0
    while count_value > 0:
        remove_option_at_index(count_value - 1)
        count_value -= 1


def _append_options(option_list, options: list[object]) -> None:
    add_options = getattr(option_list, "add_options", None)
    if callable(add_options):
        add_options(options)
        return
    add_option = getattr(option_list, "add_option", None)
    if callable(add_option):
        for option in options:
            add_option(option)


def pick_saip_profile_path_tui(bridge: SaipToolBridge) -> Path | None:
    """Run the interactive TUI file picker and return the chosen SAIP profile path."""
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Vertical
        from textual.widgets import OptionList, Static
        from textual.widgets.option_list import Option
    except Exception as error:
        raise RuntimeError(
            f"Textual is required for the SAIP OPEN picker (pip install textual): {error}"
        ) from error

    class SaipOpenPickerApp(App[Path | None]):
        BINDINGS = [
            Binding("escape", "cancel_pick", "Cancel", priority=True),
            Binding("q", "cancel_pick", "Cancel", show=False, priority=True),
            Binding("backspace", "go_parent", "Parent", priority=True),
            Binding("left", "go_parent", "Parent", show=False, priority=True),
            Binding("r", "refresh_listing", "Refresh", priority=True),
        ]

        CSS = """
        Screen {
            layout: vertical;
            background: #2E3440;
            color: #E5E9F0;
        }
        #saip_open_picker_shell {
            width: 100%;
            height: 100%;
            padding: 1 2;
        }
        #saip_open_picker_title {
            height: 1;
            color: #88C0D0;
            text-style: bold;
        }
        #saip_open_picker_directory {
            height: auto;
            margin-top: 1;
            color: #EBCB8B;
        }
        #saip_open_picker_help {
            height: auto;
            margin-top: 1;
            color: #D8DEE9;
        }
        #saip_open_picker_options {
            width: 100%;
            height: 1fr;
            margin-top: 1;
            border: solid #4C566A;
            background: #2E3440;
        }
        #saip_open_picker_status {
            height: auto;
            margin-top: 1;
            color: #A3BE8C;
        }
        """

        def __init__(self) -> None:
            super().__init__()
            self._current_directory = picker_start_directory(bridge)
            self._entries: list[SaipOpenPickerEntry] = []

        def compose(self) -> ComposeResult:
            """Compose the file/profile picker modal layout."""
            with Vertical(id="saip_open_picker_shell"):
                yield Static("SAIP profile picker", id="saip_open_picker_title")
                yield Static("", id="saip_open_picker_directory")
                yield Static(
                    "Enter descends into folders or opens the highlighted profile. "
                    "Backspace goes to the parent directory. Q or Esc cancels.",
                    id="saip_open_picker_help",
                )
                yield OptionList(id="saip_open_picker_options")
                yield Static("", id="saip_open_picker_status")

        def on_mount(self) -> None:
            self._reload_directory(status_text="Choose a SAIP profile to open in the editor.")
            self.query_one("#saip_open_picker_options", OptionList).focus()

        def _set_status(self, text: str) -> None:
            self.query_one("#saip_open_picker_status", Static).update(str(text or ""))

        def _reload_directory(self, *, status_text: str = "") -> None:
            directory_widget = self.query_one("#saip_open_picker_directory", Static)
            directory_widget.update(f"Directory: {self._current_directory}")
            option_list = self.query_one("#saip_open_picker_options", OptionList)
            _clear_option_list(option_list)
            try:
                self._entries = picker_entries_for_directory(self._current_directory)
            except (OSError, PermissionError) as error:
                self._entries = []
                self._set_status(f"Unable to read directory: {error}")
                return
            options: list[object] = []
            for entry_index, entry in enumerate(self._entries):
                options.append(Option(entry.label, id=f"entry:{entry_index}"))
            if len(options) == 0:
                options.append(Option("(directory is empty)", id="_empty"))
            _append_options(option_list, options)
            if len(status_text) > 0:
                self._set_status(status_text)
                return
            self._set_status(f"{len(self._entries)} item(s) listed.")

        def _activate_entry(self, entry_index: int) -> None:
            if entry_index < 0 or entry_index >= len(self._entries):
                return
            entry = self._entries[entry_index]
            if entry.is_directory:
                self._current_directory = entry.path
                self._reload_directory(status_text=f"Browsing {self._current_directory}")
                return
            self.exit(entry.path)

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            """Handle an OptionList selection and dismiss with the chosen profile path."""
            option_id = str(event.option_id or "").strip()
            if option_id == "_empty":
                return
            if option_id.startswith("entry:") is False:
                return
            entry_index_text = option_id.split(":", 1)[1]
            try:
                entry_index = int(entry_index_text)
            except (TypeError, ValueError):
                return
            self._activate_entry(entry_index)

        def action_go_parent(self) -> None:
            """Navigate up to the parent directory in the picker."""
            parent_directory = self._current_directory.parent.resolve()
            if parent_directory == self._current_directory:
                self._set_status("Already at the filesystem root.")
                return
            self._current_directory = parent_directory
            self._reload_directory(status_text=f"Browsing {self._current_directory}")

        def action_refresh_listing(self) -> None:
            self._reload_directory(status_text=f"Refreshed {self._current_directory}")

        def action_cancel_pick(self) -> None:
            self.exit(None)

    app = SaipOpenPickerApp()
    return app.run()
