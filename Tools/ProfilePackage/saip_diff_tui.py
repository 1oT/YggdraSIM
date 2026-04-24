"""
Standalone Textual app for visual side-by-side SAIP profile diffing.

Usage from the SAIP shell::

    DIFF-TUI <profile_a> <profile_b>

Or directly::

    python -m Tools.ProfilePackage.saip_diff_tui <profile_a> <profile_b>

The app loads both profiles via :mod:`saip_diff_loader` (transcode
JSON, simulator manifest, or SAIP DER), runs
:func:`saip_diff_engine.diff_saip_documents`, and renders:

* A left tree pane that mirrors document A with diff markers.
* A right tree pane that mirrors document B with diff markers.
* A bottom status bar showing counters and current selection.

Keybindings:

* ``n`` / ``N`` — next / previous diff entry.
* ``v`` — toggle value display.
* ``q`` / ``Ctrl+C`` — quit.

Textual is only imported inside the app launcher so this module stays
importable on hosts that do not ship the TUI extra. The standalone CLI
guards with a clear ImportError message.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from Tools.ProfilePackage.saip_diff_engine import (
    DIFF_OP_ADDED,
    DIFF_OP_CHANGED,
    DIFF_OP_MOVED,
    DIFF_OP_REMOVED,
    DiffEntry,
    DiffSummary,
    diff_saip_documents,
    format_diff_text,
)
from Tools.ProfilePackage.saip_diff_loader import (
    LoadedDocument,
    SaipDiffLoadError,
    load_two_profile_documents,
)


_OP_MARKER: dict[str, str] = {
    DIFF_OP_ADDED: "[+]",
    DIFF_OP_REMOVED: "[-]",
    DIFF_OP_CHANGED: "[~]",
    DIFF_OP_MOVED: "[>]",
}


def _path_segments(path: str) -> list[str]:
    """Split a jq-style path into labelled tree segments.

    ``sections.mf.fid`` becomes ``["sections", "mf", "fid"]``.
    ``sections.gfm[3].fid`` becomes ``["sections", "gfm[3]", "fid"]``.
    Used by the tree renderer to find the right insertion point.
    """
    if len(path) == 0:
        return []
    raw = path.split(".")
    return [segment for segment in raw if len(segment) > 0]


def _render_value(value: Any, *, limit: int = 64) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool) is True:
        return "true" if value else "false"
    if isinstance(value, (int, float)) is True:
        return str(value)
    if isinstance(value, (list, tuple)) is True:
        return f"[{len(value)} items]"
    if isinstance(value, dict) is True:
        return f"{{{len(value)} keys}}"
    text = str(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _launch(
    loaded_a: LoadedDocument,
    loaded_b: LoadedDocument,
    summary: DiffSummary,
) -> int:
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical
        from textual.widgets import Footer, Header, Static, Tree
    except ImportError as error:
        sys.stderr.write(
            "[-] DIFF-TUI requires the textual TUI extra. "
            "Install with `pip install 'yggdrasim[tui]'` or "
            "`pip install textual`. "
            f"Underlying error: {error}\n"
        )
        return 2

    class DiffApp(App):  # type: ignore[misc]
        CSS = """
        Screen {
            layout: vertical;
        }
        #panes {
            height: 1fr;
        }
        #pane-a, #pane-b {
            width: 1fr;
            border: solid $accent;
        }
        #status {
            height: 3;
            background: $boost;
            color: $text;
            padding: 0 1;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("n", "next_diff", "Next diff"),
            Binding("N", "prev_diff", "Prev diff"),
            Binding("v", "toggle_values", "Toggle values"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self._loaded_a = loaded_a
            self._loaded_b = loaded_b
            self._summary = summary
            self._show_values = True
            self._diff_cursor = 0

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="panes"):
                with Vertical(id="pane-a"):
                    yield Static(
                        f"A: {self._loaded_a.source_path}  "
                        f"[{self._loaded_a.shape}]",
                        id="label-a",
                    )
                    yield Tree("document", id="tree-a")
                with Vertical(id="pane-b"):
                    yield Static(
                        f"B: {self._loaded_b.source_path}  "
                        f"[{self._loaded_b.shape}]",
                        id="label-b",
                    )
                    yield Tree("document", id="tree-b")
            yield Static("", id="status")
            yield Footer()

        def on_mount(self) -> None:
            self._rebuild_tree("tree-a", self._loaded_a.document, side="a")
            self._rebuild_tree("tree-b", self._loaded_b.document, side="b")
            self._update_status()

        def _rebuild_tree(
            self,
            tree_id: str,
            document: dict[str, Any],
            *,
            side: str,
        ) -> None:
            tree_widget = self.query_one(f"#{tree_id}", Tree)
            tree_widget.clear()
            tree_widget.root.data = {"path": "", "side": side}
            tree_widget.root.expand()
            diff_paths: dict[str, str] = {}
            for entry in self._summary.entries:
                diff_paths[entry.path] = entry.op
            self._attach_subtree(
                tree_widget.root,
                parent_path="",
                value=document,
                diff_paths=diff_paths,
            )

        def _attach_subtree(
            self,
            parent_node: Any,
            *,
            parent_path: str,
            value: Any,
            diff_paths: dict[str, str],
        ) -> None:
            if isinstance(value, dict) is True:
                for key in sorted(value.keys(), key=str):
                    child_path = (
                        str(key)
                        if len(parent_path) == 0
                        else f"{parent_path}.{key}"
                    )
                    op = diff_paths.get(child_path, "")
                    marker = _OP_MARKER.get(op, "   ")
                    label = self._format_node_label(
                        marker=marker,
                        key_text=str(key),
                        value=value[key],
                    )
                    node = parent_node.add(label)
                    node.data = {"path": child_path, "op": op}
                    self._attach_subtree(
                        node,
                        parent_path=child_path,
                        value=value[key],
                        diff_paths=diff_paths,
                    )
                return
            if isinstance(value, (list, tuple)) is True:
                for index, child in enumerate(value):
                    child_path = f"{parent_path}[{index}]"
                    op = diff_paths.get(child_path, "")
                    marker = _OP_MARKER.get(op, "   ")
                    label = self._format_node_label(
                        marker=marker,
                        key_text=f"[{index}]",
                        value=child,
                    )
                    node = parent_node.add(label)
                    node.data = {"path": child_path, "op": op}
                    self._attach_subtree(
                        node,
                        parent_path=child_path,
                        value=child,
                        diff_paths=diff_paths,
                    )
                return

        def _format_node_label(
            self,
            *,
            marker: str,
            key_text: str,
            value: Any,
        ) -> str:
            if isinstance(value, (dict, list, tuple)) is True:
                return f"{marker} {key_text}"
            if self._show_values is False:
                return f"{marker} {key_text}"
            return f"{marker} {key_text} = {_render_value(value)}"

        def action_toggle_values(self) -> None:
            self._show_values = self._show_values is False
            self._rebuild_tree("tree-a", self._loaded_a.document, side="a")
            self._rebuild_tree("tree-b", self._loaded_b.document, side="b")
            self._update_status()

        def action_next_diff(self) -> None:
            if len(self._summary.entries) == 0:
                return
            self._diff_cursor = (
                self._diff_cursor + 1
            ) % len(self._summary.entries)
            self._focus_diff()
            self._update_status()

        def action_prev_diff(self) -> None:
            if len(self._summary.entries) == 0:
                return
            self._diff_cursor = (
                self._diff_cursor - 1 + len(self._summary.entries)
            ) % len(self._summary.entries)
            self._focus_diff()
            self._update_status()

        def _focus_diff(self) -> None:
            # Lightweight focus hint — Textual tree widgets do not
            # expose a stable "jump to data-key" primitive across 0.x
            # versions, so we just update the status line with the
            # current path and let the operator scroll to it.
            pass

        def _update_status(self) -> None:
            status_widget = self.query_one("#status", Static)
            if len(self._summary.entries) == 0:
                status_widget.update(
                    "No differences detected.  "
                    f"values={'on' if self._show_values else 'off'}  "
                    "(q quit  v toggle values)"
                )
                return
            current: DiffEntry = self._summary.entries[self._diff_cursor]
            status_widget.update(
                f"diff {self._diff_cursor + 1}/{len(self._summary.entries)}: "
                f"{current.op:7s} {current.path}  "
                f"A={_render_value(current.value_a)}  "
                f"B={_render_value(current.value_b)}  |  "
                f"added={self._summary.added}  "
                f"removed={self._summary.removed}  "
                f"changed={self._summary.changed}  "
                f"moved={self._summary.moved}  "
                f"(n/N cycle  v values  q quit)"
            )

    app = DiffApp()
    app.run()
    return 0


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="saip-diff-tui",
        description=(
            "Open two SAIP profiles in a side-by-side visual diff "
            "(transcode JSON, simulator manifest, or SAIP DER)."
        ),
    )
    parser.add_argument("profile_a", help="left-hand profile path")
    parser.add_argument("profile_b", help="right-hand profile path")
    parser.add_argument(
        "--workspace-root",
        default="",
        help="override the workspace root used for DER decode (pySim lookup)",
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="skip the Textual app and print the plain-text diff report instead",
    )
    args = parser.parse_args(argv)

    path_a = Path(args.profile_a).expanduser().resolve()
    path_b = Path(args.profile_b).expanduser().resolve()
    workspace_root = (
        Path(args.workspace_root).expanduser().resolve()
        if len(str(args.workspace_root or "").strip()) > 0
        else Path.cwd().resolve()
    )

    try:
        loaded_a, loaded_b = load_two_profile_documents(
            path_a,
            path_b,
            workspace_root=workspace_root,
        )
    except SaipDiffLoadError as error:
        sys.stderr.write(f"[-] DIFF-TUI load failed: {error}\n")
        return 3

    summary = diff_saip_documents(loaded_a.document, loaded_b.document)

    if args.text is True:
        sys.stdout.write(
            f"=== SAIP diff ===\n"
            f"  A: {loaded_a.source_path}  [{loaded_a.shape}]\n"
            f"  B: {loaded_b.source_path}  [{loaded_b.shape}]\n"
        )
        sys.stdout.write(format_diff_text(summary))
        return 0

    return _launch(loaded_a, loaded_b, summary)


if __name__ == "__main__":
    raise SystemExit(run_cli())
