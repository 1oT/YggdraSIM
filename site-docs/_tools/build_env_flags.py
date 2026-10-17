# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Generate the environment-flag reference table from the flag registry.

Reads :data:`yggdrasim_common.env_flags.FLAG_REGISTRY` -- the same source
the launcher menu and the GUI Configuration view read -- and writes a
Markdown fragment between markers:

    <!-- env-flags:start -->
    ...
    <!-- env-flags:end -->

Existing content inside the markers is replaced. Content outside the
markers is preserved verbatim.

    python site-docs/_tools/build_env_flags.py
    python site-docs/_tools/build_env_flags.py --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


TABLE_START = "<!-- env-flags:start -->"
TABLE_END = "<!-- env-flags:end -->"

KIND_LABELS: dict[str, str] = {
    "path": "path",
    "int": "integer",
    "float": "number",
    "string": "text",
}

PERSIST_LABELS: dict[str, str] = {
    "persist": "runtime root",
    "persist_home": "home",
    "session": "session only",
}

APPLIES_LABELS: dict[str, str] = {
    "runtime": "immediately",
    "startup": "next launch",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_env_flags():
    sys.path.insert(0, str(repo_root()))
    try:
        from yggdrasim_common import env_flags  # type: ignore[import-not-found]
    finally:
        sys.path.pop(0)
    return env_flags


def cell(text: str) -> str:
    """Flatten *text* into one table cell."""
    flattened = " ".join(str(text or "").split())
    return flattened.replace("|", "\\|")


def accepts(flag, env_flags) -> str:
    if flag.kind == env_flags.KIND_BOOL_TOGGLE:
        on_value = flag.bool_on_value or "1"
        off_value = flag.bool_off_value
        off_text = f"`{off_value}`" if len(off_value) > 0 else "unset"
        return f"`{on_value}` / {off_text}"
    if flag.kind == env_flags.KIND_CHOICE:
        return ", ".join(f"`{choice}`" for choice in flag.choices)
    return KIND_LABELS.get(flag.kind, flag.kind)


def render_markdown(env_flags) -> str:
    flags = env_flags.FLAG_REGISTRY
    categories = [
        category
        for category in env_flags.CATEGORY_ORDER
        if any(flag.category == category for flag in flags)
    ]
    lines = [
        TABLE_START,
        "",
        f"{len(flags)} flags in {len(categories)} categories, generated from"
        " `yggdrasim_common/env_flags.py`.",
        "",
    ]
    for category in categories:
        lines.append(f"### {category}")
        lines.append("")
        lines.append("| Variable | Accepts | Default | Applies | Persistence | Summary |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for flag in flags:
            if flag.category != category:
                continue
            summary = cell(flag.summary)
            if flag.sensitive is True:
                summary = f"(sensitive) {summary}"
            default_hint = cell(flag.default_hint) or "unset"
            lines.append(
                f"| `{flag.name}` | {cell(accepts(flag, env_flags))} | {default_hint} |"
                f" {APPLIES_LABELS.get(flag.applies, flag.applies)} |"
                f" {PERSIST_LABELS.get(flag.persist_scope, flag.persist_scope)} |"
                f" {summary} |"
            )
        lines.append("")
    lines.append(TABLE_END)
    return "\n".join(lines) + "\n"


def inject(existing_text: str, rendered: str) -> str:
    pattern = re.compile(
        re.escape(TABLE_START) + r".*?" + re.escape(TABLE_END),
        re.DOTALL,
    )
    if pattern.search(existing_text) is not None:
        return pattern.sub(rendered.rstrip("\n"), existing_text)
    return existing_text.rstrip("\n") + "\n\n" + rendered


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the environment-flag reference table."
    )
    parser.add_argument(
        "--target",
        default="site-docs/reference/env-flags.md",
        help="Target Markdown page (default: site-docs/reference/env-flags.md)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the rendered section to stdout without modifying files.",
    )
    arguments = parser.parse_args()

    env_flags = load_env_flags()
    rendered = render_markdown(env_flags=env_flags)

    if arguments.dry_run is True:
        print(rendered)
        return 0

    target_path = (repo_root() / arguments.target).resolve()
    if target_path.is_file() is False:
        print(f"error: {target_path} does not exist", file=sys.stderr)
        return 2

    existing = target_path.read_text(encoding="utf-8")
    new_text = inject(existing_text=existing, rendered=rendered)
    if new_text != existing:
        target_path.write_text(new_text, encoding="utf-8")
        print(f"Updated {target_path.relative_to(repo_root())}")
    else:
        print(f"No changes needed in {target_path.relative_to(repo_root())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
