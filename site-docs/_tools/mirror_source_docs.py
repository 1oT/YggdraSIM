from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import shutil


INCLUDED_TOP_LEVEL_DIRS = {
    "guides",
    "plugins",
    "reports",
    "scripts",
    "SCP11",
    "tests",
}

ROOT_TEXT_PAGES = ("AUTHORS", "LICENSE", "NOTICE")

# Mirrored markdown is inlined verbatim into ``site-docs/sources/``. The
# original files live in the tracked repository tree and reference sibling
# source files (``../foo.py``, ``../guides/bar.md``) which never exist
# under ``site-docs/``. Rewriting those relative targets to absolute
# GitHub blob URLs keeps the links clickable in the rendered site **and**
# silences ``mkdocs --strict`` warnings about missing in-doc targets,
# without us having to maintain a fragile per-file allow-list.
GITHUB_BLOB_BASE_URL = (
    "https://github.com/1oT/YggdraSIM/blob/main"
)

EXTERNAL_LINK_SCHEMES = (
    "http://",
    "https://",
    "mailto:",
    "tel:",
    "ftp://",
    "ftps://",
    "data:",
)

# Inline ``[text](target)`` and image ``![alt](target)`` syntax. The
# ``target`` capture stops at the first whitespace so an optional title
# (``"Tooltip"``) is preserved verbatim by the rewriter.
_MARKDOWN_LINK_PATTERN = re.compile(r"(!?)\[([^\]]*)\]\(([^)\s]+)((?:\s+\"[^\"]*\")?)\)")

GROUP_TITLES = {
    "__root__": "Repository Root",
    "guides": "Authored Guides",
    "plugins": "Plugins",
    "scripts": "Scripts",
    "SCP11": "SCP11 Module Docs",
    "tests": "Test And Harness Docs",
    "reports": "Reports",
}

GROUP_ORDER = [
    "Repository Root",
    "Authored Guides",
    "SCP11 Module Docs",
    "Plugins",
    "Scripts",
    "Test And Harness Docs",
    "Reports",
    "Other Docs",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def site_docs_root() -> Path:
    return repo_root() / "site-docs"


def mirrored_sources_root() -> Path:
    return site_docs_root() / "sources"


def iter_markdown_sources() -> list[Path]:
    root = repo_root()
    matches: list[Path] = []
    for path in root.rglob("*.md"):
        relative_path = path.relative_to(root)
        if len(relative_path.parts) == 1:
            if relative_path.name != "README.md":
                continue
        elif relative_path.parts[0] not in INCLUDED_TOP_LEVEL_DIRS:
            continue
        matches.append(relative_path)
    return sorted(matches, key=lambda item: item.as_posix().lower())


def _is_external_or_anchor(target: str) -> bool:
    if len(target) == 0:
        return True
    if target.startswith("#"):
        return True
    lowered = target.lower()
    for scheme in EXTERNAL_LINK_SCHEMES:
        if lowered.startswith(scheme):
            return True
    return False


def _rewrite_relative_link(source_relative_path: Path, target: str) -> str:
    """Resolve a markdown link target against the source's repo location.

    Returns an absolute https GitHub blob URL when the link points at a
    real repository file, otherwise leaves the target untouched. The
    fragment portion (``#anchor``) is preserved verbatim so deep-links
    keep working in the rendered HTML.
    """

    fragment_separator_index = target.find("#")
    if fragment_separator_index >= 0:
        path_part = target[:fragment_separator_index]
        fragment_part = target[fragment_separator_index:]
    else:
        path_part = target
        fragment_part = ""

    if len(path_part) == 0:
        return target

    if path_part.startswith("/"):
        repo_relative = path_part.lstrip("/")
    else:
        candidate = (source_relative_path.parent / path_part)
        try:
            resolved = candidate.resolve(strict=False)
            resolved_relative = resolved.relative_to(repo_root().resolve())
        except (ValueError, OSError):
            return target
        repo_relative = resolved_relative.as_posix()

    return f"{GITHUB_BLOB_BASE_URL}/{repo_relative}{fragment_part}"


def rewrite_markdown_links_for_mirroring(
    *, source_relative_path: Path, source_text: str
) -> str:
    def _replace(match: re.Match[str]) -> str:
        prefix = match.group(1)
        link_text = match.group(2)
        link_target = match.group(3)
        title_suffix = match.group(4) or ""
        if _is_external_or_anchor(link_target):
            return match.group(0)
        rewritten_target = _rewrite_relative_link(source_relative_path, link_target)
        return f"{prefix}[{link_text}]({rewritten_target}{title_suffix})"

    return _MARKDOWN_LINK_PATTERN.sub(_replace, source_text)


def write_markdown_wrapper(source_relative_path: Path) -> None:
    target_path = mirrored_sources_root() / source_relative_path
    target_path.parent.mkdir(parents=True, exist_ok=True)
    source_text = (repo_root() / source_relative_path).read_text(encoding="utf-8")
    if source_relative_path == Path("README.md"):
        source_text = source_text.replace("](LICENSE)", "](LICENSE/index.md)")
        source_text = source_text.replace("](NOTICE)", "](NOTICE/index.md)")
        source_text = source_text.replace("](AUTHORS)", "](AUTHORS/index.md)")
        target_path.write_text(source_text.rstrip() + "\n", encoding="utf-8")
        return
    rewritten_text = rewrite_markdown_links_for_mirroring(
        source_relative_path=source_relative_path,
        source_text=source_text,
    )
    target_path.write_text(rewritten_text.rstrip() + "\n", encoding="utf-8")


def write_root_text_wrapper(file_name: str) -> None:
    target_path = mirrored_sources_root() / file_name / "index.md"
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(
        f"# {file_name}\n\n--8<-- \"{file_name}\"\n",
        encoding="utf-8",
    )


def group_name_for(relative_path: Path) -> str:
    if len(relative_path.parts) == 1:
        return GROUP_TITLES["__root__"]
    return GROUP_TITLES.get(relative_path.parts[0], "Other Docs")


def build_source_library(markdown_sources: list[Path]) -> None:
    groups: dict[str, list[tuple[str, str]]] = defaultdict(list)

    for relative_path in markdown_sources:
        label = relative_path.as_posix()
        link_path = (Path("sources") / relative_path).as_posix()
        groups[group_name_for(relative_path)].append((label, link_path))

    for file_name in ROOT_TEXT_PAGES:
        groups[GROUP_TITLES["__root__"]].append(
            (file_name, f"sources/{file_name}/index.md")
        )

    lines = [
        "# Source Library",
        "",
        "This page mirrors the repository's authored source documents under the",
        "`sources/` subtree so the original documentation layout stays accessible",
        "inside MkDocs.",
        "",
        "Notes:",
        "",
        "- these pages are mirrored from tracked repository docs, not rewritten copies",
        "- the mirrored tree preserves the original relative path layout so cross-links continue to work",
        "- the SCP03 code-defined in-shell guides are documented separately under [Shell Guides](shell-guides/index.md)",
        "",
    ]

    for group_title in GROUP_ORDER:
        entries = sorted(groups.get(group_title, []), key=lambda item: item[0].lower())
        if not entries:
            continue
        lines.append(f"## {group_title}")
        lines.append("")
        for label, link_path in entries:
            lines.append(f"- [`{label}`]({link_path})")
        lines.append("")

    (site_docs_root() / "source-library.md").write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )


def main() -> None:
    shutil.rmtree(mirrored_sources_root(), ignore_errors=True)
    markdown_sources = iter_markdown_sources()
    for relative_path in markdown_sources:
        write_markdown_wrapper(relative_path)
    for file_name in ROOT_TEXT_PAGES:
        write_root_text_wrapper(file_name)
    build_source_library(markdown_sources)
    print(
        f"Mirrored {len(markdown_sources)} markdown docs and "
        f"{len(ROOT_TEXT_PAGES)} root text pages."
    )


if __name__ == "__main__":
    main()
