from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path
import shutil


INCLUDED_TOP_LEVEL_DIRS = {
    "guides",
    "plugins",
    "scripts",
    "SCP11",
    "tests",
}

# Top-level Markdown files that should be mirrored alongside the README so
# cross-links from authored ``site-docs/`` pages and from mirrored
# ``sources/`` content resolve under MkDocs strict mode. Do not include
# ``LICENSE``, ``NOTICE``, ``AUTHORS`` here -- those are licence text files
# rendered through ``ROOT_TEXT_PAGES``.
ROOT_MARKDOWN_FILES = (
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
)

ROOT_TEXT_PAGES = ("AUTHORS", "LICENSE", "NOTICE")

GROUP_TITLES = {
    "__root__": "Repository Root",
    "guides": "Authored Guides",
    "plugins": "Plugins",
    "scripts": "Scripts",
    "SCP11": "SCP11 Module Docs",
    "tests": "Test And Harness Docs",
}

GROUP_ORDER = [
    "Repository Root",
    "Authored Guides",
    "SCP11 Module Docs",
    "Plugins",
    "Scripts",
    "Test And Harness Docs",
    "Other Docs",
]

# Used by the link rewriter to convert references that fall outside the
# mirrored docs surface (source code, vendored assets, ``Workspace/`` etc.)
# into stable absolute URLs that browse the canonical repository tree.
GITHUB_BLOB_BASE = "https://github.com/1oT/YggdraSIM/blob/main"

# Inline link with optional title: ``[label](url "title")``. The negative
# lookbehind keeps image references (``![alt](src)``) out of scope.
INLINE_LINK_PATTERN = re.compile(
    r'(?P<prefix>!?)\[(?P<label>[^\]]*)\]\(\s*(?P<url>[^)\s]+)(?P<title>\s+"[^"]*")?\s*\)'
)


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
        if any(part.startswith(".") for part in relative_path.parts):
            continue
        if len(relative_path.parts) == 1:
            if relative_path.name not in ROOT_MARKDOWN_FILES:
                continue
        elif relative_path.parts[0] not in INCLUDED_TOP_LEVEL_DIRS:
            continue
        matches.append(relative_path)
    return sorted(matches, key=lambda item: item.as_posix().lower())


def _is_external_url(url: str) -> bool:
    lowered = url.strip().lower()
    if lowered.startswith(("http://", "https://", "mailto:", "tel:", "ftp://", "ftps://")):
        return True
    if lowered.startswith("#"):
        return True
    return False


def _split_anchor(url: str) -> tuple[str, str]:
    if "#" in url:
        path_part, _, fragment = url.partition("#")
        return path_part, "#" + fragment
    return url, ""


def _mirrored_doc_paths(markdown_sources: list[Path]) -> set[str]:
    """Repository-relative POSIX paths for every doc that ends up under ``sources/``."""

    paths = {path.as_posix() for path in markdown_sources}
    for file_name in ROOT_TEXT_PAGES:
        # Mirrored as ``sources/<NAME>/index.md`` -- treat the bare file name
        # as a valid target so legacy ``](LICENSE)`` style links keep working.
        paths.add(file_name)
    return paths


def _rewrite_url(
    url: str,
    source_relative_path: Path,
    mirrored_paths: set[str],
) -> str:
    """Return a URL that resolves under the MkDocs mirrored layout."""

    if _is_external_url(url):
        return url

    path_part, anchor = _split_anchor(url)
    if path_part == "":
        return url

    source_dir = (repo_root() / source_relative_path).parent
    try:
        resolved = (source_dir / path_part).resolve()
        target_rel = resolved.relative_to(repo_root().resolve())
    except (ValueError, OSError):
        return url

    target_str = target_rel.as_posix()

    if target_str in mirrored_paths:
        return url

    if target_str in ROOT_TEXT_PAGES:
        # Mirrored as ``sources/<NAME>/index.md``. Compute the relative path
        # from the mirror wrapper out to that index.
        mirror_wrapper = mirrored_sources_root() / source_relative_path
        target_doc = mirrored_sources_root() / target_str / "index.md"
        rel = os.path.relpath(target_doc.as_posix(), mirror_wrapper.parent.as_posix())
        return rel + anchor

    if target_str.startswith("site-docs/"):
        # Authored docs page under ``site-docs/<rest>``. The mirror wrapper
        # lives at ``site-docs/sources/<source_relative_path>``; compute a
        # path that walks back out of ``sources/`` to the authored page.
        mirror_wrapper = mirrored_sources_root() / source_relative_path
        target_doc = repo_root() / target_str
        rel = os.path.relpath(target_doc.as_posix(), mirror_wrapper.parent.as_posix())
        return rel + anchor

    # Otherwise the link points at non-mirrored content (source code,
    # ``Workspace/`` material, vendored binaries...). Rewrite to an
    # absolute GitHub URL so MkDocs treats it as an external link instead
    # of an unresolved doc reference.
    return f"{GITHUB_BLOB_BASE}/{target_str}{anchor}"


def _rewrite_links_in_text(
    text: str,
    source_relative_path: Path,
    mirrored_paths: set[str],
) -> str:
    def repl(match: re.Match[str]) -> str:
        prefix = match.group("prefix")
        label = match.group("label")
        url = match.group("url")
        title = match.group("title") or ""
        if prefix == "!":
            # Image reference -- keep verbatim. Mirrored docs do not
            # currently embed images, but if they ever do we want the
            # original asset path preserved.
            return match.group(0)
        new_url = _rewrite_url(url, source_relative_path, mirrored_paths)
        return f"{prefix}[{label}]({new_url}{title})"

    return INLINE_LINK_PATTERN.sub(repl, text)


def write_markdown_wrapper(
    source_relative_path: Path,
    mirrored_paths: set[str],
) -> None:
    target_path = mirrored_sources_root() / source_relative_path
    target_path.parent.mkdir(parents=True, exist_ok=True)

    source_text = (repo_root() / source_relative_path).read_text(encoding="utf-8")

    if source_relative_path == Path("README.md"):
        source_text = source_text.replace("](LICENSE)", "](LICENSE/index.md)")
        source_text = source_text.replace("](NOTICE)", "](NOTICE/index.md)")
        source_text = source_text.replace("](AUTHORS)", "](AUTHORS/index.md)")

    rewritten = _rewrite_links_in_text(source_text, source_relative_path, mirrored_paths)
    target_path.write_text(rewritten.rstrip() + "\n", encoding="utf-8")


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
    mirrored_paths = _mirrored_doc_paths(markdown_sources)
    for relative_path in markdown_sources:
        write_markdown_wrapper(relative_path, mirrored_paths)
    for file_name in ROOT_TEXT_PAGES:
        write_root_text_wrapper(file_name)
    build_source_library(markdown_sources)
    print(
        f"Mirrored {len(markdown_sources)} markdown docs and "
        f"{len(ROOT_TEXT_PAGES)} root text pages."
    )


if __name__ == "__main__":
    main()
