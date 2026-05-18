"""Concatenate every page in the MkDocs nav into a single Markdown file.

Walks the ``nav`` tree from ``mkdocs.yml`` in declared order. Each nav
section becomes an H1 chapter. Each page becomes an H2, with its own
headings demoted so the final document keeps a clean, strictly-increasing
outline. Relative Markdown links are rewritten to in-document anchors so
the combined file is self-contained. Front matter is stripped. Mermaid
fences, admonitions, tabs, and tables pass through unchanged.

The result is written to ``YggdraSIM.md`` at the repository root by default
(see ``--out``; the file is gitignored).

Usage:

    python site-docs/_tools/build_combined.py
    python site-docs/_tools/build_combined.py --out YggdraSIM_combined.md
    python site-docs/_tools/build_combined.py --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError as error:  # pragma: no cover
    print(f"error: PyYAML is required ({error})", file=sys.stderr)
    sys.exit(2)


FRONT_MATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)
FENCE_PATTERN = re.compile(r"^```.*?^```", re.DOTALL | re.MULTILINE)
LINK_PATTERN = re.compile(r"(?<!\!)\[([^\]]+)\]\(([^)]+)\)")
IMAGE_PATTERN = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
TAGS_MARKER_PATTERN = re.compile(r"<!--\s*material/tags\s*-->", re.IGNORECASE)
ABBREVIATION_DEF_PATTERN = re.compile(r"^\*\[[^\]]+\]:.*$", re.MULTILINE)
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "tel:", "ftp://", "ftps://")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_mkdocs_config() -> dict:
    path = repo_root() / "mkdocs.yml"
    with path.open("r", encoding="utf-8") as handle:
        return yaml.load(handle, Loader=UnsafeLoader)


class UnsafeLoader(yaml.SafeLoader):
    """Permissive loader that ignores MkDocs custom tags like !!python/name."""


def _ignore_unknown_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


UnsafeLoader.add_multi_constructor("tag:yaml.org,2002:python/name:", _ignore_unknown_tag)
UnsafeLoader.add_multi_constructor("!!python/name:", _ignore_unknown_tag)
UnsafeLoader.add_multi_constructor("", _ignore_unknown_tag)


def slugify_path(relative: Path) -> str:
    stem = relative.with_suffix("").as_posix()
    slug = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    if len(slug) == 0:
        return "page"
    return slug


def strip_front_matter(text: str) -> tuple[str, dict]:
    match = FRONT_MATTER_PATTERN.match(text)
    if match is None:
        return text, {}
    try:
        meta = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        meta = {}
    return text[match.end():], meta


def strip_leading_h1(text: str) -> tuple[str, str | None]:
    stripped = text.lstrip("\n")
    if stripped.startswith("# ") is False:
        return text, None
    newline_index = stripped.find("\n")
    if newline_index < 0:
        title_line = stripped
        remainder = ""
    else:
        title_line = stripped[:newline_index]
        remainder = stripped[newline_index + 1:]
    title = title_line[2:].strip()
    return remainder.lstrip("\n"), title


def mask_fences(text: str) -> tuple[str, list[str]]:
    fences: list[str] = []

    def capture(match: re.Match) -> str:
        index = len(fences)
        fences.append(match.group(0))
        return f"\x00FENCE{index}\x00"

    masked = FENCE_PATTERN.sub(capture, text)
    return masked, fences


def unmask_fences(text: str, fences: list[str]) -> str:
    def restore(match: re.Match) -> str:
        index = int(match.group(1))
        return fences[index]

    return re.sub(r"\x00FENCE(\d+)\x00", restore, text)


def demote_headings(text: str, shift: int) -> str:
    if shift <= 0:
        return text

    def repl(match: re.Match) -> str:
        hashes = match.group(1)
        body = match.group(2)
        new_level = min(6, len(hashes) + shift)
        return "#" * new_level + " " + body

    masked, fences = mask_fences(text)
    demoted = HEADING_PATTERN.sub(repl, masked)
    return unmask_fences(demoted, fences)


def rewrite_links(text: str, source_dir: Path, docs_root: Path, page_slug_map: dict[str, str]) -> str:
    masked, fences = mask_fences(text)

    def rewrite(match: re.Match, is_image: bool) -> str:
        label = match.group(1)
        target = match.group(2).strip()
        if len(target) == 0:
            return match.group(0)
        if any(target.lower().startswith(scheme) for scheme in EXTERNAL_SCHEMES):
            return match.group(0)
        if target.startswith("#"):
            return match.group(0)
        path_part = target
        fragment = ""
        if "#" in path_part:
            path_part, _, fragment = path_part.partition("#")
        if len(path_part) == 0:
            return match.group(0)
        if target.startswith("/"):
            candidate = (docs_root / path_part.lstrip("/")).resolve()
        else:
            candidate = (source_dir / path_part).resolve()
        candidate_md = candidate
        if candidate.suffix == "":
            if (candidate / "index.md").exists():
                candidate_md = candidate / "index.md"
            elif candidate.with_suffix(".md").exists():
                candidate_md = candidate.with_suffix(".md")
        try:
            relative = candidate_md.relative_to(docs_root)
        except ValueError:
            return match.group(0)
        if is_image is True:
            return match.group(0)
        slug = page_slug_map.get(relative.as_posix())
        if slug is None:
            return match.group(0)
        return f"[{label}](#{slug})"

    masked = LINK_PATTERN.sub(lambda match: rewrite(match, False), masked)
    masked = IMAGE_PATTERN.sub(lambda match: rewrite(match, True), masked)
    return unmask_fences(masked, fences)


def flatten_nav(nav, depth: int = 1) -> list[dict]:
    items: list[dict] = []
    for entry in nav:
        if isinstance(entry, dict):
            for title, target in entry.items():
                if isinstance(target, list):
                    items.append({"kind": "section", "title": title, "depth": depth})
                    items.extend(flatten_nav(target, depth=depth + 1))
                else:
                    items.append({"kind": "page", "title": title, "path": str(target), "depth": depth})
        elif isinstance(entry, str):
            items.append({"kind": "page", "title": None, "path": entry, "depth": depth})
    return items


def build_page_slug_map(flat_nav: list[dict]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in flat_nav:
        if item["kind"] == "page":
            rel = Path(item["path"]).as_posix()
            mapping[rel] = slugify_path(Path(rel))
    return mapping


def render_document(config: dict, docs_root: Path, flat_nav: list[dict], page_slug_map: dict[str, str]) -> str:
    site_name = config.get("site_name", "Site")
    site_description = config.get("site_description", "")

    lines: list[str] = []
    lines.append(f"# {site_name}")
    lines.append("")
    if len(site_description) > 0:
        lines.append(f"> {site_description}")
        lines.append("")
    lines.append(
        "This file is a single-document concatenation of the MkDocs site. "
        "It is regenerated from `mkdocs.yml` by "
        "`site-docs/_tools/build_combined.py`. Internal links have been "
        "rewritten to in-document anchors so this file can be read offline "
        "as one piece."
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Table of contents")
    lines.append("")
    for item in flat_nav:
        indent = "  " * max(0, item["depth"] - 1)
        if item["kind"] == "section":
            lines.append(f"{indent}- **{item['title']}**")
        else:
            title = item["title"]
            if title is None:
                title = Path(item["path"]).stem
            slug = page_slug_map[Path(item["path"]).as_posix()]
            lines.append(f"{indent}- [{title}](#{slug})")
    lines.append("")
    lines.append("---")
    lines.append("")

    for item in flat_nav:
        if item["kind"] == "section":
            lines.append(f"# {item['title']}")
            lines.append("")
            continue
        rel_path = Path(item["path"])
        full_path = docs_root / rel_path
        if full_path.is_file() is False:
            lines.append(f"<!-- missing: {rel_path.as_posix()} -->")
            lines.append("")
            continue
        raw = full_path.read_text(encoding="utf-8")
        body, meta = strip_front_matter(raw)
        body = TAGS_MARKER_PATTERN.sub("", body)
        body = ABBREVIATION_DEF_PATTERN.sub("", body)
        body, body_title = strip_leading_h1(body)
        body = rewrite_links(
            text=body,
            source_dir=full_path.parent,
            docs_root=docs_root,
            page_slug_map=page_slug_map,
        )
        title = item["title"]
        if title is None:
            title = body_title or str(meta.get("title") or rel_path.stem).replace("_", " ").replace("-", " ").title()
        slug = page_slug_map[rel_path.as_posix()]
        page_heading_level = min(6, item["depth"] + 1)
        body = demote_headings(body, shift=max(0, page_heading_level - 1))
        lines.append(f'<a id="{slug}"></a>')
        lines.append("")
        lines.append(("#" * page_heading_level) + f" {title}")
        lines.append("")
        lines.append(f"*Source: `site-docs/{rel_path.as_posix()}`*")
        lines.append("")
        stripped_body = body.strip("\n")
        if len(stripped_body) > 0:
            lines.append(stripped_body)
            lines.append("")
        lines.append("---")
        lines.append("")

    while len(lines) > 0 and len(lines[-1].strip()) == 0:
        lines.pop()
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build one big Markdown file from the MkDocs nav.")
    parser.add_argument(
        "--out",
        default="YggdraSIM.md",
        help="Output path for the combined Markdown (default: YggdraSIM.md at the repo root).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the combined Markdown to stdout without writing a file.",
    )
    arguments = parser.parse_args()

    config = load_mkdocs_config()
    docs_dir_name = config.get("docs_dir", "docs")
    docs_root = (repo_root() / docs_dir_name).resolve()
    if docs_root.is_dir() is False:
        print(f"error: docs_dir {docs_root} not found", file=sys.stderr)
        return 2

    nav = config.get("nav")
    if nav is None:
        print("error: mkdocs.yml has no nav section", file=sys.stderr)
        return 2

    flat_nav = flatten_nav(nav)
    page_slug_map = build_page_slug_map(flat_nav)
    document = render_document(
        config=config,
        docs_root=docs_root,
        flat_nav=flat_nav,
        page_slug_map=page_slug_map,
    )

    if arguments.dry_run is True:
        sys.stdout.write(document)
        return 0

    out_path = (repo_root() / arguments.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(document, encoding="utf-8")
    size_kb = out_path.stat().st_size / 1024.0
    page_count = sum(1 for item in flat_nav if item["kind"] == "page")
    section_count = sum(1 for item in flat_nav if item["kind"] == "section")
    print(
        f"Wrote {out_path.relative_to(repo_root())} "
        f"({page_count} pages, {section_count} sections, {size_kb:.1f} KB)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
