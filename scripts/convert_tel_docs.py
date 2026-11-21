# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "docs" / "tel-docs"
OUTPUT_DIR = SOURCE_DIR / "converted"
MIN_IMAGE_PIXELS = 20_000


@dataclass(frozen=True)
class PdfImage:
    page: int
    number: int
    kind: str
    width: int
    height: int


def run_command(args: list[str]) -> str:
    completed = subprocess.run(
        args,
        check=True,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def slugify(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    slug = re.sub(r"_+", "_", slug)
    return slug.strip("._") or "document"


def pdf_page_count(pdf_path: Path) -> int:
    info = run_command(["pdfinfo", str(pdf_path)])
    match = re.search(r"^Pages:\s+(\d+)\s*$", info, re.MULTILINE)
    if match is None:
        raise ValueError(f"could not read page count for {pdf_path}")
    return int(match.group(1))


def pdf_text(pdf_path: Path) -> str:
    return run_command(["pdftotext", "-layout", "-enc", "UTF-8", str(pdf_path), "-"])


def split_pages(text: str) -> list[str]:
    pages = text.split("\f")
    if pages and pages[-1].strip() == "":
        pages.pop()
    return [page.rstrip() for page in pages]


RFC_HEADER_RE = re.compile(r"^(Request for Comments|RFC|Network Working Group|Internet Engineering Task Force)", re.IGNORECASE)


def rfc_title(lines: list[str]) -> str | None:
    """Title of an RFC plain-text page 1: the centred line after the blank line that closes the header block."""
    header_at = next((index for index, line in enumerate(lines[:12]) if RFC_HEADER_RE.match(line)), None)
    if header_at is None:
        return None
    blank_at = next((index for index in range(header_at, len(lines)) if not lines[index].strip()), None)
    if blank_at is None:
        return None
    for line in lines[blank_at:]:
        if line.strip():
            return line.strip() if line.startswith(" ") else None
    return None


def first_title(page: str, fallback: str) -> str:
    lines = page.splitlines()
    title = rfc_title(lines)
    if title:
        return title
    for line in lines:
        clean = line.strip()
        if clean:
            return clean
    return fallback


def fenced_text(text: str) -> str:
    return f"```text\n{text.rstrip()}\n```\n"


def write_markdown(source_path: Path, target_dir: Path, pages: list[str], page_count: int) -> None:
    stem = source_path.stem
    md_path = target_dir / f"{slugify(stem)}.md"
    source_name = source_path.name
    title = first_title(pages[0] if pages else "", stem)
    if source_path.suffix.lower() == ".pdf":
        conversion = "layout-preserving text extraction from the local PDF source"
    else:
        conversion = "form-feed page split of the local plain-text or Markdown source"

    with md_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"# {title}\n\n")
        handle.write(f"- Source file: `{source_name}`\n")
        handle.write(f"- Source pages: {page_count}\n")
        handle.write(f"- Conversion: {conversion}\n\n")
        handle.write("## Extracted Files\n\n")
        handle.write("- `pages/`: one Markdown file per source page\n")
        handle.write("- `tables/`: page extracts for detected table captions\n")
        handle.write("- `asn1/`: detected ASN.1 modules or ASN.1-heavy page extracts\n")
        handle.write("- `images/`: deduplicated embedded raster images when present\n\n")
        for index, page in enumerate(pages, start=1):
            handle.write(f"## Page {index}\n\n")
            handle.write(fenced_text(page))
            handle.write("\n")


def write_page_chunks(target_dir: Path, pages: list[str]) -> None:
    pages_dir = target_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)
    for index, page in enumerate(pages, start=1):
        page_path = pages_dir / f"page-{index:03d}.md"
        with page_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(f"# Page {index}\n\n")
            handle.write(fenced_text(page))


TABLE_CAPTION_RE = re.compile(
    r"^\s*(Table\s+[A-Za-z0-9]+(?:[.\-][A-Za-z0-9]+)*\s*[:.\-]?\s+.+?)\s*$",
    re.IGNORECASE,
)


def table_captions(page: str) -> list[str]:
    captions: list[str] = []
    for line in page.splitlines():
        if "....." in line:
            continue
        match = TABLE_CAPTION_RE.match(line)
        if match is None:
            continue
        caption = re.sub(r"\s+", " ", match.group(1)).strip()
        captions.append(caption)
    return captions


def write_table_extracts(target_dir: Path, pages: list[str]) -> int:
    tables_dir = target_dir / "tables"
    count = 0
    for index, page in enumerate(pages, start=1):
        for caption in table_captions(page):
            count += 1
            caption_slug = slugify(caption[:80])
            table_path = tables_dir / f"table-{count:03d}-page-{index:03d}-{caption_slug}.md"
            tables_dir.mkdir(parents=True, exist_ok=True)
            with table_path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(f"# {caption}\n\n")
                handle.write(f"- Source page: {index}\n\n")
                handle.write(fenced_text(page))
    return count


ASN1_ASSIGNMENT_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9-]*\s+::=")


def find_asn1_modules(joined_text: str) -> list[str]:
    modules: list[str] = []
    module_re = re.compile(
        r"(?ms)^.*?DEFINITIONS(?:\s+[A-Z ]+)?\s+::=\s+BEGIN\b.*?^\s*END\s*$"
    )
    for match in module_re.finditer(joined_text):
        block = match.group(0).strip()
        if block:
            modules.append(block)
    return modules


def write_asn1_extracts(target_dir: Path, pages: list[str]) -> int:
    asn1_dir = target_dir / "asn1"
    joined = "\n\n".join(pages)
    modules = find_asn1_modules(joined)
    count = 0

    for module in modules:
        count += 1
        asn1_dir.mkdir(parents=True, exist_ok=True)
        module_path = asn1_dir / f"module-{count:03d}.asn"
        module_path.write_text(module + "\n", encoding="utf-8", newline="\n")

    module_pages = set()
    for module in modules:
        for index, page in enumerate(pages, start=1):
            if page and page in module:
                module_pages.add(index)

    for index, page in enumerate(pages, start=1):
        if index in module_pages:
            continue
        assignments = ASN1_ASSIGNMENT_RE.findall(page)
        if len(assignments) < 3:
            continue
        count += 1
        asn1_dir.mkdir(parents=True, exist_ok=True)
        page_path = asn1_dir / f"page-{index:03d}-asn1-extract.asn"
        page_path.write_text(page.strip() + "\n", encoding="utf-8", newline="\n")

    return count


def pdf_image_list(pdf_path: Path) -> dict[tuple[int, int], PdfImage]:
    output = run_command(["pdfimages", "-list", str(pdf_path)])
    images: dict[tuple[int, int], PdfImage] = {}
    for line in output.splitlines()[2:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            page = int(parts[0])
            number = int(parts[1])
            kind = parts[2]
            width = int(parts[3])
            height = int(parts[4])
        except ValueError:
            continue
        images[(page, number)] = PdfImage(
            page=page,
            number=number,
            kind=kind,
            width=width,
            height=height,
        )
    return images


IMAGE_NAME_RE = re.compile(r"image-(\d+)-(\d+)\.(\w+)$")


def image_file_key(path: Path) -> tuple[int, int] | None:
    match = IMAGE_NAME_RE.match(path.name)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def write_image_manifest(images_dir: Path, kept: list[tuple[Path, PdfImage]]) -> None:
    manifest_path = images_dir / "manifest.md"
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Embedded Raster Images\n\n")
        handle.write("| File | Page | Width | Height |\n")
        handle.write("| --- | ---: | ---: | ---: |\n")
        for path, info in kept:
            handle.write(f"| `{path.name}` | {info.page} | {info.width} | {info.height} |\n")


def extract_images(pdf_path: Path, target_dir: Path) -> int:
    image_info = pdf_image_list(pdf_path)
    if not image_info:
        return 0

    images_dir = target_dir / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    prefix = images_dir / "image"
    run_command(["pdfimages", "-png", "-p", str(pdf_path), str(prefix)])

    seen_hashes: set[str] = set()
    kept: list[tuple[Path, PdfImage]] = []
    for path in sorted(images_dir.glob("image-*.*")):
        key = image_file_key(path)
        info = image_info.get(key) if key is not None else None
        keep = (
            info is not None
            and info.kind == "image"
            and info.width * info.height >= MIN_IMAGE_PIXELS
        )
        if not keep:
            path.unlink()
            continue

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen_hashes:
            path.unlink()
            continue
        seen_hashes.add(digest)

        new_name = f"page-{info.page:03d}-image-{info.number:03d}{path.suffix.lower()}"
        new_path = images_dir / new_name
        path.rename(new_path)
        kept.append((new_path, info))

    if kept:
        write_image_manifest(images_dir, kept)
    else:
        images_dir.rmdir()
    return len(kept)


SOURCE_SUFFIXES = (".pdf", ".txt")
MARKDOWN_SUFFIX = ".md"
# Markdown renderings of documents the library holds in no other form. docs/tel-docs/ also
# carries working notes and Markdown copies of PDFs that are already converted, so renderings
# are listed explicitly instead of discovered; a listed file must be form-feed paginated
# (one form feed per source page), which makes it split exactly like an RFC text file. Drop
# the entry once the PDF is added, and the PDF conversion replaces the rendering.
MARKDOWN_SOURCES = frozenset({"SGP.02-v4.2.md"})


def is_paginated_markdown(path: Path) -> bool:
    if path.suffix.lower() != MARKDOWN_SUFFIX or not path.is_file() or path.name not in MARKDOWN_SOURCES:
        return False
    for sibling_suffix in SOURCE_SUFFIXES:
        if path.with_suffix(sibling_suffix).exists():
            return False
    with path.open("rb") as handle:
        return b"\f" in handle.read()


def source_documents() -> list[Path]:
    sources = [
        path for path in SOURCE_DIR.iterdir() if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
    ]
    sources.extend(path for path in SOURCE_DIR.iterdir() if is_paginated_markdown(path))
    return sorted(sources)


def convert_source(source_path: Path) -> tuple[str, int, int, int, int]:
    """Convert one PDF or form-feed paginated text or Markdown rendering into an output folder."""
    slug = slugify(source_path.stem)
    target_dir = OUTPUT_DIR / slug
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    if source_path.suffix.lower() == ".pdf":
        page_count = pdf_page_count(source_path)
        pages = split_pages(pdf_text(source_path))
    else:
        pages = split_pages(source_path.read_text(encoding="utf-8", errors="replace"))
        page_count = len(pages)
    write_markdown(source_path, target_dir, pages, page_count)
    write_page_chunks(target_dir, pages)
    table_count = write_table_extracts(target_dir, pages)
    asn1_count = write_asn1_extracts(target_dir, pages)
    image_count = extract_images(source_path, target_dir) if source_path.suffix.lower() == ".pdf" else 0
    return slug, page_count, table_count, asn1_count, image_count


SOURCE_PAGES_RE = re.compile(r"^- Source pages: (\d+)\s*$", re.MULTILINE)


def folder_row(target_dir: Path) -> tuple[str, int, int, int, int]:
    """Recount one output folder so the index covers every conversion on disk, not only this run's."""
    slug = target_dir.name
    pages = len(list((target_dir / "pages").glob("page-*.md")))
    main_md = target_dir / f"{slug}.md"
    if main_md.exists():
        match = SOURCE_PAGES_RE.search(main_md.read_text(encoding="utf-8", errors="replace")[:2000])
        if match is not None:
            pages = int(match.group(1))
    tables = len(list((target_dir / "tables").glob("table-*.md")))
    asn1 = len(list((target_dir / "asn1").glob("*.asn")))
    images = len(list((target_dir / "images").glob("page-*")))
    return slug, pages, tables, asn1, images


def converted_folders() -> list[Path]:
    return sorted(
        path
        for path in OUTPUT_DIR.iterdir()
        if path.is_dir() and not path.name.startswith("_") and (path / f"{path.name}.md").exists()
    )


def supplemental_description(index_path: Path) -> str:
    for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith("|"):
            continue
        return re.split(r"(?<=[.!?])\s", clean, maxsplit=1)[0]
    return ""


CONTEXT_TAG_RE = re.compile(
    r"^\s*([A-Z][A-Za-z0-9]+)\s*::=\s*\[(\d+)\]\s*(?:(IMPLICIT|EXPLICIT)\s+)?([A-Za-z][A-Za-z0-9-]*)([^\n]*)",
    re.MULTILINE,
)
TYPE_ASSIGNMENT_RE = re.compile(
    r"^\s*([A-Z][A-Za-z0-9-]*)\s*::=\s*(\[[^\]\n]*\]\s*)?(?:(IMPLICIT|EXPLICIT)\s+)?([A-Za-z][A-Za-z0-9-]*)",
    re.MULTILINE,
)
TAG_DEFAULT_RE = re.compile(
    r"\bDEFINITIONS\s+(?:(AUTOMATIC|IMPLICIT|EXPLICIT)\s+TAGS\s+)?(?:EXTENSIBILITY\s+IMPLIED\s+)?::="
)
SPEC_TAG_COMMENT_RE = re.compile(r"\bTag\s+'([0-9A-Fa-f]{2,6})'")
GSMA_TAG_INDEX = OUTPUT_DIR / "_indexes" / "gsma-asn1-context-tags.md"
# X.690 (02/2021): SEQUENCE / SET and their OF forms encode constructed (8.9.1-8.12.1); BOOLEAN,
# INTEGER, ENUMERATED, NULL are primitive (8.2.1, 8.3.1, 8.4, 8.8.1); the string types are primitive
# under DER (10.2), which the RSP specifications mandate.
CONSTRUCTED_KEYWORDS = frozenset({"SEQUENCE", "SET"})
PRIMITIVE_KEYWORDS = frozenset({
    "BOOLEAN", "INTEGER", "ENUMERATED", "NULL", "REAL", "OBJECT", "RELATIVE-OID", "OCTET", "BIT",
    "UTF8String", "PrintableString", "IA5String", "VisibleString", "NumericString", "BMPString",
    "UniversalString", "GeneralizedTime", "UTCTime",
})


def context_tag_hex(number: int, constructed: bool) -> str:
    """BER identifier octets of a context-specific tag, X.690 (02/2021) 8.1.2.4-8.1.2.5.

    Bit 6 marks a constructed encoding; a tag number of 31 or more follows the leading '1F' bits
    in base-128 octets, bit 8 set on every octet but the last.
    """
    leading = 0x80 | (0x20 if constructed else 0x00)
    if number < 31:
        return f"{leading | number:02X}"
    octets = [number & 0x7F]
    number >>= 7
    while number:
        octets.append(0x80 | (number & 0x7F))
        number >>= 7
    return f"{leading | 0x1F:02X}" + "".join(f"{octet:02X}" for octet in reversed(octets))


TypeAssignments = dict[str, tuple[bool, str, str]]


def tagged_type_is_constructed(
    keyword: str, tagging: str, tag_default: str, assignments: TypeAssignments, depth: int = 0
) -> bool | None:
    """Whether `[n] <keyword>` encodes constructed; None when the base type cannot be resolved.

    X.680 (02/2021) 31.2.7: the tag is explicit when EXPLICIT is written, when the module's
    TagDefault is EXPLICIT TAGS (or empty), or when the tagged type is an untagged CHOICE; it is
    implicit otherwise. X.690 (02/2021) 8.14.3-8.14.4: an explicit tag encodes constructed, an
    implicit tag keeps the primitive or constructed form of the base encoding.
    """
    if tagging == "EXPLICIT" or (tagging != "IMPLICIT" and tag_default == "EXPLICIT"):
        return True
    return base_type_is_constructed(keyword, tag_default, assignments, depth)


def base_type_is_constructed(
    keyword: str, tag_default: str, assignments: TypeAssignments, depth: int = 0
) -> bool | None:
    """Primitive or constructed form of a base type, following type references by name."""
    if keyword in ("CHOICE", *CONSTRUCTED_KEYWORDS):
        return True
    if keyword in PRIMITIVE_KEYWORDS:
        return False
    target = assignments.get(keyword)
    if target is None or depth > 8:
        return None
    tagged, tagging, inner = target
    if tagged:
        return tagged_type_is_constructed(inner, tagging, tag_default, assignments, depth + 1)
    return base_type_is_constructed(inner, tag_default, assignments, depth + 1)


def document_tag_default(folder: Path) -> str:
    """TagDefault of the document's ASN.1 module header; AUTOMATIC when the pages carry none.

    A header without a TagDefault means EXPLICIT (X.680 (02/2021) 31.2.7 b). Every SGP.* module
    header in the library reads AUTOMATIC TAGS (SGP.22 v3.1 p. 40, SGP.32 v1.2 / v1.3 p. 15); a
    document quoting RSP types without a header (SGP.23) uses that module.
    """
    for page_path in sorted((folder / "pages").glob("page-*.md")):
        match = TAG_DEFAULT_RE.search(page_path.read_text(encoding="utf-8", errors="replace"))
        if match:
            return match.group(1) or "EXPLICIT"
    return "AUTOMATIC"


def write_gsma_tag_index() -> None:
    """Regenerate the context-tag lookup from the ASN.1 extracts of every converted SGP.* document.

    A row whose ASN.1 line carries the specification's own `Tag '..'` comment is checked against
    it, and a disagreement is printed for review.
    """
    rows: list[tuple[str, str, str, str]] = []
    for folder in converted_folders():
        if not folder.name.upper().startswith("SGP."):
            continue
        asn_texts = [
            (asn_path, asn_path.read_text(encoding="utf-8", errors="replace"))
            for asn_path in sorted((folder / "asn1").glob("*.asn"))
        ]
        if not asn_texts:
            continue
        tag_default = document_tag_default(folder)
        assignments: TypeAssignments = {}
        for _, text in asn_texts:
            for name, tag, tagging, keyword in TYPE_ASSIGNMENT_RE.findall(text):
                assignments.setdefault(name, (bool(tag), tagging, keyword))
        seen: set[str] = set()
        for asn_path, text in asn_texts:
            for name, number, tagging, keyword, rest in CONTEXT_TAG_RE.findall(text):
                if name in seen:
                    continue
                seen.add(name)
                constructed = tagged_type_is_constructed(keyword, tagging, tag_default, assignments)
                if constructed is None:
                    print(f"tag index: {folder.name} {name}: base type {keyword} not resolved, row left out")
                    continue
                tag = context_tag_hex(int(number), constructed)
                stated = SPEC_TAG_COMMENT_RE.search(rest)
                if stated and stated.group(1).upper() != tag:
                    print(f"tag index: {folder.name} {name}: encodes as {tag}, the specification comment says {stated.group(1)}")
                page = asn_path.stem.split("-")[1]
                rows.append((folder.name, tag, name, page))
    if not rows:
        return
    rows.sort(key=lambda row: (row[0], int(row[1], 16), row[2]))
    GSMA_TAG_INDEX.parent.mkdir(parents=True, exist_ok=True)
    with GSMA_TAG_INDEX.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# GSMA ASN.1 Context Tags By Document\n\n")
        handle.write(
            "Generated from the `asn1/` extracts of each converted SGP.* document: every top-level type declared "
            "with a context-specific tag, with the BER tag octets it encodes to and the source page. "
            "Regenerated by `scripts/convert_tel_docs.py`; do not edit by hand.\n\n"
        )
        handle.write("| Document | Tag | Type | Page |\n")
        handle.write("| --- | --- | --- | ---: |\n")
        for document, tag, name, page in rows:
            handle.write(f"| {document} | `{tag}` | `{name}` | [{int(page)}](../{document}/asn1/page-{page}-asn1-extract.asn) |\n")


def write_index() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    index_path = OUTPUT_DIR / "_index.md"
    supplemental = sorted((OUTPUT_DIR / "_indexes").glob("*.md"))
    with index_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Telecommunications Document Conversion Index\n\n")
        if supplemental:
            handle.write("## Supplemental Indexes\n\n")
            handle.write("| Index | Description |\n")
            handle.write("| --- | --- |\n")
            for path in supplemental:
                title = first_title(path.read_text(encoding="utf-8", errors="replace"), path.stem).lstrip("# ")
                handle.write(f"| [{title}](_indexes/{path.name}) | {supplemental_description(path)} |\n")
            handle.write("\n")
        handle.write("## Converted Documents\n\n")
        handle.write("| Document | Pages | Tables | ASN.1 Extracts | Images |\n")
        handle.write("| --- | ---: | ---: | ---: | ---: |\n")
        for slug, pages, tables, asn1, images in (folder_row(path) for path in converted_folders()):
            handle.write(
                f"| [{slug}]({slug}/{slug}.md) | {pages} | {tables} | {asn1} | {images} |\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert the PDFs and form-feed paginated .txt / .md renderings in docs/tel-docs/ into per-page "
        "Markdown under docs/tel-docs/converted/. Sources whose output folder already exists are skipped unless "
        "--force is given."
    )
    parser.add_argument("--force", action="store_true", help="regenerate output folders that already exist")
    parser.add_argument(
        "--only",
        metavar="STEM",
        action="append",
        default=[],
        help="convert only sources whose file stem contains STEM (repeatable); implies --force for those",
    )
    args = parser.parse_args()

    sources = source_documents()
    if args.only:
        sources = [path for path in sources if any(needle.lower() in path.stem.lower() for needle in args.only)]
        if not sources:
            parser.error(f"no PDF, .txt or paginated .md under {SOURCE_DIR} matches {args.only}")
    converted = 0
    skipped = 0
    for source_path in sources:
        target_dir = OUTPUT_DIR / slugify(source_path.stem)
        if target_dir.exists() and not (args.force or args.only):
            skipped += 1
            continue
        slug, pages, tables, asn1, images = convert_source(source_path)
        converted += 1
        print(f"{slug}: {pages} pages, {tables} tables, {asn1} asn1, {images} images")
    write_gsma_tag_index()
    write_index()
    print(f"converted {converted}, skipped {skipped} existing, index lists {len(converted_folders())} documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
