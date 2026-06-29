# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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


def first_title(page: str, fallback: str) -> str:
    for line in page.splitlines():
        clean = line.strip()
        if clean:
            return clean
    return fallback


def fenced_text(text: str) -> str:
    return f"```text\n{text.rstrip()}\n```\n"


def write_markdown(pdf_path: Path, target_dir: Path, pages: list[str], page_count: int) -> None:
    stem = pdf_path.stem
    md_path = target_dir / f"{slugify(stem)}.md"
    source_name = pdf_path.name
    title = first_title(pages[0] if pages else "", stem)

    with md_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"# {title}\n\n")
        handle.write(f"- Source file: `{source_name}`\n")
        handle.write(f"- Source pages: {page_count}\n")
        handle.write("- Conversion: layout-preserving text extraction from the local PDF source\n\n")
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


def convert_pdf(pdf_path: Path, force: bool) -> tuple[str, int, int, int, int]:
    slug = slugify(pdf_path.stem)
    target_dir = OUTPUT_DIR / slug
    if target_dir.exists():
        if not force:
            raise FileExistsError(f"{target_dir} already exists; pass --force to regenerate")
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    page_count = pdf_page_count(pdf_path)
    pages = split_pages(pdf_text(pdf_path))
    write_markdown(pdf_path, target_dir, pages, page_count)
    write_page_chunks(target_dir, pages)
    table_count = write_table_extracts(target_dir, pages)
    asn1_count = write_asn1_extracts(target_dir, pages)
    image_count = extract_images(pdf_path, target_dir)
    return slug, page_count, table_count, asn1_count, image_count


def write_index(rows: list[tuple[str, int, int, int, int]]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    index_path = OUTPUT_DIR / "_index.md"
    with index_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Telecommunications Document Conversion Index\n\n")
        handle.write("| Document | Pages | Tables | ASN.1 Extracts | Images |\n")
        handle.write("| --- | ---: | ---: | ---: | ---: |\n")
        for slug, pages, tables, asn1, images in rows:
            handle.write(
                f"| [{slug}]({slug}/{slug}.md) | {pages} | {tables} | {asn1} | {images} |\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="regenerate existing output folders")
    args = parser.parse_args()

    pdfs = sorted(SOURCE_DIR.glob("*.pdf"))
    rows: list[tuple[str, int, int, int, int]] = []
    for pdf_path in pdfs:
        rows.append(convert_pdf(pdf_path, force=args.force))
    write_index(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
