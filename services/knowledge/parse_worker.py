"""Offline subprocess for parsing one approved office/PDF file."""

from __future__ import annotations

from pathlib import Path
import sys
from functools import lru_cache


@lru_cache(maxsize=1)
def _converter():
    from docling.datamodel.base_models import InputFormat
    from docling.document_converter import DocumentConverter, NativePdfFormatOption

    return DocumentConverter(
        allowed_formats=[InputFormat.PDF, InputFormat.DOCX, InputFormat.XLSX],
        format_options={InputFormat.PDF: NativePdfFormatOption()},
    )


def convert(path: Path) -> str:
    result = _converter().convert(path, max_file_size=8 * 1024 * 1024, max_num_pages=100)
    try:
        text = result.document.export_to_markdown()
    finally:
        result.input.release()
    if len(text) > 2 * 1024 * 1024:
        raise ValueError("parser output limit")
    return text


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(2)
    sys.stdout.write(convert(Path(sys.argv[1])))


if __name__ == "__main__":
    main()
