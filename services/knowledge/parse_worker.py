"""Offline subprocess for parsing one approved office/PDF file."""

from __future__ import annotations

from pathlib import Path
from math import ceil
import sys
from functools import lru_cache

MAX_WORKER_VMEM = 8 * 1024 * 1024 * 1024
MAX_WORKER_CPU_SECONDS = 1800


def configure_linux_limits() -> None:
    """Bound the untrusted-format worker without relaxing inherited limits."""
    if not sys.platform.startswith("linux"):
        return
    import resource

    for kind, cap in ((resource.RLIMIT_AS, MAX_WORKER_VMEM),
                      (resource.RLIMIT_CPU, MAX_WORKER_CPU_SECONDS)):
        inherited = resource.getrlimit(kind)
        bound = min([cap, *(value for value in inherited
                            if value != resource.RLIM_INFINITY)])
        resource.setrlimit(kind, (bound, bound))


def set_linux_cpu_budget(seconds: int) -> None:
    """Cap cumulative worker CPU to a fresh allowance for one conversion."""
    if not sys.platform.startswith("linux"):
        return
    import resource

    used = resource.getrusage(resource.RUSAGE_SELF)
    consumed = ceil(used.ru_utime + used.ru_stime)
    _, hard = resource.getrlimit(resource.RLIMIT_CPU)
    if hard == resource.RLIM_INFINITY:
        raise RuntimeError("parser CPU limit was not configured")
    deadline = min(consumed + seconds, hard)
    if deadline <= consumed:
        raise RuntimeError("parser worker CPU budget exhausted")
    resource.setrlimit(resource.RLIMIT_CPU, (deadline, hard))


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
