import sys
from pathlib import Path


def ensure_repo_pysim_on_path() -> Path | None:
    """Prepend the vendored ``pysim`` tree when present."""
    pysim_root = Path(__file__).resolve().parent.parent / "pysim"
    if pysim_root.is_dir() is False:
        return None
    root_text = str(pysim_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return pysim_root
