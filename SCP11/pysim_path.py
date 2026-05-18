# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 pySim path resolution: locates the pySim installation for ASN.1 codec and SAIP tool access."""
import sys
from pathlib import Path

from yggdrasim_common.runtime_paths import bundle_root as runtime_bundle_root
from yggdrasim_common.runtime_paths import workspace_root


def _candidate_pysim_roots() -> list[Path]:
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        repo_root / "pysim",
        repo_root / "pySim",
    ]
    workspace_candidate_root = Path(workspace_root()).resolve()
    candidates.extend(
        [
            workspace_candidate_root / "pysim",
            workspace_candidate_root / "pySim",
        ]
    )
    bundle_candidate_root = Path(runtime_bundle_root()).resolve()
    candidates.extend(
        [
            bundle_candidate_root / "pysim",
            bundle_candidate_root / "pySim",
        ]
    )
    unique_candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_candidates.append(resolved)
    return unique_candidates


def ensure_repo_pysim_on_path() -> Path | None:
    """Prepend an on-disk ``pySim`` checkout to ``sys.path`` when present.

    The on-disk tree is gitignored and treated as an **optional**
    developer convenience (``git clone https://gitlab.com/osmocom/pysim.git pysim``)
    for operators tracking an unreleased upstream branch.
    When this helper returns ``None``, callers must rely on the
    pip-installed upstream package, which ``pip install -e '.[saip]'``
    pulls from ``git+https://github.com/osmocom/pysim.git`` and makes
    available as the ``pySim`` module.
    """
    for pysim_root in _candidate_pysim_roots():
        if pysim_root.is_dir() is False:
            continue
        root_text = str(pysim_root)
        if root_text not in sys.path:
            sys.path.insert(0, root_text)
        return pysim_root
    return None


def describe_pysim_resolution() -> str:
    """Return a human-readable string describing how pySim was (or was not) resolved for this session."""
    pysim_root = ensure_repo_pysim_on_path()
    if pysim_root is not None:
        return f"Optional on-disk pySim checkout resolved at {pysim_root}."
    checked_paths = ", ".join(str(path) for path in _candidate_pysim_roots())
    try:
        import pySim  # type: ignore
    except ImportError as error:
        return (
            "No on-disk pySim checkout was found and the installed pySim package is unavailable. "
            "Install the upstream tree via `pip install -e '.[saip]'` (recommended), or "
            "`pip install 'pySim @ git+https://github.com/osmocom/pysim.git'`, or clone it manually "
            "(`git clone https://gitlab.com/osmocom/pysim.git pysim`). "
            f"Checked: {checked_paths}. Import error: {type(error).__name__}: {error}."
        )
    module_path = Path(getattr(pySim, "__file__", "") or "").resolve()
    return f"Installed pySim package resolved at {module_path.parent}."
