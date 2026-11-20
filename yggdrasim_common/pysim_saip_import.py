# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""pySim's SAIP templates module, imported so that two threads cannot half-build it.

``pySim/esim/saip/templates.py`` imports ``pySim.esim.saip.oid as OID``. While
another thread runs the package's ``__init__``, which imports templates, that
line waits on the package's import lock; Python breaks the two-thread lock
cycle by handing the package thread a templates module whose classes are not
defined yet ("partially initialized module 'pySim.esim.saip.templates' ... has
no attribute 'FileTemplate'"). A thread that imports the package first holds no
templates lock while it waits, so every direct import of the submodule in this
tree goes through :func:`import_saip_templates`.

Evidence, repro and the pySim patch:
``upstream_patches/osmocom-pysim-saip-templates-import-race/``. The module
imports nothing at load time, so the card engine can use it without pulling in
the SAIP tool stack; ``tests/test_saip_templates_import_race.py`` fails once the
pinned pySim carries the fix, and then this module goes.
"""

from __future__ import annotations

from typing import Any


class SaipTemplatesImportError(RuntimeError):
    """pySim's SAIP templates module came back without the classes it defines."""


def import_saip_templates() -> Any:
    """Return ``pySim.esim.saip.templates``, importing its package first.

    Call it where the caller would import pySim, after its path decision
    (``ensure_workspace_pysim_on_path``). Raises :class:`SaipTemplatesImportError`
    when the module lacks ``FileTemplate`` or ``ProfileTemplateRegistry``.
    """
    import pySim.esim.saip  # noqa: F401 -- the package first, see the module docstring
    from pySim.esim.saip import templates

    missing = [name for name in ("FileTemplate", "ProfileTemplateRegistry") if not hasattr(templates, name)]
    if missing:
        raise SaipTemplatesImportError(
            "pySim.esim.saip.templates was imported without " + ", ".join(missing)
            + " (see upstream_patches/osmocom-pysim-saip-templates-import-race)"
        )
    return templates
