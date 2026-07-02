# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

__all__ = [
    "EimLocalConfig",
    "EimLocalSession",
    "EimHandoverContext",
    "EimLocalState",
    "ensure_handover_transaction",
    "load_eim_package_document",
    "lint_eim_package_document",
]


def __getattr__(name):
    if name == "EimLocalConfig":
        from .config import EimLocalConfig

        return EimLocalConfig
    if name in ("EimLocalSession", "EimHandoverContext", "EimLocalState"):
        from .session import EimLocalSession
        from .models import EimLocalState, EimHandoverContext

        mapping = {
            "EimLocalSession": EimLocalSession,
            "EimHandoverContext": EimHandoverContext,
            "EimLocalState": EimLocalState,
        }
        return mapping[name]
    if name == "ensure_handover_transaction":
        from .models import ensure_handover_transaction

        return ensure_handover_transaction
    if name in ("load_eim_package_document", "lint_eim_package_document"):
        from .eim_package_codec import lint_eim_package_document, load_eim_package_document

        mapping = {
            "load_eim_package_document": load_eim_package_document,
            "lint_eim_package_document": lint_eim_package_document,
        }
        return mapping[name]
    raise AttributeError(name)
