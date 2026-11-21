# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Card overview payload: the profile rows keep the SGP.32 fallback flags.

SGP.32 v1.3 §4.4 defines fallbackAttribute ('9F26') and fallbackAllowed
('9F67') in ProfileInfo. The console resolves both per Profile (None when the
eUICC was not asked for the tag); the GUI's profile cards show them, so the
overview payload must carry all three states through.
"""

from __future__ import annotations

from types import SimpleNamespace

from yggdrasim_common.gui_server.actions.scp11_live import _card_snapshot_payload


def _row(**fields: object) -> SimpleNamespace:
    base = {
        "iccid": "89880000000000000001",
        "aid": "A0000005591010FFFFFFFF8900001100",
        "state": "ENABLED",
        "profile_class": "OPER",
        "nickname": "Lab",
    }
    base.update(fields)
    return SimpleNamespace(**base)


def test_profile_rows_carry_fallback_and_fallback_allowed() -> None:
    snapshot = SimpleNamespace(
        profiles=[
            _row(fallback=True, fallback_allowed=True),
            _row(fallback=False, fallback_allowed=False),
            _row(fallback=None, fallback_allowed=None),
        ]
    )
    rows = _card_snapshot_payload(snapshot)["profiles"]
    assert [(row["fallback_attribute"], row["fallback_allowed"]) for row in rows] == [
        (True, True),
        (False, False),
        (None, None),
    ]


def test_a_row_without_the_fields_reports_them_as_unknown() -> None:
    rows = _card_snapshot_payload(SimpleNamespace(profiles=[_row()]))["profiles"]
    assert rows[0]["fallback_attribute"] is None
    assert rows[0]["fallback_allowed"] is None
