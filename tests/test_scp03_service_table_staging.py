"""Regression tests for the service-table staging encoder.

Operators wanted a "what if I flipped these flags?" view for bitmap
service-table EFs (EF.UST / EF.IST / generic) -- toggle services in
the GUI, watch the resulting hex update live, and copy the bytes
into UPDATE BINARY without doing the bit-math by hand.

Contract pinned by these tests:

* ``AdvancedDecoders.encode_service_table`` is the round-trip dual of
  ``_build_service_table`` -- given a list of active service numbers
  it produces the same bitmap the decoder would consume.
* The ``scp03.stage_service_table`` action is registered, takes a
  JSON list of integers as ``active`` (no string coercion), and
  returns ``new_hex`` + a re-decoded checklist + a per-byte diff
  with ``current_hex``.
* The frontend ``app.js`` ships a ``Stage edit`` toolbar button and
  ``scp03ShowServiceTableStaging`` popout wired against
  ``apiFetch("/api/actions/scp03.stage_service_table/run", ...)``.
* The matching CSS hooks (``cc-svc-stage-*``) exist so the popout
  renders without falling back to default browser styles.

Pure-Python / static-grep tests -- no card, no GUI server.
"""

from __future__ import annotations

from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.css"
# ``yggdrasim_common/gui_server/`` is gitignored while the experimental
# Universal GUI surface is being stabilised. On checkouts where the
# directory is absent the tests below skip rather than fail.
_GUI_SERVER_TREE_AVAILABLE = (_REPO_ROOT / "yggdrasim_common" / "gui_server").is_dir()
_GUI_SERVER_SKIP_REASON = (
    "yggdrasim_common/gui_server/ is absent on this checkout; "
    "skipping GUI dispatcher / frontend assertions."
)
_GUI_SKIP = pytest.mark.skipif(
    _GUI_SERVER_TREE_AVAILABLE is False,
    reason=_GUI_SERVER_SKIP_REASON,
)


# ----------------------------------------------------------------------
# Backend encoder -- SCP03/core/decoders.py
# ----------------------------------------------------------------------


def test_encode_service_table_round_trips_with_decoder() -> None:
    """encode → decode → re-encode is stable and matches the decoder."""

    from SCP03.core.decoders import AdvancedDecoders

    sample_hex = "020A140CE33000000000100000"

    decoded = AdvancedDecoders.decode_ust(sample_hex)
    active_nums = [int(row.split(":", 1)[0]) for row in decoded["active"]]

    re_encoded = AdvancedDecoders.encode_service_table(
        active_nums, current_hex=sample_hex
    )

    assert re_encoded == sample_hex.upper(), (
        f"round-trip mismatch: {sample_hex.upper()} vs {re_encoded}"
    )


def test_encode_service_table_preserves_byte_length() -> None:
    """``current_hex`` sizing wins over ``total_bytes=None``."""

    from SCP03.core.decoders import AdvancedDecoders

    out = AdvancedDecoders.encode_service_table(
        [2], current_hex="0000000000000000"
    )
    assert len(out) == 16, f"length mismatch: got {len(out)}"


def test_encode_service_table_extends_when_bit_overflows_buffer() -> None:
    """A service number past the seed length grows the buffer."""

    from SCP03.core.decoders import AdvancedDecoders

    out = AdvancedDecoders.encode_service_table([20], total_bytes=2)
    assert len(out) // 2 >= 3, (
        "encoder must grow the buffer to fit bit 20 (byte index 2): "
        + out
    )
    assert int(out[4:6], 16) & 0x08, (
        "bit 20 should be set in byte index 2: " + out
    )


def test_encode_service_table_auto_sizes_when_no_seed() -> None:
    """Without seed or total_bytes the encoder picks a tight default."""

    from SCP03.core.decoders import AdvancedDecoders

    out = AdvancedDecoders.encode_service_table([1])
    assert out == "01", f"expected single byte 0x01, got {out!r}"

    out2 = AdvancedDecoders.encode_service_table([8])
    assert out2 == "80", f"expected single byte 0x80, got {out2!r}"

    out3 = AdvancedDecoders.encode_service_table([9])
    assert len(out3) == 4, f"bit 9 needs two bytes, got {out3!r}"


def test_encode_service_table_ignores_invalid_service_numbers() -> None:
    """Service numbers below 1 are dropped, duplicates collapse."""

    from SCP03.core.decoders import AdvancedDecoders

    out = AdvancedDecoders.encode_service_table([0, -3, 2, 2], total_bytes=1)
    assert out == "02", f"expected 0x02, got {out!r}"


# ----------------------------------------------------------------------
# Dispatcher -- yggdrasim_common/gui_server/actions/scp03.py
# ----------------------------------------------------------------------


@_GUI_SKIP
def test_dispatch_stage_service_table_returns_diff_and_decoded() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _dispatch_stage_service_table,
    )
    from yggdrasim_common.gui_server.actions.registry import ActionContext

    ctx = ActionContext()

    out = _dispatch_stage_service_table(
        ctx,
        active=[2, 6, 10],
        current_hex="020A14",
        table="ust",
    )

    assert out["table"] == "ust"
    assert out["current_hex"] == "020A14"
    assert isinstance(out["new_hex"], str) and len(out["new_hex"]) == 6
    assert out["byte_count"] == 3
    assert out["active"] == [2, 6, 10]
    assert isinstance(out["diff_bytes"], list)
    # At least one byte must differ -- we added service 6 to byte 0.
    assert len(out["diff_bytes"]) >= 1, out["diff_bytes"]
    decoded = out["decoded"]
    assert isinstance(decoded, dict)
    assert decoded.get("service_table") is True
    assert decoded.get("active_count") == 3


@_GUI_SKIP
def test_dispatch_stage_service_table_accepts_json_string() -> None:
    """The dispatcher tolerates JSON-text ``active`` for CLI / curl ergonomics."""

    from yggdrasim_common.gui_server.actions.scp03 import (
        _dispatch_stage_service_table,
    )
    from yggdrasim_common.gui_server.actions.registry import ActionContext

    out = _dispatch_stage_service_table(
        ActionContext(),
        active="[2, 6]",
        current_hex="00",
        table="generic",
    )
    assert out["active"] == [2, 6]
    assert out["new_hex"] == "22"


@_GUI_SKIP
def test_dispatch_stage_service_table_rejects_bad_payload() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _dispatch_stage_service_table,
    )
    from yggdrasim_common.gui_server.actions.registry import ActionContext

    with pytest.raises(ValueError):
        _dispatch_stage_service_table(ActionContext(), active=None)

    with pytest.raises(ValueError):
        _dispatch_stage_service_table(
            ActionContext(),
            active=[1],
            current_hex="ZZ",
        )


@_GUI_SKIP
def test_stage_service_table_spec_is_registered_pure_local() -> None:
    """The spec must be exposed without ``requires_card`` / ``requires_auth``."""

    from yggdrasim_common.gui_server.actions.registry import get_registry

    spec = get_registry().get("scp03.stage_service_table")

    assert spec.requires_card is False
    assert spec.requires_auth is False
    assert spec.subsystem == "SCP03"
    assert "staging" in spec.tags
    assert "service-table" in spec.tags
    field_names = {field.name for field in spec.inputs}
    assert {"active", "current_hex", "total_bytes", "table"} <= field_names


# ----------------------------------------------------------------------
# Frontend wiring -- yggdrasim_common/gui_server/static/app.{js,css}
# ----------------------------------------------------------------------


@_GUI_SKIP
def test_app_js_exposes_staging_popout_and_toolbar_button() -> None:
    text = _APP_JS.read_text(encoding="utf-8")

    assert "scp03ShowServiceTableStaging" in text, (
        "staging popout helper missing"
    )
    assert "cc-decoded-tools-btn--stage" in text, (
        "Stage edit toolbar button hook missing"
    )
    assert "scp03.stage_service_table" in text, (
        "frontend must call the stage action"
    )
    assert "/api/actions/scp03.stage_service_table/run" in text, (
        "stage popout must hit the /run endpoint"
    )


@_GUI_SKIP
def test_app_js_threads_raw_hex_into_decoded_block() -> None:
    text = _APP_JS.read_text(encoding="utf-8")

    # ``renderTransparentPayload`` must pass the raw EF body to
    # ``renderDecodedBlock`` so the toolbar can decide whether to
    # show the Stage-edit button.
    assert "renderDecodedBlock(payload.decoded, {" in text, (
        "renderTransparentPayload must thread meta.rawHex"
    )
    assert "rawHex: payload.hex" in text


@_GUI_SKIP
def test_app_js_send_to_update_binary_is_wired() -> None:
    text = _APP_JS.read_text(encoding="utf-8")

    assert "scp03StageOpenUpdateBinary" in text, (
        "staging popout must wire 'Send to UPDATE BINARY'"
    )
    # The helper must reuse the existing UPDATE BINARY wizard.
    assert "scp03ShowFsUpdateBinary" in text


@_GUI_SKIP
def test_app_css_exposes_staging_class_hooks() -> None:
    text = _APP_CSS.read_text(encoding="utf-8")

    for selector in (
        ".cc-svc-stage-preview",
        ".cc-svc-stage-hex-row",
        ".cc-svc-stage-hex-row--new",
        ".cc-svc-stage-actions",
        ".cc-svc-stage-list",
        ".cc-svc-stage-row",
        ".cc-svc-stage-cb",
        ".cc-svc-stage-row.is-active",
        ".cc-svc-stage-row.is-dirty",
        ".cc-decoded-tools-btn--stage",
    ):
        assert selector in text, f"CSS hook missing: {selector}"
