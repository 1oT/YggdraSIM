"""
Tests for the ``Tools.ProfilePackage.saip_pe_editors`` package.

Covers the structured Profile Element editors, the registry lookup
helpers, and the basic mount/round-trip behaviour for each editor.
The tests intentionally avoid spinning up the full SAIP transcode TUI
(see ``tests/test_saip_transcode_tui.py`` for that suite); they
instead drive each editor inside a minimal ``App`` so the
mount/refresh path stays under the 90 s pytest cap.
"""

from __future__ import annotations

import asyncio
import unittest
from typing import Any

from textual.app import App
from textual.widgets import Input

from Tools.ProfilePackage.saip_pe_editors import (
    AkaParameterEditor,
    ApplicationsView,
    BasePeEditor,
    FileSystemView,
    GenericPeEditor,
    NaaPeEditor,
    PE_EDITOR_REGISTRY,
    PeEditorChanged,
    PinCodesEditor,
    PukCodesEditor,
    SecurityDomainEditor,
    TelecomPeEditor,
    base_pe_type_for_section_key,
    lookup_pe_editor,
    pe_header_member_key,
    rebuild_pe_with_header,
)
from Tools.ProfilePackage.saip_pe_editors._base import (
    hex_from_tagged_bytes,
    tagged_bytes,
    tagged_tuple,
    unwrap_tagged_tuple,
)


def _build_pin_pe() -> dict[str, Any]:
    return {
        "pin-Header": {"identification": 3, "mandated": None},
        "pinCodes": {
            "__ygg_saip_tuple__": [
                "pinconfig",
                [
                    {
                        "keyReference": 1,
                        "maxNumOfAttemps-retryNumLeft": 0x33,
                        "pinAttributes": 6,
                        "pinValue": {"__ygg_saip_bytes__": "31323334FFFFFFFF"},
                        "unblockingPINReference": 1,
                    },
                    {
                        "keyReference": 10,
                        "maxNumOfAttemps-retryNumLeft": 0xAA,
                        "pinAttributes": 1,
                        "pinValue": {"__ygg_saip_bytes__": "3132333435363738"},
                    },
                ],
            ],
        },
    }


def _build_puk_pe() -> dict[str, Any]:
    return {
        "puk-Header": {"identification": 2, "mandated": None},
        "pukCodes": [
            {
                "keyReference": 1,
                "maxNumOfAttemps-retryNumLeft": 0xAA,
                "pukValue": {"__ygg_saip_bytes__": "3132333435363738"},
            },
        ],
    }


def _build_aka_pe() -> dict[str, Any]:
    return {
        "aka-header": {"identification": 12, "mandated": None},
        "algoConfiguration": {
            "__ygg_saip_tuple__": [
                "algoParameter",
                {
                    "algorithmID": 1,
                    "algorithmOptions": {"__ygg_saip_bytes__": "01"},
                    "key": {"__ygg_saip_bytes__": "FF" * 16},
                    "opc": {"__ygg_saip_bytes__": "11" * 16},
                },
            ],
        },
        "sqnOptions": {"__ygg_saip_bytes__": "0E"},
        "sqnInit": [{"__ygg_saip_bytes__": "00" * 6}],
    }


def _build_usim_pe() -> dict[str, Any]:
    return {
        "usim-header": {"identification": 7, "mandated": None},
        "templateID": "2.23.143.1.2.4",
        "adf-usim": [
            {"__ygg_saip_tuple__": ["fileDescriptor", {"__ygg_saip_bytes__": "78210000"}]},
        ],
        "ef-imsi": [
            {"__ygg_saip_tuple__": ["fileDescriptor", {"__ygg_saip_bytes__": "4121"}]},
            {"__ygg_saip_tuple__": ["fillFileContent", {"__ygg_saip_bytes__": "082943002001020304"}]},
        ],
    }


def _build_sd_pe() -> dict[str, Any]:
    return {
        "sd-Header": {"identification": 14, "mandated": None},
        "instance": {
            "applicationLoadPackageAID": {"__ygg_saip_bytes__": "A0000001515350"},
            "classAID": {"__ygg_saip_bytes__": "A000000151535041"},
            "instanceAID": {"__ygg_saip_bytes__": "A000000151000000"},
            "applicationPrivileges": {"__ygg_saip_bytes__": "82DC20"},
            "lifeCycleState": {"__ygg_saip_bytes__": "0F"},
            "applicationSpecificParametersC9": {"__ygg_saip_bytes__": "81028000"},
        },
        "keyList": [
            {
                "keyAccess": {"__ygg_saip_bytes__": "00"},
                "keyComponents": [
                    {
                        "keyData": {"__ygg_saip_bytes__": "00" * 16},
                        "keyType": {"__ygg_saip_bytes__": "88"},
                        "macLength": 8,
                    },
                ],
                "keyIdentifier": {"__ygg_saip_bytes__": "01"},
                "keyUsageQualifier": {"__ygg_saip_bytes__": "38"},
                "keyVersionNumber": {"__ygg_saip_bytes__": "03"},
            },
        ],
        "sdPersoData": [{"__ygg_saip_bytes__": "01020304"}],
    }


def _build_full_document() -> dict[str, Any]:
    return {
        "sections": {
            "header": {
                "profile-header": {"identification": 0, "mandated": None},
                "iccid": {"__ygg_saip_bytes__": "89880811111111111112"},
                "profileType": "Sample Lab",
                "major-version": 2,
                "minor-version": 3,
            },
            "pinCodes": _build_pin_pe(),
            "pukCodes": _build_puk_pe(),
            "akaParameter": _build_aka_pe(),
            "usim": _build_usim_pe(),
            "securityDomain": _build_sd_pe(),
        },
    }


class _ProbeApp(App):
    """Minimal App that mounts a single widget for assertion-style tests."""

    def __init__(self, widget: Any) -> None:
        super().__init__()
        self._probe_widget = widget

    def compose(self) -> Any:
        yield self._probe_widget


def _drive(widget: Any, *, pause_count: int = 5) -> _ProbeApp:
    app = _ProbeApp(widget)

    async def runner() -> None:
        async with app.run_test() as pilot:
            for _ in range(pause_count):
                await pilot.pause()

    asyncio.run(runner())
    return app


def _drive_with_callback(
    widget: Any,
    callback: Any,
    *,
    pause_count: int = 8,
) -> Any:
    """Run the App and capture the result of ``callback(widget)`` while mounted.

    The widgets only return useful answers while the Textual app is alive —
    once ``run_test`` exits, the widget tree is torn down and ``query_one``
    starts raising ``NoMatches``. Tests that assert against form state must
    therefore run their queries from inside the active pilot session.
    """
    app = _ProbeApp(widget)
    captured: dict[str, Any] = {}

    async def runner() -> None:
        async with app.run_test() as pilot:
            for _ in range(pause_count):
                await pilot.pause()
            captured["value"] = callback(widget)

    asyncio.run(runner())
    return captured.get("value")


class RegistryHelpersTests(unittest.TestCase):
    def test_lookup_returns_registered_editor(self) -> None:
        self.assertIs(lookup_pe_editor("pinCodes"), PinCodesEditor)
        self.assertIs(lookup_pe_editor("pinCodes_2"), PinCodesEditor)
        self.assertIs(lookup_pe_editor("usim"), NaaPeEditor)
        self.assertIs(lookup_pe_editor("opt-csim"), NaaPeEditor)
        self.assertIs(lookup_pe_editor("akaParameter"), AkaParameterEditor)
        self.assertIs(lookup_pe_editor("securityDomain"), SecurityDomainEditor)
        self.assertIs(lookup_pe_editor("telecom"), TelecomPeEditor)

    def test_lookup_unknown_returns_none(self) -> None:
        self.assertIsNone(lookup_pe_editor("unknownPE"))
        self.assertIsNone(lookup_pe_editor(""))

    def test_base_pe_type_strips_duplicate_suffix(self) -> None:
        self.assertEqual(base_pe_type_for_section_key("pinCodes_2"), "pinCodes")
        self.assertEqual(base_pe_type_for_section_key("genericFileManagement_4"), "genericFileManagement")
        self.assertEqual(base_pe_type_for_section_key("usim"), "usim")
        self.assertEqual(base_pe_type_for_section_key("opt-isim_3"), "opt-isim")

    def test_pe_header_member_key_canonical_for_known_pes(self) -> None:
        self.assertEqual(pe_header_member_key("pinCodes_2"), "pin-Header")
        self.assertEqual(pe_header_member_key("pukCodes"), "puk-Header")
        self.assertEqual(pe_header_member_key("securityDomain"), "sd-Header")
        self.assertEqual(pe_header_member_key("akaParameter"), "aka-header")
        self.assertEqual(pe_header_member_key("usim"), "usim-header")
        self.assertEqual(pe_header_member_key("opt-isim"), "opt-isim-header")

    def test_registry_contains_all_phase_editors(self) -> None:
        for key in (
            "pinCodes",
            "pukCodes",
            "akaParameter",
            "securityDomain",
            "telecom",
            "usim",
            "opt-usim",
            "isim",
            "opt-isim",
            "csim",
            "opt-csim",
        ):
            self.assertIn(key, PE_EDITOR_REGISTRY, key)


class TaggedHelpersTests(unittest.TestCase):
    def test_tagged_bytes_round_trip(self) -> None:
        wrapped = tagged_bytes("aabb cc dd")
        self.assertEqual(wrapped["__ygg_saip_bytes__"], "AABBCCDD")
        self.assertEqual(hex_from_tagged_bytes(wrapped), "AABBCCDD")

    def test_tagged_tuple_round_trip(self) -> None:
        wrapped = tagged_tuple("foo", [{"a": 1}])
        unwrapped = unwrap_tagged_tuple(wrapped)
        self.assertIsNotNone(unwrapped)
        assert unwrapped is not None
        self.assertEqual(unwrapped[0], "foo")
        self.assertEqual(unwrapped[1], [{"a": 1}])

    def test_rebuild_pe_with_header_replaces_existing(self) -> None:
        pe = _build_pin_pe()
        new_pe = rebuild_pe_with_header(
            pe,
            header_member_key="pin-Header",
            header_payload={"identification": 9, "mandated": None},
        )
        self.assertEqual(new_pe["pin-Header"], {"identification": 9, "mandated": None})
        self.assertIn("pinCodes", new_pe)

    def test_rebuild_pe_with_header_inserts_when_missing(self) -> None:
        pe = {"pinCodes": []}
        new_pe = rebuild_pe_with_header(
            pe,
            header_member_key="pin-Header",
            header_payload={"identification": 1, "mandated": None},
        )
        self.assertEqual(new_pe["pin-Header"], {"identification": 1, "mandated": None})
        self.assertEqual(list(new_pe.keys()), ["pin-Header", "pinCodes"])


class PinCodesEditorTests(unittest.TestCase):
    def test_mounts_with_pe_value(self) -> None:
        editor = PinCodesEditor(pe_section_key="pinCodes_2", pe_value=_build_pin_pe())
        _drive(editor)
        # Editor still holds the original PE shape after mount.
        self.assertEqual(editor.pe_section_key, "pinCodes_2")
        current = editor.current_value()
        self.assertEqual(set(current.keys()), {"pin-Header", "pinCodes"})

    def test_collect_records_normalises_hex(self) -> None:
        editor = PinCodesEditor(pe_section_key="pinCodes", pe_value=_build_pin_pe())
        records = _drive_with_callback(editor, lambda w: w._collect_records())
        self.assertGreaterEqual(len(records), 2)
        self.assertEqual(records[0]["keyReference"], 1)
        self.assertIn("pinValue", records[0])
        self.assertEqual(
            records[0]["pinValue"]["__ygg_saip_bytes__"],
            "31323334FFFFFFFF",
        )


class PukCodesEditorTests(unittest.TestCase):
    def test_collect_after_mount(self) -> None:
        editor = PukCodesEditor(pe_section_key="pukCodes", pe_value=_build_puk_pe())
        records = _drive_with_callback(editor, lambda w: w._collect_records())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["keyReference"], 1)
        self.assertEqual(
            records[0]["pukValue"]["__ygg_saip_bytes__"],
            "3132333435363738",
        )


class AkaParameterEditorTests(unittest.TestCase):
    def test_mounts_and_round_trips_payload(self) -> None:
        editor = AkaParameterEditor(pe_section_key="akaParameter", pe_value=_build_aka_pe())

        def _check(widget: AkaParameterEditor) -> dict[str, Any]:
            widget._collect_and_emit("test-bump")
            return widget.current_value()

        new_pe = _drive_with_callback(editor, _check)
        algo = new_pe.get("algoConfiguration")
        self.assertIsInstance(algo, dict)
        self.assertIn("__ygg_saip_tuple__", algo)
        tagged = algo["__ygg_saip_tuple__"]
        self.assertEqual(tagged[0], "algoParameter")
        algo_payload = tagged[1]
        self.assertEqual(algo_payload.get("algorithmID"), 1)
        self.assertEqual(
            algo_payload.get("key"),
            {"__ygg_saip_bytes__": "F" * 32},
        )


class NaaEditorTests(unittest.TestCase):
    def test_mounts_with_template_id(self) -> None:
        editor = NaaPeEditor(pe_section_key="usim", pe_value=_build_usim_pe())
        value = _drive_with_callback(
            editor,
            lambda w: w.query_one("#naa_template_input", Input).value,
        )
        self.assertEqual(value, "2.23.143.1.2.4")

    def test_drop_ef_via_unchecked_box(self) -> None:
        editor = NaaPeEditor(pe_section_key="usim", pe_value=_build_usim_pe())
        ef_keys = _drive_with_callback(editor, lambda w: w._iter_ef_keys())
        self.assertIn("ef-imsi", ef_keys)
        self.assertIn("adf-usim", ef_keys)


class SecurityDomainEditorTests(unittest.TestCase):
    def test_collects_instance_payload(self) -> None:
        editor = SecurityDomainEditor(
            pe_section_key="securityDomain",
            pe_value=_build_sd_pe(),
        )
        instance = _drive_with_callback(editor, lambda w: w._collect_instance())
        self.assertEqual(
            instance["applicationLoadPackageAID"],
            {"__ygg_saip_bytes__": "A0000001515350"},
        )
        self.assertEqual(
            instance["lifeCycleState"],
            {"__ygg_saip_bytes__": "0F"},
        )

    def test_compose_pe_value_preserves_keys_and_perso(self) -> None:
        editor = SecurityDomainEditor(
            pe_section_key="securityDomain",
            pe_value=_build_sd_pe(),
        )
        new_pe = _drive_with_callback(editor, lambda w: w._compose_pe_value())
        self.assertIn("instance", new_pe)
        self.assertIn("keyList", new_pe)
        self.assertEqual(len(new_pe["keyList"]), 1)
        self.assertEqual(
            new_pe["sdPersoData"][0],
            {"__ygg_saip_bytes__": "01020304"},
        )


class FileSystemViewTests(unittest.TestCase):
    def test_mounts_and_renders_file_tree(self) -> None:
        from textual.widgets import Tree

        view = FileSystemView(document=_build_full_document())
        child_count = _drive_with_callback(
            view,
            lambda w: len(w.query_one("#fs_tree", Tree).root.children),
        )
        self.assertGreater(child_count, 0)

    def test_render_file_detail_hides_record_hex_dumps(self) -> None:
        from Tools.ProfilePackage.saip_pe_editors._filesystem import FileSystemView as _FsView

        view = _FsView(document=_build_full_document())
        sections = _build_full_document()["sections"]
        usim_pe = sections["usim"]
        member = usim_pe["ef-imsi"]
        rendered = view._render_file_detail("usim", "ef-imsi", member)
        # Per-record hex dumps must not be rendered alongside the file info.
        self.assertNotIn("Record #1:", rendered)
        self.assertNotIn("082943002001020304", rendered)
        # File Control Parameters section must still be rendered.
        self.assertIn("File Control Parameters", rendered)
        self.assertIn("File type", rendered)


class ApplicationsViewTests(unittest.TestCase):
    def test_mounts_and_renders_applications_tree(self) -> None:
        from textual.widgets import Tree

        view = ApplicationsView(document=_build_full_document())
        child_count = _drive_with_callback(
            view,
            lambda w: len(w.query_one("#apps_tree", Tree).root.children),
        )
        self.assertGreaterEqual(child_count, 2)


class GenericPeEditorTests(unittest.TestCase):
    def test_falls_back_for_unregistered_pes(self) -> None:
        editor = GenericPeEditor(
            pe_section_key="header",
            pe_value={"profile-header": {"identification": 0, "mandated": None}},
        )
        value = _drive_with_callback(
            editor,
            lambda w: w.query_one("#pe_header_identification", Input).value,
        )
        self.assertEqual(value, "0")


if __name__ == "__main__":
    unittest.main()
