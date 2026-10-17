# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""FCP / FCI decoding and file-system command coding against the specifications.

Every vector is built from the clause it cites:

* TS 102 221 v18.4 §11.1.1.4.3 table 11.5 -- file descriptor byte
  (shareable bit, working / internal EF, DF, BER-TLV structure) and the
  record length / number of records bytes.
* TS 102 221 v18.4 §11.1.1.4.6 -- the 'A5' proprietary template holds
  UICC characteristics and available memory, never a file size.
* TS 102 221 v18.4 §11.1.1.4.7.3 / table 9.0c -- referenced security
  attributes, plain and with SEID pairs.
* TS 102 221 v18.4 §11.1.1.4.8 -- SFI in b8..b4 of the tag '88' value.
* TS 102 221 v18.4 §11.1.1.4.9 table 11.7b -- life cycle status integer.
* TS 102 221 v18.4 §11.1.1.4.10 / §9.5.2 -- PIN status template DO.
* TS 102 221 v18.4 §11.1.3 / §11.1.4 -- READ / UPDATE BINARY offsets.
* TS 102 221 v18.4 §11.1.7.2, §11.1.22 -- SEARCH RECORD Le, SUSPEND UICC.
* TS 102 222 v17.1 §6.7.2 / §6.8.2 -- TERMINATE DF / EF carry no data.
* GPC v2.3.1 §11.9.3.1 table 11-82 -- FCI proprietary template.

pySim's ``FcpTemplate`` is the parity oracle for the template decoder.
"""

from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

from SCP03.config import Config
from SCP03.logic import fs as fs_module
from SCP03.logic.fs import FileSystemController

try:
    from pySim.ts_102_221 import FcpTemplate as PysimFcpTemplate

    PYSIM_AVAILABLE = True
except ModuleNotFoundError:
    PYSIM_AVAILABLE = False


REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_FIDS = REPO_ROOT / "SCP03" / "seeds" / "fids.txt"


def tlv(tag: int, value: bytes) -> bytes:
    tag_bytes = tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")
    if len(value) < 0x80:
        length = bytes([len(value)])
    elif len(value) < 0x100:
        length = b"\x81" + bytes([len(value)])
    else:
        length = b"\x82" + len(value).to_bytes(2, "big")
    return tag_bytes + length + value


def fcp(*objects: bytes) -> bytes:
    return tlv(0x62, b"".join(objects))


def descriptor(fd_byte: int, rec_len: int = 0, rec_count: Optional[int] = None) -> bytes:
    value = bytes([fd_byte, 0x21])
    if rec_len > 0:
        value += rec_len.to_bytes(2, "big")
        if rec_count is not None:
            value += bytes([rec_count])
    return tlv(0x82, value)


FID_IMSI = tlv(0x83, bytes.fromhex("6F07"))
LCS_ACTIVATED = tlv(0x8A, b"\x05")
ARR_REF_2 = tlv(0x8B, bytes.fromhex("6F0602"))


class _RecordingTransport:
    """Answers scripted commands and records everything sent."""

    def __init__(
        self,
        responses: Optional[Dict[str, Any]] = None,
        default: Tuple[bytes, int, int] = (b"", 0x6A, 0x82),
    ) -> None:
        self.responses = dict(responses or {})
        self.default = default
        self.calls: List[str] = []

    def transmit(self, cmd: str, silent: bool = False):
        del silent
        command = str(cmd or "").strip().upper()
        self.calls.append(command)
        handler = self.responses.get(command)
        if callable(handler):
            return handler()
        if handler is None:
            return self.default
        return handler


def make_controller(transport: Any) -> FileSystemController:
    """Build a controller without touching the workspace seed or decoder registry."""
    controller = FileSystemController.__new__(FileSystemController)
    controller.tp = transport
    controller.fid_map = {"MF": ["3F00"]}
    controller.aid_registry = {}
    controller.current_fcp = {}
    controller.current_fid = None
    controller.scan_cache = {}
    controller.current_path_hint = ""
    controller._selection_restore_commands = []
    return controller


def decode(template: bytes, *, resolve: bool = False, transport: Any = None) -> Dict[str, Any]:
    controller = make_controller(transport or _RecordingTransport())
    controller.current_fid = "6F07"
    controller._parse_fcp_internal(template, target_fid="6F07", resolve=resolve)
    return controller.current_fcp


class FileDescriptorTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.1.4.3, table 11.5."""

    def test_ber_tlv_structure_is_an_ef_not_a_df(self) -> None:
        # '39' = 0 0 111 001: file type bits all set together with structure
        # '001' is the BER-TLV row, not the DF row.
        info = decode(fcp(descriptor(0x39), FID_IMSI, LCS_ACTIVATED))
        self.assertEqual(info["type"], "EF")
        self.assertEqual(info["structure"], "BER-TLV")

    def test_df_row_keeps_tree_structure(self) -> None:
        info = decode(fcp(descriptor(0x78), tlv(0x83, bytes.fromhex("7F10")), LCS_ACTIVATED))
        self.assertEqual(info["type"], "DF")
        self.assertEqual(info["structure"], "Tree")
        self.assertEqual(info["file_kind"], "DF or ADF")
        self.assertTrue(info["shareable"])

    def test_internal_ef_and_shareable_bit(self) -> None:
        internal = decode(fcp(descriptor(0x09), tlv(0x83, bytes.fromhex("6F08")), LCS_ACTIVATED))
        self.assertEqual(internal["type"], "EF")
        self.assertEqual(internal["structure"], "Transparent")
        self.assertEqual(internal["file_kind"], "internal EF")
        self.assertFalse(internal["shareable"])

        working = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED))
        self.assertEqual(working["file_kind"], "working EF")
        self.assertTrue(working["shareable"])

    def test_record_geometry_comes_from_descriptor_bytes(self) -> None:
        template = fcp(
            descriptor(0x42, rec_len=32, rec_count=10),
            tlv(0x83, bytes.fromhex("6F3A")),
            LCS_ACTIVATED,
            tlv(0x80, (320).to_bytes(2, "big")),
        )
        info = decode(template)
        self.assertEqual(info["structure"], "Linear Fixed")
        self.assertEqual(info["rec_len"], 32)
        self.assertEqual(info["rec_count"], 10)
        self.assertEqual(info["size"], 320)

    def test_record_count_falls_back_to_size_for_four_byte_descriptor(self) -> None:
        template = fcp(
            descriptor(0x46, rec_len=16),
            tlv(0x83, bytes.fromhex("6F39")),
            LCS_ACTIVATED,
            tlv(0x80, (80).to_bytes(2, "big")),
        )
        info = decode(template)
        self.assertEqual(info["structure"], "Cyclic")
        self.assertEqual(info["rec_len"], 16)
        self.assertEqual(info["rec_count"], 5)

    def test_rfu_descriptor_rows_do_not_claim_a_type(self) -> None:
        info = decode(fcp(descriptor(0x80), FID_IMSI, LCS_ACTIVATED))
        self.assertEqual(info["type"], "Unknown")
        self.assertEqual(info["file_kind"], "RFU")


class SizeAndProprietaryTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.1.4.1, §11.1.1.4.2 and §11.1.1.4.6."""

    def test_df_size_is_the_total_file_size_not_the_uicc_characteristics(self) -> None:
        proprietary = tlv(
            0xA5,
            tlv(0x80, b"\x71") + tlv(0x83, (65536).to_bytes(4, "big")) + tlv(0x87, b"\x01"),
        )
        with_total = fcp(
            descriptor(0x78),
            tlv(0x83, bytes.fromhex("3F00")),
            proprietary,
            LCS_ACTIVATED,
            tlv(0x8B, bytes.fromhex("2F0601")),
            tlv(0x81, (0x1000).to_bytes(2, "big")),
        )
        info = decode(with_total)
        self.assertEqual(info["size"], 0x1000)
        self.assertEqual(info["total_size"], 0x1000)
        self.assertEqual(info["proprietary"]["uicc_characteristics"], "71")
        self.assertEqual(info["proprietary"]["available_memory"], 65536)
        self.assertEqual(info["proprietary"]["supported_system_commands"], "01")

        without_total = fcp(descriptor(0x78), tlv(0x83, bytes.fromhex("3F00")), proprietary, LCS_ACTIVATED)
        self.assertEqual(decode(without_total)["size"], 0)

    def test_ef_size_and_total_size_are_separate(self) -> None:
        template = fcp(
            descriptor(0x41),
            FID_IMSI,
            LCS_ACTIVATED,
            tlv(0x80, (9).to_bytes(2, "big")),
            tlv(0x81, (24).to_bytes(2, "big")),
        )
        info = decode(template)
        self.assertEqual(info["size"], 9)
        self.assertEqual(info["total_size"], 24)

    def test_ber_tlv_ef_reserved_and_maximum_size(self) -> None:
        proprietary = tlv(
            0xA5,
            tlv(0x83, (64).to_bytes(2, "big"))
            + tlv(0x84, b"\x01")
            + tlv(0x85, (128).to_bytes(2, "big"))
            + tlv(0x86, (256).to_bytes(2, "big")),
        )
        info = decode(fcp(descriptor(0x39), tlv(0x83, bytes.fromhex("6FE8")), proprietary, LCS_ACTIVATED))
        self.assertEqual(info["proprietary"]["available_memory"], 64)
        self.assertEqual(info["proprietary"]["file_details"], "01")
        self.assertEqual(info["proprietary"]["reserved_size"], 128)
        self.assertEqual(info["proprietary"]["max_size"], 256)


class IdentifierTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.1.4.4, §11.1.1.4.5, §11.1.1.4.8, §11.1.1.4.9."""

    def test_fid_and_df_name_are_surfaced(self) -> None:
        aid = bytes.fromhex("A0000000871002")
        info = decode(fcp(descriptor(0x78), tlv(0x84, aid), LCS_ACTIVATED))
        self.assertEqual(info["aid"], aid.hex().upper())
        self.assertIsNone(info["fid"])
        self.assertEqual(decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED))["fid"], "6F07")

    def test_sfi_is_read_from_the_high_five_bits(self) -> None:
        info = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, tlv(0x88, b"\x38")))
        self.assertEqual(info["sfi"], "07")
        self.assertEqual(info["sfi_raw"], "38")
        self.assertTrue(info["sfi_supported"])

        arr = decode(fcp(descriptor(0x42, 55, 23), tlv(0x83, bytes.fromhex("6F06")), LCS_ACTIVATED, tlv(0x88, b"\xB8")))
        self.assertEqual(arr["sfi"], "17")

    def test_empty_sfi_tag_means_no_sfi(self) -> None:
        info = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, tlv(0x88, b"")))
        self.assertIsNone(info["sfi"])
        self.assertFalse(info["sfi_supported"])

    def test_absent_sfi_tag_uses_the_low_five_bits_of_the_fid(self) -> None:
        info = decode(fcp(descriptor(0x42, 30, 4), tlv(0x83, bytes.fromhex("6F3A")), LCS_ACTIVATED))
        self.assertEqual(info["sfi"], "1A")
        self.assertIsNone(info["sfi_raw"])
        self.assertTrue(info["sfi_supported"])
        # A DF has no SFI.
        self.assertIsNone(decode(fcp(descriptor(0x78), tlv(0x83, bytes.fromhex("7F10")), LCS_ACTIVATED))["sfi"])

    def test_life_cycle_status_names(self) -> None:
        expected = {
            0x00: "No information given",
            0x01: "Creation state",
            0x03: "Initialisation state",
            0x05: "Operational state - activated",
            0x07: "Operational state - activated",
            0x04: "Operational state - deactivated",
            0x06: "Operational state - deactivated",
            0x0C: "Termination state",
            0x0F: "Termination state",
            0x12: "Proprietary",
            0x02: "RFU",
        }
        for value, name in expected.items():
            self.assertEqual(fs_module._lcs_name(value), name, f"{value:02X}")
        info = decode(fcp(descriptor(0x41), FID_IMSI, tlv(0x8A, b"\x04")))
        self.assertEqual(info["lcs"], "04")
        self.assertEqual(info["lcs_name"], "Operational state - deactivated")


class PinStatusTemplateTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.1.4.10, §9.5.2 and table 9.3."""

    def test_ps_do_bits_map_to_key_references_in_order(self) -> None:
        pin_status = tlv(0xC6, tlv(0x90, b"\x40") + tlv(0x95, b"\x08") + tlv(0x83, b"\x01") + tlv(0x83, b"\x81"))
        info = decode(fcp(descriptor(0x78), tlv(0x84, bytes.fromhex("A0000000871002")), LCS_ACTIVATED, pin_status))
        entries = info["pin_status"]
        self.assertEqual([entry["key_ref"] for entry in entries], ["01", "81"])
        self.assertEqual(entries[0]["name"], "PIN Appl 1")
        self.assertFalse(entries[0]["enabled"])
        self.assertEqual(entries[0]["usage_qualifier"], "08")
        self.assertTrue(entries[0]["verify_required"])
        self.assertEqual(entries[1]["name"], "Second PIN Appl 1")
        self.assertTrue(entries[1]["enabled"])
        self.assertIsNone(entries[1]["usage_qualifier"])
        self.assertTrue(entries[1]["verify_required"])

    def test_universal_pin_with_do_not_use_qualifier(self) -> None:
        pin_status = tlv(0xC6, tlv(0x90, b"\x80") + tlv(0x95, b"\x00") + tlv(0x83, b"\x11"))
        info = decode(fcp(descriptor(0x78), tlv(0x83, bytes.fromhex("3F00")), LCS_ACTIVATED, pin_status))
        entry = info["pin_status"][0]
        self.assertEqual(entry["name"], "Universal PIN")
        self.assertTrue(entry["enabled"])
        self.assertFalse(entry["verify_required"])

    def test_key_reference_names(self) -> None:
        names = fs_module._pin_key_reference_name
        self.assertEqual(names(0x0A), "ADM1")
        self.assertEqual(names(0x0E), "ADM5")
        self.assertEqual(names(0x8A), "ADM6")
        self.assertEqual(names(0x8E), "ADM10")
        self.assertEqual(names(0x88), "Second PIN Appl 8")
        self.assertEqual(names(0x09), "RFU")
        self.assertEqual(names(0x90), "RFU")


class ReferencedSecurityTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.1.4.7 and table 9.0c."""

    def test_length_three_is_fid_and_record(self) -> None:
        info = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, ARR_REF_2))
        self.assertEqual(info["security"], "6F0602")
        self.assertEqual(info["security_format"], "referenced")
        self.assertEqual(info["arr_fid"], "6F06")
        self.assertEqual(info["arr_record"], 2)
        self.assertIsNone(info["arr_se_records"])

    def test_seid_pairs_pick_se01(self) -> None:
        info = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("6F0600030102"))))
        self.assertEqual(info["arr_fid"], "6F06")
        self.assertEqual(info["arr_se_records"], {"00": 3, "01": 2})
        self.assertEqual(info["arr_record"], 2)

        no_se01 = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("6F060205"))))
        self.assertEqual(no_se01["arr_record"], 5)

    def test_compact_and_expanded_formats_are_reported(self) -> None:
        compact = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, tlv(0x8C, bytes.fromhex("0100"))))
        self.assertEqual(compact["security_format"], "compact")
        self.assertIn("not decoded", compact["rules"])
        expanded = decode(fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, tlv(0xAB, tlv(0x80, b"\x01") + tlv(0x90, b""))))
        self.assertEqual(expanded["security_format"], "expanded")

    def test_resolution_reads_the_record_of_the_selected_se(self) -> None:
        transport = _RecordingTransport(
            {
                "00A40004026F06": (b"", 0x90, 0x00),
                "00B2020400": (bytes.fromhex("8001019000"), 0x90, 0x00),
                "00A40004026F07": (b"", 0x90, 0x00),
            }
        )
        template = fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("6F0600030102")))
        info = decode(template, resolve=True, transport=transport)
        self.assertIn("00B2020400", transport.calls)
        self.assertNotIn("00B2000400", transport.calls)
        self.assertNotIn("00B2030400", transport.calls)
        self.assertIsInstance(info["rules"], str)
        self.assertTrue(len(info["rules"]) > 0)

    def test_malformed_template_replaces_stale_state(self) -> None:
        controller = make_controller(_RecordingTransport())
        controller.current_fcp = {"template": "FCP", "size": 99}
        controller._parse_fcp_internal(bytes.fromhex("620282"))
        self.assertEqual(controller.current_fcp["template"], "Unknown")
        self.assertEqual(controller.current_fcp["raw"], "620282")
        self.assertIn("parse_error", controller.current_fcp)


class FciTemplateTests(unittest.TestCase):
    """GlobalPlatform Card Specification v2.3.1 §11.9.3.1, table 11-82."""

    def test_proprietary_template_objects_are_decoded(self) -> None:
        aid = bytes.fromhex("A000000151000000")
        proprietary = tlv(0xA5, tlv(0x9F6E, bytes.fromhex("000000000000")) + tlv(0x9F65, b"\xFF") + tlv(0x73, tlv(0x06, bytes.fromhex("2A864886FC6B01"))))
        info = decode(tlv(0x6F, tlv(0x84, aid) + proprietary))
        self.assertEqual(info["template"], "FCI")
        self.assertEqual(info["aid"], aid.hex().upper())
        self.assertEqual(info["max_len"], 255)
        self.assertEqual(info["app_production_lcs"], "000000000000")
        self.assertTrue(info["sd_data"].startswith("0607"))

    def test_flat_fci_is_still_read(self) -> None:
        info = decode(tlv(0x6F, tlv(0x84, bytes.fromhex("A000000151000000")) + tlv(0x9F65, b"\x00\xFF")))
        self.assertEqual(info["max_len"], 255)


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class PysimParityTests(unittest.TestCase):
    """Cross-check the template decoder against pySim's ``FcpTemplate``."""

    STRUCTURES = {
        "transparent": "Transparent",
        "linear_fixed": "Linear Fixed",
        "cyclic": "Cyclic",
        "ber_tlv": "BER-TLV",
        "no_info_given": "Tree",
    }
    FILE_TYPES = {"working_ef": "EF", "internal_ef": "EF", "df": "DF"}
    # TS 102 221 v18.4 §11.1.1.4.9 table 11.7b, in pySim's spelling. The
    # termination state is absent on purpose: no pySim name maps to it, which
    # is the upstream gap pinned by the test at the end of this class.
    LIFE_CYCLE_NAMES = {
        "no_information": "No information given",
        "creation": "Creation state",
        "initialization": "Initialisation state",
        "operational_activated": "Operational state - activated",
        "operational_deactivated": "Operational state - deactivated",
    }

    @staticmethod
    def _flatten(template: bytes) -> Dict[str, Any]:
        oracle = PysimFcpTemplate()
        oracle.from_tlv(template)
        flat: Dict[str, Any] = {}
        for item in oracle.to_dict()["fcp_template"]:
            flat.update(item)
        return flat

    def _check(self, template: bytes) -> None:
        ours = decode(template)
        theirs = self._flatten(template)
        fd_byte = theirs["file_descriptor"]["file_descriptor_byte"]
        self.assertEqual(ours["type"], self.FILE_TYPES[fd_byte["file_type"]])
        self.assertEqual(ours["structure"], self.STRUCTURES[fd_byte["structure"]])
        self.assertEqual(ours["shareable"], fd_byte["shareable"])
        self.assertEqual(ours["rec_len"], theirs["file_descriptor"]["record_len"] or 0)
        self.assertEqual(ours["rec_count"], theirs["file_descriptor"]["num_of_rec"] or 0)
        if "file_size" in theirs:
            self.assertEqual(ours["size"], theirs["file_size"])
        if "total_file_size" in theirs:
            self.assertEqual(ours["total_size"], theirs["total_file_size"])
        if "short_file_identifier" in theirs:
            if theirs["short_file_identifier"] is None:
                self.assertFalse(ours["sfi_supported"])
            else:
                self.assertEqual(int(ours["sfi"], 16), theirs["short_file_identifier"])
        if "security_attrib_referenced" in theirs:
            referenced = theirs["security_attrib_referenced"]
            self.assertEqual(ours["arr_fid"], referenced["ef_arr_file_id"].hex().upper())
            self.assertEqual(ours["arr_record"], referenced["ef_arr_record_nr"])
        if "life_cycle_status_integer" in theirs:
            state = theirs["life_cycle_status_integer"]
            expected = self.LIFE_CYCLE_NAMES.get(state)
            self.assertIsNotNone(
                expected,
                f"no name mapped for pySim's {state!r}; if this is "
                "'termination', pySim has been fixed -- see "
                "upstream_patches/osmocom-pysim-lcsi-termination/",
            )
            self.assertEqual(ours["lcs_name"], expected)
        if "file_identifier" in theirs:
            self.assertEqual(ours["fid"], theirs["file_identifier"].hex().upper())

    def test_transparent_ef(self) -> None:
        self._check(fcp(descriptor(0x41), FID_IMSI, tlv(0xA5, tlv(0x80, b"\x71")), LCS_ACTIVATED, ARR_REF_2, tlv(0x80, b"\x00\x09"), tlv(0x88, b"\x38")))

    def test_linear_fixed_ef(self) -> None:
        self._check(fcp(descriptor(0x42, 32, 10), tlv(0x83, bytes.fromhex("6F3A")), LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("6F0604")), tlv(0x80, b"\x01\x40"), tlv(0x81, b"\x01\x60"), tlv(0x88, b"\x00")))

    def test_cyclic_ef(self) -> None:
        self._check(fcp(descriptor(0x46, 16, 5), tlv(0x83, bytes.fromhex("6F39")), LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("6F0604")), tlv(0x80, b"\x00\x50"), tlv(0x88, b"\x48")))

    def test_df_with_proprietary_template(self) -> None:
        proprietary = tlv(0xA5, tlv(0x80, b"\x71") + tlv(0x83, (65536).to_bytes(4, "big")))
        self._check(fcp(descriptor(0x78), tlv(0x83, bytes.fromhex("3F00")), proprietary, LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("2F0601")), tlv(0x81, b"\x10\x00")))

    def test_ber_tlv_ef(self) -> None:
        proprietary = tlv(0xA5, tlv(0x83, b"\x00\x40") + tlv(0x84, b"\x01") + tlv(0x85, b"\x00\x80"))
        self._check(fcp(descriptor(0x39), tlv(0x83, bytes.fromhex("6FE8")), proprietary, LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("6F0603"))))

    def test_internal_ef(self) -> None:
        self._check(fcp(descriptor(0x09), tlv(0x83, bytes.fromhex("6F08")), LCS_ACTIVATED, ARR_REF_2, tlv(0x80, b"\x00\x21")))

    def test_adf_with_pin_status_template(self) -> None:
        pin_status = tlv(0xC6, tlv(0x90, b"\x40") + tlv(0x95, b"\x08") + tlv(0x83, b"\x01") + tlv(0x83, b"\x81"))
        template = fcp(descriptor(0x78), tlv(0x84, bytes.fromhex("A0000000871002")), tlv(0xA5, tlv(0x80, b"\x71")), LCS_ACTIVATED, tlv(0x8B, bytes.fromhex("6F0601")), pin_status)
        self._check(template)
        theirs = self._flatten(template)
        key_refs = [item["key_reference"] for item in theirs["pin_status_template_do"] if "key_reference" in item]
        self.assertEqual([int(entry["key_ref"], 16) for entry in decode(template)["pin_status"]], key_refs)

    def test_every_life_cycle_state_pysim_decodes_agrees(self) -> None:
        # TS 102 221 v18.4 §11.1.1.4.9 table 11.7b. '06' and '07' exercise the
        # "-" in column b2, which both decoders have to ignore.
        for value in (0x00, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07):
            template = fcp(descriptor(0x41), FID_IMSI, tlv(0x8A, bytes([value])), ARR_REF_2, tlv(0x80, b"\x00\x09"))
            with self.subTest(lcsi=f"{value:02X}"):
                self._check(template)

    def test_pysim_termination_state_is_a_known_upstream_gap(self) -> None:
        """pySim reports the termination state as an operational one.

        ``LifeCycleStatusInteger._from_bytes`` tests the operational states
        before the termination state and looks for its bits in b8 b7 instead
        of b4 b3, so table 11.7b's '0C'..'0F' never decode as `termination`.
        The evidence, the patch and the repro are in
        ``upstream_patches/osmocom-pysim-lcsi-termination/``.

        This test is the compensation for the pin, and it retires itself: the
        day the pinned pySim carries the fix it fails and says so.
        """
        for value in (0x0C, 0x0D, 0x0E, 0x0F):
            template = fcp(descriptor(0x41), FID_IMSI, tlv(0x8A, bytes([value])), ARR_REF_2, tlv(0x80, b"\x00\x09"))
            theirs = self._flatten(template)["life_cycle_status_integer"]
            if theirs == "termination":
                self.fail(
                    f"pySim now decodes LCSI '{value:02X}' as the termination "
                    "state. Delete upstream_patches/"
                    "osmocom-pysim-lcsi-termination/, add 'termination' to "
                    "PysimParityTests.LIFE_CYCLE_NAMES and drop this test."
                )
            # The upstream answer for these four values, wrong and pinned.
            self.assertIn(
                theirs,
                ("operational_activated", "operational_deactivated"),
                f"unexpected upstream decoding of LCSI '{value:02X}'",
            )
            # YggdraSIM's own decoder reads the table correctly, which is why
            # no product-code compensation is needed.
            self.assertEqual(decode(template)["lcs_name"], "Termination state")


class BinaryCommandTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.3 / §11.1.4 -- offsets in P1/P2, 256-byte chunks."""

    def test_read_binary_walks_past_256_bytes_using_the_fcp_size(self) -> None:
        first = bytes(range(256))
        second = bytes(range(44))
        transport = _RecordingTransport({"00B0000000": (first, 0x90, 0x00), "00B001002C": (second, 0x90, 0x00)})
        controller = make_controller(transport)
        controller.current_fcp = {"template": "FCP", "structure": "Transparent", "size": 300}
        data, sw1, sw2 = controller._read_binary_full()
        self.assertEqual(transport.calls, ["00B0000000", "00B001002C"])
        self.assertEqual(data, first + second)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_read_binary_without_size_stops_at_the_short_chunk(self) -> None:
        transport = _RecordingTransport({"00B0000000": (bytes(256), 0x90, 0x00), "00B0010000": (b"", 0x6B, 0x00)})
        controller = make_controller(transport)
        controller.current_fcp = {"template": "FCP", "structure": "Transparent", "size": 0}
        data, sw1, _sw2 = controller._read_binary_full()
        self.assertEqual(len(data), 256)
        self.assertEqual(sw1, 0x90)
        self.assertEqual(transport.calls, ["00B0000000", "00B0010000"])

    def test_read_binary_reports_the_first_failure(self) -> None:
        transport = _RecordingTransport({"00B0000000": (b"", 0x69, 0x82)})
        controller = make_controller(transport)
        controller.current_fcp = {"template": "FCP", "structure": "Transparent", "size": 9}
        data, sw1, sw2 = controller._read_binary_full()
        self.assertEqual((data, sw1, sw2), (b"", 0x69, 0x82))

    def test_update_binary_splits_at_255_bytes_with_offsets(self) -> None:
        payload = bytes(range(256)) + bytes(range(44))
        transport = _RecordingTransport(default=(b"", 0x90, 0x00))
        controller = make_controller(transport)
        with contextlib.redirect_stdout(io.StringIO()):
            controller.update_binary(payload.hex())
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(transport.calls[0], "00D60000FF" + payload[:255].hex().upper())
        self.assertEqual(transport.calls[1], "00D600FF2D" + payload[255:].hex().upper())

    def test_update_record_rejects_more_than_a_record_can_hold(self) -> None:
        transport = _RecordingTransport(default=(b"", 0x90, 0x00))
        controller = make_controller(transport)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            controller.update_record(1, "AA" * 256)
        self.assertEqual(transport.calls, [])
        self.assertIn("1..255", output.getvalue())


class AdminCommandTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.7, §11.1.14, §11.1.15, §11.1.22; TS 102 222 v17.1 §6.7, §6.8."""

    def test_search_record_is_a_simple_forward_search_from_record_one(self) -> None:
        # §11.1.7.2: Le present, so the matched record numbers come back.
        transport = _RecordingTransport(default=(b"", 0x90, 0x00))
        with contextlib.redirect_stdout(io.StringIO()):
            make_controller(transport).search_record("AABB")
        self.assertEqual(transport.calls, ["00A2010402AABB00"])

    def test_search_record_reports_the_matched_record_numbers(self) -> None:
        transport = _RecordingTransport({"00A2010402AABB00": (bytes([2, 5]), 0x90, 0x00)})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            make_controller(transport).search_record("AABB")
        self.assertIn("2, 5", output.getvalue())

    def test_search_record_reports_no_match_on_the_6282_warning(self) -> None:
        # §11.1.7.1: no match answers '90 00' or the warning '62 82'.
        transport = _RecordingTransport({"00A2010402AABB00": (b"", 0x62, 0x82)})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            make_controller(transport).search_record("AABB")
        self.assertIn("no record matched", output.getvalue())

    def test_suspend_uicc_carries_durations_and_le(self) -> None:
        transport = _RecordingTransport({"8076000004000102010A": (bytes.fromhex("0201") + bytes(range(8)), 0x90, 0x00)})
        controller = make_controller(transport)
        with contextlib.redirect_stdout(io.StringIO()):
            payload, sw1, _sw2 = controller.suspend_uicc()
        self.assertEqual(transport.calls, ["8076000004000102010A"])
        self.assertEqual(sw1, 0x90)
        self.assertEqual(payload[2:10], bytes(range(8)))
        with self.assertRaises(ValueError):
            controller.suspend_uicc("0501", "0201")

    def test_resume_uicc_sends_the_token(self) -> None:
        transport = _RecordingTransport(default=(b"", 0x90, 0x00))
        make_controller(transport).resume_uicc("0011223344556677")
        self.assertEqual(transport.calls, ["80760100080011223344556677"])

    def test_terminate_df_and_ef_carry_no_data_field(self) -> None:
        transport = _RecordingTransport({"00A40004027F10": (fcp(descriptor(0x78), tlv(0x83, bytes.fromhex("7F10")), LCS_ACTIVATED), 0x90, 0x00), "00A40004026F07": (fcp(descriptor(0x41), FID_IMSI, LCS_ACTIVATED), 0x90, 0x00)}, default=(b"", 0x90, 0x00))
        controller = make_controller(transport)
        with contextlib.redirect_stdout(io.StringIO()):
            controller.terminate_df("7F10")
            controller.terminate_ef("6F07")
            controller.terminate_ef()
        self.assertEqual(transport.calls, ["00A40004027F10", "00E60000", "00A40004026F07", "00E80000", "00E80000"])

    def test_activate_and_deactivate_coding(self) -> None:
        transport = _RecordingTransport(default=(b"", 0x90, 0x00))
        controller = make_controller(transport)
        controller.activate_file()
        controller.deactivate_file("6F07")
        self.assertEqual(transport.calls, ["00440000", "00040000026F07"])


class ArrLadderTests(unittest.TestCase):
    """TS 102 221 v18.4 §8.3 -- '7FFF' addresses the ADF of the active application."""

    def test_adf_arr_is_reached_through_7fff_before_the_proprietary_fid(self) -> None:
        state: Dict[str, Any] = {"adf": False}

        def select_arr():
            if state["adf"]:
                return b"", 0x90, 0x00
            return b"", 0x6A, 0x82

        def select_adf():
            state["adf"] = True
            return b"", 0x90, 0x00

        transport = _RecordingTransport({"00A40004026F06": select_arr, "00A40004027FFF": select_adf, "00B2010400": (bytes.fromhex("8001019000"), 0x90, 0x00), "00A40004026F07": (b"", 0x90, 0x00)})
        controller = make_controller(transport)
        rules = controller._resolve_arr_rules("6F06", 1, "6F07")
        self.assertIsInstance(rules, str)
        self.assertIn("00A40004027FFF", transport.calls)
        self.assertNotIn("00A40004027FF0", transport.calls)


class SeedTreeTests(unittest.TestCase):
    """The shipped ``fids.txt`` mirrors TS 31.102 v19.5 figures 4.1 / 4.2 and TS 31.103 v19."""

    @classmethod
    def setUpClass(cls) -> None:
        controller = FileSystemController.__new__(FileSystemController)
        with mock.patch.object(Config, "FIDS_FILE", str(SEED_FIDS)):
            cls.roots = controller._load_tree_structure()

    def _node(self, nodes: List[Dict[str, Any]], name: str) -> Dict[str, Any]:
        for node in nodes:
            if node["name"] == name:
                return node
        raise AssertionError(f"{name} not found among {[n['name'] for n in nodes]}")

    def _fid_of(self, nodes: List[Dict[str, Any]], name: str) -> str:
        return self._node(nodes, name)["fids"][0]

    def test_telecom_children_and_fids(self) -> None:
        mf = self._node(self.roots, "MF")
        telecom = self._node(mf["children"], "TELECOM")
        names = [child["name"] for child in telecom["children"]]
        for df_name in ("GRAPHICS", "PHONEBOOK", "MULTIMEDIA", "MMSS", "MCS", "V2X", "A2X"):
            self.assertIn(df_name, names)
        self.assertEqual(self._fid_of(telecom["children"], "EF_BDN"), "6F4D")
        self.assertEqual(self._fid_of(telecom["children"], "EF_CCP"), "6F3D")
        self.assertEqual(self._fid_of(telecom["children"], "EF_ECCP"), "6F4F")
        self.assertEqual(self._fid_of(telecom["children"], "EF_LND"), "6F44")
        self.assertEqual(names.count("EF_ARR"), 1)

    def test_usim_subtree(self) -> None:
        usim = self._node(self.roots, "USIM")
        self.assertIn("A0000000871002", usim["fids"])
        children = usim["children"]
        prose = self._node(children, "5G_PROSE")
        self.assertEqual(prose["fids"], ["5FF0"])
        self.assertEqual(self._fid_of(prose["children"], "EF_5G_PROSE_MEU"), "4F0D")
        snpn = self._node(children, "SNPN")
        self.assertNotIn("5G_PROSE", [child["name"] for child in snpn["children"]])
        for df_name, fid in (("WLAN", "5F40"), ("HNB", "5F50"), ("SOLSA", "5F70"), ("MEXE", "5F3C"), ("PROSE", "5F90"), ("ACDC", "5FA0"), ("5MBSUECONFIG", "5FF1")):
            self.assertEqual(self._fid_of(children, df_name), fid)
        self.assertEqual(self._fid_of(children, "EF_TVCONFIG"), "6FFB")

    def test_isim_subtree(self) -> None:
        isim = self._node(self.roots, "ISIM")
        self.assertIn("A0000000871004", isim["fids"])
        children = isim["children"]
        for name, fid in (("EF_AD", "6FAD"), ("EF_ARR", "6F06"), ("EF_GBABP", "6FD5"), ("EF_GBANL", "6FD7"), ("EF_NAFKCA", "6FDD"), ("EF_UICCIARI", "6FE7"), ("EF_IMSCONFIGDATA", "6FF8"), ("EF_IMSDCI", "6F0B")):
            self.assertEqual(self._fid_of(children, name), fid)


if __name__ == "__main__":
    unittest.main()
