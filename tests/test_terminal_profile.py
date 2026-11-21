# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""TERMINAL PROFILE decoder and builder against ETSI TS 102 223 V18.3.0 §5.2 / TS 31.111 V19.4.0 §5.2."""
from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common import terminal_profile as tp
from yggdrasim_common.stk_terminal import MAXIMAL_TERMINAL_PROFILE

_MODULE_PATH = Path(tp.__file__).resolve()


def _findings(profile: bytes) -> dict[str, list[str]]:
    """Severity -> the addresses (or texts, for an address-less finding) it reports."""
    found: dict[str, list[str]] = {}
    for finding in tp.decode(profile).findings:
        found.setdefault(finding.severity, []).append(finding.address or finding.text)
    return found


class TableTests(unittest.TestCase):
    def test_every_bit_of_bytes_1_to_39_has_exactly_one_entry(self) -> None:
        covered: dict[int, list[int]] = {}
        for facility in tp.FACILITIES:
            covered.setdefault(facility.byte, []).extend(
                range(facility.bit, facility.bit + facility.width)
            )
        self.assertEqual(sorted(covered), list(range(1, 40)))
        for byte, bits in covered.items():
            with self.subTest(byte=byte):
                self.assertEqual(sorted(bits), list(range(1, 9)))
        self.assertEqual(tp.LAST_DEFINED_BYTE, 39)

    def test_the_maximal_preset_is_the_toolchain_profile(self) -> None:
        # Two transcriptions of §5.2 made independently; equal bytes prove the table.
        self.assertEqual(tp.maximal(), MAXIMAL_TERMINAL_PROFILE)
        self.assertEqual(tp.decode(tp.maximal()).findings, ())

    def test_the_named_bits_sit_where_the_specification_draws_them(self) -> None:
        for address, name in (
            ("1.1", "Profile download"),
            ("5.5", "Event: Location status"),
            ("12.1", "Proactive UICC: OPEN CHANNEL"),
            ("13.6-8", "Number of channels supported by terminal"),
            ("17.7", "E-UTRAN"),
            ("32.7", "CAT service list for eCAT client"),
            ("34.6", 'REFRESH with "eUICC Profile State Change" mode'),
        ):
            with self.subTest(address=address):
                self.assertEqual(tp.resolve(address).name, name)
        # TS 31.111 V19.4.0 reads a TS 102 223 3GPP bit its own way; both are kept.
        self.assertEqual(
            tp.resolve("25.5").usat, "Event: Network Rejection for GERAN/UTRAN"
        )
        self.assertEqual(tp.resolve("25.5").owner, "3GPP")


class DecodeTests(unittest.TestCase):
    def test_every_bit_set_reports_each_bit_the_coding_keeps_zero(self) -> None:
        found = _findings(b"\xff" * 39)
        for address in (
            "7.6-8", "10.3-8", "16.5", "19.5-8", "21.5-8", "24.5-8", "26.3-8",
            "27.1-8", "28.7-8", "29.8", "34.8", "35.7-8", "32.7", "11.1-8",
        ):
            with self.subTest(address=address):
                self.assertIn(address, found["error"])
        self.assertEqual(found["warning"], ["37.5-8", "38.1-8", "39.2-8"])
        # Negative claims and the bytes of other systems are reported, not faulted.
        self.assertEqual(found["info"], ["14.6", "14.7", "19.1-4", "20.1-8"])

    def test_bytes_past_39_are_rfu(self) -> None:
        clean = tp.decode(tp.maximal() + b"\x00\x00")
        self.assertEqual(clean.findings, ())
        dirty = tp.decode(tp.maximal() + b"\x00\x04")
        self.assertEqual(len(dirty.findings), 1)
        self.assertIn("Byte 41 onwards", dirty.findings[0].text)

    def test_bits_that_serve_one_facility_are_set_together(self) -> None:
        # TS 31.111 V19.4.0 §5.2 NOTE: SMS-PP data download is 1.2 and 1.5.
        self.assertIn("1.5", _findings(b"\x02")["warning"])
        self.assertNotIn("warning", _findings(b"\x12"))
        call_control = tp.build(set_items=("2.2", "1.7", "1.8", "2.3", "2.5"), length=8)
        self.assertIn("8.8", _findings(call_control)["warning"])
        complete = tp.build(call_control, set_items=("8.8",))
        self.assertNotIn("warning", _findings(complete))
        # A profile that stops before byte 8 is not faulted for 8.8; the gap is noted.
        short = tp.decode(call_control[:2])
        noted = [finding for finding in short.findings if finding.address == "8.8"]
        self.assertEqual([finding.severity for finding in noted], ["info"])
        self.assertIn("8.8 past the profile's last byte", noted[0].text)

    def test_dns_server_requests_want_name_reuse(self) -> None:
        # TS 102 223 V18.3.0 §5.2, NOTE under byte 33.
        lacking = tp.build(tp.maximal(), clear_items=("33.2",))
        self.assertEqual(_findings(lacking)["warning"], ["33.2"])

    def test_a_short_profile_reads_its_absent_bytes_as_zero(self) -> None:
        result = tp.decode(b"\xff\x1f\x00\x00\x7f")
        self.assertEqual(result.value("5.5"), 1)
        self.assertEqual(result.value("12.1"), 0)
        self.assertIn("bytes 6-39 are absent", result.findings[-1].text)

    def test_decode_boundaries(self) -> None:
        empty = tp.decode(b"")
        self.assertTrue(all(value == 0 for _, value in empty.values))
        self.assertEqual(empty.findings[-1].text, "Empty profile: no facility is declared.")
        self.assertEqual(tp.decode(b"\x01").value("1.1"), 1)
        for raw in (b"", b"\x80", b"\x80\x10\x00", b"\x80\x10\x00\x00"):
            with self.subTest(raw=raw.hex()):
                profile, notes = tp.split_apdu(raw)
                self.assertEqual(profile, raw)
                tp.decode(profile)
        # A four-byte header stub and an over-claiming Lc are reported and the
        # input is read from its first byte.
        stub, stub_notes = tp.split_apdu(bytes.fromhex("80100000"))
        self.assertEqual(stub, bytes.fromhex("80100000"))
        self.assertIn("has no Lc", stub_notes[0].text)
        over, over_notes = tp.split_apdu(bytes.fromhex("8010000027FFFF"))
        self.assertEqual(over, bytes.fromhex("8010000027FFFF"))
        self.assertEqual(over_notes[0].severity, "warning")
        self.assertIn("Lc '27' (39 bytes) but 2 follow", over_notes[0].text)

    def test_the_apdu_header_comes_off_when_lc_fits(self) -> None:
        for cla in ("80", "A0"):
            with self.subTest(cla=cla):
                profile, notes = tp.split_apdu(bytes.fromhex(f"{cla}10000003FFFFFF"))
                self.assertEqual(profile, b"\xff\xff\xff")
                self.assertEqual(notes[0].severity, "info")
        apdu = tp.terminal_profile_apdu(MAXIMAL_TERMINAL_PROFILE)
        self.assertEqual(tp.split_apdu(apdu)[0], MAXIMAL_TERMINAL_PROFILE)

    def test_hex_input_takes_separators_and_refuses_the_rest(self) -> None:
        self.assertEqual(tp.parse_hex("0xFF 1f:00,7F\n"), bytes.fromhex("FF1F007F"))
        for text, message in (
            ("", "no hex digits"),
            ("FFF", "odd number"),
            ("FG", "not hex"),
        ):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, message):
                    tp.parse_hex(text)


class BuildTests(unittest.TestCase):
    def test_addresses_and_names_resolve(self) -> None:
        self.assertEqual(tp.resolve("13.6-8").address, "13.6-8")
        self.assertEqual(tp.resolve("event: location status").address, "5.5")
        self.assertEqual(tp.resolve("HSDPA").address, "17.8")
        for item, message in (
            ("13.7", "part of 13.6-8"),
            ("40.1", "past byte 39"),
            ("5.9", "bits run b1 to b8"),
            ("no such facility", "no facility matches"),
            # DISPLAY TEXT is named twice word for word, at 2.8 and 9.1.
            ("display text", "2 facilities match"),
        ):
            with self.subTest(item=item):
                with self.assertRaisesRegex(ValueError, message):
                    tp.resolve(item)

    def test_build_sets_clears_and_assigns(self) -> None:
        profile = tp.build(
            set_items=("3.1", "Proactive UICC: SET UP EVENT LIST", "5.5"),
            values=(("13.6-8", 3),),
        )
        self.assertEqual(profile, bytes.fromhex("000001001100000000000000" "60"))
        self.assertEqual(
            tp.build(tp.maximal(), clear_items=("33.1",))[32],
            MAXIMAL_TERMINAL_PROFILE[32] & 0xFE,
        )
        self.assertEqual(tp.build(b"\x01", length=4), b"\x01\x00\x00\x00")

    def test_build_refuses_what_does_not_fit(self) -> None:
        with self.assertRaisesRegex(ValueError, "3-bit field"):
            tp.build(set_items=("13.6-8",))
        with self.assertRaisesRegex(ValueError, "holds 0-7, not 8"):
            tp.build(values=(("13.6-8", 8),))
        with self.assertRaisesRegex(ValueError, "would cut bytes 6-39"):
            tp.build(tp.maximal(), length=5)

    def test_a_zero_coded_bit_can_be_set_on_purpose(self) -> None:
        profile = tp.apply_edits(tp.maximal(), ["+32.7", "11.1-8=0xFF"])
        self.assertEqual(profile[31], 0xFF)
        self.assertEqual(profile[10], 0xFF)
        self.assertIn("32.7", _findings(profile)["error"])

    def test_edit_tokens_apply_in_order(self) -> None:
        profile = tp.apply_edits(b"", ["+5.5", "12.1", "13.6-8=0x2", "-5.5"])
        self.assertEqual(profile, bytes.fromhex("000000000000000000000001" "40"))
        self.assertEqual(tp.apply_edits(b"", ["-5.5", "+5.5"]), bytes.fromhex("0000000010"))

    def test_diff_names_each_changed_facility(self) -> None:
        changed = tp.diff(tp.maximal(), tp.build(tp.maximal(), clear_items=("33.1",)))
        self.assertEqual([(f.address, a, b) for f, a, b in changed], [("33.1", 1, 0)])
        self.assertEqual(
            [f.address for f, _, _ in tp.diff(b"", b"\x00" * 12 + b"\x20")], ["13.6-8"]
        )


class CommandLineTests(unittest.TestCase):
    def _run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = tp.main(list(argv))
        return status, out.getvalue(), err.getvalue()

    def test_decode_prints_each_bit_and_exits_on_errors(self) -> None:
        status, out, _ = self._run("80100000", "03", "FF FF FF")
        self.assertEqual(status, 0)
        self.assertIn("1.1      [x]  Profile download", out)
        self.assertIn("header 8010000003 taken off", out)
        status, out, _ = self._run("decode", "-s", "00" * 31 + "40")
        self.assertEqual(status, 3)
        self.assertIn("32.7", out)
        self.assertNotIn("1.1 ", out)

    def test_the_profile_may_come_from_stdin(self) -> None:
        with mock.patch.object(sys, "stdin", io.StringIO("01 00\n")):
            status, out, _ = self._run()
        self.assertEqual(status, 0)
        self.assertIn("2 bytes", out)

    def test_build_list_and_diff(self) -> None:
        status, out, _ = self._run("build", "--max", "-33.1", "-q")
        self.assertEqual(status, 0)
        self.assertEqual(
            out.strip(), tp.build(tp.maximal(), clear_items=("33.1",)).hex().upper()
        )
        _, out, _ = self._run("build", "+5.5")
        self.assertIn("APDU    801000000500000000" "10", out)
        _, out, _ = self._run("list", "location status")
        self.assertIn("5.5      Event: Location status", out)
        _, out, _ = self._run("diff", "FF", "7F")
        self.assertIn("A 1 byte, B 1 byte: 1 facility differs", out)
        self.assertIn("1.8      A 1    B 0", out)

    def test_errors_go_to_stderr(self) -> None:
        status, out, err = self._run("build", "+13.7")
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        self.assertIn("part of 13.6-8", err)
        status, _, err = self._run("diff", "FF")
        self.assertEqual(status, 1)
        self.assertIn("two profiles", err)

    def test_the_file_runs_alone(self) -> None:
        # The stand-alone copy is this file; -I and a foreign cwd keep the
        # repository off the import path.
        with tempfile.TemporaryDirectory() as folder:
            completed = subprocess.run(
                [sys.executable, "-I", str(_MODULE_PATH), "build", "--max", "-q"],
                cwd=folder,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), MAXIMAL_TERMINAL_PROFILE.hex().upper())


class OfflineToolActionTests(unittest.TestCase):
    """The two Offline Tools cards; output is the GUI's key_value_lines shape."""

    @staticmethod
    def _labels(lines: list[dict]) -> list[str]:
        return [line["label"] for line in lines]

    def test_both_actions_are_offline_tools(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded

        registry = ensure_builtin_actions_loaded()
        for action_id in ("tool.tp.decode", "tool.tp.build"):
            with self.subTest(action_id=action_id):
                spec = registry.get(action_id)
                self.assertEqual(spec.subsystem, "Offline Tools")
                self.assertEqual(spec.output_kind, "key_value_lines")
                self.assertFalse(spec.requires_card)

    def test_decode_lists_bytes_bits_and_findings(self) -> None:
        from yggdrasim_common.gui_server.actions import tools
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        result = tools._dispatch_tp_decode(
            ActionContext(), profile="80 10 00 00 02 FF 1F", show="set",
        )
        self.assertEqual(result["input_length"], 2)
        self.assertEqual(result["detail_lines"][0], {"indent": 0, "label": "Profile", "value": "FF1F"})
        labels = self._labels(result["detail_lines"])
        self.assertIn("Byte 1 (Download)", labels)
        self.assertIn("2.5 Call Control by NAA", labels)
        self.assertNotIn("2.6 UCS2 Entry supported", labels)
        validation = self._labels(result["validation_lines"])
        self.assertIn("info", validation)
        # Two bytes never reach 8.8, so its Call Control by USIM bit is noted, not faulted.
        self.assertIn("info 8.8", validation)
        self.assertNotIn("warning 8.8", validation)

    def test_decode_compares_two_profiles(self) -> None:
        from yggdrasim_common.gui_server.actions import tools
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        lacking = tp.build(tp.maximal(), clear_items=("33.1",)).hex()
        result = tools._dispatch_tp_decode(
            ActionContext(), profile=tp.maximal().hex(), compare=lacking,
        )
        self.assertTrue(result["note"].startswith("1 facility differs between"))
        self.assertEqual(result["detail_lines"][-1]["value"], "1 -> 0")
        self.assertTrue(result["detail_lines"][-1]["label"].startswith("33.1 "))

    def test_build_starts_from_the_chosen_profile(self) -> None:
        from yggdrasim_common.gui_server.actions import tools
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        built = tools._dispatch_tp_build(ActionContext(), base="maximal", clear_items="33.1, 33.2")
        expected = tp.build(tp.maximal(), clear_items=("33.1", "33.2"))
        self.assertEqual(built["detail_lines"][0]["value"], expected.hex().upper())
        self.assertEqual(
            built["detail_lines"][1]["value"], tp.terminal_profile_apdu(expected).hex().upper()
        )
        named = tools._dispatch_tp_build(
            ActionContext(),
            base="empty",
            set_items="Proactive UICC: PROVIDE LOCAL INFORMATION (MCC, MNC, LAC, Cell ID & IMEI)\n5.1, 5.5",
            field_values="13.6-8=2",
            length=20,
        )
        profile = bytes.fromhex(named["detail_lines"][0]["value"])
        self.assertEqual(len(profile), 20)
        self.assertEqual((profile[3], profile[4], profile[12]), (0x40, 0x11, 0x40))
        pasted = tools._dispatch_tp_build(
            ActionContext(), base="pasted", base_profile="8010000001FF", set_items="32.7",
        )
        self.assertEqual(pasted["detail_lines"][0]["value"], "FF00000000000000000000000000000000000000000000000000000000000040")
        self.assertIn("error 32.7", self._labels(pasted["validation_lines"]))

    def test_the_run_route_takes_the_form_as_posted(self) -> None:
        # Every value arrives as a string; the route coerces enum and int fields.
        import asyncio

        from yggdrasim_common.gui_server.routes.actions import RunRequest, run_action

        built = asyncio.run(run_action("tool.tp.build", RunRequest(inputs={
            "base": "empty", "set_items": "5.1\n5.5", "field_values": "", "length": "8",
        })))
        self.assertTrue(built.ok, built.error)
        self.assertEqual(built.data["detail_lines"][0]["value"], "0000000011000000")
        decoded = asyncio.run(run_action("tool.tp.decode", RunRequest(inputs={
            "profile": "80:10:00:00:02:FF:1F", "show": "set",
        })))
        self.assertTrue(decoded.ok, decoded.error)
        self.assertEqual(decoded.data["input_length"], 2)
        refused = asyncio.run(run_action("tool.tp.decode", RunRequest(inputs={"profile": "FFF"})))
        self.assertFalse(refused.ok)
        self.assertIn("odd number of hex digits", refused.error)

    def test_build_refuses_malformed_forms(self) -> None:
        from yggdrasim_common.gui_server.actions import tools
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        for kwargs, message in (
            ({"base": "pasted"}, "base_profile is empty"),
            ({"base": "other"}, "base must be one of"),
            ({"field_values": "13.6-8"}, "is not ADDRESS=VALUE"),
            ({"field_values": "13.6-8=many"}, "is not a number"),
            ({"set_items": "13.6-8"}, "3-bit field"),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ValueError, message):
                    tools._dispatch_tp_build(ActionContext(), **kwargs)


if __name__ == "__main__":
    unittest.main()
