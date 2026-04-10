import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP03.config import Config
from SCP03.logic.fs import FileSystemController


class _NoopTransport:
    def transmit(self, cmd: str, silent: bool = False):
        del cmd
        del silent
        return b"", 0x6A, 0x82


class _EfDirFallbackTransport:
    def __init__(
        self,
        legacy_aid: str,
        discovered_aid: str,
        label_text: str = "USIM",
    ) -> None:
        self.legacy_aid = legacy_aid
        self.discovered_aid = discovered_aid
        self.label_text = label_text
        self.calls: list[str] = []

    def _dir_record(self, aid_hex: str) -> bytes:
        aid = bytes.fromhex(aid_hex)
        label = self.label_text.encode("ascii")
        inner = b"\x4F" + bytes([len(aid)]) + aid + b"\x50" + bytes([len(label)]) + label
        return b"\x61" + bytes([len(inner)]) + inner + (b"\xFF" * 6)

    def transmit(self, cmd: str, silent: bool = False):
        del silent
        command = str(cmd or "").strip().upper()
        self.calls.append(command)

        legacy_select = f"00A40400{len(self.legacy_aid)//2:02X}{self.legacy_aid}"
        discovered_select = (
            f"00A40400{len(self.discovered_aid)//2:02X}{self.discovered_aid}"
        )

        if command == "00A40004023F00":
            return b"", 0x90, 0x00
        if command in ("00A40004027FF0", "00A40004027FFF"):
            return b"", 0x6A, 0x82
        if command == legacy_select:
            return b"", 0x6A, 0x82
        if command == "00A40004022F00":
            return b"", 0x90, 0x00
        if command == "00B2010400":
            return self._dir_record(self.discovered_aid), 0x90, 0x00
        if command == "00B2020400":
            return b"", 0x6A, 0x83
        if command == discovered_select:
            return bytes.fromhex(f"6F148410{self.discovered_aid}A500"), 0x90, 0x00
        if command == "00A40004026F07":
            return bytes.fromhex("6206820101800109"), 0x90, 0x00
        return b"", 0x6A, 0x82


class _ScanTreeEfDirTransport:
    session = None

    def __init__(self, discovered_aid: str, label_text: str) -> None:
        self.discovered_aid = discovered_aid
        self.label_text = label_text
        self.calls: list[str] = []

    def reset(self) -> bool:
        return True

    def _dir_record(self) -> bytes:
        aid = bytes.fromhex(self.discovered_aid)
        label = self.label_text.encode("ascii")
        inner = b"\x4F" + bytes([len(aid)]) + aid + b"\x50" + bytes([len(label)]) + label
        return b"\x61" + bytes([len(inner)]) + inner + (b"\xFF" * 8)

    def transmit(self, cmd: str, silent: bool = False):
        del silent
        command = str(cmd or "").strip().upper()
        self.calls.append(command)

        discovered_select = (
            f"00A40400{len(self.discovered_aid)//2:02X}{self.discovered_aid}"
        )

        if command == "00A40004023F00":
            return bytes.fromhex("6202820138"), 0x90, 0x00
        if command == "00A40004022F00":
            return bytes.fromhex("620682054221002602"), 0x90, 0x00
        if command == "00B2010400":
            return self._dir_record(), 0x90, 0x00
        if command == "00B2020400":
            return b"", 0x6A, 0x83
        if command == discovered_select:
            return bytes.fromhex(f"6F148410{self.discovered_aid}A500"), 0x90, 0x00
        if command == "00A40004026F07":
            return bytes.fromhex("6206820101800109"), 0x90, 0x00
        if command.startswith("00A40400"):
            return b"", 0x6A, 0x82
        if command.startswith("00A4000402"):
            return b"", 0x6A, 0x82
        return b"", 0x6A, 0x82


class _WildcardReportTransport:
    session = None

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.selected = ""

    def reset(self) -> bool:
        return True

    def transmit(self, cmd: str, silent: bool = False):
        del silent
        command = str(cmd or "").strip().upper()
        self.calls.append(command)

        if command == "00A40004023F00":
            self.selected = "3F00"
            return bytes.fromhex("6202820138"), 0x90, 0x00
        if command == "00A40004027FF0":
            self.selected = "7FF0"
            return bytes.fromhex("6202820138"), 0x90, 0x00
        if command == "00A40004026F99":
            self.selected = "6F99"
            return bytes.fromhex("6206820101800101"), 0x90, 0x00
        if command.startswith("00A40004026F"):
            return b"", 0x6A, 0x82
        if command == "00B0000000" and self.selected == "6F99":
            return b"\xAB", 0x90, 0x00
        return b"", 0x6A, 0x82


class FileSystemControllerAdfFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self._fids_path = Path(self._temp_dir.name) / "fids.txt"
        self._fids_path.write_text(
            "USIM:7FF0:7FFF:A0000000871002FF34FF0789312E30FF\n"
            " EF_IMSI:6F07\n"
            "ISIM:7FF2:A0000000871004FF34FF0789312E30FF\n"
            "CSIM:7FF3:A0000000684353494D\n",
            encoding="utf-8",
        )
        self._fids_patch = mock.patch.object(Config, "FIDS_FILE", str(self._fids_path))
        self._fids_patch.start()
        self.addCleanup(self._fids_patch.stop)

    def _legacy_usim_aid(self) -> str:
        controller = FileSystemController(_NoopTransport(), aid_registry={})
        candidates = controller.fid_map.get("USIM", [])
        for candidate in candidates:
            if len(str(candidate)) > 4:
                return str(candidate).upper()
        raise AssertionError("Expected a long USIM AID candidate in the SCP03 FID map.")

    def test_fid_map_mirrors_application_aids_to_adf_aliases(self) -> None:
        controller = FileSystemController(_NoopTransport(), aid_registry={})

        for base_name, adf_name in (
            ("USIM", "ADF_USIM"),
            ("ISIM", "ADF_ISIM"),
            ("CSIM", "ADF_CSIM"),
        ):
            with self.subTest(base_name=base_name):
                base_candidates = controller.fid_map.get(base_name, [])
                adf_candidates = controller.fid_map.get(adf_name, [])
                long_candidates = [value for value in base_candidates if len(str(value)) > 4]

                self.assertTrue(long_candidates)
                for candidate in long_candidates:
                    self.assertIn(candidate, adf_candidates)

    def test_select_path_recovers_adf_from_ef_dir_and_caches_aliases(self) -> None:
        legacy_aid = self._legacy_usim_aid()
        discovered_aid = "A0000000871002FF86FF112233445566"
        aid_registry: dict[str, str] = {}
        transport = _EfDirFallbackTransport(
            legacy_aid,
            discovered_aid,
            label_text="Tele2 USIM",
        )
        controller = FileSystemController(transport, aid_registry=aid_registry)

        selected = controller.select("ADF_USIM/EF_IMSI", silent=True)

        self.assertTrue(selected)
        self.assertEqual(controller.current_fid, "6F07")
        self.assertEqual(aid_registry.get("USIM"), discovered_aid)
        self.assertEqual(aid_registry.get("ADF_USIM"), discovered_aid)
        self.assertIn(
            f"00A40400{len(legacy_aid)//2:02X}{legacy_aid}",
            transport.calls,
        )
        self.assertEqual(transport.calls.count("00A40004022F00"), 1)

        selected_again = controller.select("ADF_USIM", silent=True)

        self.assertTrue(selected_again)
        self.assertEqual(transport.calls.count("00A40004022F00"), 1)

    def test_select_path_recovers_ssim_from_ef_dir_label_occurrence(self) -> None:
        legacy_aid = self._legacy_usim_aid()
        discovered_aid = "A0000001515353494D11223344556677"
        aid_registry: dict[str, str] = {}
        transport = _EfDirFallbackTransport(
            legacy_aid,
            discovered_aid,
            label_text="Orbit SSIM",
        )
        controller = FileSystemController(transport, aid_registry=aid_registry)

        selected = controller.select("SSIM/EF_IMSI", silent=True)

        self.assertTrue(selected)
        self.assertEqual(controller.current_fid, "6F07")
        self.assertEqual(aid_registry.get("SSIM"), discovered_aid)
        self.assertEqual(aid_registry.get("ADF_SSIM"), discovered_aid)
        self.assertEqual(transport.calls.count("00A40004022F00"), 1)

    def test_select_recovers_from_stale_adf_alias_using_ef_dir(self) -> None:
        legacy_aid = self._legacy_usim_aid()
        discovered_aid = "A0000000871002FF86FF112233445566"
        stale_aid = "A0000000871002FF0000000000000000"
        aid_registry = {"ADF_USIM": stale_aid}
        transport = _EfDirFallbackTransport(legacy_aid, discovered_aid)
        controller = FileSystemController(transport, aid_registry=aid_registry)

        selected = controller.select("ADF_USIM", silent=True)

        self.assertTrue(selected)
        self.assertEqual(aid_registry.get("ADF_USIM"), discovered_aid)
        self.assertIn(
            f"00A40400{len(stale_aid)//2:02X}{stale_aid}",
            transport.calls,
        )
        self.assertEqual(transport.calls.count("00A40004022F00"), 1)

    def test_scan_tree_uses_live_ef_dir_aid_for_usim_and_keeps_alias_paths(self) -> None:
        discovered_aid = "A0000000871002FF86FF112233445566"
        transport = _ScanTreeEfDirTransport(discovered_aid, "Tele2 USIM")
        controller = FileSystemController(transport, aid_registry={})

        rendered = io.StringIO()
        with contextlib.redirect_stdout(rendered):
            controller.scan_tree()

        output = rendered.getvalue()
        self.assertIn("USIM [Tele2 USIM]", output)
        self.assertIn(f"({discovered_aid})", output)
        self.assertIn("EF_IMSI", output)
        self.assertIn("USIM", controller.scan_cache.values())
        self.assertIn("USIM/EF_IMSI", controller.scan_cache.values())
        self.assertEqual(controller.aid_registry.get("USIM"), discovered_aid)
        self.assertFalse(any(command.startswith("00A40404") for command in transport.calls))

    def test_scan_tree_injects_missing_ssim_root_from_ef_dir(self) -> None:
        discovered_aid = "A0000001515353494D11223344556677"
        transport = _ScanTreeEfDirTransport(discovered_aid, "Orbit SSIM")
        controller = FileSystemController(transport, aid_registry={})

        rendered = io.StringIO()
        with contextlib.redirect_stdout(rendered):
            controller.scan_tree()

        output = rendered.getvalue()
        self.assertIn("SSIM [Orbit SSIM]", output)
        self.assertIn(f"({discovered_aid})", output)
        self.assertIn("SSIM", controller.scan_cache.values())
        self.assertEqual(controller.aid_registry.get("SSIM"), discovered_aid)

    def test_scan_tree_persists_live_ef_dir_aid_candidate_to_fids_registry(self) -> None:
        discovered_aid = "A0000000871002FF86FF112233445566"
        transport = _ScanTreeEfDirTransport(discovered_aid, "Tele2 USIM")

        with tempfile.TemporaryDirectory() as temp_dir:
            fids_path = Path(temp_dir) / "fids.txt"
            fids_path.write_text("USIM:7FF0:7FFF\n EF_IMSI:6F07\n", encoding="utf-8")

            with mock.patch.object(Config, "FIDS_FILE", str(fids_path)):
                controller = FileSystemController(transport, aid_registry={})
                with contextlib.redirect_stdout(io.StringIO()):
                    controller.scan_tree()

            persisted = fids_path.read_text(encoding="utf-8")

        self.assertIn(f"USIM:7FF0:7FFF:{discovered_aid}", persisted)

    def test_scan_tree_persists_missing_ssim_root_to_fids_registry(self) -> None:
        discovered_aid = "A0000001515353494D11223344556677"
        transport = _ScanTreeEfDirTransport(discovered_aid, "Orbit SSIM")

        with tempfile.TemporaryDirectory() as temp_dir:
            fids_path = Path(temp_dir) / "fids.txt"
            fids_path.write_text("USIM:7FF0:7FFF\n EF_IMSI:6F07\n", encoding="utf-8")

            with mock.patch.object(Config, "FIDS_FILE", str(fids_path)):
                controller = FileSystemController(transport, aid_registry={})
                with contextlib.redirect_stdout(io.StringIO()):
                    controller.scan_tree()

            persisted = fids_path.read_text(encoding="utf-8")

        self.assertIn(f"SSIM:{discovered_aid}", persisted)

    def test_generate_report_persists_new_wildcard_fid_to_fids_registry(self) -> None:
        transport = _WildcardReportTransport()

        with tempfile.TemporaryDirectory() as temp_dir:
            fids_path = Path(temp_dir) / "fids.txt"
            report_path = Path(temp_dir) / "report.yaml"
            fids_path.write_text("USIM:7FF0\n EF_UNKNOWN:6Fxx\n", encoding="utf-8")

            with mock.patch.object(Config, "FIDS_FILE", str(fids_path)):
                controller = FileSystemController(transport, aid_registry={})
                with contextlib.redirect_stdout(io.StringIO()):
                    controller.generate_report(str(report_path))

            persisted = fids_path.read_text(encoding="utf-8")
            report_exists = report_path.exists()

        self.assertIn("EF_6F99:6F99", persisted)
        self.assertTrue(report_exists)


if __name__ == "__main__":
    unittest.main()
