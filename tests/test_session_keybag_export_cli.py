from __future__ import annotations

import io
import json
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
        return

    smartcard_module = types.ModuleType("smartcard")
    system_module = types.ModuleType("smartcard.System")
    card_connection_module = types.ModuleType("smartcard.CardConnection")

    system_module.readers = lambda: []
    card_connection_module.CardConnection = type("CardConnection", (), {})

    smartcard_module.System = system_module
    smartcard_module.CardConnection = card_connection_module

    sys.modules["smartcard"] = smartcard_module
    sys.modules["smartcard.System"] = system_module
    sys.modules["smartcard.CardConnection"] = card_connection_module


_install_smartcard_stubs()


from SCP03.interface.commands import CommandRegistry
from SCP03.interface.shell import ShellDispatcher


_DUMMY_ENC = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
_DUMMY_MAC = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
_DUMMY_RMAC = bytes.fromhex("FFEEDDCCBBAA99887766554433221100")


class _Scp03ShellExportKeybagTests(unittest.TestCase):
    """Covers the ``EXPORT-KEYBAG`` handler in the SCP03 shell."""

    @staticmethod
    def _make_shell(transport) -> ShellDispatcher:
        shell = ShellDispatcher.__new__(ShellDispatcher)
        shell.transport = transport
        shell.gp_ctrl = SimpleNamespace(
            target_aid=bytes.fromhex("A000000151000000"),
        )
        return shell

    def test_registry_exposes_export_keybag_as_optional_argument_command(self) -> None:
        command_map = CommandRegistry.build(SimpleNamespace(
            _handle_export_keybag=lambda *args, **kwargs: None,
            _handle_auth_scp03=lambda *args, **kwargs: None,
            _handle_auth_scp02=lambda *args, **kwargs: None,
            _handle_reset=lambda *args, **kwargs: None,
            _print_card_info=lambda *args, **kwargs: None,
            _print_atr_details=lambda *args, **kwargs: None,
            _handle_keys=lambda *args, **kwargs: None,
            _handle_logout=lambda *args, **kwargs: None,
            _run_scp80_tool=lambda *args, **kwargs: None,
            _run_stk_shell=lambda *args, **kwargs: None,
            _handle_list_profiles=lambda *args, **kwargs: None,
            _handle_profile_scan=lambda *args, **kwargs: None,
            _handle_registry=lambda *args, **kwargs: None,
            _handle_store_data=lambda *args, **kwargs: None,
            _handle_install_wizard=lambda *args, **kwargs: None,
            _handle_scan_tree=lambda *args, **kwargs: None,
            _handle_select=lambda *args, **kwargs: None,
            _handle_read_binary=lambda *args, **kwargs: None,
            _handle_read_record=lambda *args, **kwargs: None,
            _handle_update=lambda *args, **kwargs: None,
            do_dump_fs=lambda *args, **kwargs: None,
            _handle_validate=lambda *args, **kwargs: None,
            _handle_derive_opc=lambda *args, **kwargs: None,
            show_config=lambda *args, **kwargs: None,
            list_aids=lambda *args, **kwargs: None,
            _set_aid_alias=lambda *args, **kwargs: None,
            _set_defaults=lambda *args, **kwargs: None,
            do_manage_binds=lambda *args, **kwargs: None,
            _toggle_debug=lambda *args, **kwargs: None,
            _handle_decode=lambda *args, **kwargs: None,
            _handle_export_euicc=lambda *args, **kwargs: None,
            _handle_set_gold_profile=lambda *args, **kwargs: None,
            _handle_show_gold_profile=lambda *args, **kwargs: None,
            _handle_clear_gold_profile=lambda *args, **kwargs: None,
            _handle_profile_diff=lambda *args, **kwargs: None,
            _handle_arr=lambda *args, **kwargs: None,
            _handle_cert_info=lambda *args, **kwargs: None,
            _handle_guide=lambda *args, **kwargs: None,
            run_script=lambda *args, **kwargs: None,
            _print_help=lambda *args, **kwargs: None,
            _exit=lambda *args, **kwargs: None,
            _quit_all=lambda *args, **kwargs: None,
            gp_ctrl=SimpleNamespace(set_status=lambda *a, **k: None, delete_object=lambda *a, **k: None),
        ))
        self.assertIn("EXPORT-KEYBAG", command_map)
        _required, optional = CommandRegistry.get_arg_requirements()
        self.assertIn("EXPORT-KEYBAG", optional)

    def test_handler_refuses_when_session_missing(self) -> None:
        shell = self._make_shell(transport=None)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            shell._handle_export_keybag("")
        self.assertIn("No active SCP03 session", buffer.getvalue())

    def test_handler_refuses_when_session_unauthenticated(self) -> None:
        transport = SimpleNamespace(session=SimpleNamespace(
            is_authenticated=False,
            s_enc=_DUMMY_ENC,
            s_mac=_DUMMY_MAC,
        ))
        shell = self._make_shell(transport=transport)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            shell._handle_export_keybag("")
        self.assertIn("not authenticated", buffer.getvalue())

    def test_handler_writes_keybag_with_target_aid_match(self) -> None:
        transport = SimpleNamespace(session=SimpleNamespace(
            is_authenticated=True,
            s_enc=_DUMMY_ENC,
            s_mac=_DUMMY_MAC,
            s_rmac=_DUMMY_RMAC,
            ssc=1,
            chaining_value=b"\x00" * 16,
        ))
        shell = self._make_shell(transport=transport)

        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "capture.pcap.keys.json"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                shell._handle_export_keybag(f"{target} ISD-R-SD")

            self.assertTrue(target.exists())
            with target.open("rb") as handle:
                document = json.loads(handle.read().decode("utf-8"))

            self.assertEqual(document["version"], 1)
            sessions = document["sessions"]
            self.assertEqual(len(sessions), 1)
            entry = sessions[0]
            self.assertEqual(entry["label"], "ISD-R-SD")
            self.assertEqual(entry["protocol"], "scp03")
            self.assertEqual(entry["keys"]["s_enc"], _DUMMY_ENC.hex().upper())
            self.assertEqual(entry["keys"]["s_mac"], _DUMMY_MAC.hex().upper())
            self.assertEqual(entry["keys"]["s_rmac"], _DUMMY_RMAC.hex().upper())
            self.assertEqual(entry["match"]["aid"], "A000000151000000")
            self.assertEqual(entry["initial_state"]["ssc"], 1)

    def test_handler_uses_default_output_path_when_no_arg_given(self) -> None:
        transport = SimpleNamespace(session=SimpleNamespace(
            is_authenticated=True,
            s_enc=_DUMMY_ENC,
            s_mac=_DUMMY_MAC,
            s_rmac=b"",
            ssc=0,
            chaining_value=b"\x00" * 16,
        ))
        shell = self._make_shell(transport=transport)

        with tempfile.TemporaryDirectory() as tmp_dir:
            previous_cwd = Path.cwd()
            try:
                import os
                os.chdir(tmp_dir)
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    shell._handle_export_keybag("")
                default_path = Path(tmp_dir) / "scp03_session.keys.json"
                self.assertTrue(default_path.exists())
            finally:
                import os
                os.chdir(str(previous_cwd))


class _Scp11LocalAccessBspSnapshotTests(unittest.TestCase):
    """Covers the local-access BSP snapshot helper on LocalSessionState."""

    def test_snapshot_populates_state_from_bsp_sub_objects(self) -> None:
        from SCP11.local_access.session import LocalIsdrSession, LocalSessionState

        state = LocalSessionState()
        session = SimpleNamespace(
            state=state,
            cfg=SimpleNamespace(AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100")),
        )

        bsp = SimpleNamespace(
            c_algo=SimpleNamespace(s_enc=_DUMMY_ENC, block_nr=3),
            m_algo=SimpleNamespace(
                s_mac=_DUMMY_MAC,
                mac_chain=bytes(range(16)),
            ),
        )

        LocalIsdrSession._snapshot_session_bsp(session, bsp)

        self.assertEqual(state.last_bsp_s_enc_hex, _DUMMY_ENC.hex().upper())
        self.assertEqual(state.last_bsp_s_mac_hex, _DUMMY_MAC.hex().upper())
        self.assertEqual(state.last_bsp_mac_chain_hex, bytes(range(16)).hex().upper())
        self.assertEqual(state.last_bsp_block_nr, 3)
        self.assertEqual(state.last_bsp_protocol, "scp11c")
        self.assertEqual(
            state.last_bsp_aid_hex,
            "A0000005591010FFFFFFFF8900000100",
        )

    def test_snapshot_ignores_empty_bsp_keys(self) -> None:
        from SCP11.local_access.session import LocalIsdrSession, LocalSessionState

        state = LocalSessionState()
        session = SimpleNamespace(
            state=state,
            cfg=SimpleNamespace(AID_ISD_R=b""),
        )

        bsp = SimpleNamespace(
            c_algo=SimpleNamespace(s_enc=b"", block_nr=0),
            m_algo=SimpleNamespace(s_mac=b"", mac_chain=b""),
        )
        LocalIsdrSession._snapshot_session_bsp(session, bsp)

        self.assertEqual(state.last_bsp_s_enc_hex, "")
        self.assertEqual(state.last_bsp_s_mac_hex, "")


class _Scp11LocalAccessExportKeybagCmdTests(unittest.TestCase):
    """Covers the ``EXPORT-KEYBAG`` command in the local-access shell."""

    def test_cmd_refuses_without_bsp_snapshot(self) -> None:
        from SCP11.local_access.main import LocalAccessShell

        shell = LocalAccessShell.__new__(LocalAccessShell)
        shell.session = SimpleNamespace(state=SimpleNamespace(
            last_bsp_s_enc_hex="",
            last_bsp_s_mac_hex="",
            last_bsp_mac_chain_hex="",
            last_bsp_block_nr=0,
            last_bsp_aid_hex="",
        ))

        with self.assertRaises(RuntimeError) as excinfo:
            shell._cmd_export_keybag([])
        self.assertIn("LOAD-PROFILE", str(excinfo.exception))

    def test_cmd_writes_keybag_from_stored_snapshot(self) -> None:
        from SCP11.local_access.main import LocalAccessShell

        shell = LocalAccessShell.__new__(LocalAccessShell)
        shell.session = SimpleNamespace(state=SimpleNamespace(
            last_bsp_s_enc_hex=_DUMMY_ENC.hex().upper(),
            last_bsp_s_mac_hex=_DUMMY_MAC.hex().upper(),
            last_bsp_mac_chain_hex="00" * 16,
            last_bsp_block_nr=2,
            last_bsp_aid_hex="A0000005591010FFFFFFFF8900000100",
        ))

        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "local.keys.json"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                shell._cmd_export_keybag([str(target), "bsp-demo"])

            self.assertTrue(target.exists())
            with target.open("rb") as handle:
                document = json.loads(handle.read().decode("utf-8"))

            sessions = document["sessions"]
            self.assertEqual(len(sessions), 1)
            entry = sessions[0]
            self.assertEqual(entry["label"], "bsp-demo")
            self.assertEqual(entry["protocol"], "scp11c")
            self.assertEqual(entry["keys"]["s_enc"], _DUMMY_ENC.hex().upper())
            self.assertEqual(entry["initial_state"]["ssc"], 2)
            self.assertEqual(
                entry["match"]["aid"],
                "A0000005591010FFFFFFFF8900000100",
            )


class _Scp11LocalAccessDumpKeybagCliTests(unittest.TestCase):
    """Covers the ``--dump-keybag`` command-batch helper."""

    def test_append_preserves_existing_batch(self) -> None:
        from SCP11.local_access.main import _append_keybag_dump_command

        combined = _append_keybag_dump_command(
            "LOAD-PROFILE",
            "/tmp/run one.keys.json",
        )
        self.assertIn("LOAD-PROFILE", combined)
        self.assertIn("EXPORT-KEYBAG", combined)
        self.assertIn("/tmp/run one.keys.json", combined)
        self.assertIn(";", combined)

    def test_append_handles_empty_batch(self) -> None:
        from SCP11.local_access.main import _append_keybag_dump_command

        result = _append_keybag_dump_command("", "session.keys.json")
        self.assertEqual(result, "EXPORT-KEYBAG session.keys.json")

    def test_append_is_noop_without_path(self) -> None:
        from SCP11.local_access.main import _append_keybag_dump_command

        self.assertEqual(
            _append_keybag_dump_command("LOAD-PROFILE", ""),
            "LOAD-PROFILE",
        )


if __name__ == "__main__":
    unittest.main()
