# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import asyncio
import io
import json
import sys
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from yggdrasim_common import frozen_dispatch


@contextmanager
def _frozen_runtime(root: Path):
    executable = root / "yggdrasim-gui-full"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.touch()
    with (
        mock.patch.object(sys, "frozen", True, create=True),
        mock.patch.object(sys, "_MEIPASS", str(root), create=True),
        mock.patch.object(sys, "executable", str(executable)),
    ):
        yield executable


def _assert_internal(
    command: list[str],
    executable: Path,
    entry_id: str,
) -> None:
    assert command[:4] == [
        str(executable),
        frozen_dispatch.INTERNAL_ENTRY_FLAG,
        entry_id,
        frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
    ]
    assert "-m" not in command[:4]
    assert "-c" not in command[:4]


def _write_minimal_saip_profile(path: Path) -> None:
    from pySim.esim.saip import (
        ProfileElementEnd,
        ProfileElementHeader,
        ProfileElementMF,
        ProfileElementSequence,
    )

    sequence = ProfileElementSequence()
    sequence.append(ProfileElementHeader())
    sequence.append(ProfileElementMF())
    sequence.append(ProfileElementEnd())
    path.write_bytes(sequence.to_der())


def _write_realistic_saip_profile(path: Path) -> bytes:
    from pySim.esim.saip import ProfileElementApplication
    from Tools.ProfilePackage.saip_json_codec import (
        build_profile_sequence_from_document,
    )

    repository_root = Path(__file__).resolve().parents[1]
    fixture_path = (
        repository_root
        / "Tools"
        / "ProfilePackage"
        / "transcode"
        / "example_test_profile.transcode.json"
    )
    document = json.loads(fixture_path.read_text(encoding="utf-8"))
    retained_sections = {
        key: document["sections"][key]
        for key in ("header", "mf", "usim", "securityDomain", "rfm", "end")
    }
    sequence = build_profile_sequence_from_document(
        {
            "intro": ["SAIP adapter parity fixture"],
            "sections": retained_sections,
        },
        repository_root,
    )
    sequence.get_pe_for_type("header").decoded["eUICC-Mandatory-services"] = {
        "usim": None,
        "javacard": None,
    }

    def empty_component(tag: int) -> bytes:
        return bytes((tag, 0, 0))

    load_object = (
        bytes.fromhex("010011DECAFFED020200010007A0000000620301")
        + empty_component(2)
        + empty_component(4)
        + bytes.fromhex("03000B0107A00000006203010000")
        + empty_component(6)
        + empty_component(7)
        + empty_component(8)
        + empty_component(5)
        + empty_component(9)
        + empty_component(11)
    )
    application = ProfileElementApplication(pe_sequence=sequence)
    application.decoded["loadBlock"] = {
        "loadPackageAID": bytes.fromhex("A0000000620301"),
        "securityDomainAID": bytes.fromhex("A000000151000000"),
        "loadBlockObject": load_object,
    }
    application.add_instance(
        aid="A0000000620301",
        class_aid="A000000062030101",
        inst_aid="A00000006203010101",
        app_privileges="00",
        app_spec_pars="",
        process_data=[],
    )
    sequence.insert_at_index(len(sequence.pe_list) - 1, application)
    path.write_bytes(sequence.to_der())
    return load_object


def test_source_module_command_still_uses_resolved_python() -> None:
    with mock.patch.object(sys, "frozen", False, create=True):
        command = frozen_dispatch.build_module_command(
            "Tools.ProfilePackage",
            ["--cmd", "EXIT"],
        )

    assert Path(command[0]).is_file()
    assert command[1:] == [
        "-m",
        "Tools.ProfilePackage",
        "--cmd",
        "EXIT",
    ]


def test_frozen_module_command_uses_allowlisted_application_reentry(
    tmp_path: Path,
) -> None:
    with _frozen_runtime(tmp_path) as executable:
        command = frozen_dispatch.build_module_command(
            "Tools.ProfilePackage",
            ["--cmd", "EXIT"],
        )

    _assert_internal(command, executable, "profile-package")
    assert command[4:] == ["--cmd", "EXIT"]


def test_gui_frozen_children_prefer_executable_console_companion(
    tmp_path: Path,
) -> None:
    with _frozen_runtime(tmp_path) as gui_executable:
        cli_executable = tmp_path / "yggdrasim-full"
        cli_executable.touch(mode=0o700)
        command = frozen_dispatch.build_module_command("SCP03")
        assert command[0] == str(cli_executable)

        with mock.patch.object(sys, "executable", str(cli_executable)):
            nested_command = frozen_dispatch.build_module_command("SCP03")
        assert nested_command[0] == str(cli_executable)

        cli_executable.chmod(0o600)
        fallback_command = frozen_dispatch.build_module_command("SCP03")
        assert fallback_command[0] == str(gui_executable)


def test_unknown_module_and_internal_entry_are_rejected(tmp_path: Path) -> None:
    with _frozen_runtime(tmp_path):
        with mock.patch.object(
            frozen_dispatch.importlib,
            "import_module",
            side_effect=AssertionError("must not import attacker-selected module"),
        ) as importer:
            with mock.patch.object(sys, "argv", ["unchanged"]):
                error_output = io.StringIO()
                result = frozen_dispatch.dispatch_internal_entry(
                    [
                        frozen_dispatch.INTERNAL_ENTRY_FLAG,
                        "module:http.server",
                        frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
                    ],
                    stderr=error_output,
                )
            assert result == 3
            assert "not allow-listed" in error_output.getvalue()
            importer.assert_not_called()

        try:
            frozen_dispatch.build_module_command("http.server")
        except ValueError as error:
            assert "not available" in str(error)
        else:  # pragma: no cover - assertion clarity
            raise AssertionError("unknown frozen module was accepted")


def test_malformed_dispatch_recovers_missing_windowed_streams() -> None:
    class _NonClosingText(io.StringIO):
        def close(self) -> None:
            self.flush()

    streams = {
        0: _NonClosingText(),
        1: _NonClosingText(),
        2: _NonClosingText(),
    }

    def _open_stream(target, *_args, **_kwargs):
        return streams[int(target)]

    with (
        mock.patch("builtins.open", side_effect=_open_stream),
        mock.patch.object(sys, "stdin", None),
        mock.patch.object(sys, "stdout", None),
        mock.patch.object(sys, "stderr", None),
    ):
        result = frozen_dispatch.dispatch_internal_entry(
            [
                frozen_dispatch.INTERNAL_ENTRY_FLAG,
                "cli-scp03",
                "missing-separator",
            ]
        )
        assert sys.stdin is None
        assert sys.stdout is None
        assert sys.stderr is None

    assert result == 3
    assert "malformed internal-entry command" in streams[2].getvalue()


def test_mapped_callable_drift_returns_controlled_error() -> None:
    stderr = io.StringIO()
    with mock.patch.object(
        frozen_dispatch.importlib,
        "import_module",
        return_value=SimpleNamespace(),
    ):
        result = frozen_dispatch.dispatch_internal_entry(
            [
                frozen_dispatch.INTERNAL_ENTRY_FLAG,
                "cli-scp03",
                frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
            ],
            stderr=stderr,
        )

    assert result == 3
    assert "AttributeError" in stderr.getvalue()


def test_dispatch_rejects_nul_argument_count_and_payload_limits() -> None:
    rejected_arguments = [
        (["\x00"], "NUL"),
        (
            ["x"] * (frozen_dispatch._MAX_INTERNAL_ARGUMENTS + 1),
            "too many child arguments",
        ),
        (
            ["x" * (frozen_dispatch._MAX_INTERNAL_ARGUMENT_CHARS + 1)],
            "payload is too large",
        ),
    ]
    with mock.patch.object(
        frozen_dispatch.importlib,
        "import_module",
        side_effect=AssertionError("rejected arguments must not be dispatched"),
    ) as importer:
        for child_arguments, expected_error in rejected_arguments:
            stderr = io.StringIO()
            result = frozen_dispatch.dispatch_internal_entry(
                [
                    frozen_dispatch.INTERNAL_ENTRY_FLAG,
                    "cli-scp03",
                    frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
                    *child_arguments,
                ],
                stderr=stderr,
            )
            assert result == 3
            assert expected_error in stderr.getvalue()
    importer.assert_not_called()


def test_tk_picker_destroy_failure_is_controlled_and_restores_argv(
    tmp_path: Path,
) -> None:
    class _Root:
        def withdraw(self) -> None:
            return None

        def update(self) -> None:
            return None

        def destroy(self) -> None:
            raise RuntimeError("destroy failed")

    fake_filedialog = SimpleNamespace(askopenfilename=lambda **_kwargs: "")
    fake_tkinter = SimpleNamespace(Tk=_Root, filedialog=fake_filedialog)
    previous_argv = ["outer", "--kept"]
    stderr = io.StringIO()
    with (
        mock.patch.dict(sys.modules, {"tkinter": fake_tkinter}),
        mock.patch.object(sys, "argv", list(previous_argv)),
    ):
        result = frozen_dispatch.dispatch_internal_entry(
            [
                frozen_dispatch.INTERNAL_ENTRY_FLAG,
                "tk-open-file",
                frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
                "Open profile",
                str(tmp_path),
                "Profiles",
                "*.der",
            ],
            stderr=stderr,
        )
        assert sys.argv == previous_argv

    assert result == 3
    assert "destroy failed" in stderr.getvalue()


def test_dispatch_invokes_only_mapped_callable_and_restores_argv() -> None:
    observed_argv: list[str] = []

    def _entry() -> int:
        observed_argv.extend(sys.argv)
        return 7

    fake_module = SimpleNamespace(run_standalone=_entry)
    previous_argv = ["outer", "--kept"]
    with (
        mock.patch.object(
            frozen_dispatch.importlib,
            "import_module",
            return_value=fake_module,
        ) as importer,
        mock.patch.object(sys, "argv", list(previous_argv)),
    ):
        result = frozen_dispatch.dispatch_internal_entry(
            [
                frozen_dispatch.INTERNAL_ENTRY_FLAG,
                "cli-scp03",
                frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
                "--cmd",
                "LIST",
            ]
        )
        assert sys.argv == previous_argv

    assert result == 7
    assert observed_argv == ["SCP03", "--cmd", "LIST"]
    importer.assert_called_once_with("SCP03.main")


def test_tk_picker_uses_fixed_internal_capability_when_frozen(
    tmp_path: Path,
) -> None:
    with _frozen_runtime(tmp_path) as executable:
        command = frozen_dispatch.build_tk_file_picker_command(
            title="Open capture",
            initial_directory=tmp_path,
            file_filter_label="Capture files",
            file_filter_glob="*.pcap *.pcapng",
        )

    _assert_internal(command, executable, "tk-open-file")
    assert command[4:] == [
        "Open capture",
        str(tmp_path),
        "Capture files",
        "*.pcap *.pcapng",
    ]


def test_pysim_script_path_is_not_forwarded_by_frozen_command(
    tmp_path: Path,
) -> None:
    script = tmp_path / "pysim" / "contrib" / "saip-tool.py"
    script.parent.mkdir(parents=True)
    script.write_text("raise AssertionError('not run by command builder')\n")

    with _frozen_runtime(tmp_path) as executable:
        command = frozen_dispatch.build_pysim_saip_tool_command(script)

    _assert_internal(command, executable, "profile-saip-tool")
    assert command[4:] == []
    assert str(script) not in command


def test_profile_tool_rejects_legacy_frozen_app_as_interpreter(
    tmp_path: Path,
) -> None:
    from Tools.ProfilePackage.saip_tool import SaipToolBridge

    with _frozen_runtime(tmp_path) as executable:
        bridge = SaipToolBridge(
            workspace_root=tmp_path,
            tool_command=[str(executable), "-c", "print('unsafe')"],
        )
        try:
            bridge.get_tool_command()
        except ValueError as error:
            assert "cannot be configured as a Python interpreter" in str(error)
        else:  # pragma: no cover - assertion clarity
            raise AssertionError("legacy frozen Python command was accepted")


def test_profile_tool_override_uses_windows_command_line_rules(
    tmp_path: Path,
) -> None:
    from Tools.ProfilePackage import saip_tool

    bridge = saip_tool.SaipToolBridge(workspace_root=tmp_path)
    with mock.patch.object(saip_tool.sys, "platform", "win32"):
        assert bridge.set_tool_command(
            r"C:\Program Files\Vendor\saip-tool.exe --debug"
        ) == [
            r"C:\Program Files\Vendor\saip-tool.exe",
            "--debug",
        ]
        assert bridge.set_tool_command(
            r'"C:\Program Files\Vendor\saip-tool.exe" '
            r'--label "operator profile" --root "C:\Profiles\Example"'
        ) == [
            r"C:\Program Files\Vendor\saip-tool.exe",
            "--label",
            "operator profile",
            "--root",
            r"C:\Profiles\Example",
        ]

        bridge._tool_command = None
        with mock.patch.dict(
            "os.environ",
            {
                "YGGDRASIM_SAIP_TOOL": (
                    r'"C:\Program Files\Vendor\saip-tool.exe" --mode "full export"'
                )
            },
        ):
            assert bridge.get_tool_command() == [
                r"C:\Program Files\Vendor\saip-tool.exe",
                "--mode",
                "full export",
            ]


def test_profile_tool_rejects_frozen_launcher_alias_as_interpreter(
    tmp_path: Path,
) -> None:
    from Tools.ProfilePackage.saip_tool import SaipToolBridge

    with _frozen_runtime(tmp_path) as executable:
        alias = tmp_path / "python3"
        alias.hardlink_to(executable)
        bridge = SaipToolBridge(
            workspace_root=tmp_path,
            tool_command=[str(alias), "-m", "http.server"],
        )
        try:
            bridge.get_tool_command()
        except ValueError as error:
            assert "cannot be configured as a Python interpreter" in str(error)
        else:  # pragma: no cover - assertion clarity
            raise AssertionError("aliased frozen Python command was accepted")


def test_cli_and_gui_entrypoints_short_circuit_internal_dispatch() -> None:
    from main import gui
    from main import main as cli_main

    with (
        mock.patch.object(gui, "dispatch_internal_entry", return_value=19),
        mock.patch.object(
            gui,
            "_load_run_cli",
            side_effect=AssertionError("normal GUI parser must not run"),
        ),
    ):
        assert gui.main([frozen_dispatch.INTERNAL_ENTRY_FLAG]) == 19

    with (
        mock.patch.object(cli_main, "dispatch_internal_entry", return_value=23),
        mock.patch.object(
            cli_main,
            "_build_cli_parser",
            side_effect=AssertionError("normal CLI parser must not run"),
        ),
    ):
        assert cli_main.run_cli([frozen_dispatch.INTERNAL_ENTRY_FLAG]) == 23


def test_terminal_uses_frozen_module_builder(tmp_path: Path) -> None:
    from yggdrasim_common.gui_server import terminal

    spec = terminal.PtyStartSpec(module="SCP03")
    session = terminal.PtySession()
    with (
        _frozen_runtime(tmp_path) as executable,
        mock.patch("pty.fork", return_value=(1234, 55)),
        mock.patch.object(terminal, "_set_nonblocking"),
        mock.patch.object(session, "resize"),
        mock.patch.object(
            terminal,
            "build_module_command",
            wraps=frozen_dispatch.build_module_command,
        ) as builder,
    ):
        asyncio.run(session.spawn(spec))

    builder.assert_called_once_with("SCP03", ())
    command = frozen_dispatch.build_module_command
    with _frozen_runtime(tmp_path):
        built = command("SCP03")
    _assert_internal(built, executable, "cli-scp03")


def test_hil_service_and_supervisor_use_frozen_dispatch(tmp_path: Path) -> None:
    from Tools.HilBridge.router import BridgeConfig
    from Tools.HilBridge.supervisor import (
        HilBridgeSupervisor,
        HilBridgeSupervisorConfig,
        RemsimClientConfig,
    )
    from yggdrasim_common import hil_bridge_runtime

    class _IdleMonitor:
        def snapshot(self):
            raise AssertionError("not needed")

        def wait_for_change(self, timeout_seconds: float) -> None:
            del timeout_seconds

    with _frozen_runtime(tmp_path) as executable:
        options = hil_bridge_runtime.HilBridgeUserServiceOptions(
            python_executable="/usr/bin/python3",
            working_directory=str(tmp_path),
        )
        unit = hil_bridge_runtime.render_user_service_unit(options)
        supervisor = HilBridgeSupervisor(
            config=HilBridgeSupervisorConfig(
                bridge=BridgeConfig(),
                remsim_client=RemsimClientConfig(enabled=False),
                bridge_python="/usr/bin/python3",
            ),
            usb_monitor=_IdleMonitor(),
        )
        command = supervisor._build_bridge_command()

    assert (
        f"ExecStart={executable} {frozen_dispatch.INTERNAL_ENTRY_FLAG} "
        f"hil-supervisor {frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR}"
    ) in unit
    assert " -m " not in unit
    _assert_internal(command, executable, "hil-bridge")


def test_gui_hil_actions_use_frozen_dispatch(tmp_path: Path) -> None:
    from yggdrasim_common.gui_server.actions import hil
    from yggdrasim_common.gui_server.actions.registry import ActionContext

    launched: list[list[str]] = []

    class _Process:
        pid = 1234

    def _popen(command, **_kwargs):
        launched.append(list(command))
        return _Process()

    with (
        _frozen_runtime(tmp_path) as executable,
        mock.patch.object(hil.subprocess, "Popen", side_effect=_popen),
    ):
        assert hil._dispatch_bridge_launch(ActionContext(), confirm=True)["ok"]
        assert hil._dispatch_supervisor_launch(ActionContext(), confirm=True)["ok"]

    _assert_internal(launched[0], executable, "hil-bridge")
    _assert_internal(launched[1], executable, "hil-supervisor")


def test_gui_card_bridge_launch_uses_frozen_dispatch(tmp_path: Path) -> None:
    from yggdrasim_common.gui_server.actions import card_bridge
    from yggdrasim_common.gui_server.actions.registry import ActionContext

    launched: list[str] = []

    class _Process:
        pid = 4321

        @staticmethod
        def poll():
            return None

    def _popen(command, **_kwargs):
        launched.extend(command)
        return _Process()

    state_path = tmp_path / "card_bridge_state.json"
    with (
        _frozen_runtime(tmp_path) as executable,
        mock.patch.object(
            card_bridge,
            "_remote_rig_state_path",
            return_value=str(state_path),
        ),
        mock.patch.object(card_bridge, "_load_remote_rig_state", return_value={}),
        mock.patch.object(card_bridge, "_write_remote_rig_state"),
        mock.patch.object(card_bridge, "_pid_is_running", return_value=False),
        mock.patch.object(card_bridge.subprocess, "Popen", side_effect=_popen),
        mock.patch.object(card_bridge.time, "sleep"),
    ):
        result = card_bridge._dispatch_local_start(
            ActionContext(),
            port=8642,
            reader_index=0,
            confirm=True,
        )

    assert result["ok"]
    _assert_internal(launched, executable, "card-bridge")
    assert card_bridge._cmdline_is_card_bridge(launched)


def test_profile_tool_simcard_watch_and_pickers_use_frozen_dispatch(
    tmp_path: Path,
) -> None:
    from Tools.HilBridge import live_decode_tui
    from Tools.ProfilePackage import saip_tool, simcard_watch

    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    profile = profile_dir / "demo.der"
    profile.write_bytes(b"\x00")
    arrival = simcard_watch.ProfileArrival(
        iccid="8988000000000000001",
        profile_dir=profile_dir,
        manifest_path=None,
        profile_image_path=profile,
    )

    captured_picker_commands: list[list[str]] = []

    def _capture_picker(command):
        captured_picker_commands.append(list(command))
        return None

    with (
        _frozen_runtime(tmp_path) as executable,
        mock.patch.object(saip_tool.shutil, "which", return_value=None),
        mock.patch.object(
            saip_tool,
            "_run_file_picker_command",
            side_effect=_capture_picker,
        ),
        mock.patch.object(
            live_decode_tui.shutil,
            "which",
            return_value=None,
        ),
        mock.patch.object(
            live_decode_tui,
            "_run_capture_picker_command",
            side_effect=_capture_picker,
        ),
        mock.patch.dict(
            "os.environ",
            {"DISPLAY": ":0"},
            clear=False,
        ),
    ):
        bridge = saip_tool.SaipToolBridge(
            workspace_root=tmp_path,
            bundle_root_path=tmp_path,
        )
        tool_command = bridge.get_tool_command()
        watch_command = simcard_watch._build_default_tui_command(arrival)
        assert (
            saip_tool._pick_existing_file_path(
                title="Open profile",
                initial_directory=profile_dir,
                file_filter_label="Profiles",
                file_filter_glob="*.der",
            )
            is None
        )
        assert (
            live_decode_tui.pick_capture_file_path(
                str(profile),
                str(profile_dir),
            )
            is None
        )

    _assert_internal(tool_command, executable, "profile-saip-tool")
    _assert_internal(watch_command, executable, "profile-package")
    _assert_internal(captured_picker_commands[0], executable, "tk-open-file")
    _assert_internal(captured_picker_commands[1], executable, "tk-open-file")


def test_frozen_simcard_custom_python_template_rejects_arbitrary_module(
    tmp_path: Path,
) -> None:
    from Tools.ProfilePackage import simcard_watch

    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    profile = profile_dir / "demo.der"
    profile.write_bytes(b"\x00")
    arrival = simcard_watch.ProfileArrival(
        iccid="8988000000000000001",
        profile_dir=profile_dir,
        manifest_path=None,
        profile_image_path=profile,
    )

    with _frozen_runtime(tmp_path):
        with mock.patch.object(
            simcard_watch.shutil,
            "which",
            return_value=None,
        ):
            rejected = simcard_watch._expand_launcher_template(
                "{python} -m http.server",
                arrival,
            )
            accepted = simcard_watch._expand_launcher_template(
                "{python} -m Tools.ProfilePackage --cmd EXIT",
                arrival,
            )

    assert rejected == []
    assert accepted[1:4] == [
        frozen_dispatch.INTERNAL_ENTRY_FLAG,
        "profile-package",
        frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
    ]


def test_frozen_profile_adapter_runs_without_upstream_contrib_script(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "minimal.der"
    _write_minimal_saip_profile(profile)
    stdout = io.StringIO()
    stderr = io.StringIO()

    with (
        _frozen_runtime(tmp_path),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        result = frozen_dispatch.dispatch_internal_entry(
            [
                frozen_dispatch.INTERNAL_ENTRY_FLAG,
                "profile-saip-tool",
                frozen_dispatch.INTERNAL_ARGUMENT_SEPARATOR,
                str(profile),
                "info",
            ]
        )

    assert result == 0, stderr.getvalue()
    assert "SAIP profile version:" in stdout.getvalue()
    assert "profile elements" in stdout.getvalue()


def test_profile_adapter_core_flows_and_installed_pysim_import(
    tmp_path: Path,
) -> None:
    from Tools.ProfilePackage import saip_cli_adapter
    from Tools.ProfilePackage.saip_tool import SaipToolBridge

    profile = tmp_path / "minimal.der"
    _write_minimal_saip_profile(profile)
    split_dir = tmp_path / "split"
    apps_dir = tmp_path / "apps"
    without_usim = tmp_path / "without-usim.der"

    command_sets = [
        [str(profile), "dump", "--dump-decoded", "all_pe"],
        [str(profile), "tree"],
        [str(profile), "check"],
        [str(profile), "split", "--output-prefix", str(split_dir)],
        [str(profile), "extract-apps", "--output-dir", str(apps_dir)],
        [
            str(profile),
            "remove-naa",
            "--output-file",
            str(without_usim),
            "--naa-type",
            "usim",
        ],
    ]
    results: list[int] = []
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        for command in command_sets:
            results.append(saip_cli_adapter.run_cli(command))

    assert results == [0, 0, 0, 0, 0, 0]
    assert len(list(split_dir.glob("*.der"))) == 3
    assert apps_dir.is_dir()
    assert without_usim.is_file()

    error_output = io.StringIO()
    with redirect_stderr(error_output):
        assert (
            saip_cli_adapter.run_cli(
                [str(profile), "remove-pe", "--type", "header"]
            )
            == 2
        )
    assert "does not support RAW subcommand" in error_output.getvalue()
    assert "separate trusted executable" in error_output.getvalue()

    bridge = SaipToolBridge(
        workspace_root=tmp_path,
        tool_command=["external-saip-tool"],
    )
    bridge.set_input_file(str(profile))
    with mock.patch.object(bridge, "_pysim_source_dirs", return_value=[]):
        document = bridge.build_decoded_dump_document("all_pe")
    assert "header" in document["sections"]
    assert "end" in document["sections"]


def test_profile_adapter_keeps_existing_default_output_directory_permissions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from Tools.ProfilePackage import saip_cli_adapter

    profile = tmp_path / "minimal.der"
    _write_minimal_saip_profile(profile)
    original_mode = tmp_path.stat().st_mode
    monkeypatch.chdir(tmp_path)
    with (
        mock.patch.object(
            saip_cli_adapter,
            "ensure_private_directory",
            side_effect=AssertionError("existing cwd must not be chmodded"),
        ),
        redirect_stdout(io.StringIO()),
        redirect_stderr(io.StringIO()),
    ):
        assert saip_cli_adapter.run_cli([str(profile), "split"]) == 0
        assert saip_cli_adapter.run_cli([str(profile), "extract-apps"]) == 0

    assert tmp_path.stat().st_mode == original_mode
    assert len(list(tmp_path.glob("minimal-*.der"))) == 3


def test_profile_adapter_realistic_info_dump_remove_and_extract_parity(
    tmp_path: Path,
) -> None:
    import zipfile

    from pySim.esim.saip import ProfileElementSequence
    from pySim.esim.saip.validation import CheckBasicStructure
    from Tools.ProfilePackage import saip_cli_adapter

    profile = tmp_path / "realistic.der"
    load_object = _write_realistic_saip_profile(profile)

    def _run(arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = saip_cli_adapter.run_cli([str(profile), *arguments])
        return result, stdout.getvalue(), stderr.getvalue()

    result, info, error = _run(["info"])
    assert result == 0, error
    assert "NAA usim[0]" in info
    assert "Applications: 1" in info
    assert "A0000000620301" in info
    assert "Security domains: 1" in info
    assert "A000000151000000" in info
    assert "(data redacted)" in info
    assert "RFM instances: 1" in info

    result, apps_info, error = _run(["info", "--apps"])
    assert result == 0, error
    assert "Load package AID: A0000000620301" in apps_info
    assert "Security-domain AID: A000000151000000" in apps_info
    assert f"Load block bytes: {len(load_object)}" in apps_info
    assert "Instance 0: A00000006203010101" in apps_info

    result, type_dump, error = _run(
        ["dump", "all_pe_by_type", "--dump-decoded"]
    )
    assert result == 0, error
    assert "securityDomain (identification=" in type_dump
    assert "instanceAID" in type_dump
    assert "application (identification=" in type_dump

    result, naa_dump, error = _run(
        ["dump", "all_pe_by_naa", "--dump-decoded"]
    )
    assert result == 0, error
    assert "usim0" in naa_dump
    assert "usim (identification=" in naa_dump
    assert "templateID" in naa_dump

    apps_dir = tmp_path / "apps"
    result, _output, error = _run(
        ["extract-apps", "--output-dir", str(apps_dir)]
    )
    assert result == 0, error
    extracted = list(apps_dir.glob("*.cap"))
    assert len(extracted) == 1
    with zipfile.ZipFile(extracted[0]) as cap_archive:
        member_names = cap_archive.namelist()
        assert any(name.endswith("/Header.cap") for name in member_names)
        assert any(name.endswith("/Applet.cap") for name in member_names)

    without_usim = tmp_path / "without-usim.der"
    result, _output, error = _run(
        [
            "remove-naa",
            "--output-file",
            str(without_usim),
            "--naa-type",
            "usim",
        ]
    )
    assert result == 0, error
    reparsed = ProfileElementSequence.from_der(without_usim.read_bytes())
    assert [pe.type for pe in reparsed.pe_list] == [
        "header",
        "mf",
        "securityDomain",
        "application",
        "end",
    ]
    assert "usim" not in reparsed.pe_by_type
    assert "rfm" not in reparsed.pe_by_type
    assert reparsed.pe_by_type["header"][0].decoded[
        "eUICC-Mandatory-services"
    ] == {"javacard": None}
    CheckBasicStructure().check(reparsed)


def test_profile_adapter_globals_and_source_fallback(tmp_path: Path) -> None:
    from Tools.ProfilePackage import saip_cli_adapter, saip_tool

    profile = tmp_path / "minimal.der"
    _write_minimal_saip_profile(profile)
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        assert saip_cli_adapter.run_cli([str(profile), "--debug", "info"]) == 0
        assert (
            saip_cli_adapter.run_cli(
                ["--loglevel", "DEBUG", str(profile), "check"]
            )
            == 0
        )

    bridge = saip_tool.SaipToolBridge(workspace_root=tmp_path)
    bridge.set_input_file(str(profile))
    with (
        mock.patch.object(sys, "frozen", False, create=True),
        mock.patch.object(saip_tool.shutil, "which", return_value=None),
    ):
        command = bridge.get_tool_command()
        info_result = bridge.run_current(["info"])
        check_result = bridge.run_current(["check"])

    assert command[1:] == [
        "-m",
        "Tools.ProfilePackage.saip_cli_adapter",
    ]
    assert info_result.returncode == 0, info_result.stderr
    assert "SAIP profile version:" in info_result.stdout
    assert check_result.returncode == 0, check_result.stderr


def test_frozen_profile_tool_ignores_workspace_pysim_injection(
    tmp_path: Path,
) -> None:
    from Tools.ProfilePackage.saip_tool import SaipToolBridge

    fake_package = tmp_path / "pysim" / "pySim"
    fake_package.mkdir(parents=True)
    (fake_package / "__init__.py").write_text(
        "raise AssertionError('workspace pySim imported')\n",
        encoding="utf-8",
    )
    with (
        _frozen_runtime(tmp_path),
        mock.patch.dict("os.environ", {"PYTHONPATH": str(tmp_path / "pysim")}),
    ):
        bridge = SaipToolBridge(workspace_root=tmp_path)
        assert tmp_path / "pysim" not in bridge._pysim_source_dirs()
        assert "PYTHONPATH" not in bridge._subprocess_env_with_pysim()


def test_native_picker_gates_and_hidden_window_flags() -> None:
    from Tools.HilBridge import live_decode_tui
    from Tools.ProfilePackage import saip_tool

    with (
        mock.patch.dict("os.environ", {}, clear=True),
        mock.patch.object(saip_tool.sys, "platform", "win32"),
        mock.patch.object(live_decode_tui.sys, "platform", "darwin"),
    ):
        assert saip_tool._desktop_file_picker_supported()
        assert live_decode_tui._capture_file_picker_supported()

    with (
        mock.patch.object(frozen_dispatch.os, "name", "nt"),
        mock.patch.object(
            __import__("subprocess"),
            "CREATE_NO_WINDOW",
            0x08000000,
            create=True,
        ),
    ):
        assert frozen_dispatch.hidden_window_subprocess_kwargs() == {
            "creationflags": 0x08000000
        }
