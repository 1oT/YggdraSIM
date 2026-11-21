# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A Remote Lab reader is selectable from every CLI surface, not only the GUI.

The GUI resolves a reader name through the remote-reader registry before the
PC/SC enumeration. Until now the shells did not: the SCP03 shell had no
reader choice at all, the two SCP11 shells built a PC/SC channel from a
config index, and the SCP80 config had no key to carry a name. Each surface
now takes the same ``--reader`` (or ``set reader_name``) and resolves it with
``resolve_reader_name``, the one rule the GUI already applied.

Fakes stand in for the relay and PC/SC. No card is opened.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from yggdrasim_common import remote_readers
from yggdrasim_common.remote_readers import REMOTE_READER_INDEX, resolve_reader_name

READER = "Remote Lab: Site A"


@pytest.fixture()
def bound():
    remote_readers.clear_remote_readers()
    remote_readers.register_remote_reader(
        READER, relay_url="http://127.0.0.1:1/apdu", device_id="site-a", rig_id="rig-a"
    )
    yield
    remote_readers.clear_remote_readers()


class FakeChannel:
    def __init__(self, reader_name: str, *, quiet_apdu_logging: bool = False) -> None:
        self.reader_name = reader_name
        self.quiet = quiet_apdu_logging

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        self.raw = enabled

    def disconnect(self) -> None:
        return None


# --- the shared rule --------------------------------------------------------


def test_remote_name_resolves_before_pcsc(bound) -> None:
    assert resolve_reader_name(READER) == (REMOTE_READER_INDEX, READER)
    # Whitespace at the ends is tolerated; the canonical name comes back.
    assert resolve_reader_name(f"  {READER} ") == (REMOTE_READER_INDEX, READER)


def test_empty_name_is_the_first_reader_without_touching_pcsc(monkeypatch: pytest.MonkeyPatch) -> None:
    import smartcard.System

    monkeypatch.setattr(smartcard.System, "readers", lambda: (_ for _ in ()).throw(AssertionError("enumerated")))
    assert resolve_reader_name("") == (0, "")


def test_exact_pcsc_name_resolves_to_its_index(monkeypatch: pytest.MonkeyPatch) -> None:
    import smartcard.System

    monkeypatch.setattr(smartcard.System, "readers", lambda: ["Reader A 00 00", "Reader B 00 00"])
    assert resolve_reader_name("Reader B 00 00") == (1, "Reader B 00 00")


def test_unknown_name_raises_instead_of_falling_back(monkeypatch: pytest.MonkeyPatch) -> None:
    import smartcard.System

    monkeypatch.setattr(smartcard.System, "readers", lambda: ["Reader A 00 00"])
    with pytest.raises(RuntimeError, match="reader not found"):
        resolve_reader_name("Reader Z")


# --- SCP03 shell ------------------------------------------------------------


def test_transporter_opens_the_chosen_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    from SCP03.transport import card

    seen: dict[str, Any] = {}

    class FakeConnection:
        def disconnect(self) -> None:
            return None

    def fake_create(**kwargs: Any) -> FakeConnection:
        seen.update(kwargs)
        return FakeConnection()

    monkeypatch.setattr(card, "create_card_connection", fake_create)
    transporter = card.CardTransporter(reader_index=REMOTE_READER_INDEX, reader_name=READER)
    assert seen == {"reader_index": REMOTE_READER_INDEX, "reader_name": READER}
    assert transporter.reader_name == READER


def test_transporter_default_is_the_first_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    from SCP03.transport import card

    seen: dict[str, Any] = {}
    monkeypatch.setattr(card, "create_card_connection", lambda **kw: seen.update(kw) or object())
    card.CardTransporter()
    assert seen == {"reader_index": 0, "reader_name": ""}


def test_shell_dispatcher_takes_a_reader_name() -> None:
    from SCP03.interface.shell import ShellDispatcher

    assert "reader_name" in inspect.signature(ShellDispatcher.__init__).parameters


def test_scp03_entry_builds_the_dispatcher_with_the_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    import SCP03.main as scp03_main

    seen: list[str] = []

    class FakeDispatcher:
        def __init__(self, reader_name: str = "") -> None:
            seen.append(reader_name)
            self.transport = None
            self.debug_mode = False

    # _build_dispatcher imports the class at call time, so the patch goes on
    # the shell module it imports from.
    import SCP03.interface.shell as shell_module

    monkeypatch.setattr(shell_module, "ShellDispatcher", FakeDispatcher)
    dispatcher = scp03_main._build_dispatcher(reader_name=READER)
    assert isinstance(dispatcher, FakeDispatcher)
    assert seen == [READER]


def test_scp03_entry_exits_cleanly_on_an_unresolvable_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    import SCP03.main as scp03_main

    class RefusingDispatcher:
        def __init__(self, reader_name: str = "") -> None:
            raise RuntimeError(f"reader not found: {reader_name!r}")

    import SCP03.interface.shell as shell_module

    monkeypatch.setattr(shell_module, "ShellDispatcher", RefusingDispatcher)
    with pytest.raises(SystemExit) as caught:
        scp03_main._build_dispatcher(reader_name="Reader Z")
    assert caught.value.code == 2


def test_scp03_entries_accept_the_reader() -> None:
    import SCP03.main as scp03_main

    for name in ("entry", "entry_cmd", "entry_stdin"):
        assert "reader_name" in inspect.signature(getattr(scp03_main, name)).parameters


# --- local SM-DP+ shell -----------------------------------------------------


def test_local_shell_resolves_a_remote_reader_into_its_config(bound) -> None:
    from SCP11.local_access.main import LocalAccessShell

    shell = LocalAccessShell(reader_name=READER)
    assert shell.cfg.READER_INDEX == REMOTE_READER_INDEX
    assert shell.cfg.READER_NAME == READER


def test_local_shell_default_config_is_untouched() -> None:
    from SCP11.local_access.main import LocalAccessShell

    shell = LocalAccessShell()
    assert shell.cfg.READER_INDEX == 0
    assert shell.cfg.READER_NAME == ""


def test_local_session_opens_the_relay_channel_for_a_named_reader(bound, monkeypatch: pytest.MonkeyPatch) -> None:
    import SCP11.transport as transport
    from SCP11.local_access import LocalAccessConfig, LocalIsdrSession

    monkeypatch.setattr(transport, "RemoteApduChannel", FakeChannel)
    cfg = LocalAccessConfig(READER_INDEX=REMOTE_READER_INDEX, READER_NAME=READER)
    session = LocalIsdrSession(cfg=cfg)
    assert isinstance(session.apdu_channel, FakeChannel)
    assert session.apdu_channel.reader_name == READER


def test_local_session_keeps_pcsc_when_no_name_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    from SCP11.local_access import LocalAccessConfig, LocalIsdrSession, session as session_module

    built: list[int] = []

    class FakePcsc:
        def __init__(self, reader_index: int = 0, **_kw: Any) -> None:
            built.append(reader_index)

        def set_raw_apdu_logging(self, enabled: bool) -> None:
            return None

    monkeypatch.setattr(session_module, "PcscApduChannel", FakePcsc)
    LocalIsdrSession(cfg=LocalAccessConfig(READER_INDEX=1))
    assert built == [1]


def test_local_shell_entries_accept_the_reader() -> None:
    import SCP11.local_access.main as local_main

    for name in ("entry", "entry_cmd", "entry_stdin"):
        assert "reader_name" in inspect.signature(getattr(local_main, name)).parameters


# --- eSIM Management console ------------------------------------------------


def test_live_factory_builds_the_relay_channel_for_a_named_reader(bound, monkeypatch: pytest.MonkeyPatch) -> None:
    import SCP11.transport as transport
    from SCP11.live.config import SGPConfig
    from SCP11.live.factory import build_apdu_channel

    monkeypatch.setattr(transport, "RemoteApduChannel", FakeChannel)
    channel = build_apdu_channel(SGPConfig(READER_INDEX=REMOTE_READER_INDEX, READER_NAME=READER))
    assert isinstance(channel, FakeChannel)
    assert channel.reader_name == READER


def test_live_config_accepts_a_negative_index_only_when_named() -> None:
    from SCP11.live.config import SGPConfig

    named = SGPConfig(READER_INDEX=REMOTE_READER_INDEX, READER_NAME=READER)
    errors, _warnings = named.collect_startup_diagnostics()
    assert not any("READER_INDEX" in e for e in errors)
    bare = SGPConfig(READER_INDEX=REMOTE_READER_INDEX)
    errors, _warnings = bare.collect_startup_diagnostics()
    assert any("READER_INDEX" in e for e in errors)


def test_live_client_resolves_the_reader_into_its_config(bound) -> None:
    from SCP11.live.main import SGP22Client

    client = SGP22Client(reader_name=READER)
    assert client.cfg.READER_INDEX == REMOTE_READER_INDEX
    assert client.cfg.READER_NAME == READER


def test_live_preflight_reports_a_released_link_instead_of_a_pcsc_range() -> None:
    from SCP11.live.main import SCP11StartupError, SGP22Client

    remote_readers.clear_remote_readers()
    remote_readers.register_remote_reader(READER, relay_url="http://127.0.0.1:1/apdu")
    client = SGP22Client(reader_name=READER)
    remote_readers.clear_remote_readers()
    try:
        client._run_startup_preflight()
    except SCP11StartupError as error:
        assert "not connected" in str(error)
        assert "READER_INDEX" not in str(error)
    else:
        pytest.fail("a released link must fail the preflight")


# --- SCP80 -------------------------------------------------------------------


def test_scp80_config_carries_a_reader_name_beside_the_index(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    from SCP80.config import ConfigManager

    cfg = ConfigManager()
    cfg.set("reader_name", "  Remote Lab: Site A ")
    # Case and inner spaces survive: the binding is matched by exact string.
    assert cfg.get("reader_name") == READER
    assert cfg.get("reader_idx") == str(REMOTE_READER_INDEX)
    # A PC/SC pick supersedes the name.
    cfg.set("reader_idx", "0")
    assert cfg.get("reader_name") == ""
    assert cfg.get("reader_idx") == "0"


def test_scp80_set_command_keeps_the_spaces_in_a_reader_name() -> None:
    from SCP80.cli import OtaShell

    recorded: list[tuple[str, str]] = []

    class FakeConfig:
        def get(self, key: str) -> str:
            return "print"

        def set(self, key: str, value: str) -> None:
            recorded.append((key, value))

        def save(self) -> None:
            return None

    shell = OtaShell.__new__(OtaShell)
    shell.config = FakeConfig()
    shell.do_set("reader_name", "Remote", "Lab:", "Site", "A")
    shell.do_set("tar", "B0", "00", "00")
    assert recorded == [("reader_name", "Remote Lab: Site A"), ("tar", "B00000")]


def test_scp80_transport_opens_the_named_remote_reader(bound, monkeypatch: pytest.MonkeyPatch) -> None:
    from SCP80 import transport as transport_module

    seen: dict[str, Any] = {}

    class FakeConnection:
        def getProtocol(self) -> str:  # noqa: N802 -- pyscard API name
            return "T=1"

    def fake_create(**kwargs: Any) -> FakeConnection:
        seen.update(kwargs)
        return FakeConnection()

    class FakeConfig:
        data = {"reader_idx": str(REMOTE_READER_INDEX), "reader_name": READER}

        def get_int(self, key: str) -> int:
            return int(self.data[key])

    monkeypatch.setattr(transport_module, "create_card_connection", fake_create)
    monkeypatch.setattr(transport_module, "PYSCRARD_AVAIL", True, raising=False)
    transport = transport_module.Transport(FakeConfig())
    monkeypatch.setattr(transport, "_stk_bootstrap", lambda verbose=False: None)
    assert transport.connect() is True
    assert seen["reader_name"] == READER
    assert seen["reader_index"] == REMOTE_READER_INDEX


def test_scp80_transport_refuses_a_stale_remote_name(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from SCP80 import transport as transport_module

    remote_readers.clear_remote_readers()
    called: list[bool] = []
    monkeypatch.setattr(transport_module, "create_card_connection", lambda **kw: called.append(True))
    monkeypatch.setattr(transport_module, "PYSCRARD_AVAIL", True, raising=False)

    class FakeConfig:
        data = {"reader_idx": str(REMOTE_READER_INDEX), "reader_name": READER}

        def get_int(self, key: str) -> int:
            return int(self.data[key])

    transport = transport_module.Transport(FakeConfig())
    assert transport.connect() is False
    assert called == []
    assert "not connected" in capsys.readouterr().out
