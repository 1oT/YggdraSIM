# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Narrow tests for the live-hardware GUI surface (Milestone B-3).

These target the parts that are safe to exercise without a physical
reader: activation-code parsing, the level inference on the tee'd
stdout, and the ``/api/live/readers`` HTTP endpoint with ``pyscard``
stubbed out.
"""

from __future__ import annotations

import sys
import types

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("starlette")


# --- Pure helpers (no FastAPI needed, but route module imports fastapi
# at the top so we gate the whole file anyway) -----------------------


from yggdrasim_common.gui_server.routes import live as live_module  # noqa: E402


class TestActivationCodeParser:
    def test_full_lpa_uri(self) -> None:
        smdp, matching = live_module._parse_activation_code(
            "LPA:1$smdp.example.com$MATCHINGID"
        )
        assert smdp == "smdp.example.com"
        assert matching == "MATCHINGID"

    def test_shorthand_with_matching(self) -> None:
        smdp, matching = live_module._parse_activation_code("smdp.example.com$ABC")
        assert smdp == "smdp.example.com"
        assert matching == "ABC"

    def test_bare_smdp(self) -> None:
        smdp, matching = live_module._parse_activation_code("smdp.example.com")
        assert smdp == "smdp.example.com"
        assert matching == ""

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            live_module._parse_activation_code("")

    def test_surrounding_whitespace(self) -> None:
        smdp, matching = live_module._parse_activation_code(" LPA:1$host$MID ")
        assert smdp == "host"
        assert matching == "MID"


class TestLevelInference:
    def test_error_marker(self) -> None:
        assert live_module._infer_level("[-] something failed") == "error"

    def test_success_marker(self) -> None:
        assert live_module._infer_level("[+] OK") == "info"

    def test_warn_marker(self) -> None:
        assert live_module._infer_level("WARNING: slow path") == "warn"

    def test_default_info(self) -> None:
        assert live_module._infer_level("hello") == "info"


class TestReaderRowHelpers:
    def test_remote_row_duplicate_matches_local_reader_name(self) -> None:
        remote = live_module.ReaderInfo(
            name="🌐 Example USB Reader (remote@http://127.0.0.1:9997)",
            atr_hex="3B00",
            status="card present (remote bridge)",
            kind="remote",
            source_url="http://127.0.0.1:9997",
        )

        assert live_module._remote_row_duplicates_local_reader(
            remote,
            ["Example USB Reader", "Example Contacted Reader"],
        )

    def test_remote_row_distinct_reader_is_kept(self) -> None:
        remote = live_module.ReaderInfo(
            name="🌐 Lab relay reader (remote@http://127.0.0.1:9997)",
            atr_hex="3B00",
            status="card present (remote bridge)",
            kind="remote",
            source_url="http://127.0.0.1:9997",
        )

        assert not live_module._remote_row_duplicates_local_reader(
            remote,
            ["Example USB Reader"],
        )


# --- HTTP route with pyscard stubbed out -------------------------------


@pytest.fixture()
def stub_pyscard(monkeypatch: pytest.MonkeyPatch):
    """Install a fake ``smartcard.System`` so the readers endpoint
    exercises the happy path without requiring a PC/SC daemon.
    """

    class _FakeConnection:
        def __init__(self, atr: list[int], fail: bool = False) -> None:
            self._atr = atr
            self._fail = fail

        def connect(self) -> None:
            if self._fail:
                raise RuntimeError("no card")

        def getATR(self) -> list[int]:
            return list(self._atr)

        def disconnect(self) -> None:
            pass

    class _FakeReader:
        def __init__(self, name: str, atr: list[int], fail: bool = False) -> None:
            self._name = name
            self._atr = atr
            self._fail = fail

        def __str__(self) -> str:
            return self._name

        def createConnection(self) -> _FakeConnection:
            return _FakeConnection(self._atr, fail=self._fail)

    fake_readers = [
        _FakeReader("YggdraSIM Virtual Reader 0", [0x3B, 0x9F, 0x96]),
        _FakeReader("Empty Reader 1", [], fail=True),
    ]

    smartcard_pkg = types.ModuleType("smartcard")
    smartcard_system = types.ModuleType("smartcard.System")

    def _readers():
        return list(fake_readers)

    smartcard_system.readers = _readers
    smartcard_pkg.System = smartcard_system

    monkeypatch.setitem(sys.modules, "smartcard", smartcard_pkg)
    monkeypatch.setitem(sys.modules, "smartcard.System", smartcard_system)
    yield


@pytest.fixture(scope="module")
def test_client():
    from starlette.testclient import TestClient

    from yggdrasim_common.gui_server.app import create_app
    from yggdrasim_common.gui_server.config import GuiServerConfig

    config = GuiServerConfig(
        mode="desktop",
        host="127.0.0.1",
        port=0,
        token="abcdef1234567890abcdef1234567890",
        allow_origins=tuple(),
        tls_cert_path="",
        tls_key_path="",
        tls_self_signed=False,
        token_source="test-fixture",
        token_strength="generated",
        allow_ephemeral_port=True,
        idle_seconds=300,
        webview_debug=False,
    )
    app = create_app(config)
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer " + config.token})
    yield client


class TestLiveReadersRoute:
    def test_pyscard_missing_returns_200_with_note(self, test_client, monkeypatch) -> None:
        # Force the import path to fail.
        monkeypatch.setitem(sys.modules, "smartcard", None)
        monkeypatch.setitem(sys.modules, "smartcard.System", None)
        response = test_client.get("/api/live/readers")
        assert response.status_code == 200
        payload = response.json()
        assert payload["backend"] == "missing"
        assert payload["readers"] == []
        assert "pyscard" in payload["note"]

    def test_pyscard_stub_lists_readers(self, test_client, stub_pyscard) -> None:
        response = test_client.get("/api/live/readers")
        assert response.status_code == 200
        payload = response.json()
        assert payload["backend"] == "pyscard"
        assert len(payload["readers"]) == 2
        first = payload["readers"][0]
        assert first["name"].startswith("YggdraSIM Virtual Reader")
        assert first["atr_hex"] == "3B9F96"
        assert first["status"] == "card present"
        second = payload["readers"][1]
        assert second["atr_hex"] == ""
        assert "no card" in second["status"]

    def test_atr_probe_specific_reader(self, test_client, stub_pyscard) -> None:
        response = test_client.post(
            "/api/live/atr",
            json={"reader": "YggdraSIM Virtual Reader 0"},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["atr_hex"] == "3B9F96"

    def test_atr_probe_unknown_reader_404(self, test_client, stub_pyscard) -> None:
        response = test_client.post(
            "/api/live/atr",
            json={"reader": "ghost"},
        )
        assert response.status_code == 404


# --- Regression: ATR probe must not power-cycle the card -----------------
#
# Background: the 5 s reader-bar poll used to call ``connection.connect()``
# with pyscard's default ``disposition=SCARD_UNPOWER_CARD``. On
# ``SCARD_SHARE_SHARED`` setups (ours), that unpower propagates to the
# live scp03 scan session and silently cold-resets the card between
# polls — so every subsequent file-click failed with 6A82 and the GUI
# had to recover-scan after each click. The contract below codifies
# the fix: probe with ``SCARD_LEAVE_CARD`` and only use the cached ATR
# as a fallback for non-presence errors.


class _RecordingConnection:
    """Records every ``connect()`` + ``disconnect()`` call so tests can
    assert the disposition we pass to pyscard is the non-destructive one.
    """

    def __init__(self, atr: list[int]) -> None:
        self._atr = atr
        self.connect_calls: list[dict] = []
        self.disconnect_calls: int = 0
        self.disposition: object | None = None

    def connect(self, *args, **kwargs) -> None:
        self.connect_calls.append(dict(kwargs))
        if "disposition" in kwargs:
            self.disposition = kwargs["disposition"]

    def getATR(self) -> list[int]:
        return list(self._atr)

    def disconnect(self) -> None:
        self.disconnect_calls += 1


class _RecordingReader:
    def __init__(self, name: str, atr: list[int]) -> None:
        self._name = name
        self._atr = atr
        self.connection: _RecordingConnection | None = None

    def __str__(self) -> str:
        return self._name

    def createConnection(self) -> _RecordingConnection:
        conn = _RecordingConnection(self._atr)
        self.connection = conn
        return conn


class TestProbeLeavesCardPowered:
    """``_probe_reader`` must pass ``SCARD_LEAVE_CARD`` to connect so
    the subsequent ``disconnect()`` does not signal pcscd to unpower
    the card out from under any sibling scp03 session.
    """

    def test_probe_requests_leave_card_disposition(self) -> None:
        reader = _RecordingReader("Fake Reader", [0x3B, 0x9E, 0x95, 0x80])
        info = live_module._probe_reader(reader)
        assert info.atr_hex == "3B9E9580"
        assert info.status == "card present"
        assert reader.connection is not None
        assert len(reader.connection.connect_calls) == 1
        call = reader.connection.connect_calls[0]
        # SCARD_LEAVE_CARD == 0 in pyscard's scard module. We resolve it
        # lazily so the numeric 0 fallback is an acceptable result too
        # (both mean "do not reset / unpower the card").
        assert call.get("disposition") in (0, 0x00000000)
        assert reader.connection.disposition in (0, 0x00000000)

    def test_probe_swallows_connect_typeerror_for_old_pyscard(self) -> None:
        """Old pyscard releases don't expose ``disposition`` as a kwarg.
        The probe must gracefully fall back and still set the instance
        attribute so the subsequent disconnect honours LEAVE_CARD.
        """

        class _LegacyConnection(_RecordingConnection):
            def connect(self, *args, **kwargs) -> None:
                if "disposition" in kwargs:
                    # Emulate a pyscard version that rejects the kwarg.
                    raise TypeError("unexpected keyword argument 'disposition'")
                self.connect_calls.append(dict(kwargs))

        class _LegacyReader(_RecordingReader):
            def createConnection(self) -> _LegacyConnection:  # type: ignore[override]
                conn = _LegacyConnection(self._atr)
                self.connection = conn
                return conn

        reader = _LegacyReader("Legacy Reader", [0x3B, 0x00])
        info = live_module._probe_reader(reader)
        assert info.atr_hex == "3B00"
        # Fallback path assigns the disposition to the instance directly.
        assert reader.connection is not None
        assert reader.connection.disposition in (0, 0x00000000)


class TestProbeCachedAtrFallback:
    """Cached ATRs must not mask a removed card."""

    def test_cached_atr_still_validates_reader_presence(self) -> None:
        reader = _RecordingReader("Session Reader", [0xDE, 0xAD, 0xBE, 0xEF])
        info = live_module._probe_reader(reader, cached_atr="DEADBEEF")
        assert info.atr_hex == "DEADBEEF"
        assert info.status == "card present"
        assert reader.connection is not None
        assert len(reader.connection.connect_calls) == 1

    def test_empty_cached_atr_falls_through_to_probe(self) -> None:
        reader = _RecordingReader("No-Session Reader", [0x3B, 0x9F])
        info = live_module._probe_reader(reader, cached_atr="")
        assert info.atr_hex == "3B9F"
        assert info.status == "card present"
        assert reader.connection is not None

    def test_cached_atr_does_not_mask_no_card(self) -> None:
        class NoCardException(Exception):
            pass

        class _NoCardConnection(_RecordingConnection):
            def connect(self, *args, **kwargs) -> None:
                self.connect_calls.append(dict(kwargs))
                raise NoCardException("No smart card inserted. (0x8010000C)")

        class _NoCardReader(_RecordingReader):
            def createConnection(self) -> _NoCardConnection:  # type: ignore[override]
                conn = _NoCardConnection(self._atr)
                self.connection = conn
                return conn

        reader = _NoCardReader("Empty Reader", [])
        info = live_module._probe_reader(reader, cached_atr="DEADBEEF")
        assert info.atr_hex == ""
        assert "no card" in info.status.lower()

    def test_cached_atr_falls_back_for_non_presence_probe_error(self) -> None:
        class _SharingErrorConnection(_RecordingConnection):
            def connect(self, *args, **kwargs) -> None:
                self.connect_calls.append(dict(kwargs))
                raise RuntimeError("sharing violation")

        class _SharingErrorReader(_RecordingReader):
            def createConnection(self) -> _SharingErrorConnection:  # type: ignore[override]
                conn = _SharingErrorConnection(self._atr)
                self.connection = conn
                return conn

        reader = _SharingErrorReader("Busy Reader", [])
        info = live_module._probe_reader(reader, cached_atr="DEADBEEF")
        assert info.atr_hex == "DEADBEEF"
        assert "cached" in info.status.lower()


class TestSessionAtrLookup:
    """``_session_atr_by_reader_name`` walks the live session registry
    and returns ATRs for readers currently in use, so ``list_readers``
    can substitute cached values instead of re-probing.
    """

    def test_maps_scp03_sessions_to_atr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _FakeManager:
            def list(self) -> list[dict]:
                return [
                    {
                        "kind": "scp03",
                        "metadata": {
                            "reader_name": "Reader A",
                            "atr_hex": "3B9F94",
                        },
                    },
                    {
                        "kind": "scp11",  # different kind, must be ignored
                        "metadata": {
                            "reader_name": "Reader B",
                            "atr_hex": "FFFFFF",
                        },
                    },
                    {
                        "kind": "scp03",
                        "metadata": {
                            "reader_name": "(default)",  # sentinel, ignore
                            "atr_hex": "0000",
                        },
                    },
                    {
                        "kind": "scp03",
                        "metadata": {
                            "reader_name": "Reader C",
                            "atr_hex": "",  # no ATR stored yet
                        },
                    },
                ]

        monkeypatch.setattr(
            "yggdrasim_common.gui_server.sessions.get_manager",
            lambda: _FakeManager(),
        )
        mapping = live_module._session_atr_by_reader_name()
        assert mapping == {"Reader A": "3B9F94"}

    def test_closes_stale_scp03_sessions_for_reader(self, monkeypatch: pytest.MonkeyPatch) -> None:
        closed: list[str] = []

        class _FakeManager:
            def list(self) -> list[dict]:
                return [
                    {
                        "id": "deadbeef",
                        "kind": "scp03",
                        "metadata": {
                            "reader_name": "Reader A",
                            "atr_hex": "3B9F94",
                        },
                    },
                    {
                        "id": "ignored",
                        "kind": "scp03",
                        "metadata": {
                            "reader_name": "Reader B",
                            "atr_hex": "3B00",
                        },
                    },
                ]

            def close(self, session_id: str) -> bool:
                closed.append(session_id)
                return True

        monkeypatch.setattr(
            "yggdrasim_common.gui_server.sessions.get_manager",
            lambda: _FakeManager(),
        )

        assert live_module._close_scp03_sessions_for_reader_name("Reader A") == 1
        assert closed == ["deadbeef"]
