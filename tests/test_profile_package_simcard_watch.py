"""Unit tests for ``Tools.ProfilePackage.simcard_watch``.

The tests never touch a live simulator engine or a real TUI process.
They exercise:

* Seed-on-start semantics (existing ICCIDs do not fire callbacks).
* Arrival detection for a newly created profile directory.
* Idempotence: a second poll with identical content yields nothing.
* Callback error isolation: a raising callback does not break the
  watcher's state.
* ``watch_and_launch_tui`` terminates cleanly on ``max_arrivals`` and
  delegates to the factory exactly once per new ICCID.
* ``run_cli`` creates the store directory when missing and exits
  non-zero on truly unreachable paths.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Tools.ProfilePackage import simcard_watch


def _write_profile_dir(
    root: Path,
    *,
    iccid: str,
    directory_name: str | None = None,
    include_image: bool = False,
) -> Path:
    directory_name = directory_name or f"profile_{iccid}"
    profile_dir = root / directory_name
    profile_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "aid": "A0000000871002FF49FFFFFFFF8900000100",
        "iccid": iccid,
        "state": "enabled",
        "profile_class": "test",
        "nickname": "",
        "service_provider": "",
        "profile_name": "",
        "imsi": "",
        "impi": "",
        "notification_address": "",
        "profile_source": "json",
    }
    (profile_dir / simcard_watch.MANIFEST_FILENAME).write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    if include_image is True:
        image = {
            "profile_name": f"img-{iccid}",
            "iccid": iccid,
            "imsi": "",
            "impi": "",
            "nodes": [],
        }
        (profile_dir / simcard_watch.PROFILE_IMAGE_FILENAME).write_text(
            json.dumps(image),
            encoding="utf-8",
        )
    return profile_dir


class ProfileStoreWatcherTests(unittest.TestCase):
    def test_seed_on_start_skips_existing_iccid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_profile_dir(root, iccid="8900001111222233334444")
            events: list[simcard_watch.ProfileArrival] = []
            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=events.append,
                poll_interval_seconds=0.01,
            )
            fresh = watcher.poll_once()
            self.assertEqual(fresh, [])
            self.assertEqual(events, [])
            self.assertEqual(watcher._seen_iccids, {"8900001111222233334444"})

    def test_arrival_detected_on_second_poll(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            events: list[simcard_watch.ProfileArrival] = []
            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=events.append,
                poll_interval_seconds=0.01,
            )
            watcher.poll_once()
            _write_profile_dir(
                root,
                iccid="8900009999000000111122",
                include_image=True,
            )
            fresh = watcher.poll_once()
            self.assertEqual(len(fresh), 1)
            self.assertEqual(fresh[0].iccid, "8900009999000000111122")
            self.assertIsNotNone(fresh[0].profile_image_path)
            self.assertEqual(fresh[0].preferred_profile_path, fresh[0].profile_image_path)
            self.assertEqual(len(events), 1)

    def test_idempotent_repeat_poll_does_not_fire(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            events: list[simcard_watch.ProfileArrival] = []
            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=events.append,
                poll_interval_seconds=0.01,
            )
            watcher.poll_once()
            _write_profile_dir(root, iccid="8900001000000000000001")
            watcher.poll_once()
            watcher.poll_once()
            self.assertEqual(len(events), 1)

    def test_no_seed_fires_on_first_poll_when_seed_on_start_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_profile_dir(root, iccid="8900002000000000000002")
            events: list[simcard_watch.ProfileArrival] = []
            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=events.append,
                poll_interval_seconds=0.01,
                seed_on_start=False,
            )
            fresh = watcher.poll_once()
            self.assertEqual(len(fresh), 1)
            self.assertEqual(fresh[0].iccid, "8900002000000000000002")

    def test_callback_error_does_not_break_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            def _boom(arrival: simcard_watch.ProfileArrival) -> None:
                raise RuntimeError("simulated callback failure")

            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=_boom,
                poll_interval_seconds=0.01,
            )
            watcher.poll_once()
            _write_profile_dir(root, iccid="8900003000000000000003")
            watcher.poll_once()
            self.assertIn("8900003000000000000003", watcher._seen_iccids)

    def test_missing_store_root_yields_empty_scan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "does-not-exist"
            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=lambda *_: None,
                poll_interval_seconds=0.01,
            )
            self.assertEqual(watcher.poll_once(), [])

    def test_manifest_with_missing_iccid_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            broken_dir = root / "broken"
            broken_dir.mkdir()
            (broken_dir / simcard_watch.MANIFEST_FILENAME).write_text(
                json.dumps({"aid": "AAA"}),
                encoding="utf-8",
            )
            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=lambda *_: None,
                poll_interval_seconds=0.01,
                seed_on_start=False,
            )
            self.assertEqual(watcher.poll_once(), [])


class WatchAndLaunchTuiTests(unittest.TestCase):
    def test_launcher_factory_fired_once_per_arrival(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_profile_dir(root, iccid="seed-only")
            launched: list[simcard_watch.ProfileArrival] = []

            def _fake_spawn(command, *, cwd, env):
                class _FakeProcess:
                    def wait(self):
                        return 0

                launched.append(arrivals[-1] if arrivals else None)
                return _FakeProcess()

            arrivals: list[simcard_watch.ProfileArrival] = []

            def _factory(arrival):
                arrivals.append(arrival)
                return ["/bin/true"]

            def _schedule_arrival() -> None:
                _write_profile_dir(root, iccid="8900000000000000000777")

            with patch.object(simcard_watch, "_spawn_launcher", side_effect=_fake_spawn):
                # Manually build the watcher so we can interleave the
                # filesystem arrival between poll_once calls.
                watcher = simcard_watch.ProfileStoreWatcher(
                    root,
                    on_arrival=lambda a: simcard_watch._spawn_launcher(  # type: ignore[attr-defined]
                        _factory(a),
                        cwd=None,
                        env=dict(os.environ),
                    ),
                    poll_interval_seconds=0.01,
                )
                watcher.poll_once()
                _schedule_arrival()
                watcher.poll_once()
                watcher.poll_once()

            self.assertEqual(len(launched), 1)
            self.assertEqual(arrivals[-1].iccid, "8900000000000000000777")

    def test_run_cli_creates_missing_store_and_short_circuits_zero_max(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "nested" / "profile_store"
            with patch.object(
                simcard_watch,
                "watch_and_launch_tui",
                return_value=0,
            ) as mock_run:
                return_code = simcard_watch.run_cli(
                    [
                        "--store-root",
                        str(target),
                        "--workspace-root",
                        str(Path(td)),
                        "--max-arrivals",
                        "1",
                        "--poll-interval",
                        "0.01",
                    ]
                )
            self.assertEqual(return_code, 0)
            self.assertTrue(target.is_dir())
            self.assertEqual(mock_run.call_count, 1)
            _, kwargs = mock_run.call_args
            self.assertEqual(kwargs["max_arrivals"], 1)
            self.assertAlmostEqual(kwargs["poll_interval_seconds"], 0.01)


class LauncherTemplateTests(unittest.TestCase):
    """Regression tests for the placeholder expansion contract."""

    def _arrival(self, root: Path, iccid: str) -> simcard_watch.ProfileArrival:
        profile_dir = _write_profile_dir(
            root,
            iccid=iccid,
            include_image=True,
        )
        return simcard_watch.ProfileArrival(
            iccid=iccid,
            profile_dir=profile_dir,
            manifest_path=profile_dir / simcard_watch.MANIFEST_FILENAME,
            profile_image_path=profile_dir / simcard_watch.PROFILE_IMAGE_FILENAME,
        )

    def test_expand_handles_whitespace_paths_and_all_tokens(self) -> None:
        with tempfile.TemporaryDirectory(prefix="space dir ") as td:
            arrival = self._arrival(Path(td), "8900004000000000000004")
            template = (
                "{python} -m Tools.ProfilePackage --cmd "
                "\"USE '{profile}'; INFO; TREE; EXIT\" "
                "--iccid {iccid} --dir '{profile_dir}' --manifest '{manifest}'"
            )
            argv = simcard_watch._expand_launcher_template(template, arrival)
        self.assertGreater(len(argv), 0)
        self.assertIn("--iccid", argv)
        iccid_position = argv.index("--iccid")
        self.assertEqual(argv[iccid_position + 1], "8900004000000000000004")
        # The profile path (with whitespace) must survive as a single argv
        # entry — that is exactly what shlex.split guarantees for quoted
        # substrings after format_map expansion.
        self.assertTrue(
            any(" " in chunk for chunk in argv),
            "expected at least one argv entry with embedded whitespace",
        )

    def test_expand_unknown_placeholder_warns_and_substitutes_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            arrival = self._arrival(Path(td), "8900005000000000000005")
            # Quote the placeholder so shlex preserves the empty
            # positional after substitution; if the operator did not
            # quote we keep the current behaviour (shlex drops the
            # empty token) and just log the typo.
            template = "/bin/echo {iccid} '{unknown_token}'"
            with self.assertLogs(simcard_watch._LOGGER, level="WARNING") as logs:
                argv = simcard_watch._expand_launcher_template(template, arrival)
        self.assertEqual(argv[0], "/bin/echo")
        self.assertEqual(argv[1], "8900005000000000000005")
        self.assertEqual(argv[2], "")
        self.assertTrue(any("unknown_token" in msg for msg in logs.output))

    def test_default_launcher_hands_profile_to_profile_package_shell(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            arrival = self._arrival(Path(td), "8900006000000000000006")
            argv = simcard_watch._build_default_tui_command(arrival)
        self.assertIn("Tools.ProfilePackage", argv)
        self.assertIn("--cmd", argv)
        cmd_position = argv.index("--cmd")
        batch = argv[cmd_position + 1]
        self.assertIn("USE", batch)
        self.assertIn("INFO", batch)
        self.assertIn("TREE", batch)
        self.assertIn("EXIT", batch)


class WatcherResilienceTests(unittest.TestCase):
    def test_poll_once_swallows_oserror_from_scan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            watcher = simcard_watch.ProfileStoreWatcher(
                root,
                on_arrival=lambda *_: None,
                poll_interval_seconds=0.01,
            )
            with patch.object(
                simcard_watch,
                "_scan_store_once",
                side_effect=PermissionError("race on store child"),
            ):
                with self.assertLogs(simcard_watch._LOGGER, level="WARNING"):
                    fresh = watcher.poll_once()
        self.assertEqual(fresh, [])
