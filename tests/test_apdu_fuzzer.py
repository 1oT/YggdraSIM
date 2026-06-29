# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Unit tests for the APDU mutation fuzzer.

The tests cover the three safety-critical layers without requiring a
live card:

* Mutators are deterministic given a seeded ``random.Random`` and each
  produces a legal (non-empty, length-plausible) APDU.
* Corpus loader handles both recorder-dump JSON and bare-list JSON
  inputs and rejects malformed hex.
* Safety gate refuses runs without the opt-in token, without an
  allow-list, or when the probed card identity does not match.
* Crash-dump records land in the run directory with filenames that
  encode the mutation description.
* The runner halts immediately on a crash-class SW and writes exactly
  one crash dump.
"""

from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from Tools.ApduFuzz.corpus import (
    Corpus,
    CorpusEntry,
    filter_select_only,
    load_corpus,
)
from Tools.ApduFuzz.mutators import (
    MUTATORS,
    MutationResult,
    mutate_bit_flip,
    mutate_length_mangle,
    mutate_padding_bloat,
    mutate_tag_shuffle,
    mutate_zero_lc,
    choose_mutator,
)
from Tools.ApduFuzz.runner import FuzzerRunner
from Tools.ApduFuzz.safety import (
    FuzzerSafetyError,
    SafetyConfig,
    assert_safety_gate,
    build_allow_set,
    create_run_dir,
    dump_crash,
    resolve_crash_dump_root,
)


_SELECT_MF_APDU = bytes.fromhex("00A40004023F00")
_SELECT_EF_ICCID = bytes.fromhex("00A40004022FE2")


class MutatorDeterminismTests(unittest.TestCase):
    def test_bit_flip_is_reproducible_for_the_same_seed(self) -> None:
        rng_a = random.Random(1234)
        rng_b = random.Random(1234)
        first = mutate_bit_flip(_SELECT_MF_APDU, rng_a)
        second = mutate_bit_flip(_SELECT_MF_APDU, rng_b)
        self.assertEqual(first, second)
        self.assertNotEqual(first.mutated_apdu, _SELECT_MF_APDU)

    def test_length_mangle_changes_lc_but_preserves_header(self) -> None:
        rng = random.Random(1)
        result = mutate_length_mangle(_SELECT_MF_APDU, rng)
        self.assertEqual(result.mutated_apdu[:4], _SELECT_MF_APDU[:4])
        self.assertNotEqual(result.mutated_apdu[4], _SELECT_MF_APDU[4])

    def test_zero_lc_sets_lc_to_zero(self) -> None:
        result = mutate_zero_lc(_SELECT_MF_APDU, random.Random(0))
        self.assertEqual(result.mutated_apdu[4], 0x00)
        self.assertEqual(result.mutated_apdu[:4], _SELECT_MF_APDU[:4])

    def test_padding_bloat_appends_bytes(self) -> None:
        result = mutate_padding_bloat(_SELECT_MF_APDU, random.Random(42))
        self.assertGreater(len(result.mutated_apdu), len(_SELECT_MF_APDU))
        self.assertEqual(result.mutated_apdu[: len(_SELECT_MF_APDU)], _SELECT_MF_APDU)

    def test_tag_shuffle_noops_on_empty_data(self) -> None:
        bare_header = b"\x00\xA4\x00\x04\x00"
        result = mutate_tag_shuffle(bare_header, random.Random(0))
        self.assertEqual(result.mutated_apdu, bare_header)
        self.assertIn("no_data", result.description)

    def test_choose_mutator_enforces_subset(self) -> None:
        rng = random.Random(99)
        chosen = choose_mutator(rng, enabled_names=("bit_flip",))
        self.assertEqual(chosen, MUTATORS["bit_flip"])
        with self.assertRaises(ValueError):
            choose_mutator(rng, enabled_names=())


class CorpusLoaderTests(unittest.TestCase):
    def test_loads_recorder_dump(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.json"
            payload = {
                "session_id": "abc",
                "apdu_trace": [
                    {"index": 0, "command": "00A40004023F00", "response": "9000"},
                    {"index": 1, "command": "00B200010400000020", "response": "6A82"},
                ],
            }
            path.write_text(json.dumps(payload), "utf-8")
            corpus = load_corpus(path)
            self.assertEqual(corpus.session_id, "abc")
            self.assertEqual(corpus.command_count, 2)
            self.assertEqual(corpus.entries[0].command_bytes(), _SELECT_MF_APDU)

    def test_loads_bare_hex_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "raw.json"
            path.write_text(json.dumps(["00A40004023F00", "80CA00FA00"]), "utf-8")
            corpus = load_corpus(path)
            self.assertEqual(corpus.command_count, 2)

    def test_rejects_odd_length_hex(self) -> None:
        entry = CorpusEntry(index=0, command_hex="00A4000")
        with self.assertRaises(ValueError):
            entry.command_bytes()

    def test_rejects_non_hex_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text(json.dumps([{"command": "GARBAGE!!"}]), "utf-8")
            with self.assertRaises(ValueError):
                load_corpus(path)

    def test_filter_select_only_strips_non_select(self) -> None:
        corpus = Corpus(
            source_path=Path("/tmp/x.json"),
            session_id="t",
            entries=(
                CorpusEntry(index=0, command_hex="00A40004023F00"),
                CorpusEntry(index=1, command_hex="80CA00FA00"),
                CorpusEntry(index=2, command_hex="00A40004022FE2"),
            ),
        )
        filtered = filter_select_only(corpus)
        self.assertEqual(filtered.command_count, 2)
        for entry in filtered.entries:
            self.assertEqual(entry.command_bytes()[1], 0xA4)


class SafetyGateTests(unittest.TestCase):
    def test_gate_refuses_without_i_mean_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=False,
                allowed_iccids=build_allow_set(["89880011112222"]),
            )
            with self.assertRaises(FuzzerSafetyError) as ctx:
                assert_safety_gate(config, probed_iccid="89880011112222", probed_imsi="")
            self.assertIn("--i-mean-it", str(ctx.exception))

    def test_gate_refuses_without_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
            )
            with self.assertRaises(FuzzerSafetyError) as ctx:
                assert_safety_gate(config, probed_iccid="8900", probed_imsi="")
            self.assertIn("allowed ICCID", str(ctx.exception))

    def test_gate_refuses_mismatched_card(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
                allowed_iccids=build_allow_set(["8900FFFFFFFF"]),
            )
            with self.assertRaises(FuzzerSafetyError):
                assert_safety_gate(config, probed_iccid="8900000000", probed_imsi="")

    def test_gate_accepts_matching_iccid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
                allowed_iccids=build_allow_set(["8900ABCDEF"]),
            )
            # Case-insensitive match
            assert_safety_gate(config, probed_iccid="8900abcdef", probed_imsi="")

    def test_gate_accepts_matching_imsi(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
                allowed_imsis=build_allow_set(["001010123456789"]),
            )
            assert_safety_gate(
                config,
                probed_iccid="",
                probed_imsi="001010123456789",
            )

    def test_gate_refuses_empty_probe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
                allowed_iccids=build_allow_set(["8900"]),
            )
            with self.assertRaises(FuzzerSafetyError):
                assert_safety_gate(config, probed_iccid="", probed_imsi="")

    def test_crash_dump_root_default_lives_under_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
                allowed_iccids=build_allow_set(["8900"]),
            )
            root = resolve_crash_dump_root(config)
            self.assertTrue(str(root).startswith(str(Path(td).resolve())))
            self.assertIn("reports", str(root))

    def test_dump_crash_filename_encodes_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
                allowed_iccids=build_allow_set(["8900"]),
            )
            run_dir = create_run_dir(config, tag="unit")
            dump_path = dump_crash(
                run_dir,
                sequence_index=7,
                mutation_description="length_mangle@lc=23->drift+1=24",
                original_apdu=b"\x00\xA4\x00\x04\x02\x3F\x00",
                mutated_apdu=b"\x00\xA4\x00\x04\x24\x3F\x00",
                response_bytes=b"",
                sw=0x6F00,
                notes="crash_sw",
            )
            self.assertTrue(dump_path.is_file())
            self.assertIn("length_mangle", dump_path.name)
            self.assertIn("000007", dump_path.name)

    def test_run_dir_and_crash_file_are_operator_private_on_posix(self) -> None:
        # Session-key / APDU mutation payloads may expose card secrets;
        # the crash-dump tree must be 0o700 dirs and 0o600 files so a
        # multi-user CI host cannot read another operator's reports.
        import os
        import stat

        if hasattr(os, "chmod") is False:
            self.skipTest("platform lacks os.chmod")
        with tempfile.TemporaryDirectory() as td:
            config = SafetyConfig(
                workspace_root=Path(td),
                i_mean_it=True,
                allowed_iccids=build_allow_set(["8900"]),
            )
            run_dir = create_run_dir(config, tag="perm-check")
            dump_path = dump_crash(
                run_dir,
                sequence_index=0,
                mutation_description="bit_flip@byte=5,bit=1",
                original_apdu=b"\x00\xA4\x00\x04\x02\x3F\x00",
                mutated_apdu=b"\x00\xA4\x00\x04\x02\x3F\x02",
                response_bytes=b"",
                sw=0x6F00,
                notes="crash_sw",
            )
            try:
                dir_mode = stat.S_IMODE(run_dir.stat().st_mode)
                file_mode = stat.S_IMODE(dump_path.stat().st_mode)
            except OSError:
                self.skipTest("stat not supported on this platform")
            # Windows Python reports 0o666 regardless; only assert on POSIX.
            if os.name == "posix":
                self.assertEqual(dir_mode, 0o700)
                self.assertEqual(file_mode, 0o600)


class _FakeTransport:
    def __init__(
        self,
        *,
        iccid: str = "8988000000000000AA",
        imsi: str = "",
        responses: list[tuple[bytes, int]] | None = None,
    ) -> None:
        self._iccid = iccid
        self._imsi = imsi
        self._responses = responses or []
        self._counter = 0
        self.closed = False
        self.transmitted: list[bytes] = []

    def probe_card_identity(self) -> tuple[str, str]:
        return self._iccid, self._imsi

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        self.transmitted.append(apdu)
        if self._counter < len(self._responses):
            result = self._responses[self._counter]
            self._counter += 1
            return result
        return b"", 0x9000

    def close(self) -> None:
        self.closed = True


class RunnerTests(unittest.TestCase):
    def _build_config(self, workspace: Path) -> SafetyConfig:
        return SafetyConfig(
            workspace_root=workspace,
            i_mean_it=True,
            allowed_iccids=build_allow_set(["8988000000000000AA"]),
            max_apdus_per_run=100,
        )

    def test_runner_sends_max_apdus_when_no_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            transport = _FakeTransport()
            corpus = Corpus(
                source_path=workspace / "c.json",
                session_id="unit",
                entries=(CorpusEntry(index=0, command_hex="00A40004023F00"),),
            )
            runner = FuzzerRunner(
                config=self._build_config(workspace),
                corpus=corpus,
                transport=transport,
                seed=7,
                max_apdus=5,
            )
            stats = runner.execute()
            self.assertEqual(stats.sent, 5)
            self.assertEqual(stats.crashes, 0)
            self.assertEqual(stats.halt_reason, "max_apdus_reached")
            self.assertTrue(transport.closed)

    def test_runner_halts_on_crash_sw(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            transport = _FakeTransport(
                responses=[
                    (b"", 0x9000),
                    (b"", 0x6F00),
                    (b"", 0x9000),
                ]
            )
            corpus = Corpus(
                source_path=workspace / "c.json",
                session_id="unit",
                entries=(CorpusEntry(index=0, command_hex="00A40004023F00"),),
            )
            runner = FuzzerRunner(
                config=self._build_config(workspace),
                corpus=corpus,
                transport=transport,
                seed=3,
                max_apdus=10,
            )
            stats = runner.execute()
            self.assertEqual(stats.crashes, 1)
            self.assertEqual(stats.sent, 2)
            self.assertEqual(stats.halt_reason, "crash_sw")
            self.assertEqual(len(stats.crash_records), 1)
            self.assertTrue(stats.crash_records[0].is_file())

    def test_runner_dumps_crash_on_transport_exception(self) -> None:
        class _ExplodingTransport(_FakeTransport):
            def transmit(self, apdu: bytes) -> tuple[bytes, int]:
                raise ConnectionError("card disconnected")

        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            transport = _ExplodingTransport()
            corpus = Corpus(
                source_path=workspace / "c.json",
                session_id="unit",
                entries=(CorpusEntry(index=0, command_hex="00A40004023F00"),),
            )
            runner = FuzzerRunner(
                config=self._build_config(workspace),
                corpus=corpus,
                transport=transport,
                seed=3,
                max_apdus=5,
            )
            stats = runner.execute()
            self.assertEqual(stats.crashes, 1)
            self.assertEqual(stats.halt_reason, "transport_exception")

    def test_runner_refuses_when_safety_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            config = SafetyConfig(
                workspace_root=workspace,
                i_mean_it=False,
                allowed_iccids=build_allow_set(["8900"]),
            )
            transport = _FakeTransport()
            corpus = Corpus(
                source_path=workspace / "c.json",
                session_id="unit",
                entries=(CorpusEntry(index=0, command_hex="00A40004023F00"),),
            )
            runner = FuzzerRunner(
                config=config,
                corpus=corpus,
                transport=transport,
                seed=1,
                max_apdus=3,
            )
            with self.assertRaises(FuzzerSafetyError):
                runner.execute()
            self.assertTrue(transport.closed)
