import logging
import unittest

from SCP11.shared.safe_parse import (
    reset_safe_parse_rollup,
    safe_parse,
    safe_parse_rollup_snapshot,
)


class SafeParseTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_safe_parse_rollup()

    def tearDown(self) -> None:
        reset_safe_parse_rollup()

    def test_returns_parser_result_when_parser_succeeds(self) -> None:
        result = safe_parse(
            "test.ok",
            b"\x01\x02\x03",
            lambda buf: buf[::-1],
            default=b"",
        )
        self.assertEqual(result, b"\x03\x02\x01")
        self.assertEqual(safe_parse_rollup_snapshot(), {})

    def test_returns_default_when_parser_raises(self) -> None:
        def _broken_parser(_buffer: bytes) -> bytes:
            raise ValueError("synthetic parse failure")

        result = safe_parse(
            "test.broken",
            b"\x00\x11\x22\x33",
            _broken_parser,
            default=b"fallback",
        )
        self.assertEqual(result, b"fallback")

    def test_rollup_counts_distinct_label_and_exception_pairs(self) -> None:
        def _broken(exc_cls):
            def _inner(_buffer: bytes):
                raise exc_cls("boom")

            return _inner

        safe_parse("label.alpha", b"\xAA", _broken(ValueError), default=None)
        safe_parse("label.alpha", b"\xAA", _broken(ValueError), default=None)
        safe_parse("label.alpha", b"\xAA", _broken(TypeError), default=None)
        safe_parse("label.beta", b"\xAA", _broken(ValueError), default=None)

        snapshot = safe_parse_rollup_snapshot()
        self.assertEqual(snapshot[("label.alpha", "ValueError")], 2)
        self.assertEqual(snapshot[("label.alpha", "TypeError")], 1)
        self.assertEqual(snapshot[("label.beta", "ValueError")], 1)

    def test_only_first_failure_per_pair_logs_warning(self) -> None:
        def _broken(_buffer: bytes):
            raise ValueError("again")

        with self.assertLogs("SCP11.shared.safe_parse", level="WARNING") as captured:
            safe_parse("label.first", b"\xFF", _broken, default=None)
            safe_parse("label.first", b"\xFF", _broken, default=None)
            safe_parse("label.first", b"\xFF", _broken, default=None)

        warning_records = [
            record for record in captured.records if record.levelno == logging.WARNING
        ]
        self.assertEqual(len(warning_records), 1)
        self.assertIn("label.first", warning_records[0].getMessage())
        self.assertEqual(safe_parse_rollup_snapshot()[("label.first", "ValueError")], 3)

    def test_handles_none_buffer_without_raising(self) -> None:
        result = safe_parse(
            "test.none",
            None,
            lambda buf: len(buf),
            default=-1,
        )
        self.assertEqual(result, 0)

    def test_preview_truncates_long_buffers_in_debug_log(self) -> None:
        def _broken(_buffer: bytes):
            raise RuntimeError("truncate me")

        long_buffer = bytes(range(64))
        with self.assertLogs("SCP11.shared.safe_parse", level="DEBUG") as captured:
            safe_parse(
                "test.truncate",
                long_buffer,
                _broken,
                default=None,
                preview_bytes=8,
            )

        debug_messages = [record.getMessage() for record in captured.records]
        joined = "\n".join(debug_messages)
        self.assertIn("0001020304050607", joined)
        self.assertIn("+56 more", joined)


if __name__ == "__main__":
    unittest.main()
