import unittest

from Tools.ProfilePackage.saip_transcode_sync import (
    der_byte_range_to_json_editor_range,
    enclosing_json_value_span,
    json_editor_range_to_der_byte_range,
    scan_json_list_items,
    scan_json_object_members,
)


class SaipTranscodeSyncTests(unittest.TestCase):
    def test_enclosing_finds_inner_object(self) -> None:
        text = """{
  "sections": {
    "mf": {
      "inner": {"a": 1},
      "x": 2
    }
  }
}"""
        inner_open = text.find('"inner"')
        colon = text.find(":", inner_open)
        brace = text.find("{", colon)
        lo = text.find('"a"', brace)
        s, e = enclosing_json_value_span(text, lo, lo)
        frag = text[s:e]
        self.assertTrue(frag.strip().startswith("{"))
        self.assertIn('"a"', frag)
        self.assertNotIn('"sections"', frag)

    def test_enclosing_array_element(self) -> None:
        text = '["aa", {"k": "v"}]'
        obj = text.find('{"k"')
        idx = obj + 1
        s, e = enclosing_json_value_span(text, idx, idx)
        frag = text[s:e]
        self.assertEqual(frag, '{"k": "v"}')

    def test_scan_json_object_members_handles_partial_edit_without_raising(self) -> None:
        text = '{"sections": {"mf": {"a": 1}, '
        members = scan_json_object_members(text, text.find("{", text.find('"sections"')), len(text))

        self.assertEqual(len(members), 1)
        self.assertEqual(members[0][0], "mf")

    def test_scan_json_list_items_handles_partial_edit_without_raising(self) -> None:
        text = '[{"a": 1}, '
        items = scan_json_list_items(text, 0, len(text))

        self.assertEqual(len(items), 1)
        self.assertEqual(text[items[0][0] : items[0][1]], '{"a": 1}')

    def test_partial_json_range_maps_to_partial_der_range(self) -> None:
        keys = ["mf"]
        spans = {"mf": (4, 12, 32)}
        ranges_by_key = {"mf": (0, 20)}

        byte_range = json_editor_range_to_der_byte_range(
            keys,
            spans,
            ranges_by_key,
            18,
            20,
            empty_selection=False,
        )

        self.assertIsNotNone(byte_range)
        assert byte_range is not None
        self.assertGreater(byte_range[0], 0)
        self.assertLess(byte_range[1], 20)

    def test_partial_der_range_maps_to_partial_json_range(self) -> None:
        keys = ["mf"]
        spans = {"mf": (4, 12, 32)}
        ranges_by_key = {"mf": (0, 20)}

        json_range = der_byte_range_to_json_editor_range(
            keys,
            spans,
            ranges_by_key,
            6,
            8,
        )

        self.assertIsNotNone(json_range)
        assert json_range is not None
        self.assertGreater(json_range[0], 12)
        self.assertLess(json_range[1], 32)


if __name__ == "__main__":
    unittest.main()
