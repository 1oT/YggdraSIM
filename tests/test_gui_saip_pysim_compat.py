# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the pySim compatibility shim used by the SAIP GUI.

Guards :func:`yggdrasim_common.gui_server.actions.saip._patch_pysim_profile_element`.
Upstream pySim's ``ProfileElement.from_der`` classmethod calls
``ProfileElement(decoded, pe_sequence=...)`` before assigning
``inst.type`` for PE types not registered in ``class_for_petype``. When
the ASN.1 decoder hands back a falsy ``decoded`` for that PE (empty
OrderedDict / None), the ``__init__`` else-branch dereferences
``self.header_name`` which in turn reads ``self.type`` — and crashes
with ``AttributeError: 'ProfileElement' object has no attribute 'type'``.

The patch installed by ``_ensure_pysim_importable()`` converts that
specific failure into a benign no-op: ``self.decoded`` still becomes an
empty dict, the header bootstrap is skipped, and the caller then
assigns ``inst.type`` as it always did. Registered subclasses, which
carry ``type`` as a class attribute, keep their existing behaviour.
"""

import importlib
import unittest


class PysimProfileElementPatchTests(unittest.TestCase):
    """Verify the monkey-patch keeps backwards-compatible semantics."""

    def setUp(self) -> None:
        saip_actions = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )
        # Force a fresh re-patch check so a previously-patched global
        # doesn't short-circuit the install under test.
        saip_actions._PYSIM_PROFILE_ELEMENT_PATCHED = False
        saip_actions._ensure_pysim_importable()
        self.saip_actions = saip_actions

    def _profile_element_cls(self):
        from pySim.esim.saip import ProfileElement

        return ProfileElement

    def test_patch_flag_is_set_after_ensure_importable(self) -> None:
        self.assertTrue(self.saip_actions._PYSIM_PROFILE_ELEMENT_PATCHED)
        cls = self._profile_element_cls()
        self.assertTrue(
            getattr(cls.__init__, "_yggdrasim_patched", False),
            "ProfileElement.__init__ must carry the patch sentinel",
        )

    def test_ctor_with_none_decoded_does_not_crash(self) -> None:
        """The regression: ``ProfileElement(None)`` used to raise here."""
        cls = self._profile_element_cls()
        inst = cls(decoded=None, pe_sequence=None)
        self.assertFalse(
            hasattr(inst, "type"),
            "base ProfileElement must not magic-assign a type attribute",
        )
        self.assertEqual(dict(inst.decoded), {})

    def test_caller_can_assign_type_after_ctor(self) -> None:
        """Matches the pySim ``from_der`` fallback sequence."""
        cls = self._profile_element_cls()
        inst = cls(decoded=None, pe_sequence=None)
        inst.type = "opt-foo"
        self.assertEqual(inst.header_name, "optfoo-header")

    def test_non_empty_decoded_preserves_upstream_behaviour(self) -> None:
        cls = self._profile_element_cls()
        payload = {"some": "data"}
        inst = cls(decoded=payload, pe_sequence=None)
        self.assertIs(inst.decoded, payload)

    def test_registered_subclass_still_initialises(self) -> None:
        from pySim.esim.saip import ProfileElementPin

        inst = ProfileElementPin({"pin-Header": {"identification": None}})
        # Subclasses declare ``type`` as a class attribute; the patch
        # must not shadow or clobber that.
        self.assertEqual(inst.type, "pinCodes")

    def test_patch_is_idempotent(self) -> None:
        before = self._profile_element_cls().__init__
        self.saip_actions._patch_pysim_profile_element()
        self.saip_actions._patch_pysim_profile_element()
        after = self._profile_element_cls().__init__
        self.assertIs(before, after)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
