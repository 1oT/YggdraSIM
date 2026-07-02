# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the shell tab-completion surface, especially the TOKENS
namespace and token-name completion for destructive commands.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.shell import ProfilePackageShell


class _CompletionHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self._workspace_root = Path(self._workspace.name)
        profile_dir = self._workspace_root / "Workspace" / "SAIP" / "profile"
        profile_dir.mkdir(parents=True)
        template_path = profile_dir / "tpl.json"
        template_path.write_text(
            json.dumps(
                {
                    "__ygg_token_defs__": {
                        "ICCID": {"hex": "AA"},
                        "IMSI": "BB",
                        "KI": "CC",
                    },
                    "sections": {},
                }
            ),
            encoding="utf-8",
        )
        self.shell = ProfilePackageShell(workspace_root=self._workspace_root)

    def tearDown(self) -> None:
        self._workspace.cleanup()


class TokensNamespaceCompletionTests(_CompletionHarness):

    def test_empty_argument_lists_all_subcommands(self) -> None:
        options = self.shell._completion_options_for("TOKENS", "")
        self.assertIn("LIST ", options)
        self.assertIn("ADD ", options)
        self.assertIn("RENAME ", options)
        self.assertIn("RETOKENISE-LENGTHS ", options)

    def test_prefix_filters_subcommands(self) -> None:
        options = self.shell._completion_options_for("TOKENS", "LI")
        self.assertEqual(options, ["LIST "])

    def test_after_subcommand_completes_file_paths(self) -> None:
        options = self.shell._completion_options_for("TOKENS", "LIST ")
        self.assertIn("tpl.json", options)


class TokenNameCompletionTests(_CompletionHarness):

    def test_remove_token_offers_existing_names(self) -> None:
        options = self.shell._completion_options_for(
            "REMOVE-TOKEN", "tpl.json "
        )
        self.assertIn("ICCID ", options)
        self.assertIn("IMSI ", options)
        self.assertIn("KI ", options)

    def test_remove_token_filters_by_prefix(self) -> None:
        options = self.shell._completion_options_for(
            "REMOVE-TOKEN", "tpl.json I"
        )
        self.assertEqual(options, ["ICCID ", "IMSI "])

    def test_rename_token_completes_old_name_only(self) -> None:
        options = self.shell._completion_options_for(
            "RENAME-TOKEN", "tpl.json K"
        )
        self.assertEqual(options, ["KI "])

    def test_flag_prefix_limits_to_safety_flags(self) -> None:
        options = self.shell._completion_options_for(
            "REMOVE-TOKEN", "tpl.json ICCID --"
        )
        self.assertIn("--dry-run ", options)
        self.assertIn("--no-backup ", options)


class HelpTopicCompletionTests(_CompletionHarness):

    def test_help_lists_topics(self) -> None:
        options = self.shell._completion_options_for("HELP", "")
        self.assertIn("TOKENS ", options)
        self.assertIn("TEMPLATE ", options)
        self.assertIn("EDIT ", options)
        self.assertIn("LINT ", options)

    def test_help_prefix_filters(self) -> None:
        options = self.shell._completion_options_for("HELP", "T")
        self.assertEqual(sorted(options), sorted(["TOKENS ", "TEMPLATE ", "TOPICS "]))


if __name__ == "__main__":
    unittest.main()
