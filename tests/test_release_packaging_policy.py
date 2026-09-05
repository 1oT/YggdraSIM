# SPDX-License-Identifier: GPL-3.0-or-later
"""Release-boundary regression tests for bundles, wheels, and metadata."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts.release import source_boundary
from scripts.release import verify_sdist as sdist_verifier
from scripts.release import verify_wheel as wheel_verifier


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(relative_path: str, module_name: str):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bundle_data = _load(
    "scripts/release/prepare_bundle_data.py",
    "test_prepare_bundle_data",
)
release_validation = _load(
    "scripts/release/validate_release.py",
    "test_validate_release",
)
sbom_generator = _load(
    "scripts/release/generate_sbom.py",
    "test_generate_sbom",
)
class BundleDataPolicyTests(unittest.TestCase):
    def test_manifest_sources_are_git_tracked_in_checkout(self) -> None:
        """Keep operator-local or ignored files out of release manifests."""

        manifest = json.loads(
            (REPO_ROOT / "scripts/release/bundle-data.json").read_text(
                encoding="utf-8"
            )
        )
        manifest_paths = {entry["path"] for entry in manifest["entries"]}

        try:
            checkout = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except FileNotFoundError:
            self.skipTest("Git is unavailable; source archives have no index")
        if checkout.returncode != 0 or checkout.stdout.strip() != "true":
            self.skipTest("not running from a Git checkout")

        tracked_result = subprocess.run(
            ["git", "ls-files", "-z", "--", *sorted(manifest_paths)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(
            tracked_result.returncode,
            0,
            msg=tracked_result.stderr,
        )
        tracked_paths = {
            path for path in tracked_result.stdout.split("\0") if path
        }
        self.assertEqual(
            sorted(manifest_paths - tracked_paths),
            [],
            msg="bundle-data sources must be committed before publication",
        )

    def test_clean_and_full_stage_only_manifest_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stage_root = Path(temp_dir)
            clean_datas, clean_manifest = bundle_data.prepare_bundle_data(
                REPO_ROOT,
                "clean",
                stage_dir=stage_root / "clean",
            )
            full_datas, full_manifest = bundle_data.prepare_bundle_data(
                REPO_ROOT,
                "full",
                stage_dir=stage_root / "full",
            )

            clean_payload = json.loads(clean_manifest.read_text(encoding="utf-8"))
            full_payload = json.loads(full_manifest.read_text(encoding="utf-8"))
            clean_paths = {item["path"] for item in clean_payload["files"]}
            full_paths = {item["path"] for item in full_payload["files"]}

            self.assertNotIn("Tools/HilBridge/RSPRO.asn", clean_paths)
            self.assertIn("Tools/HilBridge/RSPRO.asn", full_paths)
            self.assertEqual(len(clean_datas), len(clean_paths) + 1)
            self.assertEqual(len(full_datas), len(full_paths) + 1)
            self.assertTrue(
                all(
                    set(item) == {"mode", "path", "sha256", "size"}
                    and item["mode"] == "0644"
                    for item in clean_payload["files"] + full_payload["files"]
                )
            )
            for path_text in clean_paths | full_paths:
                self.assertNotIn(
                    Path(path_text).parts[0].casefold(),
                    bundle_data.PROHIBITED_TOP_LEVEL,
                )

    def test_python_source_boundary_rejects_ignored_nested_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package = root / "Tools" / "Published"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
            ignored = package / "operator_local.py"
            ignored.write_text("SECRET = 'canary'\n", encoding="utf-8")
            (root / ".git").mkdir()
            with mock.patch.object(
                bundle_data.subprocess,
                "run",
                return_value=mock.Mock(
                    returncode=0,
                    stdout=b"Tools/Published/operator_local.py\0",
                    stderr=b"",
                ),
            ):
                with self.assertRaisesRegex(
                    bundle_data.BundleDataError,
                    "ignored Python source",
                ):
                    bundle_data.assert_no_ignored_python_sources(
                        root,
                        ["Tools.Published"],
                    )

    def test_python_source_boundary_rejects_canary_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package = root / "published"
            package.mkdir()
            (package / "__init__.py").write_text(
                "VALUE = 'release-source-canary'\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"YGGDRASIM_RELEASE_CANARIES": "release-source-canary"},
            ):
                with self.assertRaisesRegex(
                    bundle_data.BundleDataError,
                    "canary",
                ):
                    bundle_data.assert_no_ignored_python_sources(
                        root,
                        ["published"],
                    )

    def test_rejects_symlink_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repo"
            outside = Path(temp_dir) / "outside.txt"
            root.mkdir()
            outside.write_text("public-looking but outside", encoding="utf-8")
            (root / "safe").mkdir()
            (root / "safe" / "linked.txt").symlink_to(outside)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "entries": [{"path": "safe/linked.txt"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(bundle_data.BundleDataError):
                bundle_data.prepare_bundle_data(
                    root,
                    "clean",
                    stage_dir=Path(temp_dir) / "stage",
                    manifest_path=manifest,
                )

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repo"
            root.mkdir()
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "entries": [{"path": "../outside.txt"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(bundle_data.BundleDataError):
                bundle_data.prepare_bundle_data(
                    root,
                    "clean",
                    stage_dir=Path(temp_dir) / "stage",
                    manifest_path=manifest,
                )

    def test_release_canary_blocks_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repo"
            (root / "safe").mkdir(parents=True)
            (root / "safe" / "data.txt").write_text("UNIQUE-CANARY", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "entries": [{"path": "safe/data.txt"}],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"YGGDRASIM_RELEASE_CANARIES": "UNIQUE-CANARY"},
            ):
                with self.assertRaises(bundle_data.BundleDataError):
                    bundle_data.prepare_bundle_data(
                        root,
                        "clean",
                        stage_dir=Path(temp_dir) / "stage",
                        manifest_path=manifest,
                    )

    def test_refuses_to_delete_unowned_stage_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stage = Path(temp_dir) / "stage"
            stage.mkdir()
            operator_file = stage / "operator-owned.txt"
            operator_file.write_text("preserve me", encoding="utf-8")
            with self.assertRaisesRegex(
                bundle_data.BundleDataError,
                "unowned non-empty",
            ):
                bundle_data.prepare_bundle_data(
                    REPO_ROOT,
                    "clean",
                    stage_dir=stage,
                )
            self.assertEqual(
                operator_file.read_text(encoding="utf-8"),
                "preserve me",
            )


class ReleaseMetadataTests(unittest.TestCase):
    def test_operator_ca_lookup_caches_are_explicitly_excluded(self) -> None:
        manifest_lines = {
            line.strip()
            for line in (REPO_ROOT / "MANIFEST.in")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        }
        self.assertIn("exclude SCP11/es9_ca_lookup.json", manifest_lines)
        self.assertIn(
            "exclude SCP11/live/es9_ca_lookup.json",
            manifest_lines,
        )

        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            pyproject = tomllib.load(handle)
        excluded = pyproject["tool"]["setuptools"]["exclude-package-data"]
        self.assertEqual(excluded["SCP11"], ["es9_ca_lookup.json"])
        self.assertEqual(excluded["SCP11.live"], ["es9_ca_lookup.json"])

    def test_stale_ipad_discovery_fixture_is_excluded_from_sdist(self) -> None:
        manifest_lines = {
            line.strip()
            for line in (REPO_ROOT / "MANIFEST.in")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        }
        self.assertIn(
            "exclude SCP11/eim_local/eim_packages/ipad_discover_package.json",
            manifest_lines,
        )
        bundle_manifest = json.loads(
            (REPO_ROOT / "scripts/release/bundle-data.json").read_text(
                encoding="utf-8"
            )
        )
        approved = {entry["path"] for entry in bundle_manifest["entries"]}
        self.assertNotIn(
            "SCP11/eim_local/eim_packages/ipad_discover_package.json",
            approved,
        )

    def test_release_verifier_scripts_support_direct_cli_execution(self) -> None:
        for relative_path in (
            "scripts/release/source_boundary.py",
            "scripts/release/verify_sdist.py",
            "scripts/release/verify_wheel.py",
        ):
            completed = subprocess.run(
                [sys.executable, relative_path, "--help"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"{relative_path}: {completed.stderr}",
            )
            self.assertIn("usage:", completed.stdout.lower())

    def test_reviewed_package_manifest_matches_setuptools_discovery(self) -> None:
        reviewed = list(source_boundary.load_reviewed_packages())
        additions = set(source_boundary.load_reviewed_source_additions())
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            pyproject = tomllib.load(handle)
        discovery = pyproject["tool"]["setuptools"]["packages"]["find"]

        self.assertTrue(discovery["namespaces"])
        self.assertEqual(discovery["include"], reviewed)
        self.assertNotIn("Tools.OperatorLocalTool", reviewed)
        self.assertFalse(any("*" in package for package in reviewed))
        self.assertNotIn("Tools/OperatorLocalTool/server.py", additions)
        self.assertTrue(
            additions
            <= set(source_boundary.reviewed_python_sources(REPO_ROOT, reviewed))
        )

    def test_explicit_source_addition_allows_only_that_untracked_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package = root / "public"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            reviewed_addition = package / "reviewed.py"
            reviewed_addition.write_text("VALUE = 1\n", encoding="utf-8")
            unreviewed = package / "operator_local.py"
            unreviewed.write_text("PRIVATE = True\n", encoding="utf-8")
            (root / ".git").mkdir()
            with mock.patch.object(
                source_boundary.subprocess,
                "run",
                return_value=mock.Mock(
                    returncode=0,
                    stdout=b"public/__init__.py\0",
                    stderr=b"",
                ),
            ):
                with self.assertRaisesRegex(
                    source_boundary.SourceBoundaryError,
                    "operator_local.py",
                ):
                    source_boundary.assert_no_untracked_reviewed_sources(
                        root,
                        ("public",),
                        source_additions=("public/reviewed.py",),
                    )

    def test_source_boundary_rejects_ignored_file_in_reviewed_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package = root / "public"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            ignored = package / "operator_local.py"
            ignored.write_text("SECRET = 'canary'\n", encoding="utf-8")
            (root / ".git").mkdir()
            with mock.patch.object(
                source_boundary.subprocess,
                "run",
                return_value=mock.Mock(
                    returncode=0,
                    stdout=b"public/operator_local.py\0",
                    stderr=b"",
                ),
            ):
                with self.assertRaisesRegex(
                    source_boundary.SourceBoundaryError,
                    "ignored Python source",
                ):
                    source_boundary.assert_no_ignored_reviewed_python_sources(
                        root,
                        ("public",),
                    )

    def test_source_boundary_rejects_untracked_file_in_reviewed_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package = root / "public"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            local_source = package / "operator_local.py"
            local_source.write_text("PRIVATE = True\n", encoding="utf-8")
            (root / ".git").mkdir()
            with mock.patch.object(
                source_boundary.subprocess,
                "run",
                return_value=mock.Mock(
                    returncode=0,
                    stdout=b"public/__init__.py\0",
                    stderr=b"",
                ),
            ):
                with self.assertRaisesRegex(
                    source_boundary.SourceBoundaryError,
                    "untracked file",
                ):
                    source_boundary.assert_no_untracked_reviewed_sources(
                        root,
                        ("public",),
                    )

    def test_artifact_python_boundary_rejects_local_tool_namespace(self) -> None:
        with self.assertRaisesRegex(
            source_boundary.SourceBoundaryError,
            "unreviewed package 'Tools.OperatorLocalTool'",
        ):
            source_boundary.assert_artifact_python_path_is_reviewed(
                "Tools/OperatorLocalTool/server.py"
            )

    def test_tag_must_exactly_match_project_version(self) -> None:
        # The literals track pyproject's version deliberately: deriving them
        # from project_version() would restate validate_tag's own comparison
        # and pass even with the function gutted. Bump them with the release.
        self.assertEqual(
            release_validation.validate_tag(REPO_ROOT, "v2.1.0"),
            "2.1.0",
        )
        with self.assertRaises(release_validation.ReleaseValidationError):
            release_validation.validate_tag(REPO_ROOT, "v2.1.1")

    def test_archive_listing_scan_matches_real_directory_components(self) -> None:
        listing = (
            "Contents of 'app' (PKG/CArchive):\n"
            "position, length, uncompressed_length, is_compressed, typecode, name\n"
            "123, 42, 42, 1, 'x', 'plugins/local_operator.py'\n"
            "456, 42, 42, 1, 'x', 'myplugins/public.py'\n"
            "789, 42, 42, 1, 'x', 'pySim/esim/asn1/saip.asn'\n"
        )
        self.assertEqual(
            release_validation._forbidden_listing_components(listing),
            ["plugins"],
        )

    def test_archive_listing_allows_known_qt_plugin_directories(self) -> None:
        listing = (
            "Contents of 'app' (PKG/CArchive):\n"
            "position, length, uncompressed_length, is_compressed, typecode, name\n"
            "123, 42, 42, 1, 'x', 'PyQt6/Qt6/plugins/platforms/libqxcb.so'\n"
            "456, 42, 42, 1, 'x', 'PyQt5/Qt5/plugins/webview/libqt.so'\n"
            "789, 42, 42, 1, 'x', 'pySim/esim/asn1/saip.asn'\n"
        )
        self.assertEqual(
            release_validation._forbidden_listing_components(listing),
            [],
        )

    def test_archive_listing_rejects_other_nested_sensitive_directories(
        self,
    ) -> None:
        listing = (
            "Contents of 'app' (PKG/CArchive):\n"
            "position, length, uncompressed_length, is_compressed, typecode, name\n"
            "123, 42, 42, 1, 'x', 'package/plugins/operator.py'\n"
            "456, 42, 42, 1, 'x', 'vendor/reports/schema.json'\n"
            "789, 42, 42, 1, 'x', 'package/state/defaults.json'\n"
            "101, 42, 42, 1, 'x', 'public/workspace/index.html'\n"
            "112, 42, 42, 1, 'x', 'assets/yggdrasim-data/icon.svg'\n"
        )
        self.assertEqual(
            release_validation._forbidden_listing_components(listing),
            [
                "plugins",
                "reports",
                "state",
                "workspace",
                "yggdrasim-data",
            ],
        )

    def test_archive_listing_normalizes_windows_separators(self) -> None:
        listing = (
            "Contents of 'app' (PKG/CArchive):\n"
            "position, length, uncompressed_length, is_compressed, typecode, name\n"
            r"123, 42, 42, 1, 'x', 'plugins\\local_operator.py'" "\n"
            r"456, 42, 42, 1, 'x', 'STATE\\remote-rig.json'" "\n"
            r"789, 42, 42, 1, 'x', 'package\\plugins\\platform.dll'" "\n"
        )
        self.assertEqual(
            release_validation._forbidden_listing_components(listing),
            ["plugins", "state"],
        )

    def test_archive_listing_rejects_unsafe_member_paths(self) -> None:
        header = (
            "Contents of 'app' (PKG/CArchive):\n"
            "position, length, uncompressed_length, is_compressed, typecode, name\n"
        )
        for member_path in (
            "../plugins/operator.py",
            "safe/../plugins/operator.py",
            r".\plugins\operator.py",
            "/plugins/operator.py",
            r"C:\plugins\operator.py",
            r"\\server\share\operator.py",
        ):
            with self.subTest(member_path=member_path):
                row = f"123, 42, 42, 1, 'x', {member_path!r}\n"
                with self.assertRaisesRegex(
                    release_validation.ReleaseValidationError,
                    "unsafe path",
                ):
                    release_validation._forbidden_listing_components(header + row)

    def test_archive_listing_parser_fails_closed(self) -> None:
        header = (
            "Contents of 'app' (PKG/CArchive):\n"
            "position, length, uncompressed_length, is_compressed, typecode, name\n"
        )
        with self.assertRaisesRegex(
            release_validation.ReleaseValidationError,
            "unsupported .* format",
        ):
            release_validation._forbidden_listing_components("unexpected output")
        with self.assertRaisesRegex(
            release_validation.ReleaseValidationError,
            "no member records",
        ):
            release_validation._forbidden_listing_components(header)
        with self.assertRaisesRegex(
            release_validation.ReleaseValidationError,
            "malformed .* row",
        ):
            release_validation._forbidden_listing_components(
                header + "this is not a member row\n"
            )

    def test_archive_listing_uses_active_python_instead_of_path_launcher(self) -> None:
        completed = mock.Mock(returncode=0, stdout="archive listing", stderr="")
        with mock.patch.object(
            release_validation.subprocess,
            "run",
            return_value=completed,
        ) as mocked_run:
            listing = release_validation._archive_listing(Path("release artifact"))

        self.assertEqual(listing, "archive listing")
        command = mocked_run.call_args.args[0]
        self.assertEqual(
            command[:3],
            [
                sys.executable,
                "-m",
                "PyInstaller.utils.cliutils.archive_viewer",
            ],
        )
        self.assertEqual(command[-2:], ["-l", "release artifact"])

    def test_spec_uses_generated_runtime_metadata_without_source_stamp(self) -> None:
        text = (REPO_ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")
        self.assertIn("runtime_hooks=[str(BUILD_METADATA_HOOK)]", text)
        self.assertIn('"osmocom"', text)
        self.assertNotIn('"pyosmocom"', text)
        self.assertNotIn('ROOT / "yggdrasim_common" / "_build_flavor.py"', text)
        self.assertNotIn('package_candidates.append("Tools")', text)
        self.assertIn("assert_no_ignored_python_sources(ROOT, package_candidates)", text)

    def test_lock_contains_commit_pinned_pysim_and_hashes(self) -> None:
        with (REPO_ROOT / "uv.lock").open("rb") as handle:
            lock = tomllib.load(handle)
        pysim = next(item for item in lock["package"] if item["name"] == "pysim")
        self.assertIn("c50f4b4a0222a964710ce3124a66fe13c804be65", pysim["source"]["git"])
        registry_packages = [
            item
            for item in lock["package"]
            if item.get("source", {}).get("registry")
        ]
        self.assertTrue(registry_packages)
        self.assertTrue(
            all(item.get("wheels") or item.get("sdist") for item in registry_packages)
        )

    def test_sbom_is_deterministic_and_lists_pinned_pysim(self) -> None:
        first = sbom_generator.build_sbom(REPO_ROOT / "uv.lock", "yggdrasim", "2.0.0")
        second = sbom_generator.build_sbom(REPO_ROOT / "uv.lock", "yggdrasim", "2.0.0")
        self.assertEqual(first, second)
        pysim = next(
            item for item in first["components"] if item["name"] == "pysim"
        )
        properties = {
            item["name"]: item["value"] for item in pysim.get("properties", [])
        }
        self.assertIn(
            "c50f4b4a0222a964710ce3124a66fe13c804be65",
            properties["yggdrasim:lock-source:git"],
        )

    def test_clean_requirements_do_not_install_hil_dependency(self) -> None:
        requirements = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertNotIn("\npyudev", requirements)
        self.assertIn(
            "pysim.git@c50f4b4a0222a964710ce3124a66fe13c804be65",
            requirements.casefold(),
        )

    def test_wheel_verifier_rejects_unlisted_resource(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "entries": [{"path": "example/approved.json"}],
                    }
                ),
                encoding="utf-8",
            )
            wheel = root / "example.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("SCP11/__init__.py", "VALUE = 1\n")
                archive.writestr("example/approved.json", "{}")
                archive.writestr("SCP11/unlisted.json", "{}")
                archive.writestr("example-1.0.dist-info/METADATA", "Name: example\n")
            with mock.patch.object(
                wheel_verifier,
                "tracked_reviewed_python_sources",
                return_value=("SCP11/__init__.py",),
            ):
                with self.assertRaisesRegex(RuntimeError, "outside release allowlist"):
                    wheel_verifier.verify_wheel(wheel, manifest)

    def test_wheel_verifier_rejects_local_tool_python(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "entries": []}),
                encoding="utf-8",
            )
            wheel = root / "example.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "Tools/OperatorLocalTool/server.py",
                    "PRIVATE = True\n",
                )
            with mock.patch.object(
                wheel_verifier,
                "tracked_reviewed_python_sources",
                return_value=(),
            ):
                with self.assertRaisesRegex(
                    source_boundary.SourceBoundaryError,
                    "Tools.OperatorLocalTool",
                ):
                    wheel_verifier.verify_wheel(wheel, manifest)

    def test_wheel_verifier_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "entries": []}),
                encoding="utf-8",
            )
            wheel = root / "example.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("../outside.py", "VALUE = 1\n")
            with mock.patch.object(
                wheel_verifier,
                "tracked_reviewed_python_sources",
                return_value=(),
            ):
                with self.assertRaisesRegex(RuntimeError, "unsafe wheel path"):
                    wheel_verifier.verify_wheel(wheel, manifest)

    def test_sdist_verifier_rejects_unlisted_package_resource(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "entries": [{"path": "SCP11/approved.json"}],
                    }
                ),
                encoding="utf-8",
            )
            package_root = root / "example-1.0"
            (package_root / "SCP11").mkdir(parents=True)
            (package_root / "SCP11" / "__init__.py").write_text("", encoding="utf-8")
            (package_root / "SCP11" / "approved.json").write_text("{}", encoding="utf-8")
            (package_root / "SCP11" / "unlisted.json").write_text("{}", encoding="utf-8")
            archive_path = root / "example-1.0.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(package_root, arcname=package_root.name)
            with mock.patch.object(
                sdist_verifier,
                "tracked_reviewed_python_sources",
                return_value=("SCP11/__init__.py",),
            ):
                with self.assertRaisesRegex(RuntimeError, "outside release allowlist"):
                    sdist_verifier.verify_sdist(archive_path, manifest)

    def test_sdist_verifier_rejects_local_tool_python(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "entries": []}),
                encoding="utf-8",
            )
            package_root = root / "example-1.0"
            local_tool = package_root / "Tools" / "OperatorLocalTool" / "server.py"
            local_tool.parent.mkdir(parents=True)
            local_tool.write_text("PRIVATE = True\n", encoding="utf-8")
            archive_path = root / "example-1.0.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(package_root, arcname=package_root.name)
            with mock.patch.object(
                sdist_verifier,
                "tracked_reviewed_python_sources",
                return_value=(),
            ):
                with self.assertRaisesRegex(
                    source_boundary.SourceBoundaryError,
                    "Tools.OperatorLocalTool",
                ):
                    sdist_verifier.verify_sdist(archive_path, manifest)

    def test_sdist_verifier_rejects_unreviewed_release_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "entries": []}),
                encoding="utf-8",
            )
            package_root = root / "example-1.0"
            helper = package_root / "scripts" / "release" / "private_publish.py"
            helper.parent.mkdir(parents=True)
            helper.write_text("PRIVATE = True\n", encoding="utf-8")
            archive_path = root / "example-1.0.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(package_root, arcname=package_root.name)
            with mock.patch.object(
                sdist_verifier,
                "tracked_reviewed_python_sources",
                return_value=(),
            ):
                with self.assertRaisesRegex(
                    source_boundary.SourceBoundaryError,
                    "unreviewed release helper",
                ):
                    sdist_verifier.verify_sdist(archive_path, manifest)


if __name__ == "__main__":
    unittest.main()
