from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lucebox_formal.manifest import ManifestError, capsule_matches, load_manifest


MANIFEST = """\
schema_version = 1

[toolchain]
esbmc_version = "8.4"
verifier_image = "example.invalid/verifier@sha256:deadbeef"
repair_image = "example.invalid/repair@sha256:deadbeef"

[[capsules]]
id = "state"
description = "state capsule"
harness = "formal/harness.cpp"
entry_function = "main"
include_dirs = ["server/src"]
timeout_seconds = 30
defines = ["CAP=2"]
nightly_defines = ["CAP=4"]
esbmc_args = ["--unwind", "4"]
trigger_paths = ["server/src/**", "formal/**"]
mutable_paths = ["server/src/state.h"]
contract_paths = ["formal/harness.cpp"]
native_test = "test_state"
native_test_source = "server/test/test_state.cpp"
"""


class ManifestTests(unittest.TestCase):
    def test_load_and_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.toml"
            path.write_text(MANIFEST, encoding="utf-8")
            manifest = load_manifest(path)
        self.assertEqual(manifest.capsules[0].id, "state")
        self.assertTrue(
            capsule_matches(
                manifest.capsules[0], ("server/src/server/state.cpp",)
            )
        )
        self.assertFalse(
            capsule_matches(manifest.capsules[0], ("README.md",))
        )

    def test_rejects_unknown_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.toml"
            path.write_text(
                MANIFEST.replace("schema_version = 1", "schema_version = 2"),
                encoding="utf-8",
            )
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_rejects_capsule_id_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.toml"
            path.write_text(
                MANIFEST.replace('id = "state"', 'id = "../../escape"'),
                encoding="utf-8",
            )
            with self.assertRaises(ManifestError):
                load_manifest(path)


if __name__ == "__main__":
    unittest.main()
