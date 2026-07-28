from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lucebox_formal.verifier import run_verify


class VerifierTests(unittest.TestCase):
    def _workspace(self, root: Path) -> Path:
        (root / "formal").mkdir()
        (root / "server/src").mkdir(parents=True)
        (root / "formal/harness.cpp").write_text(
            "int main() { return 0; }\n", encoding="utf-8"
        )
        (root / "server/src/state.h").write_text(
            "#pragma once\n", encoding="utf-8"
        )
        manifest = root / "formal/manifest.toml"
        manifest.write_text(
            """\
schema_version = 1
[toolchain]
esbmc_version = "8.4"

[[capsules]]
id = "state"
harness = "formal/harness.cpp"
entry_function = "main"
include_dirs = ["server/src"]
timeout_seconds = 10
defines = ["CAP=2"]
nightly_defines = ["CAP=4"]
esbmc_args = ["--unwind", "4"]
trigger_paths = ["formal/**"]
mutable_paths = ["server/src/state.h"]
contract_paths = ["formal/harness.cpp"]
""",
            encoding="utf-8",
        )
        return manifest

    def _fake_esbmc(self, root: Path, result: str, exit_code: int) -> Path:
        fake = root / "fake-esbmc"
        fake.write_text(
            f"""#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ESBMC version 8.4.0"
else
  echo "{result}"
  exit {exit_code}
fi
""",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        return fake

    def test_success_report_without_git_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self._workspace(root)
            fake = self._fake_esbmc(
                root, "VERIFICATION SUCCESSFUL", 0
            )
            output = root / "results"
            with patch.dict(os.environ, {"ESBMC_PATH": str(fake)}):
                code = run_verify(manifest, "", "all", output)

            self.assertEqual(code, 0)
            report = json.loads(
                (output / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["head_sha"], "isolated-bundle")
            self.assertEqual(report["results"][0]["status"], "passed")
            self.assertTrue((output / "junit.xml").is_file())
            self.assertTrue((output / "summary.md").is_file())

    def test_only_counterexamples_create_repair_bundles(self) -> None:
        for result, exit_code, expected_code, expected_bundle in (
            ("VERIFICATION FAILED", 1, 10, True),
            ("ERROR: Timed out", 1, 11, False),
        ):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest = self._workspace(root)
                fake = self._fake_esbmc(root, result, exit_code)
                output = root / "results"
                with patch.dict(os.environ, {"ESBMC_PATH": str(fake)}):
                    code = run_verify(manifest, "", "all", output)
                bundles = list(output.glob("failure-bundle-*.tar.gz"))
                self.assertEqual(code, expected_code)
                self.assertEqual(bool(bundles), expected_bundle)


if __name__ == "__main__":
    unittest.main()
