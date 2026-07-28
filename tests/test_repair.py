from __future__ import annotations

import json
import os
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from lucebox_formal.repair import _esbmc_ai_model_class, run_validate
from lucebox_formal.verifier import run_verify


class ValidationTests(unittest.TestCase):
    def test_candidate_is_accepted_only_after_secretless_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
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
            fake = root / "fake-esbmc"
            fake.write_text(
                """#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ESBMC version 8.4.0"
elif [ "$FAKE_RESULT" = "success" ]; then
  echo "VERIFICATION SUCCESSFUL"
else
  printf '%s\n' '<html>counterexample</html>' > report-1.html
  echo "VERIFICATION FAILED"
  exit 1
fi
""",
                encoding="utf-8",
            )
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

            failed = root / "failed"
            with patch.dict(
                os.environ,
                {
                    "ESBMC_PATH": str(fake),
                    "FAKE_RESULT": "failure",
                },
            ):
                self.assertEqual(run_verify(manifest, "", "all", failed), 10)
            bundle = next(failed.glob("failure-bundle-*.tar.gz"))
            with tarfile.open(bundle, "r:gz") as archive:
                failure = json.load(archive.extractfile("failure.json"))
            self.assertIn(
                "formal/manifest.toml", failure["contract_hashes"]
            )

            # Deliberately incorrect hunk counts exercise the validator's
            # safe recounting of model-generated unified diffs.
            candidate = root / "candidate.patch"
            candidate.write_text(
                """\
diff --git a/server/src/state.h b/server/src/state.h
--- a/server/src/state.h
+++ b/server/src/state.h
@@ -1,9 +1,10 @@
 #pragma once
+// validated candidate
""",
                encoding="utf-8",
            )
            accepted = root / "accepted"
            with patch.dict(
                os.environ,
                {
                    "ESBMC_PATH": str(fake),
                    "FAKE_RESULT": "success",
                    "OPENAI_API_KEY": "must-not-reach-subprocesses",
                },
            ):
                self.assertEqual(
                    run_validate(bundle, candidate, accepted), 0
                )
            report = json.loads(
                (accepted / "validation-report.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(report["successful"])
            self.assertFalse(
                report["validator_received_model_credentials"]
            )
            self.assertTrue((accepted / "candidate.patch").is_file())

            rejected = root / "rejected"
            with patch.dict(
                os.environ,
                {
                    "ESBMC_PATH": str(fake),
                    "FAKE_RESULT": "failure",
                },
            ):
                self.assertEqual(
                    run_validate(bundle, candidate, rejected), 20
                )
            self.assertTrue(
                (
                    rejected
                    / "counterexamples/state/report-1.html"
                ).is_file()
            )


class RepairDependencyTests(unittest.TestCase):
    def test_esbmc_ai_config_does_not_reparse_adapter_cli(self) -> None:
        calls: list[dict] = []

        class FakeConfig:
            def __init__(self, **kwargs) -> None:
                calls.append(kwargs)

        class FakeAIModel:
            pass

        package = types.ModuleType("esbmc_ai")
        package.__path__ = []
        config = types.ModuleType("esbmc_ai.config")
        config.Config = FakeConfig
        models = types.ModuleType("esbmc_ai.ai_models")
        models.AIModel = FakeAIModel

        with patch.dict(
            sys.modules,
            {
                "esbmc_ai": package,
                "esbmc_ai.config": config,
                "esbmc_ai.ai_models": models,
            },
        ):
            model_class = _esbmc_ai_model_class()

        self.assertIs(model_class, FakeAIModel)
        self.assertEqual(calls, [{"_cli_parse_args": False}])


if __name__ == "__main__":
    unittest.main()
