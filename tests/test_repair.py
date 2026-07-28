from __future__ import annotations

import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lucebox_formal.repair import run_validate
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

            candidate = root / "candidate.patch"
            candidate.write_text(
                """\
diff --git a/server/src/state.h b/server/src/state.h
--- a/server/src/state.h
+++ b/server/src/state.h
@@ -1 +1,2 @@
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


if __name__ == "__main__":
    unittest.main()
