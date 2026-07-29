from __future__ import annotations

import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lucebox_formal.contract_proposal import _load_gap_bundle
from lucebox_formal.plan import run_plan
from lucebox_formal.repair import run_validate
from lucebox_formal.verifier import run_verify_plan

REGISTRY = """\
schema_version = 1

[registry]
compatibility_manifest = "formal/manifest.toml"

[toolchain]
esbmc_version = "8.4"

[[critical_paths]]
id = "state"
description = "state transitions"
paths = ["server/src/**"]

[[targets]]
id = "state-contract"
policy = "required"
source_paths = ["server/src/state.h"]
trigger_paths = ["formal/contracts/registry.toml", "server/src/state.h"]
symbol = "verify_state"
signature = "int()"
template = "formal/contracts/state.cpp.in"
description = "state contract"
entry_function = "verify_state"
include_dirs = ["server/src"]
timeout_seconds = 10
mutable_paths = ["server/src/state.h"]
contract_paths = [
  "formal/contracts/properties.md",
  "server/test/test_state.cpp",
]
native_test = "test_state"
native_test_source = "server/test/test_state.cpp"
"""


class PlanVerifierTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        process = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        )
        return process.stdout.strip()

    def _workspace(self, root: Path) -> tuple[str, str]:
        self._git(root, "init", "-q")
        self._git(root, "config", "user.email", "formal@example.invalid")
        self._git(root, "config", "user.name", "Formal Test")
        (root / "formal/contracts").mkdir(parents=True)
        (root / "server/src").mkdir(parents=True)
        (root / "server/test").mkdir(parents=True)
        (root / "formal/contracts/registry.toml").write_text(REGISTRY, encoding="utf-8")
        (root / "formal/manifest.toml").write_text(
            'schema_version = 1\n\n[toolchain]\nesbmc_version = "8.4"\n',
            encoding="utf-8",
        )
        (root / "formal/contracts/state.cpp.in").write_text(
            "int verify_state() { return 0; }\n", encoding="utf-8"
        )
        (root / "formal/contracts/properties.md").write_text("state is safe\n", encoding="utf-8")
        (root / "server/src/state.h").write_text(
            "#pragma once\ninline int state_value() { return 1; }\n",
            encoding="utf-8",
        )
        (root / "server/test/test_state.cpp").write_text(
            '#include "state.h"\n'
            "int main() { return state_value() == 1 ? 0 : 1; }\n",
            encoding="utf-8",
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "base")
        base = self._git(root, "rev-parse", "HEAD")
        (root / "server/src/state.h").write_text(
            "#pragma once\n"
            "inline int state_value() { return 1; }\n"
            "// changed\n",
            encoding="utf-8",
        )
        self._git(root, "add", "server/src/state.h")
        self._git(root, "commit", "-qm", "change")
        return base, self._git(root, "rev-parse", "HEAD")

    def _fake_esbmc(self, root: Path) -> Path:
        fake = root / "fake-esbmc"
        fake.write_text(
            """#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ESBMC version 8.4.0"
elif [ "$FAKE_RESULT" = "success" ]; then
  echo "VERIFICATION SUCCESSFUL"
elif [ "$FAKE_RESULT" = "timeout" ]; then
  echo "ERROR: Timed out"
  exit 1
else
  printf '%s\\n' '<html>counterexample</html>' > report-1.html
  echo "VERIFICATION FAILED"
  exit 1
fi
""",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        return fake

    def _plan(self, root: Path, base: str, head: str) -> Path:
        output = root / "plan"
        self.assertEqual(
            run_plan(
                root,
                "formal/contracts/registry.toml",
                base,
                head,
                "pr",
                output,
            ),
            0,
        )
        return output / "plan.json"

    def test_verifies_exact_generated_plan_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = self._workspace(root)
            fake = self._fake_esbmc(root)
            plan = self._plan(root, base, head)
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "success"},
            ):
                code = run_verify_plan(root, plan, plan.parent, root / "ok")
            self.assertEqual(code, 0)
            report = json.loads((root / "ok/report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["conclusion"], "verified")
            self.assertEqual(report["results"][0]["status"], "verified")

            generated = root / "plan/generated/state-contract.cpp"
            generated.write_text("// tampered\n", encoding="utf-8")
            code = run_verify_plan(root, plan, plan.parent, root / "tampered")
            self.assertEqual(code, 13)
            report = json.loads((root / "tampered/report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["conclusion"], "invalid_contract")
            junit = (root / "tampered/junit.xml").read_text(encoding="utf-8")
            self.assertIn('errors="1"', junit)
            summary = (root / "tampered/summary.md").read_text(encoding="utf-8")
            self.assertNotIn("hash mismatch", summary)

    def test_rejects_tampered_drift_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = self._workspace(root)
            plan = self._plan(root, base, head)
            payload = json.loads(plan.read_text(encoding="utf-8"))
            payload["drift"]["coordinate"]["merge_base_sha"] = "0" * 40
            plan.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            code = run_verify_plan(root, plan, plan.parent, root / "tampered-drift")
            self.assertEqual(code, 13)
            report = json.loads(
                (root / "tampered-drift/report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["conclusion"], "invalid_contract")
            self.assertIn("drift evidence", report["error"])

    def test_policy_shrink_runs_base_contract_then_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, _ = self._workspace(root)
            registry = root / "formal/contracts/registry.toml"
            registry.write_text(
                REGISTRY.replace(
                    'paths = ["server/src/**"]',
                    'paths = ["server/other/**"]',
                ),
                encoding="utf-8",
            )
            self._git(root, "add", str(registry.relative_to(root)))
            self._git(root, "commit", "-qm", "shrink protected policy")
            head = self._git(root, "rev-parse", "HEAD")
            fake = self._fake_esbmc(root)
            plan = self._plan(root, base, head)
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "success"},
            ):
                code = run_verify_plan(root, plan, plan.parent, root / "policy-shrink")
            self.assertEqual(code, 13)
            report = json.loads(
                (root / "policy-shrink/report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["conclusion"], "invalid_contract")
            statuses = {
                result["id"]: result["status"] for result in report["results"]
            }
            self.assertEqual(statuses["state-contract"], "verified")
            self.assertEqual(statuses["drift-integrity"], "invalid_contract")

    def test_divergent_base_and_head_are_valid_exact_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            common, head = self._workspace(root)
            self._git(root, "checkout", "-q", common)
            (root / "base-note.md").write_text("target branch advanced\n", encoding="utf-8")
            self._git(root, "add", "base-note.md")
            self._git(root, "commit", "-qm", "advance target")
            divergent_base = self._git(root, "rev-parse", "HEAD")
            self._git(root, "checkout", "-q", head)
            fake = self._fake_esbmc(root)
            plan = self._plan(root, divergent_base, head)
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "success"},
            ):
                code = run_verify_plan(root, plan, plan.parent, root / "divergent")
            self.assertEqual(code, 0)
            report = json.loads((root / "divergent/report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["conclusion"], "verified")

    def test_coverage_gap_is_advisory_and_junit_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, _ = self._workspace(root)
            (root / "server/src/new_state.h").write_text("// uncovered\n", encoding="utf-8")
            self._git(root, "add", "server/src/new_state.h")
            self._git(root, "commit", "-qm", "add uncovered state")
            head = self._git(root, "rev-parse", "HEAD")
            fake = self._fake_esbmc(root)
            plan = self._plan(root, base, head)
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "success"},
            ):
                code = run_verify_plan(root, plan, plan.parent, root / "gap")
            self.assertEqual(code, 0)
            report = json.loads((root / "gap/report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["conclusion"], "coverage_gap")
            gap = next(item for item in report["results"] if item["status"] == "coverage_gap")
            self.assertTrue(gap["id"].startswith("coverage-gap-"))
            bundle_relative = gap["artifacts"]["coverage_gap_bundles"][0]
            bundle = root / "gap" / bundle_relative
            with tarfile.open(bundle, "r:gz") as archive:
                names = set(archive.getnames())
                gap_report = json.load(archive.extractfile("gap.json"))
                bundled_plan = archive.extractfile("formal-plan/plan.json").read()
            self.assertEqual(gap_report["event"], "coverage_gap")
            self.assertEqual(gap_report["base_sha"], base)
            self.assertEqual(gap_report["head_sha"], head)
            self.assertIn("server/src/new_state.h", names)
            self.assertIn("formal/contracts/registry.toml", names)
            self.assertIn("formal/contracts/state.cpp.in", names)
            self.assertEqual(bundled_plan, plan.read_bytes())
            with tempfile.TemporaryDirectory() as extracted:
                loaded = _load_gap_bundle(bundle, Path(extracted))
            self.assertEqual(
                loaded["head_files"][0]["path"],
                "server/src/new_state.h",
            )
            junit = (root / "gap/junit.xml").read_text(encoding="utf-8")
            self.assertIn("<skipped", junit)

    def test_inconclusive_is_exit_11_and_junit_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = self._workspace(root)
            fake = self._fake_esbmc(root)
            plan = self._plan(root, base, head)
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "timeout"},
            ):
                code = run_verify_plan(root, plan, plan.parent, root / "timeout")
            self.assertEqual(code, 11)
            report = json.loads((root / "timeout/report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["conclusion"], "inconclusive")
            junit = (root / "timeout/junit.xml").read_text(encoding="utf-8")
            self.assertIn('errors="1"', junit)

    def test_counterexample_bundle_replays_the_exact_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = self._workspace(root)
            fake = self._fake_esbmc(root)
            plan = self._plan(root, base, head)
            failed = root / "failed"
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "failure"},
            ):
                self.assertEqual(run_verify_plan(root, plan, plan.parent, failed), 10)
            bundle = next(failed.glob("failure-bundle-*.tar.gz"))
            with tarfile.open(bundle, "r:gz") as archive:
                names = set(archive.getnames())
                failure = json.load(archive.extractfile("failure.json"))
            self.assertEqual(failure["verification_kind"], "plan")
            self.assertIn("formal-plan/plan.json", names)
            self.assertIn("formal-plan/generated/state-contract.cpp", names)

            candidate = root / "candidate.patch"
            candidate.write_text(
                """\
diff --git a/server/src/state.h b/server/src/state.h
--- a/server/src/state.h
+++ b/server/src/state.h
@@ -1,3 +1,4 @@
 #pragma once
 inline int state_value() { return 1; }
 // changed
+// repaired
""",
                encoding="utf-8",
            )
            accepted = root / "accepted"
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "success"},
            ):
                self.assertEqual(run_validate(bundle, candidate, accepted), 0)
            report = json.loads((accepted / "validation-report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["successful"])
            self.assertEqual(report["formal_report"]["conclusion"], "verified")

    def test_base_native_regression_catches_head_test_weakening(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, _ = self._workspace(root)
            (root / "server/src/state.h").write_text(
                "#pragma once\n"
                "inline int state_value() { return 0; }\n"
                "// call-site regression\n",
                encoding="utf-8",
            )
            (root / "server/test/test_state.cpp").write_text(
                "int main() { return 0; }\n",
                encoding="utf-8",
            )
            self._git(root, "add", "server/src/state.h", "server/test/test_state.cpp")
            self._git(root, "commit", "-qm", "regress state and weaken head test")
            head = self._git(root, "rev-parse", "HEAD")
            fake = self._fake_esbmc(root)
            plan = self._plan(root, base, head)
            output = root / "native-failure"
            with patch.dict(
                os.environ,
                {"ESBMC_PATH": str(fake), "FAKE_RESULT": "success"},
            ):
                code = run_verify_plan(root, plan, plan.parent, output)

            self.assertEqual(code, 10)
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            result = next(
                item for item in report["results"] if item["id"] == "state-contract"
            )
            self.assertEqual(result["status"], "counterexample")
            self.assertEqual(
                result["assumptions"]["native_test"]["native_test_source"],
                "server/test/test_state.cpp",
            )
            self.assertIn("base-approved native regression", result["output"])

            bundle = next(output.glob("failure-bundle-*.tar.gz"))
            with tarfile.open(bundle, "r:gz") as archive:
                bundled_test = archive.extractfile("server/test/test_state.cpp").read()
            self.assertIn(b"state_value() == 1", bundled_test)
            self.assertNotEqual(
                bundled_test,
                (root / "server/test/test_state.cpp").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
