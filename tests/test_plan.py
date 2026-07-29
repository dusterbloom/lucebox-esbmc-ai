from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from lucebox_formal.plan import (
    MAX_TEMPLATE_BYTES,
    PlanError,
    load_registry,
    run_plan,
)

REGISTRY = """\
schema_version = 1

[toolchain]
esbmc_version = "8.4"

[[critical_paths]]
id = "server-state"
description = "server state transitions"
paths = ["server/src/server/**"]

[[targets]]
id = "slot-selector"
policy = "required"
source_paths = ["server/src/server/prefix_cache_state.h"]
trigger_paths = ["server/src/server/prefix_cache_state.h"]
symbol = "dflash::common::select_inline_free_slot"
signature = "int(int next_slot, int capacity, uint64_t occupied_slots)"
template = "formal/contracts/templates/slot-selector.cpp.in"
template_variables = { MAX_CAP = "4" }
description = "slot selector"
entry_function = "verify_slot_selector"
include_dirs = ["server/src"]
timeout_seconds = 30
pr_defines = ["CAP=4"]
nightly_defines = ["CAP=16"]
pr_esbmc_args = ["--unwind", "5"]
nightly_esbmc_args = ["--unwind", "17"]
mutable_paths = ["server/src/server/prefix_cache_state.h"]
contract_paths = [
  "formal/contracts/properties.md",
  "server/test/test_prefix_cache_state.cpp",
]
native_test = "test_prefix_cache_state"
native_test_source = "server/test/test_prefix_cache_state.cpp"
"""


TEMPLATE = """\
// {{ID}}
// {{SYMBOL}}
// {{SIGNATURE}}
static_assert({{MAX_CAP}} > 0);
"""


class PlanTests(unittest.TestCase):
    def _run(self, root: Path, *arguments: str) -> str:
        process = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        )
        return process.stdout.strip()

    def _workspace(self, root: Path) -> str:
        self._run(root, "init", "-q")
        self._run(root, "config", "user.email", "formal@example.invalid")
        self._run(root, "config", "user.name", "Formal Test")
        (root / "formal/contracts/templates").mkdir(parents=True)
        (root / "server/src/server").mkdir(parents=True)
        (root / "server/test").mkdir(parents=True)
        (root / "formal/contracts/properties.md").write_text("properties\n", encoding="utf-8")
        (root / "formal/contracts/registry.toml").write_text(REGISTRY, encoding="utf-8")
        (root / "formal/contracts/templates/slot-selector.cpp.in").write_text(
            TEMPLATE, encoding="utf-8"
        )
        (root / "server/src/server/prefix_cache_state.h").write_text("// base\n", encoding="utf-8")
        (root / "server/test/test_prefix_cache_state.cpp").write_text(
            "int main() {}\n", encoding="utf-8"
        )
        self._run(root, "add", ".")
        self._run(root, "commit", "-qm", "base policy")
        return self._run(root, "rev-parse", "HEAD")

    def _commit_change(self, root: Path, path: str, contents: str) -> str:
        (root / path).write_text(contents, encoding="utf-8")
        self._run(root, "add", path)
        self._run(root, "commit", "-qm", "change")
        return self._run(root, "rev-parse", "HEAD")

    def test_plans_base_locked_generated_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            head = self._commit_change(root, "server/src/server/prefix_cache_state.h", "// head\n")
            output = root / "out"
            self.assertEqual(
                run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output),
                0,
            )
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            item = report["items"][0]
            self.assertEqual(item["status"], "planned")
            self.assertEqual(item["generated_harness"], "generated/slot-selector.cpp")
            self.assertEqual(item["execution"]["entry_function"], "verify_slot_selector")
            self.assertEqual(item["execution"]["policy"], "required")
            self.assertEqual(item["execution"]["defines"], ["CAP=4"])
            self.assertEqual(
                item["execution"]["mutable_paths"], ["server/src/server/prefix_cache_state.h"]
            )
            generated = (output / item["generated_harness"]).read_text(encoding="utf-8")
            self.assertIn("select_inline_free_slot", generated)
            self.assertIn("static_assert(4 > 0)", generated)
            self.assertEqual(report["contract_changes"], [])
            self.assertEqual(len(report["provenance"]["templates"]), 1)
            snapshots = item["provenance"]["contract_paths"]
            self.assertEqual(
                [snapshot["path"] for snapshot in snapshots],
                [
                    "formal/contracts/properties.md",
                    "server/test/test_prefix_cache_state.cpp",
                ],
            )
            self.assertEqual(len(snapshots[0]["sha256"]), 64)
            self.assertEqual(snapshots[0]["content"], "properties\n")

    def test_template_change_is_advisory_and_uses_base_template(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            head = self._commit_change(
                root,
                "formal/contracts/templates/slot-selector.cpp.in",
                "// malicious PR policy\n",
            )
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(report["items"][0]["status"], "not_applicable")
            self.assertEqual(report["contract_changes"][0]["target_id"], "slot-selector")
            self.assertFalse((output / "generated/slot-selector.cpp").exists())

    def test_reports_critical_coverage_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            head = self._commit_change(root, "server/src/server/new_state.h", "// new\n")
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(report["items"][0]["status"], "coverage_gap")
            self.assertEqual(report["items"][0]["critical_path"]["id"], "server-state")

    def test_rejects_non_sha_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            with self.assertRaises(PlanError):
                run_plan(
                    root, "formal/contracts/registry.toml", "origin/main", base, "pr", root / "out"
                )

    def test_rejects_workspace_not_checked_out_at_head_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            head = self._commit_change(root, "server/src/server/prefix_cache_state.h", "// head\n")
            self._run(root, "checkout", "-q", base)
            with self.assertRaisesRegex(PlanError, "workspace HEAD"):
                run_plan(root, "formal/contracts/registry.toml", base, head, "pr", root / "out")

    def test_requires_esbmc_version_in_base_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._workspace(root)
            invalid = self._commit_change(
                root,
                "formal/contracts/registry.toml",
                REGISTRY.replace('esbmc_version = "8.4"', "esbmc_version = 8"),
            )
            with self.assertRaisesRegex(PlanError, "esbmc_version"):
                run_plan(
                    root, "formal/contracts/registry.toml", invalid, invalid, "pr", root / "out"
                )

    def test_requires_native_test_source_as_an_immutable_contract_path(self) -> None:
        with self.assertRaisesRegex(PlanError, "native_test_source"):
            load_registry(
                "formal/contracts/registry.toml",
                REGISTRY.replace(
                    '  "server/test/test_prefix_cache_state.cpp",\n',
                    "",
                ),
            )

    def test_rejects_template_that_omits_production_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._workspace(root)
            base = self._commit_change(
                root,
                "formal/contracts/templates/slot-selector.cpp.in",
                "// {{ID}}\nstatic_assert({{MAX_CAP}} > 0);\n",
            )
            head = self._commit_change(root, "server/src/server/prefix_cache_state.h", "// head\n")
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            item = json.loads((output / "plan.json").read_text())["items"][0]
            self.assertEqual(item["status"], "generation_error")
            self.assertIn("omits declared production symbol", item["reason"])

    def test_caps_oversized_template(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._workspace(root)
            base = self._commit_change(
                root,
                "formal/contracts/templates/slot-selector.cpp.in",
                "dflash::common::select_inline_free_slot\n" + "x" * MAX_TEMPLATE_BYTES,
            )
            head = self._commit_change(root, "server/src/server/prefix_cache_state.h", "// head\n")
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            item = json.loads((output / "plan.json").read_text())["items"][0]
            self.assertEqual(item["status"], "generation_error")
            self.assertIn("byte limit", item["reason"])

    def test_empty_pr_diff_is_explicitly_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, base, "pr", output)
            items = json.loads((output / "plan.json").read_text())["items"]
            self.assertEqual(
                items,
                [
                    {
                        "id": "not-applicable",
                        "status": "not_applicable",
                        "reason": "pull request diff is empty",
                        "paths": [],
                    }
                ],
            )


if __name__ == "__main__":
    unittest.main()
