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

[registry]
compatibility_manifest = "formal/manifest.toml"

[toolchain]
esbmc_version = "8.4"

[[critical_paths]]
id = "server-state"
description = "server state transitions"
paths = ["server/src/server/prefix_cache_state.h"]
watch_paths = ["server/src/server/*_state.h"]
include_roots = ["server/src"]

[[targets]]
id = "slot-selector"
policy = "required"
source_paths = ["server/src/server/prefix_cache_state.h"]
trigger_paths = [
  "formal/contracts/registry.toml",
  "server/src/server/prefix_cache_state.h",
]
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
        (root / "formal/manifest.toml").write_text(
            'schema_version = 1\n\n[toolchain]\nesbmc_version = "8.4"\n',
            encoding="utf-8",
        )
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
        (root / path).parent.mkdir(parents=True, exist_ok=True)
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
            self.assertEqual(
                report["drift"]["coordinate"]["merge_base_sha"],
                base,
            )
            self.assertEqual(
                report["drift"]["changes"][0]["paths"][0]["relations"],
                ["declared_boundary", "target_trigger"],
            )
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
            self.assertEqual(
                report["drift"]["changes"][0]["paths"][0]["relations"],
                ["watch_match"],
            )

    def test_reports_transitively_included_header_without_overclaiming_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            (root / "server/src/server/prefix_cache_state.h").write_text(
                '#include "server/detail/eviction_policy.h"\n',
                encoding="utf-8",
            )
            (root / "server/src/server/detail").mkdir(parents=True)
            (root / "server/src/server/detail/eviction_policy.h").write_text(
                "#pragma once\n",
                encoding="utf-8",
            )
            self._run(root, "add", "server/src")
            self._run(root, "commit", "-qm", "extract adjacent header")
            head = self._run(root, "rev-parse", "HEAD")

            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            adjacent = next(
                relation
                for change in report["drift"]["changes"]
                for relation in change["paths"]
                if relation["path"].endswith("eviction_policy.h")
            )
            self.assertEqual(adjacent["relations"], ["include_adjacent"])
            self.assertEqual(adjacent["selected_targets"], [])
            self.assertTrue(
                any(
                    item["status"] == "coverage_gap"
                    and item["paths"] == [
                        "server/src/server/detail/eviction_policy.h"
                    ]
                    for item in report["items"]
                )
            )

    def test_unrelated_new_file_remains_explicitly_unmodeled(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            head = self._commit_change(
                root,
                "server/src/server/unrelated.cpp",
                "int unrelated = 0;\n",
            )
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(report["items"][0]["status"], "not_applicable")
            self.assertEqual(
                report["drift"]["changes"][0]["paths"][0]["relations"],
                ["unmodeled"],
            )
            self.assertEqual(report["drift"]["findings"], [])

    def test_protected_boundary_rename_is_blocking_and_records_both_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            self._run(
                root,
                "mv",
                "server/src/server/prefix_cache_state.h",
                "server/src/server/prefix_cache_state_v2.h",
            )
            self._run(root, "commit", "-qm", "rename protected boundary")
            head = self._run(root, "rev-parse", "HEAD")
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            change = report["drift"]["changes"][0]
            self.assertEqual(change["status"], "renamed")
            self.assertEqual(
                [relation["path"] for relation in change["paths"]],
                [
                    "server/src/server/prefix_cache_state.h",
                    "server/src/server/prefix_cache_state_v2.h",
                ],
            )
            finding = next(
                finding
                for finding in report["drift"]["findings"]
                if finding["kind"] == "boundary_renamed"
            )
            self.assertEqual(finding["severity"], "blocking")

    def test_protected_boundary_deletion_is_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            (root / "server/src/server/prefix_cache_state.h").unlink()
            self._run(root, "add", "-u")
            self._run(root, "commit", "-qm", "delete protected boundary")
            head = self._run(root, "rev-parse", "HEAD")
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    finding["kind"] == "boundary_deleted"
                    and finding["severity"] == "blocking"
                    for finding in report["drift"]["findings"]
                )
            )

    def test_policy_shrink_is_blocking_but_old_target_is_still_planned(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            proposed = REGISTRY.replace(
                'paths = ["server/src/server/prefix_cache_state.h"]',
                'paths = ["server/src/server/replacement_state.h"]',
            )
            head = self._commit_change(
                root,
                "formal/contracts/registry.toml",
                proposed,
            )
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(report["items"][0]["status"], "planned")
            self.assertEqual(report["items"][0]["id"], "slot-selector")
            self.assertTrue(report["contract_changes"])
            registry_relation = report["drift"]["changes"][0]["paths"][0]
            self.assertEqual(
                registry_relation["relations"],
                ["policy_change", "target_trigger"],
            )
            self.assertEqual(
                report["drift"]["policy_delta"]["removed_boundaries"],
                ["server-state:server/src/server/prefix_cache_state.h"],
            )
            self.assertTrue(
                any(
                    finding["kind"] == "policy_shrunk"
                    and finding["severity"] == "blocking"
                    for finding in report["drift"]["findings"]
                )
            )

    def test_submodule_pointer_inventory_records_base_and_head(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            initial = self._workspace(root)
            (root / ".gitmodules").write_text(
                '[submodule "dep"]\n'
                "\tpath = server/deps/dep\n"
                "\turl = https://example.invalid/dep.git\n",
                encoding="utf-8",
            )
            self._run(root, "add", ".gitmodules")
            self._run(
                root,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{initial},server/deps/dep",
            )
            self._run(root, "commit", "-qm", "add submodule pointer")
            base = self._run(root, "rev-parse", "HEAD")
            self._run(
                root,
                "update-index",
                "--cacheinfo",
                f"160000,{base},server/deps/dep",
            )
            self._run(root, "commit", "-qm", "bump submodule pointer")
            head = self._run(root, "rev-parse", "HEAD")
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(
                report["drift"]["coordinate"]["submodules"],
                [
                    {
                        "path": "server/deps/dep",
                        "base_sha": initial,
                        "head_sha": base,
                    }
                ],
            )
            self.assertTrue(
                any(
                    finding["kind"] == "dependency_changed"
                    for finding in report["drift"]["findings"]
                )
            )

    def test_manifest_toolchain_mismatch_is_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            head = self._commit_change(
                root,
                "formal/manifest.toml",
                'schema_version = 1\n\n[toolchain]\nesbmc_version = "9.0"\n',
            )
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(
                report["drift"]["toolchain_consistency"],
                {
                    "manifest_path": "formal/manifest.toml",
                    "base": "match",
                    "head": "mismatch",
                },
            )
            self.assertTrue(
                any(
                    finding["kind"] == "toolchain_mismatch"
                    and finding["severity"] == "blocking"
                    for finding in report["drift"]["findings"]
                )
            )

    def test_coordinated_toolchain_change_is_still_protected_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            (root / "formal/contracts/registry.toml").write_text(
                REGISTRY.replace('esbmc_version = "8.4"', 'esbmc_version = "9.0"'),
                encoding="utf-8",
            )
            (root / "formal/manifest.toml").write_text(
                'schema_version = 1\n\n[toolchain]\nesbmc_version = "9.0"\n',
                encoding="utf-8",
            )
            self._run(root, "add", "formal")
            self._run(root, "commit", "-qm", "propose coordinated toolchain change")
            head = self._run(root, "rev-parse", "HEAD")
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(
                report["drift"]["toolchain_consistency"],
                {
                    "manifest_path": "formal/manifest.toml",
                    "base": "match",
                    "head": "match",
                },
            )
            self.assertIn(
                "registry:toolchain",
                report["drift"]["policy_delta"]["weakened_targets"],
            )
            self.assertTrue(
                any(
                    finding["kind"] == "policy_shrunk"
                    and finding["severity"] == "blocking"
                    for finding in report["drift"]["findings"]
                )
            )

    def test_invalid_head_registry_is_blocking_without_replacing_base_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = self._workspace(root)
            head = self._commit_change(
                root,
                "formal/contracts/registry.toml",
                "not valid toml = [",
            )
            output = root / "out"
            run_plan(root, "formal/contracts/registry.toml", base, head, "pr", output)
            report = json.loads((output / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(report["items"][0]["id"], "slot-selector")
            self.assertEqual(report["items"][0]["status"], "planned")
            self.assertTrue(
                any(
                    finding["kind"] == "head_policy_invalid"
                    and finding["severity"] == "blocking"
                    for finding in report["drift"]["findings"]
                )
            )

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
