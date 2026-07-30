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

from lucebox_formal.contract_proposal import (
    ContractProposalError,
    _load_gap_bundle,
    _parse_response,
    _proposal_provenance,
    run_validate_contract,
)
from lucebox_formal.plan import run_plan
from lucebox_formal.security import extract_bundle
from lucebox_formal.verifier import run_verify_plan

REGISTRY = """\
schema_version = 1

[toolchain]
esbmc_version = "8.4"

[[critical_paths]]
id = "new-state"
description = "new state transition"
paths = ["server/src/new_state.h"]

[[targets]]
id = "existing-state"
policy = "required"
source_paths = ["server/src/existing.h"]
trigger_paths = ["server/src/existing.h"]
symbol = "dflash::existing_state"
signature = "int(int)"
template = "formal/contracts/existing.cpp.in"
description = "existing state contract"
entry_function = "verify_existing"
include_dirs = ["server/src"]
timeout_seconds = 30
pr_esbmc_args = ["--quiet", "--z3", "--unwind", "2"]
nightly_esbmc_args = ["--quiet", "--z3", "--unwind", "4"]
contract_paths = [
  "formal/contracts/existing.cpp.in",
  "formal/contracts/existing.md",
]
"""

CONTRACT = """\
#include "new_state.h"
#include <cassert>

int verify_contract() {
    const int value = dflash::new_state(0);
    assert(value >= 0);
    return 0;
}
"""

METADATA = {
    "id": "new-state-contract",
    "source_path": "server/src/new_state.h",
    "symbol": "dflash::new_state",
    "signature": "int(int)",
    "entry_function": "verify_contract",
    "include_dirs": ["server/src"],
    "timeout_seconds": 30,
    "esbmc_args": ["--quiet", "--z3", "--unwind", "2"],
}


class ContractProposalTests(unittest.TestCase):
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
        (root / "formal/contracts/registry.toml").write_text(REGISTRY, encoding="utf-8")
        (root / "formal/contracts/existing.cpp.in").write_text(
            "int verify_existing() { return dflash::existing_state(0); }\n",
            encoding="utf-8",
        )
        (root / "formal/contracts/existing.md").write_text(
            "existing state remains safe\n", encoding="utf-8"
        )
        (root / "server/src/existing.h").write_text(
            "namespace dflash { inline int existing_state(int x) { return x; } }\n",
            encoding="utf-8",
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "base")
        base = self._git(root, "rev-parse", "HEAD")
        (root / "server/src/new_state.h").write_text(
            "namespace dflash { inline int new_state(int x) { return x; } }\n",
            encoding="utf-8",
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "new uncovered state")
        return base, self._git(root, "rev-parse", "HEAD")

    def _fake_esbmc(self, root: Path) -> Path:
        fake = root / "fake-esbmc"
        fake.write_text(
            """#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ESBMC version 8.4.0"
elif [ -n "$ZAI_API_KEY" ]; then
  echo "credential leaked" >&2
  exit 2
else
  echo "VERIFICATION SUCCESSFUL"
fi
""",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        return fake

    def _gap_bundle(self, root: Path, base: str, head: str, fake: Path) -> Path:
        plan_dir = root / "plan"
        self.assertEqual(
            run_plan(
                root,
                "formal/contracts/registry.toml",
                base,
                head,
                "pr",
                plan_dir,
            ),
            0,
        )
        results = root / "results"
        with patch.dict(os.environ, {"ESBMC_PATH": str(fake)}):
            self.assertEqual(
                run_verify_plan(
                    root,
                    plan_dir / "plan.json",
                    plan_dir,
                    results,
                ),
                0,
            )
        return next(results.glob("coverage-gap-bundle-*.tar.gz"))

    def _write_proposal(self, bundle: Path, proposal_dir: Path) -> None:
        with tempfile.TemporaryDirectory() as extracted:
            inputs = _load_gap_bundle(bundle, Path(extracted))
            response = (
                "```json\n"
                + json.dumps(METADATA, sort_keys=True)
                + "\n```\n```cpp\n"
                + CONTRACT.rstrip()
                + "\n```"
            )
            metadata, contract = _parse_response(response, inputs)
            proposal = {
                "schema_version": 1,
                "advisory_only": True,
                "executed_candidate_code": False,
                "metadata": metadata,
                "contract_sha256": __import__("hashlib").sha256(contract.encode()).hexdigest(),
                "provenance": _proposal_provenance(inputs),
            }
        proposal_dir.mkdir()
        (proposal_dir / "proposal.json").write_text(json.dumps(proposal), encoding="utf-8")
        (proposal_dir / "contract.cpp").write_text(contract, encoding="utf-8")

    def test_secretless_validation_marks_only_verified_proposal_ready(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = self._workspace(root)
            fake = self._fake_esbmc(root)
            bundle = self._gap_bundle(root, base, head, fake)
            proposal_dir = root / "proposal"
            self._write_proposal(bundle, proposal_dir)

            output = root / "validated"
            with patch.dict(
                os.environ,
                {
                    "ESBMC_PATH": str(fake),
                    "ZAI_API_KEY": "must-not-reach-esbmc",
                },
            ):
                self.assertEqual(
                    run_validate_contract(bundle, proposal_dir, root, output),
                    0,
                )
            report = json.loads((output / "proposal-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "proposal_ready")
            self.assertFalse(report["validator_received_model_credentials"])

    def test_rejects_non_whitelisted_esbmc_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = self._workspace(root)
            fake = self._fake_esbmc(root)
            bundle = self._gap_bundle(root, base, head, fake)
            with tempfile.TemporaryDirectory() as extracted:
                inputs = _load_gap_bundle(bundle, Path(extracted))
                metadata = {**METADATA, "esbmc_args": ["--dangerous"]}
                response = (
                    "```json\n"
                    + json.dumps(metadata)
                    + "\n```\n```cpp\n"
                    + CONTRACT.rstrip()
                    + "\n```"
                )
                with self.assertRaisesRegex(ContractProposalError, "not whitelisted"):
                    _parse_response(response, inputs)

    def test_rejects_gap_metadata_that_disagrees_with_exact_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = self._workspace(root)
            fake = self._fake_esbmc(root)
            bundle = self._gap_bundle(root, base, head, fake)
            stage = root / "tampered-stage"
            stage.mkdir()
            extract_bundle(bundle, stage)
            gap_path = stage / "gap.json"
            gap = json.loads(gap_path.read_text(encoding="utf-8"))
            gap["head_sha"] = base
            gap_path.write_text(json.dumps(gap), encoding="utf-8")
            tampered = root / "tampered.tar.gz"
            with tarfile.open(tampered, "w:gz") as archive:
                for source in sorted(path for path in stage.rglob("*") if path.is_file()):
                    archive.add(
                        source,
                        arcname=source.relative_to(stage).as_posix(),
                        recursive=False,
                    )
            with tempfile.TemporaryDirectory() as extracted:
                with self.assertRaisesRegex(ContractProposalError, "head SHA"):
                    _load_gap_bundle(tampered, Path(extracted))


if __name__ == "__main__":
    unittest.main()
