from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from lucebox_formal.cli import _parser, main


class CliTests(unittest.TestCase):
    def test_verify_accepts_legacy_manifest_or_generated_plan(self) -> None:
        legacy = _parser().parse_args(
            ["verify", "--manifest", "formal/manifest.toml", "--out", "out"]
        )
        self.assertEqual(legacy.manifest, Path("formal/manifest.toml"))
        self.assertIsNone(legacy.plan)

        planned = _parser().parse_args(
            [
                "verify",
                "--plan",
                "plan/plan.json",
                "--workspace",
                "workspace",
                "--generated-root",
                "plan",
                "--out",
                "out",
            ]
        )
        self.assertEqual(planned.plan, Path("plan/plan.json"))
        self.assertEqual(planned.workspace, Path("workspace"))

    def test_plan_verification_requires_explicit_roots(self) -> None:
        stderr = io.StringIO()
        with (
            patch(
                "sys.argv",
                [
                    "lucebox-formal",
                    "verify",
                    "--plan",
                    "plan.json",
                    "--out",
                    "out",
                ],
            ),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as exit_info,
        ):
            main()
        self.assertEqual(exit_info.exception.code, 13)
        self.assertIn("--workspace", stderr.getvalue())

    def test_contract_proposal_commands_expose_split_trust_inputs(
        self,
    ) -> None:
        propose = _parser().parse_args(
            [
                "propose-contract",
                "--bundle",
                "gap.tar.gz",
                "--model",
                "openai:glm-5",
                "--out",
                "proposed",
            ]
        )
        self.assertEqual(propose.model, "openai:glm-5")

        validate = _parser().parse_args(
            [
                "validate-contract",
                "--bundle",
                "gap.tar.gz",
                "--proposal-dir",
                "proposed",
                "--workspace",
                "head",
                "--out",
                "validated",
            ]
        )
        self.assertEqual(validate.workspace, Path("head"))


if __name__ == "__main__":
    unittest.main()
