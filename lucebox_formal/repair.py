from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .manifest import load_manifest
from .security import (
    BundleError,
    extract_bundle,
    safe_repo_path,
    sha256_file,
    validate_patch_paths,
)
from .verifier import run_verify


SYSTEM_PROMPT = """\
You are repairing a bounded C++ verification failure in Lucebox.

Hard constraints:
- Treat the formal harness, property documents, assumptions, and manifest as
  immutable specifications.
- Modify only the explicitly mutable production files.
- Preserve the intended external behavior; do not delete checks, weaken
  assertions, add assumptions, or special-case the bounded test constants.
- Make the smallest general repair supported by the counterexample.

Return exactly two sections:
DIAGNOSIS:
One concise explanation grounded in the counterexample.

PATCH:
```diff
A unified diff rooted at the repository root.
```
"""


def _extract_patch(response: str) -> tuple[str, str]:
    marker = "```diff"
    start = response.find(marker)
    if start < 0:
        raise BundleError("model response did not contain a diff fence")
    body_start = response.find("\n", start)
    end = response.find("```", body_start + 1)
    if body_start < 0 or end < 0:
        raise BundleError("model response contained an incomplete diff fence")
    patch = response[body_start + 1 : end].strip() + "\n"
    diagnosis = response[:start].strip()
    return diagnosis, patch


def _prompt(failure: dict, workspace: Path, feedback: str) -> str:
    capsule = failure["capsule"]
    mutable_paths = failure["mutable_paths"]
    contracts = capsule["contract_paths"]
    sections = [
        "CAPSULE:",
        capsule["id"],
        "",
        "DECLARED PROPERTIES AND BOUNDS:",
    ]
    for relative in contracts:
        path = safe_repo_path(workspace, relative)
        sections.extend([f"--- {relative}", path.read_text(encoding="utf-8")])
    sections.extend(
        [
            "",
            "ESBMC COUNTEREXAMPLE:",
            failure["result"]["output"],
            "",
            "MUTABLE PRODUCTION FILES:",
        ]
    )
    for relative in mutable_paths:
        path = safe_repo_path(workspace, relative)
        sections.extend(
            [
                f"--- {relative}",
                "```cpp",
                path.read_text(encoding="utf-8"),
                "```",
            ]
        )
    if feedback:
        sections.extend(["", "PREVIOUS CANDIDATE RESULT:", feedback])
    return "\n".join(sections)


def _validate_contracts(
    workspace: Path, expected_hashes: dict[str, str]
) -> None:
    for relative, expected in expected_hashes.items():
        actual = sha256_file(safe_repo_path(workspace, relative))
        if actual != expected:
            raise BundleError(f"candidate modified immutable contract: {relative}")


def _run_native_test(workspace: Path, source: str | None) -> tuple[bool, str]:
    if not source:
        return True, "no native test declared"
    source_path = safe_repo_path(workspace, source)
    with tempfile.TemporaryDirectory(prefix="lucebox-native-test-") as temp:
        executable = Path(temp) / "native-test"
        compile_process = subprocess.run(
            [
                "c++",
                "-std=c++17",
                "-O0",
                "-I",
                str(workspace / "server/src"),
                str(source_path),
                "-o",
                str(executable),
            ],
            cwd=workspace,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        if compile_process.returncode != 0:
            return False, "native compile failed:\n" + compile_process.stdout
        test_process = subprocess.run(
            [str(executable)],
            cwd=workspace,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        return (
            test_process.returncode == 0,
            "native test output:\n" + test_process.stdout,
        )


def run_repair(
    bundle: Path,
    model: str,
    max_attempts: int,
    output_dir: Path,
) -> int:
    if max_attempts < 1 or max_attempts > 5:
        raise ValueError("max_attempts must be between 1 and 5")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Importing ESBMC-AI is intentionally limited to the repair image and
    # repair subcommand. The deterministic verifier image has no LLM stack.
    from esbmc_ai.ai_models import AIModel
    from langchain_core.messages import HumanMessage, SystemMessage

    with tempfile.TemporaryDirectory(prefix="lucebox-repair-") as temp:
        pristine = Path(temp) / "pristine"
        pristine.mkdir()
        extract_bundle(bundle, pristine)
        failure = json.loads(
            (pristine / "failure.json").read_text(encoding="utf-8")
        )
        if failure.get("schema_version") != 1:
            raise BundleError("unsupported failure bundle schema")

        mutable_paths = set(failure.get("mutable_paths", []))
        if not mutable_paths:
            raise BundleError("failure bundle declares no mutable files")
        for relative in mutable_paths:
            safe_repo_path(pristine, relative)
        _validate_contracts(pristine, failure["contract_hashes"])

        ai_model = AIModel.get_model(model=model, temperature=0)
        history = [SystemMessage(content=SYSTEM_PROMPT)]
        feedback = ""
        attempts: list[dict] = []
        final_patch = ""
        final_diagnosis = ""

        for attempt_number in range(1, max_attempts + 1):
            prompt = _prompt(failure, pristine, feedback)
            history.append(HumanMessage(content=prompt))
            response = ai_model.invoke(history)
            history.append(response)
            response_text = response.text
            if not isinstance(response_text, str):
                response_text = str(response_text)

            try:
                diagnosis, patch = _extract_patch(response_text)
                validate_patch_paths(patch, mutable_paths)
            except BundleError as exc:
                feedback = str(exc)
                attempts.append(
                    {
                        "attempt": attempt_number,
                        "status": "invalid_patch",
                        "detail": feedback,
                    }
                )
                continue

            attempt_root = Path(temp) / f"attempt-{attempt_number}"
            shutil.copytree(pristine, attempt_root)
            patch_path = attempt_root / "candidate.patch"
            patch_path.write_text(patch, encoding="utf-8")
            check = subprocess.run(
                ["git", "apply", "--check", str(patch_path)],
                cwd=attempt_root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if check.returncode != 0:
                feedback = "git apply --check failed:\n" + check.stdout
                attempts.append(
                    {
                        "attempt": attempt_number,
                        "status": "invalid_patch",
                        "detail": feedback,
                    }
                )
                continue
            apply_process = subprocess.run(
                ["git", "apply", str(patch_path)],
                cwd=attempt_root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if apply_process.returncode != 0:
                feedback = "git apply failed:\n" + apply_process.stdout
                attempts.append(
                    {
                        "attempt": attempt_number,
                        "status": "invalid_patch",
                        "detail": feedback,
                    }
                )
                continue

            try:
                _validate_contracts(attempt_root, failure["contract_hashes"])
            except BundleError as exc:
                feedback = str(exc)
                attempts.append(
                    {
                        "attempt": attempt_number,
                        "status": "contract_modified",
                        "detail": feedback,
                    }
                )
                continue

            verify_output = Path(temp) / f"verify-{attempt_number}"
            manifest_path = attempt_root / "formal/manifest.toml"
            verify_code = run_verify(
                manifest_path, base_sha="", mode="all", output_dir=verify_output
            )
            manifest = load_manifest(manifest_path)
            capsule_id = failure["capsule"]["id"]
            capsule = next(
                item for item in manifest.capsules if item.id == capsule_id
            )
            native_ok, native_output = _run_native_test(
                attempt_root, capsule.native_test_source
            )
            if verify_code == 0 and native_ok:
                attempts.append(
                    {
                        "attempt": attempt_number,
                        "status": "reverified",
                        "formal_exit_code": verify_code,
                        "native_test": native_output,
                    }
                )
                final_patch = patch
                final_diagnosis = diagnosis
                break

            report_text = (verify_output / "report.json").read_text(
                encoding="utf-8"
            )
            feedback = (
                f"Formal exit code: {verify_code}\n{report_text}\n{native_output}"
            )
            attempts.append(
                {
                    "attempt": attempt_number,
                    "status": "verification_failed",
                    "formal_exit_code": verify_code,
                    "native_test": native_output,
                }
            )

        successful = bool(final_patch)
        if successful:
            (output_dir / "candidate.patch").write_text(
                final_patch, encoding="utf-8"
            )
            (output_dir / "diagnosis.md").write_text(
                final_diagnosis + "\n", encoding="utf-8"
            )
        else:
            (output_dir / "diagnosis.md").write_text(
                "No candidate passed the immutable formal contract.\n",
                encoding="utf-8",
            )
        (output_dir / "repair-report.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "model": model,
                    "successful": successful,
                    "attempts": attempts,
                    "advisory_only": True,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return 0 if successful else 20
