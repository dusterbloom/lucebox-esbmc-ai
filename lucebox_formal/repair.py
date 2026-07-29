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
    sanitized_subprocess_environment,
    sha256_file,
    validate_patch_paths,
)
from .verifier import run_verify, run_verify_plan

MAX_PATCH_BYTES = 256_000

SYSTEM_PROMPT = """\
You are repairing a bounded C++ verification failure in Lucebox.

Hard constraints:
- Treat the formal harness, property documents, assumptions, native tests, and
  manifest as immutable specifications.
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


def _esbmc_ai_model_class():
    # ESBMC-AI's Config is a singleton whose default settings source parses
    # sys.argv. This adapter already owns the CLI, so allowing the dependency
    # to parse `lucebox-formal propose --bundle ...` rejects our arguments
    # before any model request. Initialize its singleton explicitly with CLI
    # parsing disabled before AIModel asks Config for request settings.
    from esbmc_ai.ai_models import AIModel
    from esbmc_ai.config import Config as ESBMCAIConfig

    ESBMCAIConfig(_cli_parse_args=False)
    return AIModel


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
    if len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
        raise BundleError("candidate patch exceeds size limit")
    diagnosis = response[:start].strip()
    return diagnosis, patch


def _load_failure(bundle: Path, workspace: Path) -> dict:
    extract_bundle(bundle, workspace)
    failure_path = workspace / "failure.json"
    if not failure_path.is_file():
        raise BundleError("failure bundle is missing failure.json")
    failure = json.loads(failure_path.read_text(encoding="utf-8"))
    if failure.get("schema_version") != 1:
        raise BundleError("unsupported failure bundle schema")
    verification_kind = failure.get("verification_kind", "manifest")
    if verification_kind not in {"manifest", "plan"}:
        raise BundleError("failure bundle has invalid verification kind")

    mutable_paths = failure.get("mutable_paths")
    if not isinstance(mutable_paths, list) or not mutable_paths:
        raise BundleError("failure bundle declares no mutable files")
    if not all(isinstance(path, str) for path in mutable_paths):
        raise BundleError("failure bundle has invalid mutable paths")
    for relative in mutable_paths:
        path = safe_repo_path(workspace, relative)
        if not path.is_file():
            raise BundleError(f"mutable file is missing: {relative}")
    _validate_contracts(workspace, failure.get("contract_hashes", {}))
    if verification_kind == "plan":
        plan_bundle = failure.get("plan_bundle")
        if not isinstance(plan_bundle, dict):
            raise BundleError("plan failure bundle is missing plan metadata")
        for field in ("plan_path", "generated_root", "item_id"):
            if not isinstance(plan_bundle.get(field), str):
                raise BundleError(f"plan bundle has invalid {field}")
        plan_path = safe_repo_path(workspace, plan_bundle["plan_path"])
        generated_root = safe_repo_path(workspace, plan_bundle["generated_root"])
        if not plan_path.is_file() or not generated_root.is_dir():
            raise BundleError("plan replay inputs are missing")
        plan_item = failure.get("plan_item")
        if not isinstance(plan_item, dict) or plan_item.get("id") != plan_bundle["item_id"]:
            raise BundleError("plan failure item does not match replay metadata")
    return failure


def _prompt(failure: dict, workspace: Path) -> str:
    if failure.get("verification_kind", "manifest") == "plan":
        capsule = failure["plan_item"]
        contract_paths = capsule["execution"]["contract_paths"]
    else:
        capsule = failure["capsule"]
        contract_paths = capsule["contract_paths"]
    sections = [
        "CAPSULE:",
        capsule["id"],
        "",
        "DECLARED PROPERTIES AND BOUNDS:",
    ]
    for relative in contract_paths:
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
    for relative in failure["mutable_paths"]:
        path = safe_repo_path(workspace, relative)
        sections.extend(
            [
                f"--- {relative}",
                "```cpp",
                path.read_text(encoding="utf-8"),
                "```",
            ]
        )
    return "\n".join(sections)


def _validate_contracts(workspace: Path, expected_hashes: dict[str, str]) -> None:
    if not isinstance(expected_hashes, dict) or not expected_hashes:
        raise BundleError("failure bundle declares no immutable contracts")
    for relative, expected in expected_hashes.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise BundleError("failure bundle has invalid contract hashes")
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
            env=sanitized_subprocess_environment(),
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
            env=sanitized_subprocess_environment(),
        )
        return (
            test_process.returncode == 0,
            "native test output:\n" + test_process.stdout,
        )


def run_propose(bundle: Path, model: str, output_dir: Path) -> int:
    """Ask the model for one bounded patch without executing candidate code."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # These dependencies exist only in the repair image. This process performs
    # no compilation or verification while it holds a model credential.
    from langchain_core.messages import HumanMessage, SystemMessage

    AIModel = _esbmc_ai_model_class()

    with tempfile.TemporaryDirectory(prefix="lucebox-propose-") as temp:
        workspace = Path(temp) / "workspace"
        workspace.mkdir()
        failure = _load_failure(bundle, workspace)
        mutable_paths = set(failure["mutable_paths"])

        ai_model = AIModel.get_model(model=model, temperature=0)
        response = ai_model.invoke(
            [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=_prompt(failure, workspace)),
            ]
        )
        response_text = response.text
        if not isinstance(response_text, str):
            response_text = str(response_text)
        diagnosis, patch = _extract_patch(response_text)
        validate_patch_paths(patch, mutable_paths)

        (output_dir / "candidate.patch").write_text(patch, encoding="utf-8")
        (output_dir / "diagnosis.md").write_text(diagnosis + "\n", encoding="utf-8")
        (output_dir / "proposal-report.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "model": model,
                    "advisory_only": True,
                    "executed_candidate_code": False,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    return 0


def run_validate(bundle: Path, patch_path: Path, output_dir: Path) -> int:
    """Apply and reverify a proposal in a secretless, networkless process."""
    output_dir.mkdir(parents=True, exist_ok=True)
    patch = patch_path.read_text(encoding="utf-8")
    if len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
        raise BundleError("candidate patch exceeds size limit")

    with tempfile.TemporaryDirectory(prefix="lucebox-validate-") as temp:
        workspace = Path(temp) / "workspace"
        workspace.mkdir()
        failure = _load_failure(bundle, workspace)
        mutable_paths = set(failure["mutable_paths"])
        validate_patch_paths(patch, mutable_paths)

        local_patch = Path(temp) / "candidate.patch"
        local_patch.write_text(patch, encoding="utf-8")
        environment = sanitized_subprocess_environment()
        check = subprocess.run(
            ["git", "apply", "--recount", "--check", str(local_patch)],
            cwd=workspace,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            env=environment,
        )
        if check.returncode != 0:
            detail = "git apply --check failed:\n" + check.stdout
            _write_validation_report(output_dir, False, detail, None, "")
            return 20
        applied = subprocess.run(
            ["git", "apply", "--recount", str(local_patch)],
            cwd=workspace,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            env=environment,
        )
        if applied.returncode != 0:
            detail = "git apply failed:\n" + applied.stdout
            _write_validation_report(output_dir, False, detail, None, "")
            return 20

        _validate_contracts(workspace, failure["contract_hashes"])
        verify_output = Path(temp) / "formal-results"
        verification_kind = failure.get("verification_kind", "manifest")
        if verification_kind == "plan":
            plan_bundle = failure["plan_bundle"]
            capsule_id = plan_bundle["item_id"]
            verify_code = run_verify_plan(
                workspace,
                safe_repo_path(workspace, plan_bundle["plan_path"]),
                safe_repo_path(workspace, plan_bundle["generated_root"]),
                verify_output,
            )
            native_ok = True
            native_output = "base-approved native regression executed by plan verifier"
        else:
            manifest_path = workspace / "formal/manifest.toml"
            capsule_id = failure["capsule"]["id"]
            verify_code = run_verify(
                manifest_path,
                base_sha="",
                mode="all",
                output_dir=verify_output,
                only_capsules={capsule_id},
            )
            manifest = load_manifest(manifest_path)
            try:
                capsule = next(item for item in manifest.capsules if item.id == capsule_id)
            except StopIteration as exc:
                raise BundleError(f"manifest no longer contains capsule {capsule_id}") from exc
            native_source = capsule.native_test_source
            native_ok, native_output = _run_native_test(workspace, native_source)
        report = json.loads((verify_output / "report.json").read_text(encoding="utf-8"))
        counterexamples = verify_output / "counterexamples"
        if counterexamples.is_dir():
            shutil.copytree(
                counterexamples,
                output_dir / "counterexamples",
                dirs_exist_ok=True,
            )
        if verification_kind == "plan":
            matching = [
                result for result in report.get("results", []) if result.get("id") == capsule_id
            ]
            formal_ok = (
                verify_code == 0 and len(matching) == 1 and matching[0].get("status") == "verified"
            )
        else:
            formal_ok = verify_code == 0
        successful = formal_ok and native_ok
        detail = (
            "candidate passed the immutable formal and native contracts"
            if successful
            else "candidate did not pass revalidation"
        )
        _write_validation_report(output_dir, successful, detail, report, native_output)
        if successful:
            shutil.copyfile(patch_path, output_dir / "candidate.patch")
        return 0 if successful else 20


def _write_validation_report(
    output_dir: Path,
    successful: bool,
    detail: str,
    formal_report: dict | None,
    native_output: str,
) -> None:
    (output_dir / "validation-report.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "successful": successful,
                "detail": detail,
                "formal_report": formal_report,
                "native_test": native_output,
                "advisory_only": True,
                "validator_received_model_credentials": False,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
