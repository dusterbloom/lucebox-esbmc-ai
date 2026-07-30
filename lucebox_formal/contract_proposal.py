"""Advisory contract proposals for uncovered, critical PR changes.

This module deliberately does not update a registry, manifest, or checkout.
The credential-bearing proposer only writes an untrusted proposal; the
credential-free validator rechecks that proposal against an exact gap bundle
and the checked-out head revision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from .repair import _esbmc_ai_model_class
from .security import BundleError, extract_bundle, safe_repo_path, sanitized_subprocess_environment

MAX_RESPONSE_BYTES = 256_000
MAX_METADATA_BYTES = 32_000
MAX_CONTRACT_BYTES = 128_000
MAX_PROMPT_BYTES = 1_000_000
MAX_CHANGED_FILES = 64
MAX_TEMPLATE_FILES = 64
MAX_CAPTURE_BYTES = 512_000
MAX_TIMEOUT_SECONDS = 300
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
PROPOSAL_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
CPP_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]{0,255}$")
CPP_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
CPP_SIGNATURE = re.compile(r"^[A-Za-z_][A-Za-z0-9_:<>, *&()]{0,511}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FENCED_RESPONSE = re.compile(
    r"\A```json\n(?P<metadata>.*?)\n```\s*```cpp\n(?P<contract>.*?)\n```\s*\Z",
    re.DOTALL,
)

ALLOWED_ESBMC_FLAGS = {
    "--quiet",
    "--z3",
    "--memory-leak-check",
    "--overflow-check",
    "--generate-html-report",
}


class ContractProposalError(BundleError):
    pass


SYSTEM_PROMPT = """\
You are proposing an advisory, bounded C++ ESBMC contract for an uncovered
Lucebox state transition. This is not an approved specification.

Return exactly two fenced sections and no other text:
```json
{"id":"lowercase-id","source_path":"repository/path.cpp","symbol":"ns::symbol","signature":"int(int)","entry_function":"verify_contract","include_dirs":["server/src"],"timeout_seconds":120,"esbmc_args":["--quiet","--z3","--unwind","5"]}
```
```cpp
// a harness that includes and calls the real production symbol
```

The harness must call the declared production symbol and contain at least one
assertion or ESBMC postcondition. Do not modify any repository file, registry,
or existing contract.
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repo_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractProposalError(f"{field} must be a non-empty repository path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) == ".":
        raise ContractProposalError(f"{field} escapes its declared root")
    return value


def _read_hashed(root: Path, raw: object, field: str) -> tuple[str, str, bytes]:
    if not isinstance(raw, dict):
        raise ContractProposalError(f"{field} must be an object")
    relative = _repo_path(raw.get("path"), f"{field}.path")
    digest = raw.get("sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ContractProposalError(f"{field}.sha256 is invalid")
    path = safe_repo_path(root, relative)
    if not path.is_file():
        raise ContractProposalError(f"{field} is missing: {relative}")
    data = path.read_bytes()
    if _sha256(data) != digest:
        raise ContractProposalError(f"{field} hash mismatch: {relative}")
    return relative, digest, data


def _load_gap_bundle(bundle: Path, destination: Path) -> dict[str, Any]:
    """Extract and authenticate schema-v1 coverage-gap replay inputs."""
    extract_bundle(bundle, destination)
    gap_path = destination / "gap.json"
    if not gap_path.is_file():
        raise ContractProposalError("coverage-gap bundle is missing gap.json")
    raw_gap = gap_path.read_bytes()
    if len(raw_gap) > MAX_METADATA_BYTES:
        raise ContractProposalError("gap.json exceeds size limit")
    try:
        gap = json.loads(raw_gap)
    except json.JSONDecodeError as exc:
        raise ContractProposalError("gap.json is invalid JSON") from exc
    if not isinstance(gap, dict) or gap.get("schema_version") != 1:
        raise ContractProposalError("unsupported coverage-gap bundle schema")
    for field in ("base_sha", "head_sha"):
        if not isinstance(gap.get(field), str) or not GIT_SHA.fullmatch(gap[field]):
            raise ContractProposalError(f"gap.json has invalid {field}")
    if gap.get("event") != "coverage_gap":
        raise ContractProposalError("gap.json must describe a coverage_gap event")
    if not isinstance(gap.get("item_id"), str) or not PROPOSAL_ID.fullmatch(gap["item_id"]):
        raise ContractProposalError("gap.json has invalid item_id")
    changed_paths = gap.get("paths")
    if not isinstance(changed_paths, list) or not changed_paths:
        raise ContractProposalError("gap.json coverage gap must name changed paths")
    if not all(isinstance(path, str) for path in changed_paths):
        raise ContractProposalError("gap.json coverage paths are invalid")
    changed_paths = [_repo_path(path, "gap path") for path in changed_paths]

    plan_path = _repo_path(gap.get("plan_path"), "plan_path")
    plan_file = safe_repo_path(destination, plan_path)
    if not plan_file.is_file():
        raise ContractProposalError("bundled plan is missing")
    plan_bytes = plan_file.read_bytes()
    if len(plan_bytes) > MAX_RESPONSE_BYTES:
        raise ContractProposalError("bundled plan exceeds size limit")
    plan_hash = _sha256(plan_bytes)
    try:
        plan = json.loads(plan_bytes)
    except json.JSONDecodeError as exc:
        raise ContractProposalError("bundled plan is invalid JSON") from exc
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise ContractProposalError("bundled plan is not schema v1")
    if plan.get("base_sha") != gap["base_sha"]:
        raise ContractProposalError("gap base SHA does not match plan")
    if plan.get("head_sha") != gap["head_sha"]:
        raise ContractProposalError("gap head SHA does not match plan")
    if plan.get("mode") != gap.get("mode"):
        raise ContractProposalError("gap mode does not match plan")
    plan_items = plan.get("items")
    if not isinstance(plan_items, list):
        raise ContractProposalError("bundled plan items are invalid")
    matching_items = [
        item for item in plan_items if isinstance(item, dict) and item.get("id") == gap["item_id"]
    ]
    if (
        len(matching_items) != 1
        or matching_items[0].get("status") != "coverage_gap"
        or matching_items[0].get("paths") != changed_paths
        or matching_items[0].get("critical_path") != gap.get("critical_area")
    ):
        raise ContractProposalError("coverage-gap item does not match bundled plan")
    policy_path, policy_hash, policy_bytes = _read_hashed(
        destination, gap.get("base_policy"), "base_policy"
    )
    if plan.get("base_policy") != policy_path:
        raise ContractProposalError("gap base policy path does not match plan")
    plan_provenance = plan.get("provenance")
    if not isinstance(plan_provenance, dict) or plan_provenance.get("base_policy") != {
        "path": policy_path,
        "sha256": policy_hash,
    }:
        raise ContractProposalError("gap base policy hash does not match plan")
    templates = gap.get("templates", [])
    if not isinstance(templates, list) or len(templates) > MAX_TEMPLATE_FILES:
        raise ContractProposalError("gap.json templates are invalid")
    template_inputs = [_read_hashed(destination, item, "template") for item in templates]
    try:
        registry = tomllib.loads(policy_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ContractProposalError("bundled base policy is invalid") from exc
    registry_targets = registry.get("targets")
    if not isinstance(registry_targets, list):
        raise ContractProposalError("bundled base policy targets are invalid")
    approved_templates = {
        target.get("template") for target in registry_targets if isinstance(target, dict)
    }
    if len(approved_templates) != len(registry_targets):
        raise ContractProposalError("bundled base policy targets are invalid")
    bundled_templates = {path for path, _, _ in template_inputs}
    if (
        None in approved_templates
        or len(bundled_templates) != len(template_inputs)
        or bundled_templates != approved_templates
    ):
        raise ContractProposalError("bundled templates do not match approved base policy")
    changed = gap.get("head_files", [])
    if not isinstance(changed, list) or not changed or len(changed) > MAX_CHANGED_FILES:
        raise ContractProposalError("gap.json head_files are invalid")
    changed_inputs: list[dict[str, Any]] = []
    recorded_head_paths: set[str] = set()
    for item in changed:
        if not isinstance(item, dict):
            raise ContractProposalError("head_file must be an object")
        relative = _repo_path(item.get("path"), "head_file.path")
        if relative in recorded_head_paths or relative not in changed_paths:
            raise ContractProposalError("head_file paths do not match gap")
        recorded_head_paths.add(relative)
        if item.get("deleted") is True:
            continue
        relative, digest, data = _read_hashed(destination, item, "head_file")
        if item.get("size") != len(data):
            raise ContractProposalError("head_file size mismatch")
        changed_inputs.append({"path": relative, "sha256": digest, "content": data})
    if recorded_head_paths != set(changed_paths):
        raise ContractProposalError("head_file records do not cover the gap")
    return {
        "gap": gap,
        "gap_sha256": _sha256(raw_gap),
        "plan": {"path": plan_path, "sha256": plan_hash, "content": plan_bytes},
        "base_policy": {"path": policy_path, "sha256": policy_hash, "content": policy_bytes},
        "templates": [
            {"path": path, "sha256": digest, "content": data}
            for path, digest, data in template_inputs
        ],
        "head_files": changed_inputs,
    }


def _decode_for_prompt(value: bytes, label: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractProposalError(f"{label} is not UTF-8 text") from exc


def _prompt(inputs: dict[str, Any]) -> str:
    gap = inputs["gap"]
    sections = [
        "COVERAGE GAP:",
        json.dumps(gap, sort_keys=True),
        "",
        "EXACT PLAN:",
        _decode_for_prompt(inputs["plan"]["content"], "plan"),
        "",
        "BASE POLICY:",
        _decode_for_prompt(inputs["base_policy"]["content"], "base policy"),
    ]
    for template in inputs["templates"]:
        sections.extend(
            [
                "",
                f"TEMPLATE: {template['path']}",
                _decode_for_prompt(template["content"], "template"),
            ]
        )
    for changed in inputs["head_files"]:
        sections.extend(
            [
                "",
                f"CHANGED HEAD FILE: {changed['path']}",
                _decode_for_prompt(changed["content"], "changed head file"),
            ]
        )
    prompt = "\n".join(sections)
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise ContractProposalError("coverage-gap prompt exceeds size limit")
    return prompt


def _validate_esbmc_args(value: object) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise ContractProposalError("esbmc_args must contain 1 to 16 arguments")
    if not all(isinstance(argument, str) for argument in value):
        raise ContractProposalError("esbmc_args must be strings")
    result = list(value)
    index = 0
    while index < len(result):
        argument = result[index]
        if argument in ALLOWED_ESBMC_FLAGS:
            index += 1
        elif argument == "--unwind":
            if (
                index + 1 >= len(result)
                or not result[index + 1].isdigit()
                or not 1 <= int(result[index + 1]) <= 128
            ):
                raise ContractProposalError("--unwind requires a bound from 1 to 128")
            index += 2
        elif argument == "--enforce-contract":
            if index + 1 >= len(result) or not CPP_IDENTIFIER.fullmatch(result[index + 1]):
                raise ContractProposalError("--enforce-contract requires a C++ identifier")
            index += 2
        else:
            raise ContractProposalError(f"ESBMC argument is not whitelisted: {argument}")
    return result


def _parse_response(response: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if len(response.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise ContractProposalError("model response exceeds size limit")
    match = FENCED_RESPONSE.fullmatch(response)
    if match is None:
        raise ContractProposalError(
            "model response must contain exactly JSON and C++ fenced sections"
        )
    metadata_text = match.group("metadata")
    contract = match.group("contract").strip() + "\n"
    if (
        len(metadata_text.encode("utf-8")) > MAX_METADATA_BYTES
        or len(contract.encode("utf-8")) > MAX_CONTRACT_BYTES
    ):
        raise ContractProposalError("proposal section exceeds size limit")
    try:
        metadata = json.loads(metadata_text)
    except json.JSONDecodeError as exc:
        raise ContractProposalError("proposal metadata is invalid JSON") from exc
    if not isinstance(metadata, dict):
        raise ContractProposalError("proposal metadata must be an object")
    proposal_id = metadata.get("id")
    source_path = metadata.get("source_path")
    symbol = metadata.get("symbol")
    signature = metadata.get("signature")
    entry_function = metadata.get("entry_function")
    if not isinstance(proposal_id, str) or not PROPOSAL_ID.fullmatch(proposal_id):
        raise ContractProposalError("proposal id is invalid")
    source_path = _repo_path(source_path, "proposal source_path")
    if source_path not in inputs["gap"]["paths"]:
        raise ContractProposalError("proposal source_path is not a changed gap path")
    if not isinstance(symbol, str) or not CPP_SYMBOL.fullmatch(symbol):
        raise ContractProposalError("proposal symbol is invalid")
    if not isinstance(signature, str) or not CPP_SIGNATURE.fullmatch(signature):
        raise ContractProposalError("proposal signature is invalid")
    if not isinstance(entry_function, str) or not CPP_IDENTIFIER.fullmatch(entry_function):
        raise ContractProposalError("proposal entry_function is invalid")
    include_dirs = metadata.get("include_dirs")
    if include_dirs != ["server/src"]:
        raise ContractProposalError("proposal include_dirs must be exactly [server/src]")
    timeout = metadata.get("timeout_seconds")
    if not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ContractProposalError("proposal timeout_seconds is invalid")
    metadata["esbmc_args"] = _validate_esbmc_args(metadata.get("esbmc_args"))
    if symbol not in contract:
        raise ContractProposalError("proposal contract omits declared production symbol")
    if "assert(" not in contract and "__ESBMC_ensures" not in contract:
        raise ContractProposalError("proposal contract has no assertion or postcondition")
    return metadata, contract


def _proposal_provenance(inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "gap_sha256": inputs["gap_sha256"],
        "base_sha": inputs["gap"]["base_sha"],
        "head_sha": inputs["gap"]["head_sha"],
        "plan": {key: inputs["plan"][key] for key in ("path", "sha256")},
        "base_policy": {key: inputs["base_policy"][key] for key in ("path", "sha256")},
        "templates": [
            {key: item[key] for key in ("path", "sha256")} for item in inputs["templates"]
        ],
        "head_files": [
            {key: item[key] for key in ("path", "sha256")} for item in inputs["head_files"]
        ],
    }


def run_propose_contract(bundle: Path, model: str, output_dir: Path) -> int:
    """Create an untrusted proposal; this function never executes C++ code."""
    output_dir.mkdir(parents=True, exist_ok=True)
    from langchain_core.messages import HumanMessage, SystemMessage

    with tempfile.TemporaryDirectory(prefix="lucebox-contract-propose-") as temp:
        inputs = _load_gap_bundle(bundle, Path(temp) / "bundle")
        AIModel = _esbmc_ai_model_class()
        response = AIModel.get_model(model=model, temperature=0).invoke(
            [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=_prompt(inputs))]
        )
        response_text = response.text if isinstance(response.text, str) else str(response.text)
        metadata, contract = _parse_response(response_text, inputs)
        proposal = {
            "schema_version": 1,
            "advisory_only": True,
            "executed_candidate_code": False,
            "metadata": metadata,
            "contract_sha256": _sha256(contract.encode("utf-8")),
            "provenance": _proposal_provenance(inputs),
        }
        (output_dir / "proposal.json").write_text(
            json.dumps(proposal, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output_dir / "contract.cpp").write_text(contract, encoding="utf-8")
        (output_dir / "advisory-report.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "proposal_created",
                    "advisory_only": True,
                    "executed_candidate_code": False,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


def _load_proposal(proposal_dir: Path, inputs: dict[str, Any]) -> tuple[dict[str, Any], str]:
    proposal_path = proposal_dir / "proposal.json"
    contract_path = proposal_dir / "contract.cpp"
    if not proposal_path.is_file() or not contract_path.is_file():
        raise ContractProposalError("proposal directory is incomplete")
    if (
        proposal_path.stat().st_size > MAX_METADATA_BYTES
        or contract_path.stat().st_size > MAX_CONTRACT_BYTES
    ):
        raise ContractProposalError("proposal file exceeds size limit")
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    if (
        not isinstance(proposal, dict)
        or proposal.get("schema_version") != 1
        or proposal.get("advisory_only") is not True
    ):
        raise ContractProposalError("proposal is not an advisory schema-v1 proposal")
    contract = contract_path.read_text(encoding="utf-8")
    expected = proposal.get("contract_sha256")
    if not isinstance(expected, str) or _sha256(contract.encode("utf-8")) != expected:
        raise ContractProposalError("proposal contract hash mismatch")
    metadata = proposal.get("metadata")
    if not isinstance(metadata, dict):
        raise ContractProposalError("proposal metadata is missing")
    # Reuse the strict response validator without relying on model output.
    response = (
        "```json\n"
        + json.dumps(metadata, sort_keys=True)
        + "\n```\n```cpp\n"
        + contract.rstrip("\n")
        + "\n```"
    )
    metadata, contract = _parse_response(response, inputs)
    if proposal.get("provenance") != _proposal_provenance(inputs):
        raise ContractProposalError("proposal provenance does not match re-extracted bundle")
    return metadata, contract


def _workspace_head(workspace: Path) -> str:
    process = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=workspace,
        check=False,
        text=True,
        capture_output=True,
        env=sanitized_subprocess_environment(),
    )
    if process.returncode != 0:
        raise ContractProposalError("workspace is not a Git checkout")
    head = process.stdout.strip()
    if not GIT_SHA.fullmatch(head):
        raise ContractProposalError("workspace HEAD is invalid")
    return head


def _validate_workspace_changed_files(
    workspace: Path, inputs: dict[str, Any], source_path: str
) -> None:
    matching = [item for item in inputs["head_files"] if item["path"] == source_path]
    if len(matching) != 1:
        raise ContractProposalError("proposal source path is not uniquely bundled")
    workspace_file = safe_repo_path(workspace, source_path)
    if (
        not workspace_file.is_file()
        or _sha256(workspace_file.read_bytes()) != matching[0]["sha256"]
    ):
        raise ContractProposalError("workspace source does not match bundled head file")


def run_validate_contract(
    bundle: Path, proposal_dir: Path, workspace: Path, output_dir: Path
) -> int:
    """Secretless, advisory ESBMC validation; it never promotes a contract."""
    output_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema_version": 1,
        "advisory_only": True,
        "status": "proposal_failed",
        "validator_received_model_credentials": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="lucebox-contract-validate-") as temp:
            inputs = _load_gap_bundle(bundle, Path(temp) / "bundle")
            if _workspace_head(workspace.resolve()) != inputs["gap"]["head_sha"]:
                raise ContractProposalError("workspace HEAD does not match bundled head SHA")
            metadata, contract = _load_proposal(proposal_dir, inputs)
            _validate_workspace_changed_files(workspace.resolve(), inputs, metadata["source_path"])
            contract_file = Path(temp) / "contract.cpp"
            contract_file.write_text(contract, encoding="utf-8")
            esbmc = os.environ.get("ESBMC_PATH", "esbmc")
            command = [
                esbmc,
                str(contract_file),
                "--function",
                metadata["entry_function"],
                "--timeout",
                f"{metadata['timeout_seconds']}s",
                "--show-stacktrace",
                "-I" + str(safe_repo_path(workspace.resolve(), "server/src")),
                *metadata["esbmc_args"],
            ]
            process = subprocess.run(
                command,
                cwd=Path(temp),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=metadata["timeout_seconds"] + 10,
                env=sanitized_subprocess_environment(),
            )
            output = process.stdout.decode("utf-8", errors="replace")
            if len(output.encode("utf-8")) > MAX_CAPTURE_BYTES:
                output = (
                    output.encode("utf-8")[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
                    + "\n[lucebox-formal: output truncated]\n"
                )
            ready = process.returncode == 0 and "VERIFICATION SUCCESSFUL" in output
            report.update(
                {
                    "status": "proposal_ready" if ready else "proposal_failed",
                    "command": command,
                    "output": output,
                    "return_code": process.returncode,
                    "provenance": _proposal_provenance(inputs),
                }
            )
    except (
        ContractProposalError,
        BundleError,
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        report["error"] = str(exc)
    (output_dir / "proposal-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if report["status"] == "proposal_ready" else 20
