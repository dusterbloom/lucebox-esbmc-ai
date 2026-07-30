from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import tomllib
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from .drift import (
    MAX_REVISION_TEXT_BYTES,
    DriftError,
    analyze_drift,
    blocking_findings,
    validate_drift_report,
)
from .manifest import ManifestError, capsule_matches, changed_paths, load_manifest
from .model import Capsule, CapsuleResult, Manifest
from .plan import PlanError, load_registry
from .security import (
    MAX_BUNDLE_BYTES,
    MAX_MEMBER_BYTES,
    safe_repo_path,
    sanitized_subprocess_environment,
    sha256_file,
)

MAX_CAPTURE_BYTES = 512_000
MAX_HTML_REPORT_BYTES = 16_000_000
MAX_HTML_REPORTS = 8
MAX_PLAN_BYTES = 12_000_000
MAX_PLAN_ITEMS = 512
MAX_CHANGED_PATHS = 4096
MAX_GENERATED_HARNESS_BYTES = 1_000_000
MAX_CONTRACT_SNAPSHOT_BYTES = 1_000_000
MAX_TOTAL_CONTRACT_SNAPSHOT_BYTES = 8_000_000
NATIVE_TEST_TIMEOUT_SECONDS = 120
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PLAN_ITEM_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _tool_version(esbmc: str) -> str:
    try:
        process = subprocess.run(
            [esbmc, "--version"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=sanitized_subprocess_environment(),
        )
    except OSError as exc:
        return f"unavailable ({exc})"
    return process.stdout.strip().splitlines()[0] if process.stdout else "unknown"


def _command(
    esbmc: str,
    root: Path,
    capsule: Capsule,
    mode: str,
) -> list[str]:
    defines = capsule.nightly_defines if mode == "nightly" else capsule.defines
    command = [
        esbmc,
        str(safe_repo_path(root, capsule.harness)),
        "--function",
        capsule.entry_function,
        "--timeout",
        f"{capsule.timeout_seconds}s",
        "--show-stacktrace",
    ]
    command.extend(f"-I{safe_repo_path(root, path)}" for path in capsule.include_dirs)
    command.extend(f"-D{define}" for define in defines)
    command.extend(capsule.esbmc_args)
    if "--generate-html-report" not in capsule.esbmc_args:
        command.append("--generate-html-report")
    return command


def verify_capsule(
    esbmc: str,
    root: Path,
    capsule: Capsule,
    mode: str,
    output_dir: Path,
) -> CapsuleResult:
    command = _command(esbmc, root, capsule, mode)
    started = time.monotonic()
    artifacts: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory(prefix=f".{capsule.id}-", dir=output_dir) as report_temp:
        report_workdir = Path(report_temp)
        try:
            process = subprocess.run(
                command,
                cwd=report_workdir,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=capsule.timeout_seconds + 10,
                env=sanitized_subprocess_environment(),
            )
            output = process.stdout.decode("utf-8", errors="replace")
            if "Timed out" in output or "timed out" in output:
                status = "timeout"
            elif process.returncode == 0 and "VERIFICATION SUCCESSFUL" in output:
                status = "passed"
            elif "VERIFICATION FAILED" in output:
                status = "counterexample"
            else:
                status = "tool_error"
            return_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            captured = exc.stdout or b""
            output = captured.decode("utf-8", errors="replace")
            status = "timeout"
            return_code = None
        except OSError as exc:
            output = str(exc)
            status = "tool_error"
            return_code = None

        html_reports = sorted(report_workdir.glob("report-*.html"))
        if len(html_reports) > MAX_HTML_REPORTS:
            output += (
                f"\n[lucebox-formal: omitted HTML reports beyond the limit of {MAX_HTML_REPORTS}]\n"
            )
            html_reports = html_reports[:MAX_HTML_REPORTS]
        published_reports: list[str] = []
        for report in html_reports:
            if not report.is_file():
                continue
            if report.stat().st_size > MAX_HTML_REPORT_BYTES:
                output += f"\n[lucebox-formal: omitted oversized HTML report {report.name}]\n"
                continue
            destination = output_dir / "counterexamples" / capsule.id / report.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(report, destination)
            published_reports.append(destination.relative_to(output_dir).as_posix())
        if published_reports:
            artifacts["html_reports"] = published_reports
    duration = time.monotonic() - started
    if len(output.encode("utf-8")) > MAX_CAPTURE_BYTES:
        output = output.encode("utf-8")[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
        output += "\n[lucebox-formal: output truncated]\n"
    defines = capsule.nightly_defines if mode == "nightly" else capsule.defines
    return CapsuleResult(
        id=capsule.id,
        description=capsule.description,
        status=status,
        duration_seconds=duration,
        command=command,
        output=output,
        return_code=return_code,
        assumptions={
            "mode": mode,
            "defines": list(defines),
            "esbmc_args": list(capsule.esbmc_args),
            "timeout_seconds": capsule.timeout_seconds,
        },
        artifacts=artifacts,
    )


def _plan_repo_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{field} must be a non-empty repository path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ManifestError(f"{field} must stay inside its declared root")
    return value


def _plan_string_list(raw: dict, field: str) -> tuple[str, ...]:
    value = raw.get(field, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"{field} must be a list of strings")
    return tuple(value)


def _plan_repo_paths(raw: dict, field: str) -> tuple[str, ...]:
    return tuple(_plan_repo_path(value, field) for value in _plan_string_list(raw, field))


def _git_output(workspace: Path, arguments: list[str]) -> bytes:
    process = subprocess.run(
        ["git", *arguments],
        cwd=workspace,
        check=False,
        capture_output=True,
        env=sanitized_subprocess_environment(),
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise ManifestError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout


def _validate_plan_provenance(workspace: Path, plan: dict) -> None:
    base_sha = plan.get("base_sha")
    head_sha = plan.get("head_sha")
    if not isinstance(base_sha, str) or not GIT_SHA.fullmatch(base_sha):
        raise ManifestError("plan base_sha must be a full lowercase Git SHA")
    if not isinstance(head_sha, str) or not GIT_SHA.fullmatch(head_sha):
        raise ManifestError("plan head_sha must be a full lowercase Git SHA")

    if (workspace / ".git").exists():
        actual_head = _git_output(workspace, ["rev-parse", "HEAD"]).decode("ascii").strip()
        if actual_head != head_sha:
            raise ManifestError(
                f"plan head_sha {head_sha} does not match workspace HEAD {actual_head}"
            )
        _git_output(workspace, ["cat-file", "-e", f"{base_sha}^{{commit}}"])

    base_policy = _plan_repo_path(plan.get("base_policy"), "base_policy")
    provenance = plan.get("provenance")
    if not isinstance(provenance, dict):
        raise ManifestError("plan provenance must be an object")
    policy_provenance = provenance.get("base_policy")
    if not isinstance(policy_provenance, dict):
        raise ManifestError("plan provenance.base_policy must be an object")
    if policy_provenance.get("path") != base_policy:
        raise ManifestError("base policy provenance path does not match plan")
    policy_hash = policy_provenance.get("sha256")
    if not isinstance(policy_hash, str) or not SHA256.fullmatch(policy_hash):
        raise ManifestError("base policy provenance has invalid sha256")

    templates = provenance.get("templates", [])
    if not isinstance(templates, list):
        raise ManifestError("plan provenance.templates must be a list")
    immutable: dict[str, str] = {base_policy: policy_hash}
    for template in templates:
        if not isinstance(template, dict):
            raise ManifestError("template provenance must be an object")
        path = _plan_repo_path(template.get("path"), "template path")
        digest = template.get("sha256")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ManifestError(f"template {path} has invalid sha256")
        if path in immutable:
            raise ManifestError(f"duplicate provenance path: {path}")
        immutable[path] = digest

    for relative, expected in immutable.items():
        if (workspace / ".git").exists():
            content = _git_output(workspace, ["show", f"{base_sha}:{relative}"])
            actual = hashlib.sha256(content).hexdigest()
        else:
            path = safe_repo_path(workspace, relative)
            if not path.is_file():
                raise ManifestError(f"bundled provenance file is missing: {relative}")
            actual = sha256_file(path)
        if actual != expected:
            raise ManifestError(
                f"provenance hash mismatch for {relative}: expected {expected}, found {actual}"
            )


def _revision_text(workspace: Path, revision: str, relative: str) -> str | None:
    object_name = f"{revision}:{relative}"
    try:
        size_raw = _git_output(workspace, ["cat-file", "-s", object_name])
    except ManifestError:
        return None
    try:
        size = int(size_raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ManifestError(f"could not determine drift source size: {relative}") from exc
    if size < 0 or size > MAX_REVISION_TEXT_BYTES:
        raise ManifestError(
            f"drift source exceeds {MAX_REVISION_TEXT_BYTES} byte limit: {relative}"
        )
    content = _git_output(workspace, ["show", object_name])
    if len(content) > MAX_REVISION_TEXT_BYTES:
        raise ManifestError(
            f"drift source exceeds {MAX_REVISION_TEXT_BYTES} byte limit: {relative}"
        )
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"drift source is not UTF-8 text: {relative}") from exc


def _validate_and_recompute_drift(workspace: Path, plan: dict) -> None:
    drift = plan.get("drift")
    policy_hash = plan["provenance"]["base_policy"]["sha256"]
    changed = tuple(plan["changed_paths"])
    try:
        validate_drift_report(
            drift,
            base_sha=plan["base_sha"],
            head_sha=plan["head_sha"],
            base_policy_sha256=policy_hash,
            changed=changed,
        )
    except DriftError as exc:
        raise ManifestError(str(exc)) from exc
    if not (workspace / ".git").exists():
        return

    policy_text = _revision_text(workspace, plan["base_sha"], plan["base_policy"])
    if policy_text is None:
        raise ManifestError("base policy is missing while recomputing drift")
    try:
        registry = load_registry(plan["base_policy"], policy_text)
    except PlanError as exc:
        raise ManifestError(f"base policy is invalid while recomputing drift: {exc}") from exc

    proposed_text = _revision_text(workspace, plan["head_sha"], plan["base_policy"])
    head_registry = None
    head_error = None
    if proposed_text is None:
        head_error = "proposed head removes the protected registry"
    else:
        try:
            head_registry = load_registry(plan["base_policy"], proposed_text)
        except PlanError as exc:
            head_error = str(exc)

    def git_text(arguments: list[str]) -> str:
        try:
            return _git_output(workspace, arguments).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ManifestError("Git drift output is not UTF-8") from exc

    try:
        expected = analyze_drift(
            mode=plan["mode"],
            base_sha=plan["base_sha"],
            head_sha=plan["head_sha"],
            base_policy_sha256=policy_hash,
            registry=registry,
            git_output=git_text,
            read_text=lambda revision, relative: _revision_text(
                workspace, revision, relative
            ),
            head_registry=head_registry,
            head_registry_error=head_error,
        )
    except DriftError as exc:
        raise ManifestError(str(exc)) from exc
    if drift != expected:
        raise ManifestError("plan drift evidence does not match the authenticated revisions")


def _plan_execution(item: dict, mode: str) -> dict:
    execution = item.get("execution")
    if not isinstance(execution, dict):
        raise ManifestError(f"{item.get('id', '<unknown>')}: execution must be an object")
    entry_function = execution.get("entry_function", "main")
    if not isinstance(entry_function, str) or not entry_function:
        raise ManifestError("execution.entry_function must be non-empty")
    policy = execution.get("policy")
    if policy not in {"required", "advisory"}:
        raise ManifestError("execution.policy must be required or advisory")
    description = execution.get("description", item["id"])
    if not isinstance(description, str):
        raise ManifestError("execution.description must be a string")
    timeout = execution.get("timeout_seconds", 120)
    if not isinstance(timeout, int) or timeout <= 0 or timeout > 3600:
        raise ManifestError("execution.timeout_seconds is invalid")
    native_test = execution.get("native_test")
    if native_test is not None and not isinstance(native_test, str):
        raise ManifestError("execution.native_test must be a string or null")
    native_source = execution.get("native_test_source")
    if native_source is not None:
        native_source = _plan_repo_path(native_source, "execution.native_test_source")
    if (native_test is None) != (native_source is None):
        raise ManifestError(
            "execution.native_test and execution.native_test_source must be declared together"
        )
    includes = _plan_repo_paths(execution, "include_dirs")
    defines = _plan_string_list(execution, "defines")
    esbmc_args = _plan_string_list(execution, "esbmc_args")
    pr_defines = _plan_string_list(execution, "pr_defines")
    nightly_defines = _plan_string_list(execution, "nightly_defines")
    pr_esbmc_args = _plan_string_list(execution, "pr_esbmc_args")
    nightly_esbmc_args = _plan_string_list(execution, "nightly_esbmc_args")
    expected_defines = nightly_defines if mode == "nightly" else pr_defines
    expected_args = nightly_esbmc_args if mode == "nightly" else pr_esbmc_args
    if defines != expected_defines or esbmc_args != expected_args:
        raise ManifestError(f"{item['id']}: materialized execution settings do not match mode")
    return {
        "policy": policy,
        "description": description,
        "entry_function": entry_function,
        "include_dirs": includes,
        "timeout_seconds": timeout,
        "defines": defines,
        "esbmc_args": esbmc_args,
        "mutable_paths": _plan_repo_paths(execution, "mutable_paths"),
        "contract_paths": _plan_repo_paths(execution, "contract_paths"),
        "native_test": native_test,
        "native_test_source": native_source,
    }


def _resolve_generated_harness(
    plan_path: Path,
    generated_root: Path,
    item: dict,
) -> Path:
    relative = _plan_repo_path(item.get("generated_harness"), "generated_harness")
    candidate = (plan_path.parent / relative).resolve()
    root = generated_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ManifestError(f"{item['id']}: generated harness escapes generated root") from exc
    if not candidate.is_file():
        raise ManifestError(f"{item['id']}: generated harness is missing: {relative}")
    if candidate.stat().st_size > MAX_GENERATED_HARNESS_BYTES:
        raise ManifestError(f"{item['id']}: generated harness exceeds size limit")
    expected = item.get("generated_harness_sha256")
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise ManifestError(f"{item['id']}: generated harness has invalid sha256")
    actual = sha256_file(candidate)
    if actual != expected:
        raise ManifestError(f"{item['id']}: generated harness hash mismatch")
    return candidate


def _validate_plan_item_provenance(
    workspace: Path, plan: dict, item: dict, execution: dict
) -> None:
    provenance = item.get("provenance")
    if not isinstance(provenance, dict):
        raise ManifestError(f"{item['id']}: provenance must be an object")
    global_provenance = plan["provenance"]
    policy_hash = global_provenance["base_policy"]["sha256"]
    if provenance.get("base_policy") != plan["base_policy"]:
        raise ManifestError(f"{item['id']}: base policy path provenance mismatch")
    if provenance.get("base_policy_sha256") != policy_hash:
        raise ManifestError(f"{item['id']}: base policy provenance mismatch")
    if provenance.get("base_sha") != plan["base_sha"]:
        raise ManifestError(f"{item['id']}: base SHA provenance mismatch")
    template_path = item.get("template")
    if not isinstance(template_path, str) or not template_path:
        raise ManifestError(f"{item['id']}: template must be non-empty")
    template_hashes = {
        entry["path"]: entry["sha256"] for entry in global_provenance.get("templates", [])
    }
    expected = template_hashes.get(template_path)
    if expected is None:
        raise ManifestError(f"{item['id']}: template is absent from global provenance")
    if provenance.get("template_sha256") != expected:
        raise ManifestError(f"{item['id']}: template provenance mismatch")
    if provenance.get("template") != template_path:
        raise ManifestError(f"{item['id']}: template path provenance mismatch")
    contracts = provenance.get("contract_paths", [])
    if not isinstance(contracts, list):
        raise ManifestError(f"{item['id']}: contract path provenance must be a list")
    expected_paths = set(execution["contract_paths"])
    if execution["native_test_source"]:
        expected_paths.add(execution["native_test_source"])
    seen: set[str] = set()
    total_contract_bytes = 0
    for contract in contracts:
        if not isinstance(contract, dict):
            raise ManifestError(f"{item['id']}: contract provenance must be an object")
        path = _plan_repo_path(contract.get("path"), "contract provenance path")
        digest = contract.get("sha256")
        content = contract.get("content")
        if (
            not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
            or not isinstance(content, str)
        ):
            raise ManifestError(f"{item['id']}: invalid contract provenance for {path}")
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_CONTRACT_SNAPSHOT_BYTES:
            raise ManifestError(f"{item['id']}: contract snapshot exceeds size limit: {path}")
        total_contract_bytes += len(content_bytes)
        if total_contract_bytes > MAX_TOTAL_CONTRACT_SNAPSHOT_BYTES:
            raise ManifestError(f"{item['id']}: contract snapshots exceed total size limit")
        actual = hashlib.sha256(content_bytes).hexdigest()
        if actual != digest:
            raise ManifestError(f"{item['id']}: contract content hash mismatch for {path}")
        if path in seen:
            raise ManifestError(f"{item['id']}: duplicate contract provenance path {path}")
        seen.add(path)
        if (workspace / ".git").exists():
            base_content = _git_output(workspace, ["show", f"{plan['base_sha']}:{path}"])
            if base_content != content_bytes:
                raise ManifestError(f"{item['id']}: base contract content mismatch for {path}")
    if seen != expected_paths:
        raise ManifestError(f"{item['id']}: contract provenance paths do not match execution")


def _validate_head_sources(workspace: Path, plan: dict, item: dict, execution: dict) -> None:
    paths = item.get("paths")
    if not isinstance(paths, list) or not paths:
        raise ManifestError(f"{item['id']}: planned item has no source paths")
    declared = {_plan_repo_path(path, "planned source path") for path in paths}
    declared.update(execution["mutable_paths"])
    if not (workspace / ".git").exists():
        for relative in declared:
            if not safe_repo_path(workspace, relative).is_file():
                raise ManifestError(f"{item['id']}: bundled source is missing: {relative}")
        return
    for relative in declared:
        working = safe_repo_path(workspace, relative)
        if not working.is_file():
            raise ManifestError(f"{item['id']}: head source is missing: {relative}")
        committed = _git_output(workspace, ["show", f"{plan['head_sha']}:{relative}"])
        if hashlib.sha256(committed).hexdigest() != sha256_file(working):
            raise ManifestError(f"{item['id']}: workspace source differs from head: {relative}")


def _verify_plan_native_test(
    workspace: Path,
    item: dict,
    execution: dict,
    output_dir: Path,
) -> CapsuleResult:
    source_relative = execution["native_test_source"]
    if not source_relative:
        raise ManifestError(f"{item['id']}: native test source is missing")
    snapshots = [
        contract
        for contract in item["provenance"].get("contract_paths", [])
        if contract.get("path") == source_relative
    ]
    if len(snapshots) != 1:
        raise ManifestError(
            f"{item['id']}: expected one base native test snapshot for {source_relative}"
        )
    source_content = snapshots[0]["content"]
    source_hash = snapshots[0]["sha256"]
    started = time.monotonic()
    status = "inconclusive"
    return_code: int | None = None
    output = ""
    command: list[str] = []

    with tempfile.TemporaryDirectory(prefix=f".{item['id']}-native-") as temp:
        native_root = Path(temp)
        source_path = native_root / Path(source_relative).name
        executable = native_root / "native-test"
        source_path.write_text(source_content, encoding="utf-8")
        compile_command = [
            "c++",
            "-std=c++17",
            "-O0",
            "-Wall",
            "-Wextra",
            "-Werror",
        ]
        for include_dir in execution["include_dirs"]:
            compile_command.extend(["-I", str(safe_repo_path(workspace, include_dir))])
        compile_command.extend([str(source_path), "-o", str(executable)])
        command = compile_command
        try:
            compiled = subprocess.run(
                compile_command,
                cwd=workspace,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=NATIVE_TEST_TIMEOUT_SECONDS,
                env=sanitized_subprocess_environment(),
            )
            output = "native compile output:\n" + compiled.stdout
            if compiled.returncode != 0:
                return_code = compiled.returncode
            else:
                command = [str(executable)]
                tested = subprocess.run(
                    command,
                    cwd=workspace,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=NATIVE_TEST_TIMEOUT_SECONDS,
                    env=sanitized_subprocess_environment(),
                )
                return_code = tested.returncode
                output += "native test output:\n" + tested.stdout
                status = "verified" if tested.returncode == 0 else "counterexample"
        except subprocess.TimeoutExpired as exc:
            captured = exc.stdout or ""
            if isinstance(captured, bytes):
                captured = captured.decode("utf-8", errors="replace")
            output += f"native test timed out:\n{captured}"
        except OSError as exc:
            output += f"native test could not execute: {exc}"

    encoded = output.encode("utf-8")
    if len(encoded) > MAX_CAPTURE_BYTES:
        output = encoded[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
        output += "\n[lucebox-formal: native output truncated]\n"
    return CapsuleResult(
        id=item["id"],
        description=f"{execution['description']} (base-approved native regression)",
        status=status,
        duration_seconds=time.monotonic() - started,
        command=command,
        output=output,
        return_code=return_code,
        assumptions={
            "native_test": execution["native_test"],
            "native_test_source": source_relative,
            "native_test_source_sha256": source_hash,
        },
    )


def _verify_plan_item(
    esbmc: str,
    workspace: Path,
    harness: Path,
    item: dict,
    execution: dict,
    mode: str,
    output_dir: Path,
) -> CapsuleResult:
    defines = execution["defines"]
    started = time.monotonic()
    artifacts: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory(prefix=f".{item['id']}-", dir=output_dir) as report_temp:
        report_workdir = Path(report_temp)
        snapshot_root = report_workdir / "base-contracts"
        snapshot_include_dirs = [snapshot_root / "repository"]
        for index, _ in enumerate(execution["include_dirs"]):
            snapshot_include_dirs.append(snapshot_root / "includes" / str(index))
        for contract in item["provenance"]["contract_paths"]:
            content = contract["content"].encode("utf-8")
            relative = contract["path"]
            destinations = [safe_repo_path(snapshot_include_dirs[0], relative)]
            contract_path = PurePosixPath(relative)
            for index, include_dir in enumerate(execution["include_dirs"]):
                try:
                    include_relative = contract_path.relative_to(PurePosixPath(include_dir))
                except ValueError:
                    continue
                destinations.append(
                    safe_repo_path(
                        snapshot_include_dirs[index + 1],
                        include_relative.as_posix(),
                    )
                )
            for destination in destinations:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)

        command = [
            esbmc,
            str(harness),
            "--function",
            execution["entry_function"],
            "--timeout",
            f"{execution['timeout_seconds']}s",
            "--show-stacktrace",
        ]
        command.extend(f"-I{path}" for path in snapshot_include_dirs)
        command.extend(
            f"-I{safe_repo_path(workspace, path)}" for path in execution["include_dirs"]
        )
        command.extend(f"-D{define}" for define in defines)
        command.extend(execution["esbmc_args"])
        if "--generate-html-report" not in execution["esbmc_args"]:
            command.append("--generate-html-report")
        try:
            process = subprocess.run(
                command,
                cwd=report_workdir,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=execution["timeout_seconds"] + 10,
                env=sanitized_subprocess_environment(),
            )
            output = process.stdout.decode("utf-8", errors="replace")
            if "Timed out" in output or "timed out" in output:
                status = "inconclusive"
            elif process.returncode == 0 and "VERIFICATION SUCCESSFUL" in output:
                status = "verified"
            elif "VERIFICATION FAILED" in output:
                status = "counterexample"
            else:
                status = "inconclusive"
            return_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or b"").decode("utf-8", errors="replace")
            status = "inconclusive"
            return_code = None
        except OSError as exc:
            output = str(exc)
            status = "inconclusive"
            return_code = None

        reports = sorted(report_workdir.glob("report-*.html"))
        for report in reports[:MAX_HTML_REPORTS]:
            if not report.is_file() or report.stat().st_size > MAX_HTML_REPORT_BYTES:
                continue
            destination = output_dir / "counterexamples" / item["id"] / report.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(report, destination)
            artifacts.setdefault("html_reports", []).append(
                destination.relative_to(output_dir).as_posix()
            )

    if len(output.encode("utf-8")) > MAX_CAPTURE_BYTES:
        output = output.encode("utf-8")[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
        output += "\n[lucebox-formal: output truncated]\n"
    return CapsuleResult(
        id=item["id"],
        description=execution["description"],
        status=status,
        duration_seconds=time.monotonic() - started,
        command=command,
        output=output,
        return_code=return_code,
        assumptions={
            "mode": mode,
            "defines": list(defines),
            "esbmc_args": list(execution["esbmc_args"]),
            "timeout_seconds": execution["timeout_seconds"],
            "base_sha": item["provenance"]["base_sha"],
            "base_policy_sha256": item["provenance"]["base_policy_sha256"],
            "template_sha256": item["provenance"]["template_sha256"],
            "generated_harness_sha256": item["generated_harness_sha256"],
        },
        artifacts=artifacts,
    )


def _write_junit(results: list[CapsuleResult], output: Path) -> None:
    failures = sum(result.status == "counterexample" for result in results)
    errors = sum(
        result.status in {"timeout", "tool_error", "inconclusive", "invalid_contract"}
        for result in results
    )
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": "lucebox-formal",
            "tests": str(len(results)),
            "failures": str(failures),
            "errors": str(errors),
        },
    )
    for result in results:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": "formal",
                "name": result.id,
                "time": f"{result.duration_seconds:.3f}",
            },
        )
        if result.status == "counterexample":
            failure = ElementTree.SubElement(case, "failure", {"message": "ESBMC counterexample"})
            failure.text = result.output
        elif result.status in {
            "timeout",
            "tool_error",
            "inconclusive",
            "invalid_contract",
        }:
            error = ElementTree.SubElement(case, "error", {"message": result.status})
            error.text = result.output
        elif result.status in {
            "skipped",
            "coverage_gap",
            "not_applicable",
            "proposal_ready",
            "proposal_failed",
        }:
            ElementTree.SubElement(case, "skipped")
        system_out = ElementTree.SubElement(case, "system-out")
        system_out.text = result.output
    ElementTree.ElementTree(suite).write(output, encoding="utf-8", xml_declaration=True)


def _write_summary(
    results: list[CapsuleResult],
    version: str,
    changed: tuple[str, ...],
    output: Path,
) -> None:
    lines = [
        "# Lucebox formal verification",
        "",
        f"- ESBMC: `{version}`",
        f"- Changed paths considered: `{len(changed)}`",
        "",
        "| Capsule | Status | Duration | Artifacts |",
        "|---|---:|---:|---|",
    ]
    for result in results:
        artifact_paths = [path for paths in result.artifacts.values() for path in paths]
        artifacts = "<br>".join(f"`{path}`" for path in artifact_paths) if artifact_paths else "—"
        lines.append(
            f"| `{result.id}` | **{result.status}** | "
            f"{result.duration_seconds:.2f}s | {artifacts} |"
        )
    lines.extend(
        [
            "",
            "A pass is a bounded result under the assumptions recorded in "
            "`report.json`; it is not a proof of the complete Lucebox system.",
        ]
    )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _create_failure_bundle(
    manifest: Manifest,
    root: Path,
    capsule: Capsule,
    result: CapsuleResult,
    output_dir: Path,
) -> Path:
    contract_hashes: dict[str, str] = {}
    manifest_relative = str(manifest.path.relative_to(root))
    bundle_paths = set(capsule.mutable_paths) | set(capsule.contract_paths)
    bundle_paths.add(manifest_relative)
    if capsule.native_test_source:
        bundle_paths.add(capsule.native_test_source)
    immutable_paths = set(capsule.contract_paths) | {manifest_relative}
    if capsule.native_test_source:
        immutable_paths.add(capsule.native_test_source)
    for path in immutable_paths:
        contract_hashes[path] = sha256_file(safe_repo_path(root, path))

    failure = {
        "schema_version": 1,
        "capsule": asdict(capsule),
        "result": result.to_dict(),
        "contract_hashes": contract_hashes,
        "mutable_paths": list(capsule.mutable_paths),
    }

    bundle = output_dir / f"failure-bundle-{capsule.id}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="lucebox-formal-bundle-") as temp:
        failure_path = Path(temp) / "failure.json"
        failure_path.write_text(json.dumps(failure, indent=2, sort_keys=True), encoding="utf-8")
        with tarfile.open(bundle, "w:gz") as archive:
            archive.add(failure_path, arcname="failure.json", recursive=False)
            for relative in sorted(bundle_paths):
                source = safe_repo_path(root, relative)
                if not source.is_file():
                    raise ValueError(f"bundle input is not a file: {relative}")
                archive.add(source, arcname=relative, recursive=False)
    return bundle


def _copy_bytes(destination: Path, content: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)


def _create_plan_failure_bundle(
    workspace: Path,
    plan_path: Path,
    plan: dict,
    planned: list[tuple[dict, dict, Path]],
    failed_item: dict,
    result: CapsuleResult,
    output_dir: Path,
) -> Path:
    bundle = output_dir / f"failure-bundle-{failed_item['id']}.tar.gz"
    failure_execution = next(
        execution for item, execution, _ in planned if item["id"] == failed_item["id"]
    )
    provenance_paths = {
        plan["base_policy"]: plan["provenance"]["base_policy"]["sha256"],
        **{item["path"]: item["sha256"] for item in plan["provenance"].get("templates", [])},
    }

    with tempfile.TemporaryDirectory(prefix="lucebox-formal-plan-bundle-") as temp:
        stage = Path(temp) / "stage"
        stage.mkdir()
        bundled_plan = stage / "formal-plan/plan.json"
        _copy_bytes(bundled_plan, plan_path.read_bytes())

        immutable_paths: set[str] = {"formal-plan/plan.json"}
        mutable_paths = set(failure_execution["mutable_paths"])
        bundled_contract_content: dict[str, bytes] = {}
        for item, _, _ in planned:
            for contract in item["provenance"].get("contract_paths", []):
                content = contract["content"].encode("utf-8")
                existing = bundled_contract_content.get(contract["path"])
                if existing is not None and existing != content:
                    raise ManifestError(
                        f"planned targets disagree on immutable contract {contract['path']}"
                    )
                bundled_contract_content[contract["path"]] = content

        for item, execution, harness in planned:
            harness_relative = _plan_repo_path(item["generated_harness"], "generated_harness")
            bundled_relative = f"formal-plan/{harness_relative}"
            _copy_bytes(stage / bundled_relative, harness.read_bytes())
            immutable_paths.add(bundled_relative)
            source_paths = (
                set(execution["mutable_paths"])
                | set(execution["contract_paths"])
                | {_plan_repo_path(path, "planned source path") for path in item.get("paths", [])}
            )
            if execution["native_test_source"]:
                source_paths.add(execution["native_test_source"])
            for relative in source_paths:
                if relative in provenance_paths or relative in bundled_contract_content:
                    continue
                source = safe_repo_path(workspace, relative)
                if not source.is_file():
                    raise ManifestError(f"bundle input is not a file: {relative}")
                destination = stage / relative
                if not destination.exists():
                    _copy_bytes(destination, source.read_bytes())
                if relative not in mutable_paths:
                    immutable_paths.add(relative)

        for relative, content in bundled_contract_content.items():
            _copy_bytes(stage / relative, content)
            immutable_paths.add(relative)

        for relative in provenance_paths:
            if (workspace / ".git").exists():
                content = _git_output(
                    workspace,
                    ["show", f"{plan['base_sha']}:{relative}"],
                )
            else:
                content = safe_repo_path(workspace, relative).read_bytes()
            _copy_bytes(stage / relative, content)
            immutable_paths.add(relative)

        contract_hashes = {
            relative: sha256_file(stage / relative) for relative in sorted(immutable_paths)
        }
        failure = {
            "schema_version": 1,
            "verification_kind": "plan",
            "plan_bundle": {
                "plan_path": "formal-plan/plan.json",
                "generated_root": "formal-plan",
                "item_id": failed_item["id"],
            },
            "plan_item": failed_item,
            "result": result.to_dict(),
            "contract_hashes": contract_hashes,
            "mutable_paths": sorted(mutable_paths),
            "native_test_source": failure_execution["native_test_source"],
        }
        failure_path = stage / "failure.json"
        failure_path.write_text(
            json.dumps(failure, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        with tarfile.open(bundle, "w:gz") as archive:
            for source in sorted(path for path in stage.rglob("*") if path.is_file()):
                archive.add(
                    source,
                    arcname=source.relative_to(stage).as_posix(),
                    recursive=False,
                )
    return bundle


def _bounded_stage_file(
    stage: Path,
    relative: str,
    content: bytes,
    sizes: dict[str, int],
) -> None:
    if len(content) > MAX_MEMBER_BYTES:
        raise ManifestError(f"bundle member exceeds size limit: {relative}")
    previous = sizes.get(relative)
    if previous is not None:
        existing = (stage / relative).read_bytes()
        if existing != content:
            raise ManifestError(f"bundle members disagree on content: {relative}")
        return
    if sum(sizes.values()) + len(content) > MAX_BUNDLE_BYTES:
        raise ManifestError("bundle exceeds total size limit")
    _copy_bytes(stage / relative, content)
    sizes[relative] = len(content)


def _base_blob(workspace: Path, base_sha: str, relative: str) -> bytes:
    if (workspace / ".git").exists():
        return _git_output(workspace, ["show", f"{base_sha}:{relative}"])
    return safe_repo_path(workspace, relative).read_bytes()


def _approved_template_paths(policy: bytes) -> tuple[str, ...]:
    try:
        registry = tomllib.loads(policy.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"could not parse bundled base policy: {exc}") from exc
    targets = registry.get("targets", [])
    if not isinstance(targets, list):
        raise ManifestError("base policy targets must be a list")
    templates: list[str] = []
    for target in targets:
        if not isinstance(target, dict):
            raise ManifestError("base policy target must be an object")
        template = _plan_repo_path(target.get("template"), "base policy template")
        if template not in templates:
            templates.append(template)
    return tuple(templates)


def _create_coverage_gap_bundle(
    workspace: Path,
    plan_path: Path,
    plan: dict,
    item: dict,
    output_dir: Path,
) -> str | None:
    # Replay workspaces deliberately have no Git metadata and need not emit
    # another synthesis request while validating a repair candidate.
    if not (workspace / ".git").exists():
        return None
    bundle_name = f"coverage-gap-bundle-{item['id']}.tar.gz"
    bundle = output_dir / bundle_name
    base_sha = plan["base_sha"]
    head_sha = plan["head_sha"]
    policy_path = plan["base_policy"]
    policy = _base_blob(workspace, base_sha, policy_path)
    policy_sha = hashlib.sha256(policy).hexdigest()
    if policy_sha != plan["provenance"]["base_policy"]["sha256"]:
        raise ManifestError("coverage gap base policy hash mismatch")

    with tempfile.TemporaryDirectory(prefix="lucebox-formal-gap-bundle-") as temp:
        stage = Path(temp) / "stage"
        stage.mkdir()
        sizes: dict[str, int] = {}
        _bounded_stage_file(
            stage,
            "formal-plan/plan.json",
            plan_path.read_bytes(),
            sizes,
        )
        _bounded_stage_file(stage, policy_path, policy, sizes)

        template_records: list[dict[str, str]] = []
        for template_path in _approved_template_paths(policy):
            content = _base_blob(workspace, base_sha, template_path)
            digest = hashlib.sha256(content).hexdigest()
            _bounded_stage_file(stage, template_path, content, sizes)
            template_records.append({"path": template_path, "sha256": digest})

        raw_paths = item.get("paths")
        if not isinstance(raw_paths, list) or not raw_paths:
            raise ManifestError(f"{item['id']}: coverage gap declares no changed paths")
        head_files: list[dict[str, object]] = []
        for raw_path in raw_paths:
            relative = _plan_repo_path(raw_path, "coverage gap path")
            process = subprocess.run(
                ["git", "show", f"{head_sha}:{relative}"],
                cwd=workspace,
                check=False,
                capture_output=True,
                env=sanitized_subprocess_environment(),
            )
            if process.returncode != 0:
                head_files.append({"path": relative, "deleted": True})
                continue
            content = process.stdout
            _bounded_stage_file(stage, relative, content, sizes)
            head_files.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                }
            )

        gap = {
            "schema_version": 1,
            "event": "coverage_gap",
            "item_id": item["id"],
            "reason": item.get("reason", ""),
            "mode": plan["mode"],
            "base_sha": base_sha,
            "head_sha": head_sha,
            "critical_area": item.get("critical_path"),
            "paths": raw_paths,
            "plan_path": "formal-plan/plan.json",
            "base_policy": {
                "path": policy_path,
                "sha256": policy_sha,
            },
            "templates": template_records,
            "head_files": head_files,
        }
        gap_content = (json.dumps(gap, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _bounded_stage_file(stage, "gap.json", gap_content, sizes)
        with tarfile.open(bundle, "w:gz") as archive:
            for source in sorted(path for path in stage.rglob("*") if path.is_file()):
                archive.add(
                    source,
                    arcname=source.relative_to(stage).as_posix(),
                    recursive=False,
                )
    return bundle_name


def _write_plan_outputs(
    output_dir: Path,
    plan: dict,
    version: str,
    conclusion: str,
    results: list[CapsuleResult],
    error: str | None = None,
) -> None:
    report = {
        "schema_version": 1,
        "verification_kind": "plan",
        "conclusion": conclusion,
        "esbmc_version": version,
        "base_sha": plan.get("base_sha", ""),
        "head_sha": plan.get("head_sha", ""),
        "mode": plan.get("mode", ""),
        "toolchain": plan.get("toolchain", {}),
        "provenance": plan.get("provenance", {}),
        "changed_paths": plan.get("changed_paths", []),
        "drift": plan.get("drift", {}),
        "contract_changes": plan.get("contract_changes", []),
        "plan_items": plan.get("items", []),
        "results": [result.to_dict() for result in results],
    }
    if error:
        report["error"] = error
    (output_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    _write_junit(results, output_dir / "junit.xml")
    lines = [
        "# Lucebox formal verification plan",
        "",
        f"- Conclusion: **{conclusion}**",
        f"- ESBMC: `{version}`",
        f"- Planned results: `{len(results)}`",
    ]
    if error:
        lines.extend(
            [
                "",
                "Plan validation failed. See the bounded `report.json` artifact for details.",
            ]
        )
    lines.extend(
        [
            "",
            "| Contract | Conclusion | Duration |",
            "|---|---:|---:|",
        ]
    )
    for result in results:
        lines.append(f"| `{result.id}` | **{result.status}** | {result.duration_seconds:.2f}s |")
    lines.extend(
        [
            "",
            "Only `verified` means an approved bounded contract passed. "
            "Coverage gaps are advisory in schema v1.",
        ]
    )
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_verify_plan(
    workspace: Path,
    plan_path: Path,
    generated_root: Path,
    output_dir: Path,
) -> int:
    """Verify a self-contained schema-v1 plan without trusting head policy."""
    workspace = workspace.resolve()
    plan_path = plan_path.resolve()
    generated_root = generated_root.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    plan: dict = {}
    results: list[CapsuleResult] = []
    version = "unknown"

    try:
        try:
            if plan_path.stat().st_size > MAX_PLAN_BYTES:
                raise ManifestError("verification plan exceeds size limit")
            loaded = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"could not load verification plan: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ManifestError("verification plan must be a JSON object")
        plan = loaded
        if plan.get("schema_version") != 1:
            raise ManifestError("unsupported verification plan schema_version")
        if (workspace / ".git").exists() and plan.get("workspace") != str(workspace):
            raise ManifestError("plan workspace does not match verification workspace")
        if not isinstance(plan.get("workspace"), str):
            raise ManifestError("plan workspace must be a string")
        mode = plan.get("mode")
        if mode not in {"pr", "all", "nightly"}:
            raise ManifestError("plan mode is invalid")
        changed = plan.get("changed_paths")
        if not isinstance(changed, list) or not all(isinstance(path, str) for path in changed):
            raise ManifestError("plan changed_paths must be a list of strings")
        if len(changed) > MAX_CHANGED_PATHS:
            raise ManifestError("plan changed_paths exceeds size limit")
        for path in changed:
            _plan_repo_path(path, "changed path")
        contract_changes = plan.get("contract_changes", [])
        if not isinstance(contract_changes, list) or not all(
            isinstance(change, dict) for change in contract_changes
        ):
            raise ManifestError("plan contract_changes must be a list")
        _validate_plan_provenance(workspace, plan)
        _validate_and_recompute_drift(workspace, plan)

        items = plan.get("items")
        if not isinstance(items, list):
            raise ManifestError("plan items must be a list")
        if len(items) > MAX_PLAN_ITEMS:
            raise ManifestError("plan items exceeds size limit")
        seen: set[str] = set()
        planned: list[tuple[dict, dict, Path]] = []
        has_gap = False
        blocked = blocking_findings(plan["drift"])
        if blocked:
            results.append(
                CapsuleResult(
                    id="drift-integrity",
                    description="Protected formal-policy drift",
                    status="invalid_contract",
                    duration_seconds=0.0,
                    output=json.dumps(blocked, indent=2, sort_keys=True),
                )
            )
        for item in items:
            if not isinstance(item, dict):
                raise ManifestError("each plan item must be an object")
            item_id = item.get("id")
            if not isinstance(item_id, str) or not PLAN_ITEM_ID.fullmatch(item_id):
                raise ManifestError("plan item has invalid id")
            if item_id in seen:
                raise ManifestError(f"duplicate plan item id: {item_id}")
            seen.add(item_id)
            status = item.get("status")
            if status == "planned":
                execution = _plan_execution(item, mode)
                _validate_plan_item_provenance(workspace, plan, item, execution)
                _validate_head_sources(workspace, plan, item, execution)
                harness = _resolve_generated_harness(plan_path, generated_root, item)
                planned.append((item, execution, harness))
            elif status == "coverage_gap":
                has_gap = True
                gap_result = CapsuleResult(
                    id=item_id,
                    description=str(item.get("reason", item_id)),
                    status="coverage_gap",
                    duration_seconds=0.0,
                )
                gap_bundle = _create_coverage_gap_bundle(
                    workspace, plan_path, plan, item, output_dir
                )
                if gap_bundle is not None:
                    gap_result.artifacts["coverage_gap_bundles"] = [gap_bundle]
                results.append(gap_result)
            elif status == "not_applicable":
                results.append(
                    CapsuleResult(
                        id=item_id,
                        description=str(item.get("reason", item_id)),
                        status="not_applicable",
                        duration_seconds=0.0,
                    )
                )
            elif status == "generation_error":
                raise ManifestError(
                    f"{item_id}: contract generation failed: {item.get('reason', 'unknown error')}"
                )
            else:
                raise ManifestError(f"{item_id}: unsupported planner status {status!r}")

        esbmc = os.environ.get("ESBMC_PATH", "esbmc")
        version = _tool_version(esbmc)
        toolchain = plan.get("toolchain", {})
        if not isinstance(toolchain, dict):
            raise ManifestError("plan toolchain must be an object")
        expected_version = toolchain.get("esbmc_version")
        if expected_version is not None and (
            not isinstance(expected_version, str) or expected_version not in version
        ):
            for item, execution, _ in planned:
                results.append(
                    CapsuleResult(
                        id=item["id"],
                        description=execution["description"],
                        status="inconclusive",
                        duration_seconds=0.0,
                        output=(f"expected ESBMC {expected_version}, found {version}"),
                    )
                )
        else:
            for item, execution, harness in planned:
                result = _verify_plan_item(
                    esbmc,
                    workspace,
                    harness,
                    item,
                    execution,
                    mode,
                    output_dir,
                )
                if result.status == "verified" and execution["native_test_source"]:
                    native_result = _verify_plan_native_test(
                        workspace,
                        item,
                        execution,
                        output_dir,
                    )
                    result.duration_seconds += native_result.duration_seconds
                    result.output += (
                        "\n[base-approved native regression]\n" + native_result.output
                    )
                    result.assumptions["native_test"] = {
                        **native_result.assumptions,
                        "status": native_result.status,
                        "command": native_result.command,
                    }
                    if native_result.status != "verified":
                        result.status = native_result.status
                        result.return_code = native_result.return_code
                results.append(result)
                if result.status == "counterexample":
                    _create_plan_failure_bundle(
                        workspace,
                        plan_path,
                        plan,
                        planned,
                        item,
                        result,
                        output_dir,
                    )

        statuses = {result.status for result in results}
        if "counterexample" in statuses:
            conclusion, code = "counterexample", 10
        elif "invalid_contract" in statuses:
            conclusion, code = "invalid_contract", 13
        elif "inconclusive" in statuses:
            conclusion, code = "inconclusive", 11
        elif has_gap or "coverage_gap" in statuses:
            conclusion, code = "coverage_gap", 0
        elif planned:
            conclusion, code = "verified", 0
        else:
            conclusion, code = "not_applicable", 0
        _write_plan_outputs(output_dir, plan, version, conclusion, results)
        return code
    except (ManifestError, ValueError, OSError) as exc:
        result = CapsuleResult(
            id="plan-validation",
            description="Verification plan validation",
            status="invalid_contract",
            duration_seconds=0.0,
            output=str(exc),
        )
        results.append(result)
        _write_plan_outputs(
            output_dir,
            plan,
            version,
            "invalid_contract",
            results,
            error=str(exc),
        )
        return 13


def run_verify(
    manifest_path: Path,
    base_sha: str,
    mode: str,
    output_dir: Path,
    only_capsules: set[str] | None = None,
) -> int:
    manifest = load_manifest(manifest_path)
    root = manifest.path.parent.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    esbmc = os.environ.get("ESBMC_PATH", "esbmc")
    version = _tool_version(esbmc)
    expected_version = manifest.toolchain["esbmc_version"]
    version_matches = expected_version in version
    changed = changed_paths(root, base_sha) if mode == "pr" else ()

    results: list[CapsuleResult] = []
    for capsule in manifest.capsules:
        selected_by_id = only_capsules is None or capsule.id in only_capsules
        selected_by_scope = mode in {"all", "nightly"} or capsule_matches(capsule, changed)
        selected = selected_by_id and selected_by_scope
        if selected and not version_matches:
            result = CapsuleResult(
                id=capsule.id,
                description=capsule.description,
                status="tool_error",
                duration_seconds=0.0,
                output=(f"expected ESBMC {expected_version}, found {version}"),
            )
        elif selected:
            result = verify_capsule(esbmc, root, capsule, mode, output_dir)
        else:
            result = CapsuleResult(
                id=capsule.id,
                description=capsule.description,
                status="skipped",
                duration_seconds=0.0,
            )
        results.append(result)
        if result.status == "counterexample":
            _create_failure_bundle(manifest, root, capsule, result, output_dir)

    head_process = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    head_sha = head_process.stdout.strip() if head_process.returncode == 0 else "isolated-bundle"
    report = {
        "schema_version": 1,
        "esbmc_version": version,
        "manifest": str(manifest.path.relative_to(root)),
        "mode": mode,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "changed_paths": list(changed),
        "results": [result.to_dict() for result in results],
    }
    (output_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    _write_junit(results, output_dir / "junit.xml")
    _write_summary(results, version, changed, output_dir / "summary.md")

    if any(result.status == "counterexample" for result in results):
        return 10
    if any(result.status == "timeout" for result in results):
        return 11
    if any(result.status == "tool_error" for result in results):
        return 12
    return 0
