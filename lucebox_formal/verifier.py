from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from xml.etree import ElementTree

from .manifest import capsule_matches, changed_paths, load_manifest
from .model import Capsule, CapsuleResult, Manifest
from .security import (
    safe_repo_path,
    sanitized_subprocess_environment,
    sha256_file,
)


MAX_CAPTURE_BYTES = 512_000
MAX_HTML_REPORT_BYTES = 16_000_000
MAX_HTML_REPORTS = 8


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
    with tempfile.TemporaryDirectory(
        prefix=f".{capsule.id}-", dir=output_dir
    ) as report_temp:
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
                "\n[lucebox-formal: omitted HTML reports beyond "
                f"the limit of {MAX_HTML_REPORTS}]\n"
            )
            html_reports = html_reports[:MAX_HTML_REPORTS]
        published_reports: list[str] = []
        for report in html_reports:
            if not report.is_file():
                continue
            if report.stat().st_size > MAX_HTML_REPORT_BYTES:
                output += (
                    "\n[lucebox-formal: omitted oversized HTML report "
                    f"{report.name}]\n"
                )
                continue
            destination = (
                output_dir / "counterexamples" / capsule.id / report.name
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(report, destination)
            published_reports.append(
                destination.relative_to(output_dir).as_posix()
            )
        if published_reports:
            artifacts["html_reports"] = published_reports
    duration = time.monotonic() - started
    if len(output.encode("utf-8")) > MAX_CAPTURE_BYTES:
        output = output.encode("utf-8")[:MAX_CAPTURE_BYTES].decode(
            "utf-8", errors="replace"
        )
        output += "\n[lucebox-formal: output truncated]\n"
    defines = (
        capsule.nightly_defines if mode == "nightly" else capsule.defines
    )
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


def _write_junit(results: list[CapsuleResult], output: Path) -> None:
    failures = sum(result.status == "counterexample" for result in results)
    errors = sum(result.status in {"timeout", "tool_error"} for result in results)
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
            failure = ElementTree.SubElement(
                case, "failure", {"message": "ESBMC counterexample"}
            )
            failure.text = result.output
        elif result.status in {"timeout", "tool_error"}:
            error = ElementTree.SubElement(
                case, "error", {"message": result.status}
            )
            error.text = result.output
        elif result.status == "skipped":
            ElementTree.SubElement(case, "skipped")
        system_out = ElementTree.SubElement(case, "system-out")
        system_out.text = result.output
    ElementTree.ElementTree(suite).write(
        output, encoding="utf-8", xml_declaration=True
    )


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
        artifact_paths = [
            path
            for paths in result.artifacts.values()
            for path in paths
        ]
        artifacts = (
            "<br>".join(f"`{path}`" for path in artifact_paths)
            if artifact_paths
            else "—"
        )
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
        failure_path.write_text(
            json.dumps(failure, indent=2, sort_keys=True), encoding="utf-8"
        )
        with tarfile.open(bundle, "w:gz") as archive:
            archive.add(failure_path, arcname="failure.json", recursive=False)
            for relative in sorted(bundle_paths):
                source = safe_repo_path(root, relative)
                if not source.is_file():
                    raise ValueError(f"bundle input is not a file: {relative}")
                archive.add(source, arcname=relative, recursive=False)
    return bundle


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
        selected_by_scope = (
            mode in {"all", "nightly"} or capsule_matches(capsule, changed)
        )
        selected = selected_by_id and selected_by_scope
        if selected and not version_matches:
            result = CapsuleResult(
                id=capsule.id,
                description=capsule.description,
                status="tool_error",
                duration_seconds=0.0,
                output=(
                    f"expected ESBMC {expected_version}, found {version}"
                ),
            )
        elif selected:
            result = verify_capsule(
                esbmc, root, capsule, mode, output_dir
            )
        else:
            result = CapsuleResult(
                id=capsule.id,
                description=capsule.description,
                status="skipped",
                duration_seconds=0.0,
            )
        results.append(result)
        if result.status == "counterexample":
            _create_failure_bundle(
                manifest, root, capsule, result, output_dir
            )

    head_process = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    head_sha = (
        head_process.stdout.strip()
        if head_process.returncode == 0
        else "isolated-bundle"
    )
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
