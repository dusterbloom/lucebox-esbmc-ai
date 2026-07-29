from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from .drift import (
    MAX_REVISION_TEXT_BYTES,
    DriftError,
    analyze_drift,
    drift_changed_paths,
    matches,
)
from .model import ContractRegistry, CriticalArea, RegistryTarget
from .security import sanitized_subprocess_environment


class PlanError(ValueError):
    pass


TARGET_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
VARIABLE_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
MAX_REGISTRY_BYTES = 512_000
MAX_TEMPLATE_BYTES = 1_000_000
MAX_CONTRACT_PATH_BYTES = 1_000_000
MAX_RENDERED_HARNESS_BYTES = 1_000_000
MAX_TOTAL_CONTRACT_BYTES = 8_000_000
MAX_TARGETS = 128
MAX_CRITICAL_PATHS = 64
MAX_PLAN_ITEMS = 1_024


def _repo_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlanError(f"{field} must be a non-empty repository path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) == ".":
        raise PlanError(f"{field} must stay inside the repository")
    return value


def _paths(raw: dict[str, Any], field: str, *, required: bool = False) -> tuple[str, ...]:
    value = raw.get(field, [])
    if required and field not in raw:
        raise PlanError(f"{field} is required")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PlanError(f"{field} must be a list of strings")
    return tuple(_repo_path(item, field) for item in value)


def _string_list(raw: dict[str, Any], field: str) -> tuple[str, ...]:
    value = raw.get(field, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PlanError(f"{field} must be a list of strings")
    return tuple(value)


def _optional_path(raw: dict[str, Any], field: str) -> str | None:
    value = raw.get(field)
    if value is None:
        return None
    return _repo_path(value, field)


def _template_variables(raw: dict[str, Any]) -> dict[str, str]:
    value = raw.get("template_variables", {})
    if not isinstance(value, dict):
        raise PlanError("template_variables must be a table")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not VARIABLE_NAME.fullmatch(key):
            raise PlanError("template variable names must be uppercase identifiers")
        if not isinstance(item, str):
            raise PlanError("template variable values must be strings")
        result[key] = item
    return result


def load_registry(path: str, contents: str) -> ContractRegistry:
    """Parse a base-revision registry; never read a PR-side policy file."""
    try:
        data = tomllib.loads(contents)
    except tomllib.TOMLDecodeError as exc:
        raise PlanError(f"invalid base policy TOML: {exc}") from exc
    if data.get("schema_version") != 1:
        raise PlanError("unsupported registry schema_version")
    toolchain = data.get("toolchain", {})
    if not isinstance(toolchain, dict):
        raise PlanError("toolchain must be a table")
    if not isinstance(toolchain.get("esbmc_version"), str) or not toolchain["esbmc_version"]:
        raise PlanError("toolchain.esbmc_version must be a non-empty string")
    critical_paths: list[CriticalArea] = []
    seen_critical: set[str] = set()
    raw_critical_paths = data.get("critical_paths", [])
    if not isinstance(raw_critical_paths, list):
        raise PlanError("critical_paths must be a list")
    if len(raw_critical_paths) > MAX_CRITICAL_PATHS:
        raise PlanError(f"registry exceeds {MAX_CRITICAL_PATHS} critical path areas")
    for raw_critical in raw_critical_paths:
        if not isinstance(raw_critical, dict):
            raise PlanError("each critical_paths entry must be a table")
        critical_id = raw_critical.get("id")
        description = raw_critical.get("description")
        if not isinstance(critical_id, str) or not TARGET_ID.fullmatch(critical_id):
            raise PlanError("critical path id must contain lowercase letters, digits, or hyphens")
        if critical_id in seen_critical:
            raise PlanError(f"duplicate critical path id: {critical_id}")
        if not isinstance(description, str) or not description:
            raise PlanError(f"{critical_id}: critical path description is required")
        seen_critical.add(critical_id)
        paths = _paths(raw_critical, "paths", required=True)
        if not paths:
            raise PlanError(f"{critical_id}: critical paths must not be empty")
        critical_policy = raw_critical.get("policy", "advisory")
        if critical_policy not in {"required", "advisory"}:
            raise PlanError(f"{critical_id}: critical-path policy must be required or advisory")
        critical_paths.append(
            CriticalArea(
                id=critical_id,
                description=description,
                paths=paths,
                watch_paths=_paths(raw_critical, "watch_paths"),
                include_roots=_paths(raw_critical, "include_roots"),
                policy=critical_policy,
            )
        )

    targets: list[RegistryTarget] = []
    seen: set[str] = set()
    raw_targets = data.get("targets", [])
    if not isinstance(raw_targets, list):
        raise PlanError("targets must be a list")
    if len(raw_targets) > MAX_TARGETS:
        raise PlanError(f"registry exceeds {MAX_TARGETS} targets")
    for raw in raw_targets:
        if not isinstance(raw, dict):
            raise PlanError("each registry target must be a table")
        target_id = raw.get("id")
        if not isinstance(target_id, str) or not TARGET_ID.fullmatch(target_id):
            raise PlanError("target id must contain lowercase letters, digits, or hyphens")
        if target_id in seen:
            raise PlanError(f"duplicate target id: {target_id}")
        seen.add(target_id)
        symbol = raw.get("symbol")
        signature = raw.get("signature")
        if not isinstance(symbol, str) or not symbol:
            raise PlanError(f"{target_id}: symbol is required")
        if not isinstance(signature, str) or not signature:
            raise PlanError(f"{target_id}: signature is required")
        timeout = raw.get("timeout_seconds", 120)
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 3600:
            raise PlanError(f"{target_id}: invalid timeout_seconds")
        source_paths = _paths(raw, "source_paths", required=True)
        if not source_paths:
            raise PlanError(f"{target_id}: source_paths must not be empty")
        trigger_paths = _paths(raw, "trigger_paths") or source_paths
        policy = raw.get("policy")
        if policy not in {"required", "advisory"}:
            raise PlanError(f"{target_id}: policy must be required or advisory")
        native_test = raw.get("native_test")
        if native_test is not None and not isinstance(native_test, str):
            raise PlanError(f"{target_id}: native_test must be a string")
        contract_paths = _paths(raw, "contract_paths")
        native_test_source = _optional_path(raw, "native_test_source")
        if native_test_source is not None and native_test_source not in contract_paths:
            raise PlanError(f"{target_id}: native_test_source must appear in contract_paths")
        targets.append(
            RegistryTarget(
                id=target_id,
                source_paths=source_paths,
                trigger_paths=trigger_paths,
                policy=policy,
                symbol=symbol,
                signature=signature,
                template=_repo_path(raw.get("template"), "template"),
                template_variables=_template_variables(raw),
                description=str(raw.get("description", target_id)),
                entry_function=str(raw.get("entry_function", "main")),
                include_dirs=_paths(raw, "include_dirs"),
                timeout_seconds=timeout,
                pr_defines=_string_list(raw, "pr_defines"),
                nightly_defines=_string_list(raw, "nightly_defines"),
                pr_esbmc_args=_string_list(raw, "pr_esbmc_args"),
                nightly_esbmc_args=_string_list(raw, "nightly_esbmc_args"),
                mutable_paths=_paths(raw, "mutable_paths"),
                contract_paths=contract_paths,
                native_test=native_test,
                native_test_source=native_test_source,
            )
        )
    if not targets:
        raise PlanError("registry must define at least one target")
    return ContractRegistry(
        path=_repo_path(path, "base_policy"),
        schema_version=1,
        toolchain=dict(toolchain),
        critical_paths=tuple(critical_paths),
        targets=tuple(targets),
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(workspace: Path, arguments: list[str]) -> str:
    try:
        process = subprocess.run(
            ["git", *arguments],
            cwd=workspace,
            check=False,
            text=True,
            capture_output=True,
            env=sanitized_subprocess_environment(),
        )
    except OSError as exc:
        raise PlanError(f"could not execute git: {exc}") from exc
    if process.returncode != 0:
        raise PlanError(process.stderr.strip() or f"git {' '.join(arguments)} failed")
    return process.stdout


def _validate_commit(value: str, field: str) -> None:
    if not COMMIT_SHA.fullmatch(value):
        raise PlanError(f"{field} must be a commit SHA")


def _resolve_commit(workspace: Path, value: str, field: str) -> str:
    _validate_commit(value, field)
    resolved = _git(workspace, ["rev-parse", "--verify", f"{value}^{{commit}}"])
    return resolved.strip()


def _base_file(workspace: Path, base_sha: str, relative: str, maximum_bytes: int) -> bytes:
    size_text = _git(workspace, ["cat-file", "-s", f"{base_sha}:{relative}"]).strip()
    try:
        size = int(size_text)
    except ValueError as exc:
        raise PlanError(f"could not determine base file size: {relative}") from exc
    if size < 0 or size > maximum_bytes:
        raise PlanError(f"base file exceeds {maximum_bytes} byte limit: {relative}")
    data = _git(workspace, ["show", f"{base_sha}:{relative}"]).encode("utf-8")
    if len(data) > maximum_bytes:
        raise PlanError(f"base file exceeds {maximum_bytes} byte limit: {relative}")
    return data


def _matches(paths: tuple[str, ...], patterns: tuple[str, ...]) -> bool:
    return any(matches(path, patterns) for path in paths)


def _revision_text(workspace: Path, revision: str, relative: str) -> str | None:
    """Read one bounded committed text blob, returning None when it is absent."""

    object_name = f"{revision}:{relative}"
    exists = subprocess.run(
        ["git", "cat-file", "-e", object_name],
        cwd=workspace,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=sanitized_subprocess_environment(),
    )
    if exists.returncode != 0:
        return None
    size_text = _git(workspace, ["cat-file", "-s", object_name]).strip()
    try:
        size = int(size_text)
    except ValueError as exc:
        raise PlanError(f"could not determine drift source size: {relative}") from exc
    if size < 0 or size > MAX_REVISION_TEXT_BYTES:
        raise PlanError(
            f"drift source exceeds {MAX_REVISION_TEXT_BYTES} byte limit: {relative}"
        )
    data = _git(workspace, ["show", object_name])
    if len(data.encode("utf-8")) > MAX_REVISION_TEXT_BYTES:
        raise PlanError(
            f"drift source exceeds {MAX_REVISION_TEXT_BYTES} byte limit: {relative}"
        )
    return data


def _render(template: bytes, target: RegistryTarget) -> bytes:
    text = template.decode("utf-8")
    variables = {
        "ID": target.id,
        "SYMBOL": target.symbol,
        "SIGNATURE": target.signature,
        **target.template_variables,
    }
    for name, value in variables.items():
        text = text.replace("{{" + name + "}}", value)
    unresolved = re.findall(r"\{\{([A-Z][A-Z0-9_]*)\}\}", text)
    if unresolved:
        raise PlanError(
            f"{target.id}: template has unresolved variables: {', '.join(sorted(set(unresolved)))}"
        )
    rendered = text.encode("utf-8")
    if len(rendered) > MAX_RENDERED_HARNESS_BYTES:
        raise PlanError(
            f"{target.id}: rendered harness exceeds {MAX_RENDERED_HARNESS_BYTES} byte limit"
        )
    if target.symbol not in text:
        raise PlanError(f"{target.id}: rendered harness omits declared production symbol")
    return rendered


def _append_item(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    if len(items) >= MAX_PLAN_ITEMS:
        raise PlanError(f"plan exceeds {MAX_PLAN_ITEMS} items")
    items.append(item)


def _contract_provenance(
    workspace: Path,
    base_sha: str,
    target: RegistryTarget,
    used_bytes: int,
) -> tuple[list[dict[str, str]], int]:
    snapshots: list[dict[str, str]] = []
    for relative in target.contract_paths:
        data = _base_file(workspace, base_sha, relative, MAX_CONTRACT_PATH_BYTES)
        used_bytes += len(data)
        if used_bytes > MAX_TOTAL_CONTRACT_BYTES:
            raise PlanError(
                f"selected contract snapshots exceed {MAX_TOTAL_CONTRACT_BYTES} byte limit"
            )
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PlanError(f"contract path is not UTF-8 text: {relative}") from exc
        snapshots.append({"path": relative, "sha256": _sha256(data), "content": content})
    return snapshots, used_bytes


def _execution(target: RegistryTarget, mode: str) -> dict[str, Any]:
    nightly = mode == "nightly"
    return {
        "policy": target.policy,
        "description": target.description,
        "entry_function": target.entry_function,
        "include_dirs": list(target.include_dirs),
        "timeout_seconds": target.timeout_seconds,
        "defines": list(target.nightly_defines if nightly else target.pr_defines),
        "pr_defines": list(target.pr_defines),
        "nightly_defines": list(target.nightly_defines),
        "esbmc_args": list(target.nightly_esbmc_args if nightly else target.pr_esbmc_args),
        "pr_esbmc_args": list(target.pr_esbmc_args),
        "nightly_esbmc_args": list(target.nightly_esbmc_args),
        "mutable_paths": list(target.mutable_paths),
        "contract_paths": list(target.contract_paths),
        "native_test": target.native_test,
        "native_test_source": target.native_test_source,
    }


def run_plan(
    workspace: Path,
    base_policy: str,
    base_sha: str,
    head_sha: str,
    mode: str,
    output_dir: Path,
) -> int:
    """Create an immutable, base-policy contract plan for one revision pair."""
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise PlanError("workspace must be an existing directory")
    if mode not in {"pr", "all", "nightly"}:
        raise PlanError("mode must be pr, all, or nightly")
    base_sha = _resolve_commit(workspace, base_sha, "base_sha")
    head_sha = _resolve_commit(workspace, head_sha, "head_sha")
    workspace_head = _git(workspace, ["rev-parse", "--verify", "HEAD^{commit}"]).strip()
    if workspace_head != head_sha:
        raise PlanError("workspace HEAD does not match head_sha")
    base_policy = _repo_path(base_policy, "base_policy")
    policy_bytes = _base_file(workspace, base_sha, base_policy, MAX_REGISTRY_BYTES)
    registry = load_registry(base_policy, policy_bytes.decode("utf-8"))
    head_registry: ContractRegistry | None = None
    head_registry_error: str | None = None
    proposed_policy = _revision_text(workspace, head_sha, base_policy)
    if proposed_policy is None:
        head_registry_error = "proposed head removes the protected registry"
    else:
        try:
            head_registry = load_registry(base_policy, proposed_policy)
        except PlanError as exc:
            head_registry_error = str(exc)
    try:
        drift = analyze_drift(
            mode=mode,
            base_sha=base_sha,
            head_sha=head_sha,
            base_policy_sha256=_sha256(policy_bytes),
            registry=registry,
            git_output=lambda arguments: _git(workspace, arguments),
            read_text=lambda revision, relative: _revision_text(
                workspace, revision, relative
            ),
            head_registry=head_registry,
            head_registry_error=head_registry_error,
        )
        changed = drift_changed_paths(drift)
    except DriftError as exc:
        raise PlanError(str(exc)) from exc
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_dir = output_dir / "generated"
    generated_dir.mkdir(exist_ok=True)

    policy_changed = base_policy in changed
    templates: dict[str, str] = {}
    items: list[dict[str, Any]] = []
    contract_changes: list[dict[str, Any]] = []
    selected_paths: set[str] = set()
    contract_bytes = 0
    for target in registry.targets:
        selected = mode != "pr" or _matches(changed, target.trigger_paths)
        template_changed = target.template in changed
        if policy_changed or template_changed:
            template_hash = None
            if template_changed:
                template_hash = _sha256(
                    _base_file(workspace, base_sha, target.template, MAX_TEMPLATE_BYTES)
                )
            contract_changes.append(
                {
                    "reason": "base policy changed in head"
                    if policy_changed
                    else "approved template changed in head",
                    "target_id": target.id,
                    "paths": [base_policy] if policy_changed else [target.template],
                    "provenance": {
                        "base_sha": base_sha,
                        "head_sha": head_sha,
                        "base_policy": base_policy,
                        "base_policy_sha256": _sha256(policy_bytes),
                        "template": target.template,
                        "template_sha256": template_hash,
                    },
                }
            )
        if selected:
            selected_paths.update(
                path for path in changed if _matches((path,), target.trigger_paths)
            )
            try:
                template = _base_file(workspace, base_sha, target.template, MAX_TEMPLATE_BYTES)
                template_hash = _sha256(template)
                templates[target.template] = template_hash
                rendered = _render(template, target)
                contract_snapshots, contract_bytes = _contract_provenance(
                    workspace, base_sha, target, contract_bytes
                )
                generated_relative = f"generated/{target.id}.cpp"
                (output_dir / generated_relative).write_bytes(rendered)
                _append_item(
                    items,
                    {
                        "id": target.id,
                        "status": "planned",
                        "reason": "all targets selected by mode"
                        if mode != "pr"
                        else "changed path matched target trigger path",
                        "paths": list(target.source_paths),
                        "symbol": target.symbol,
                        "signature": target.signature,
                        "template": target.template,
                        "generated_harness": generated_relative,
                        "generated_harness_sha256": _sha256(rendered),
                        "execution": _execution(target, mode),
                        "provenance": {
                            "base_sha": base_sha,
                            "base_policy": base_policy,
                            "base_policy_sha256": _sha256(policy_bytes),
                            "template": target.template,
                            "template_sha256": template_hash,
                            "contract_paths": contract_snapshots,
                        },
                    },
                )
            except (PlanError, UnicodeDecodeError) as exc:
                _append_item(
                    items,
                    {
                        "id": target.id,
                        "status": "generation_error",
                        "reason": str(exc),
                        "paths": list(target.source_paths),
                        "provenance": {
                            "base_sha": base_sha,
                            "base_policy": base_policy,
                            "base_policy_sha256": _sha256(policy_bytes),
                            "template": target.template,
                            "template_sha256": templates.get(target.template),
                        },
                    },
                )

    if mode == "pr":
        unmatched = [path for path in changed if path not in selected_paths]
        relation_by_path = {
            relation["path"]: relation
            for change in drift["changes"]
            for relation in change["paths"]
        }
        areas_by_id = {area.id: area for area in registry.critical_paths}
        ordinary: list[str] = []
        for path in unmatched:
            relation = relation_by_path.get(path, {})
            areas = [
                areas_by_id[area_id]
                for area_id in relation.get("areas", [])
                if area_id in areas_by_id
            ]
            if not areas:
                ordinary.append(path)
                continue
            for area in areas:
                _append_item(
                    items,
                    {
                        "id": "coverage-gap-"
                        + area.id
                        + "-"
                        + _sha256(path.encode("utf-8"))[:12],
                        "status": "coverage_gap",
                        "reason": "changed formal-risk path has no approved target",
                        "critical_path": {
                            "id": area.id,
                            "description": area.description,
                            "paths": list(area.paths),
                            "watch_paths": list(area.watch_paths),
                            "include_roots": list(area.include_roots),
                            "policy": area.policy,
                        },
                        "paths": [path],
                    },
                )
        if ordinary:
            _append_item(
                items,
                {
                    "id": "not-applicable",
                    "status": "not_applicable",
                    "reason": "changed paths have no formal target and are outside critical coverage",
                    "paths": ordinary,
                },
            )

    if mode == "pr" and not changed:
        _append_item(
            items,
            {
                "id": "not-applicable",
                "status": "not_applicable",
                "reason": "pull request diff is empty",
                "paths": [],
            },
        )

    report = {
        "schema_version": 1,
        "workspace": str(workspace),
        "base_policy": base_policy,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "mode": mode,
        "changed_paths": list(changed),
        "drift": drift,
        "toolchain": registry.toolchain,
        "provenance": {
            "base_policy": {"path": base_policy, "sha256": _sha256(policy_bytes)},
            "templates": [
                {"path": path, "sha256": digest} for path, digest in sorted(templates.items())
            ],
        },
        "contract_changes": contract_changes,
        "items": items,
    }
    (output_dir / "plan.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0
