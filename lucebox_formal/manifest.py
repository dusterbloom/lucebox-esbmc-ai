from __future__ import annotations

import fnmatch
import re
import subprocess
import tomllib
from pathlib import Path, PurePosixPath

from .model import Capsule, Manifest


class ManifestError(ValueError):
    pass


CAPSULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _string_tuple(raw: dict, name: str) -> tuple[str, ...]:
    value = raw.get(name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"{name} must be a list of strings")
    return tuple(value)


def _repo_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{field} must be a non-empty repository path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ManifestError(f"{field} must stay inside the repository")
    return value


def _repo_paths(raw: dict, name: str) -> tuple[str, ...]:
    return tuple(
        _repo_path(value, name) for value in _string_tuple(raw, name)
    )


def load_manifest(path: Path) -> Manifest:
    path = path.resolve()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ManifestError("unsupported manifest schema_version")
    toolchain = data.get("toolchain")
    if not isinstance(toolchain, dict):
        raise ManifestError("toolchain table is required")
    if not isinstance(toolchain.get("esbmc_version"), str):
        raise ManifestError("toolchain.esbmc_version must be a string")

    capsules: list[Capsule] = []
    seen: set[str] = set()
    for raw in data.get("capsules", []):
        if not isinstance(raw, dict):
            raise ManifestError("each capsule must be a table")
        capsule_id = raw.get("id")
        if not isinstance(capsule_id, str) or not CAPSULE_ID.fullmatch(capsule_id):
            raise ManifestError(
                "capsule id must contain lowercase letters, digits, or hyphens"
            )
        if capsule_id in seen:
            raise ManifestError(f"duplicate capsule id: {capsule_id}")
        seen.add(capsule_id)
        timeout = raw.get("timeout_seconds", 120)
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 3600:
            raise ManifestError(f"{capsule_id}: invalid timeout_seconds")
        capsules.append(
            Capsule(
                id=capsule_id,
                description=str(raw.get("description", capsule_id)),
                harness=_repo_path(raw.get("harness"), "harness"),
                entry_function=str(raw.get("entry_function", "main")),
                include_dirs=_repo_paths(raw, "include_dirs"),
                timeout_seconds=timeout,
                defines=_string_tuple(raw, "defines"),
                nightly_defines=_string_tuple(raw, "nightly_defines"),
                esbmc_args=_string_tuple(raw, "esbmc_args"),
                trigger_paths=_repo_paths(raw, "trigger_paths"),
                mutable_paths=_repo_paths(raw, "mutable_paths"),
                contract_paths=_repo_paths(raw, "contract_paths"),
                native_test=raw.get("native_test"),
                native_test_source=(
                    _repo_path(
                        raw.get("native_test_source"), "native_test_source"
                    )
                    if raw.get("native_test_source") is not None
                    else None
                ),
            )
        )
    if not capsules:
        raise ManifestError("manifest must define at least one capsule")
    return Manifest(
        path=path,
        schema_version=1,
        toolchain=toolchain,
        capsules=tuple(capsules),
    )


def changed_paths(repo_root: Path, base_sha: str) -> tuple[str, ...]:
    if not base_sha:
        return ()
    process = subprocess.run(
        ["git", "diff", "--name-only", f"{base_sha}...HEAD"],
        cwd=repo_root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        raise ManifestError(
            f"could not compute changed paths from {base_sha}: {process.stderr.strip()}"
        )
    return tuple(line for line in process.stdout.splitlines() if line)


def capsule_matches(capsule: Capsule, paths: tuple[str, ...]) -> bool:
    if not paths:
        return True
    return any(
        fnmatch.fnmatchcase(path, pattern)
        for path in paths
        for pattern in capsule.trigger_paths
    )
