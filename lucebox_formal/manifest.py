from __future__ import annotations

import fnmatch
import subprocess
import tomllib
from pathlib import Path

from .model import Capsule, Manifest


class ManifestError(ValueError):
    pass


def _string_tuple(raw: dict, name: str) -> tuple[str, ...]:
    value = raw.get(name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"{name} must be a list of strings")
    return tuple(value)


def load_manifest(path: Path) -> Manifest:
    path = path.resolve()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ManifestError("unsupported manifest schema_version")
    toolchain = data.get("toolchain")
    if not isinstance(toolchain, dict):
        raise ManifestError("toolchain table is required")

    capsules: list[Capsule] = []
    seen: set[str] = set()
    for raw in data.get("capsules", []):
        capsule_id = raw.get("id")
        if not isinstance(capsule_id, str) or not capsule_id:
            raise ManifestError("each capsule needs a non-empty id")
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
                harness=str(raw["harness"]),
                entry_function=str(raw.get("entry_function", "main")),
                include_dirs=_string_tuple(raw, "include_dirs"),
                timeout_seconds=timeout,
                defines=_string_tuple(raw, "defines"),
                nightly_defines=_string_tuple(raw, "nightly_defines"),
                esbmc_args=_string_tuple(raw, "esbmc_args"),
                trigger_paths=_string_tuple(raw, "trigger_paths"),
                mutable_paths=_string_tuple(raw, "mutable_paths"),
                contract_paths=_string_tuple(raw, "contract_paths"),
                native_test=raw.get("native_test"),
                native_test_source=raw.get("native_test_source"),
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
