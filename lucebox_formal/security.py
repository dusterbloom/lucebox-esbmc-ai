from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
from pathlib import Path, PurePosixPath

# A schema-v1 plan may contain up to 8 MiB of immutable contract snapshots.
# Plan failure bundles intentionally preserve that JSON plus exact extracted
# contract files, so validation needs bounded headroom for the duplicated
# replay material.
MAX_MEMBER_BYTES = 12_000_000
MAX_BUNDLE_BYTES = 32_000_000


class BundleError(ValueError):
    pass


def sanitized_subprocess_environment() -> dict[str, str]:
    """Return the process environment without credential-shaped variables."""
    blocked_fragments = (
        "API_KEY",
        "CREDENTIAL",
        "PASSWORD",
        "SECRET",
        "TOKEN",
    )
    return {
        key: value
        for key, value in os.environ.items()
        if not any(fragment in key.upper() for fragment in blocked_fragments)
    }


def safe_repo_path(root: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise BundleError(f"unsafe repository path: {value}")
    resolved = (root / Path(*relative.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise BundleError(f"path escapes repository: {value}") from exc
    return resolved


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_bundle(bundle: Path, destination: Path) -> None:
    total = 0
    with tarfile.open(bundle, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            relative = PurePosixPath(member.name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or member.issym()
                or member.islnk()
                or member.isdev()
            ):
                raise BundleError(f"unsafe bundle member: {member.name}")
            if member.size > MAX_MEMBER_BYTES:
                raise BundleError(f"bundle member too large: {member.name}")
            total += member.size
            if total > MAX_BUNDLE_BYTES:
                raise BundleError("bundle exceeds total size limit")

        for member in members:
            target = safe_repo_path(destination, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise BundleError(f"could not read bundle member: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)


def validate_patch_paths(patch: str, mutable_paths: set[str]) -> None:
    seen: set[str] = set()
    for line in patch.splitlines():
        if not line.startswith(("--- ", "+++ ")):
            continue
        value = line[4:].split("\t", 1)[0]
        if value == "/dev/null":
            raise BundleError("patch may not add or delete files")
        if value.startswith(("a/", "b/")):
            value = value[2:]
        safe_repo_path(Path("/tmp/lucebox-patch-root"), value)
        if value not in mutable_paths:
            raise BundleError(f"patch touches non-mutable path: {value}")
        seen.add(value)
    if not seen:
        raise BundleError("response does not contain a unified diff")
