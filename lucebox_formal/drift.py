"""Bounded, deterministic drift classification shared by plan and verify."""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable

from .model import ContractRegistry, CriticalArea


class DriftError(ValueError):
    pass


GitOutput = Callable[[list[str]], str]
RevisionText = Callable[[str, str], str | None]

MAX_CHANGES = 512
MAX_CHANGED_PATHS = 1_024
MAX_FINDINGS = 1_024
MAX_INCLUDE_NODES = 256
MAX_INCLUDE_DEPTH = 32
MAX_SUBMODULES = 64
MAX_REASON_BYTES = 4_096
MAX_REVISION_TEXT_BYTES = 1_000_000
MAX_REVISION_TEXT_CACHE_BYTES = 16_000_000
MAX_REVISION_TEXT_CACHE_ENTRIES = 4_096
INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
PATTERN_META = frozenset("*?[")
CHANGE_STATUS = {
    "A": "added",
    "M": "modified",
    "D": "deleted",
    "R": "renamed",
    "C": "copied",
    "T": "type_changed",
}


@dataclass(frozen=True)
class GitChange:
    status: str
    old_path: str | None
    new_path: str | None
    score: int | None = None

    def paths(self) -> tuple[tuple[str, str], ...]:
        if self.old_path is not None and self.new_path is not None:
            return ((self.old_path, "old"), (self.new_path, "new"))
        if self.old_path is not None:
            return ((self.old_path, "old"),)
        if self.new_path is not None:
            return ((self.new_path, "new"),)
        return ()


def _repo_path(value: str, field: str) -> str:
    if not value:
        raise DriftError(f"{field} must not be empty")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) == ".":
        raise DriftError(f"{field} must stay inside the repository")
    return path.as_posix()


def matches(path: str, patterns: tuple[str, ...]) -> bool:
    """Match documented repository-relative patterns.

    Schema v1 retains fnmatch semantics for compatibility. A later schema can
    distinguish exact and Git-style glob patterns without silently changing
    already approved policy.
    """

    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def parse_name_status(raw: str) -> tuple[GitChange, ...]:
    """Parse `git diff --name-status -z` without ambiguous path delimiters."""

    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    changes: list[GitChange] = []
    cursor = 0
    while cursor < len(fields):
        raw_status = fields[cursor]
        cursor += 1
        if not raw_status:
            raise DriftError("Git change status must not be empty")
        code = raw_status[0]
        status = CHANGE_STATUS.get(code)
        if status is None:
            raise DriftError(f"unsupported Git change status: {raw_status}")
        score: int | None = None
        if len(raw_status) > 1:
            try:
                score = int(raw_status[1:])
            except ValueError as exc:
                raise DriftError(f"invalid Git similarity score: {raw_status}") from exc
        required = 2 if code in {"R", "C"} else 1
        if cursor + required > len(fields):
            raise DriftError("truncated NUL-delimited Git change inventory")
        paths = tuple(
            _repo_path(fields[cursor + index], "changed path")
            for index in range(required)
        )
        cursor += required
        if code in {"R", "C"}:
            change = GitChange(status, paths[0], paths[1], score)
        elif code == "D":
            change = GitChange(status, paths[0], None, score)
        else:
            change = GitChange(status, None, paths[0], score)
        changes.append(change)
        if len(changes) > MAX_CHANGES:
            raise DriftError(f"Git change inventory exceeds {MAX_CHANGES} entries")
    return tuple(changes)


def changed_paths(changes: tuple[GitChange, ...]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for change in changes:
        for path, _ in change.paths():
            if path not in seen:
                seen.add(path)
                result.append(path)
                if len(result) > MAX_CHANGED_PATHS:
                    raise DriftError(
                        f"changed path inventory exceeds {MAX_CHANGED_PATHS} entries"
                    )
    return tuple(result)


def _is_exact_path(pattern: str) -> bool:
    return not any(character in pattern for character in PATTERN_META)


def _inside_roots(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def _include_candidates(
    current: str,
    included: str,
    roots: tuple[str, ...],
) -> tuple[str, ...]:
    raw_candidates = [str(PurePosixPath(current).parent / included)]
    raw_candidates.extend(str(PurePosixPath(root) / included) for root in roots)
    result: list[str] = []
    for raw in raw_candidates:
        candidate = PurePosixPath(raw)
        if candidate.is_absolute() or ".." in candidate.parts:
            continue
        normalized = candidate.as_posix()
        if _inside_roots(normalized, roots) and normalized not in result:
            result.append(normalized)
    return tuple(result)


def include_closure(
    revision: str,
    area: CriticalArea,
    read_text: RevisionText,
) -> frozenset[str]:
    """Return bounded project-local quoted-include reachability for one area."""

    if not area.include_roots:
        return frozenset()
    seeds = [path for path in area.paths if _is_exact_path(path)]
    closure: set[str] = set()
    frontier: list[tuple[str, int]] = [(path, 0) for path in seeds]
    while frontier:
        path, depth = frontier.pop()
        if path in closure:
            continue
        source = read_text(revision, path)
        if source is None:
            continue
        closure.add(path)
        if len(closure) > MAX_INCLUDE_NODES:
            raise DriftError(
                f"{area.id}: include closure exceeds {MAX_INCLUDE_NODES} files"
            )
        if depth >= MAX_INCLUDE_DEPTH:
            raise DriftError(
                f"{area.id}: include closure exceeds depth {MAX_INCLUDE_DEPTH}"
            )
        for included in INCLUDE.findall(source):
            for candidate in _include_candidates(path, included, area.include_roots):
                if candidate not in closure and read_text(revision, candidate) is not None:
                    frontier.append((candidate, depth + 1))
                    break
    return frozenset(closure)


def _submodule_paths(revision: str, read_text: RevisionText) -> tuple[str, ...]:
    source = read_text(revision, ".gitmodules")
    if source is None:
        return ()
    result: list[str] = []
    for line in source.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "path":
            path = _repo_path(value.strip(), "submodule path")
            if path not in result:
                result.append(path)
                if len(result) > MAX_SUBMODULES:
                    raise DriftError(
                        f"submodule inventory exceeds {MAX_SUBMODULES} entries"
                    )
    return tuple(result)


def _submodule_pointer(revision: str, path: str, git_output: GitOutput) -> str | None:
    output = git_output(["ls-tree", revision, "--", path]).strip()
    if not output:
        return None
    metadata, separator, listed_path = output.partition("\t")
    fields = metadata.split()
    if separator != "\t" or listed_path != path or len(fields) != 3:
        raise DriftError(f"could not parse submodule tree entry: {path}")
    mode, kind, pointer = fields
    if mode != "160000" or kind != "commit" or not re.fullmatch(r"[0-9a-f]{40}", pointer):
        raise DriftError(f"invalid submodule tree entry: {path}")
    return pointer


def _policy_delta(
    base: ContractRegistry,
    head: ContractRegistry | None,
    head_error: str | None,
) -> tuple[dict[str, list[str]], list[dict[str, object]]]:
    delta = {
        "removed_areas": [],
        "removed_boundaries": [],
        "weakened_targets": [],
    }
    findings: list[dict[str, object]] = []
    if head_error is not None:
        findings.append(
            {
                "kind": "head_policy_invalid",
                "severity": "blocking",
                "paths": [base.path],
                "areas": [],
                "reason": head_error,
            }
        )
        return delta, findings
    if head is None:
        return delta, findings

    head_areas = {area.id: area for area in head.critical_paths}
    for area in base.critical_paths:
        proposed = head_areas.get(area.id)
        if proposed is None:
            delta["removed_areas"].append(area.id)
            continue
        removed = sorted(set(area.paths) - set(proposed.paths))
        delta["removed_boundaries"].extend(f"{area.id}:{path}" for path in removed)

    head_targets = {target.id: target for target in head.targets}
    for target in base.targets:
        proposed = head_targets.get(target.id)
        if proposed is None:
            delta["weakened_targets"].append(f"{target.id}:removed")
        elif target.policy == "required" and proposed.policy != "required":
            delta["weakened_targets"].append(f"{target.id}:policy")
        else:
            removed_sources = sorted(set(target.source_paths) - set(proposed.source_paths))
            delta["weakened_targets"].extend(
                f"{target.id}:source:{path}" for path in removed_sources
            )

    for values in delta.values():
        values[:] = sorted(set(values))
    if any(delta.values()):
        findings.append(
            {
                "kind": "policy_shrunk",
                "severity": "blocking",
                "paths": [base.path],
                "areas": list(delta["removed_areas"]),
                "reason": "proposed policy removes a protected area, boundary, or target",
            }
        )
    return delta, findings


def _finding_id(kind: str, paths: list[str]) -> str:
    digest = hashlib.sha256((kind + "\0" + "\0".join(paths)).encode("utf-8")).hexdigest()
    return f"drift-{kind}-{digest[:12]}"


def analyze_drift(
    *,
    mode: str,
    base_sha: str,
    head_sha: str,
    base_policy_sha256: str,
    registry: ContractRegistry,
    git_output: GitOutput,
    read_text: RevisionText,
    head_registry: ContractRegistry | None = None,
    head_registry_error: str | None = None,
) -> dict[str, object]:
    """Build the canonical bounded drift report for a revision pair."""

    text_cache: dict[tuple[str, str], str | None] = {}
    cached_bytes = 0

    def cached_text(revision: str, path: str) -> str | None:
        nonlocal cached_bytes
        key = (revision, path)
        if key not in text_cache:
            if len(text_cache) >= MAX_REVISION_TEXT_CACHE_ENTRIES:
                raise DriftError(
                    "drift source cache exceeds "
                    f"{MAX_REVISION_TEXT_CACHE_ENTRIES} entries"
                )
            source = read_text(revision, path)
            if source is not None:
                cached_bytes += len(source.encode("utf-8"))
                if cached_bytes > MAX_REVISION_TEXT_CACHE_BYTES:
                    raise DriftError(
                        "drift source cache exceeds "
                        f"{MAX_REVISION_TEXT_CACHE_BYTES} bytes"
                    )
            text_cache[key] = source
        return text_cache[key]

    merge_base = git_output(["merge-base", base_sha, head_sha]).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", merge_base):
        raise DriftError("git merge-base did not return a full commit SHA")
    if mode == "pr":
        raw = git_output(
            [
                "diff",
                "--name-status",
                "-z",
                "--find-renames",
                "--find-copies",
                f"{base_sha}...{head_sha}",
            ]
        )
        changes = parse_name_status(raw)
    else:
        changes = ()

    closures: dict[tuple[str, str], frozenset[str]] = {}
    for area in registry.critical_paths:
        closures[(area.id, "base")] = include_closure(base_sha, area, cached_text)
        closures[(area.id, "head")] = include_closure(head_sha, area, cached_text)

    rendered_changes: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    for change in changes:
        path_relations: list[dict[str, object]] = []
        for path, side in change.paths():
            revision_side = "base" if side == "old" else "head"
            relations: list[str] = []
            areas: list[str] = []
            for area in registry.critical_paths:
                direct = matches(path, area.paths)
                adjacent = path in closures[(area.id, revision_side)]
                watched = matches(path, area.watch_paths)
                if direct:
                    relations.append("declared_boundary")
                if adjacent and not direct:
                    relations.append("include_adjacent")
                if watched and not direct and not adjacent:
                    relations.append("watch_match")
                if direct or adjacent or watched:
                    areas.append(area.id)
            selected = sorted(
                target.id for target in registry.targets if matches(path, target.trigger_paths)
            )
            if selected:
                relations.append("target_trigger")
            if not relations:
                relations.append("unmodeled")
            path_relations.append(
                {
                    "path": path,
                    "side": side,
                    "relations": sorted(set(relations)),
                    "areas": sorted(set(areas)),
                    "selected_targets": selected,
                }
            )
            if areas and not selected and side != "old":
                findings.append(
                    {
                        "kind": "no_contract_invoked",
                        "severity": "warning",
                        "paths": [path],
                        "areas": sorted(set(areas)),
                        "reason": "changed formal-risk path selected no approved target",
                    }
                )

        if change.status in {"deleted", "renamed"}:
            old = next((item for item in path_relations if item["side"] == "old"), None)
            if old is not None and "declared_boundary" in old["relations"]:
                findings.append(
                    {
                        "kind": (
                            "boundary_deleted"
                            if change.status == "deleted"
                            else "boundary_renamed"
                        ),
                        "severity": "blocking",
                        "paths": [path for path, _ in change.paths()],
                        "areas": old["areas"],
                        "reason": "a protected boundary was deleted or renamed",
                    }
                )

        rendered_changes.append(
            {
                "status": change.status,
                "old_path": change.old_path,
                "new_path": change.new_path,
                "score": change.score,
                "paths": path_relations,
            }
        )

    policy_delta, policy_findings = _policy_delta(
        registry, head_registry, head_registry_error
    )
    findings.extend(policy_findings)

    submodule_paths = sorted(
        set(_submodule_paths(base_sha, cached_text))
        | set(_submodule_paths(head_sha, cached_text))
    )
    submodules: list[dict[str, str | None]] = []
    for path in submodule_paths:
        base_pointer = _submodule_pointer(base_sha, path, git_output)
        head_pointer = _submodule_pointer(head_sha, path, git_output)
        submodules.append(
            {"path": path, "base_sha": base_pointer, "head_sha": head_pointer}
        )
        if base_pointer != head_pointer:
            findings.append(
                {
                    "kind": "dependency_changed",
                    "severity": "warning",
                    "paths": [path],
                    "areas": [],
                    "reason": "Git submodule pointer changed",
                }
            )

    if len(findings) > MAX_FINDINGS:
        raise DriftError(f"drift report exceeds {MAX_FINDINGS} findings")
    for finding in findings:
        finding["id"] = _finding_id(str(finding["kind"]), list(finding["paths"]))
    findings.sort(key=lambda item: str(item["id"]))

    return {
        "schema_version": 1,
        "coordinate": {
            "base_sha": base_sha,
            "head_sha": head_sha,
            "merge_base_sha": merge_base,
            "base_policy_sha256": base_policy_sha256,
            "registry_schema_version": registry.schema_version,
            "submodules": submodules,
        },
        "changes": rendered_changes,
        "findings": findings,
        "policy_delta": policy_delta,
    }


def drift_changed_paths(report: dict[str, object]) -> tuple[str, ...]:
    """Extract the canonical flattened path list from a trusted report."""

    raw_changes = report.get("changes")
    if not isinstance(raw_changes, list):
        raise DriftError("drift changes must be a list")
    paths: list[str] = []
    seen: set[str] = set()
    for change in raw_changes:
        if not isinstance(change, dict) or not isinstance(change.get("paths"), list):
            raise DriftError("each drift change must contain a path list")
        for relation in change["paths"]:
            if not isinstance(relation, dict):
                raise DriftError("each drift path relation must be an object")
            path = relation.get("path")
            if not isinstance(path, str):
                raise DriftError("drift relation path must be a string")
            path = _repo_path(path, "drift relation path")
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return tuple(paths)


def blocking_findings(report: dict[str, object]) -> tuple[dict[str, object], ...]:
    raw = report.get("findings")
    if not isinstance(raw, list):
        raise DriftError("drift findings must be a list")
    return tuple(
        finding
        for finding in raw
        if isinstance(finding, dict) and finding.get("severity") == "blocking"
    )


def validate_drift_report(
    report: object,
    *,
    base_sha: str,
    head_sha: str,
    base_policy_sha256: str,
    changed: tuple[str, ...],
) -> None:
    """Validate the bounded schema before a verifier consumes drift evidence."""

    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise DriftError("plan drift must be a schema-v1 object")
    coordinate = report.get("coordinate")
    if not isinstance(coordinate, dict):
        raise DriftError("drift coordinate must be an object")
    if coordinate.get("base_sha") != base_sha or coordinate.get("head_sha") != head_sha:
        raise DriftError("drift coordinate revision mismatch")
    merge_base = coordinate.get("merge_base_sha")
    if not isinstance(merge_base, str) or not re.fullmatch(r"[0-9a-f]{40}", merge_base):
        raise DriftError("drift coordinate has invalid merge-base SHA")
    if coordinate.get("base_policy_sha256") != base_policy_sha256:
        raise DriftError("drift coordinate policy hash mismatch")
    if coordinate.get("registry_schema_version") != 1:
        raise DriftError("drift coordinate registry schema mismatch")
    submodules = coordinate.get("submodules")
    if not isinstance(submodules, list) or len(submodules) > MAX_SUBMODULES:
        raise DriftError("drift coordinate has invalid submodule inventory")
    for submodule in submodules:
        if not isinstance(submodule, dict):
            raise DriftError("drift submodule entry must be an object")
        _repo_path(submodule.get("path"), "drift submodule path")  # type: ignore[arg-type]
        for field in ("base_sha", "head_sha"):
            pointer = submodule.get(field)
            if pointer is not None and (
                not isinstance(pointer, str) or not re.fullmatch(r"[0-9a-f]{40}", pointer)
            ):
                raise DriftError(f"drift submodule has invalid {field}")

    raw_changes = report.get("changes")
    if not isinstance(raw_changes, list) or len(raw_changes) > MAX_CHANGES:
        raise DriftError("drift changes must be a bounded list")
    allowed_relations = {
        "declared_boundary",
        "target_trigger",
        "include_adjacent",
        "watch_match",
        "unmodeled",
    }
    for change in raw_changes:
        if not isinstance(change, dict) or change.get("status") not in set(CHANGE_STATUS.values()):
            raise DriftError("drift change has invalid status")
        for field in ("old_path", "new_path"):
            path = change.get(field)
            if path is not None:
                if not isinstance(path, str):
                    raise DriftError(f"drift change {field} must be a string or null")
                _repo_path(path, f"drift change {field}")
        score = change.get("score")
        if score is not None and (not isinstance(score, int) or not 0 <= score <= 100):
            raise DriftError("drift change has invalid similarity score")
        relations = change.get("paths")
        if not isinstance(relations, list) or not 1 <= len(relations) <= 2:
            raise DriftError("drift change must contain one or two path relations")
        for relation in relations:
            if not isinstance(relation, dict):
                raise DriftError("drift path relation must be an object")
            path = relation.get("path")
            if not isinstance(path, str):
                raise DriftError("drift relation path must be a string")
            _repo_path(path, "drift relation path")
            if relation.get("side") not in {"old", "new"}:
                raise DriftError("drift relation side is invalid")
            raw_relations = relation.get("relations")
            if (
                not isinstance(raw_relations, list)
                or not raw_relations
                or not all(item in allowed_relations for item in raw_relations)
                or raw_relations != sorted(set(raw_relations))
            ):
                raise DriftError("drift relation labels are invalid")
            for field in ("areas", "selected_targets"):
                values = relation.get(field)
                if (
                    not isinstance(values, list)
                    or len(values) > 128
                    or not all(isinstance(item, str) and item for item in values)
                    or values != sorted(set(values))
                ):
                    raise DriftError(f"drift relation {field} is invalid")

    flattened = drift_changed_paths(report)
    if flattened != changed:
        raise DriftError("drift change inventory does not match plan changed_paths")

    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise DriftError("drift findings must be a bounded list")
    seen_findings: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise DriftError("drift finding must be an object")
        finding_id = finding.get("id")
        if (
            not isinstance(finding_id, str)
            or not re.fullmatch(r"drift-[a-z_]+-[0-9a-f]{12}", finding_id)
            or finding_id in seen_findings
        ):
            raise DriftError("drift finding has invalid or duplicate id")
        seen_findings.add(finding_id)
        if finding.get("severity") not in {"info", "warning", "blocking"}:
            raise DriftError("drift finding has invalid severity")
        if not isinstance(finding.get("kind"), str) or not finding["kind"]:
            raise DriftError("drift finding has invalid kind")
        paths = finding.get("paths")
        areas = finding.get("areas")
        if (
            not isinstance(paths, list)
            or not paths
            or len(paths) > 2
            or not all(isinstance(path, str) for path in paths)
        ):
            raise DriftError("drift finding paths are invalid")
        for path in paths:
            _repo_path(path, "drift finding path")
        if (
            not isinstance(areas, list)
            or len(areas) > 64
            or not all(isinstance(area, str) and area for area in areas)
        ):
            raise DriftError("drift finding areas are invalid")
        reason = finding.get("reason")
        if (
            not isinstance(reason, str)
            or not reason
            or len(reason.encode("utf-8")) > MAX_REASON_BYTES
        ):
            raise DriftError("drift finding reason is invalid")
        if finding_id != _finding_id(str(finding["kind"]), list(paths)):
            raise DriftError("drift finding id does not match its content")

    delta = report.get("policy_delta")
    if not isinstance(delta, dict) or set(delta) != {
        "removed_areas",
        "removed_boundaries",
        "weakened_targets",
    }:
        raise DriftError("drift policy_delta has invalid fields")
    for field, values in delta.items():
        if (
            not isinstance(values, list)
            or len(values) > 256
            or not all(isinstance(value, str) and value for value in values)
            or values != sorted(set(values))
        ):
            raise DriftError(f"drift policy_delta.{field} is invalid")
