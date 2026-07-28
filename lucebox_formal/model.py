from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Capsule:
    id: str
    description: str
    harness: str
    entry_function: str
    include_dirs: tuple[str, ...]
    timeout_seconds: int
    defines: tuple[str, ...]
    nightly_defines: tuple[str, ...]
    esbmc_args: tuple[str, ...]
    trigger_paths: tuple[str, ...]
    mutable_paths: tuple[str, ...]
    contract_paths: tuple[str, ...]
    native_test: str | None = None
    native_test_source: str | None = None


@dataclass(frozen=True)
class Manifest:
    path: Path
    schema_version: int
    toolchain: dict[str, Any]
    capsules: tuple[Capsule, ...]


@dataclass
class CapsuleResult:
    id: str
    description: str
    status: str
    duration_seconds: float
    command: list[str] = field(default_factory=list)
    output: str = ""
    return_code: int | None = None
    assumptions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
