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


@dataclass(frozen=True)
class RegistryTarget:
    """An approved, base-revision contract template binding."""

    id: str
    source_paths: tuple[str, ...]
    trigger_paths: tuple[str, ...]
    policy: str
    symbol: str
    signature: str
    template: str
    template_variables: dict[str, str]
    description: str
    entry_function: str
    include_dirs: tuple[str, ...]
    timeout_seconds: int
    pr_defines: tuple[str, ...]
    nightly_defines: tuple[str, ...]
    pr_esbmc_args: tuple[str, ...]
    nightly_esbmc_args: tuple[str, ...]
    mutable_paths: tuple[str, ...]
    contract_paths: tuple[str, ...]
    native_test: str | None = None
    native_test_source: str | None = None


@dataclass(frozen=True)
class CriticalArea:
    """A human-approved formal-risk boundary and its advisory routing metadata."""

    id: str
    description: str
    paths: tuple[str, ...]
    watch_paths: tuple[str, ...] = ()
    include_roots: tuple[str, ...] = ()
    policy: str = "advisory"


@dataclass(frozen=True)
class ContractRegistry:
    path: str
    schema_version: int
    toolchain: dict[str, Any]
    critical_paths: tuple[CriticalArea, ...]
    targets: tuple[RegistryTarget, ...]


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
    artifacts: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
