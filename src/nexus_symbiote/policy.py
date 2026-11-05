"""Strict, fail-closed policy loading; absence alone selects defaults."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

ScannerName = Literal[
    "mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"
]
OutputFormat = Literal["json", "cyclonedx", "spdx", "sarif"]


class PolicyError(ValueError):
    """An existing policy cannot be interpreted without weakening its meaning."""


class PolicySection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


def _default_scanners() -> list[ScannerName]:
    return ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]


class ScanPolicy(PolicySection):
    scanners: list[ScannerName] = Field(default_factory=_default_scanners, min_length=1)
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["node_modules", ".git", "__pycache__", ".venv"]
    )
    failure_mode: Literal["error", "report-only"] = "error"

    @model_validator(mode="after")
    def valid_paths(self) -> ScanPolicy:
        if len(set(self.scanners)) != len(self.scanners):
            raise ValueError("scanners must be unique")
        if any(
            not p.strip() or Path(p).is_absolute() or ".." in Path(p).parts
            for p in self.exclude_paths
        ):
            raise ValueError("exclude_paths must be nonempty paths beneath the scan root")
        return self


class RiskPolicy(PolicySection):
    fail_threshold: float = Field(default=50.0, gt=0)
    warn_threshold: float = Field(default=25.0, ge=0)
    ignore_categories: list[str] = Field(default_factory=list)
    fail_on_severity: Literal["critical", "high", "medium", "low", "info", "none"] = "critical"

    @model_validator(mode="after")
    def valid_thresholds(self) -> RiskPolicy:
        if self.warn_threshold > self.fail_threshold:
            raise ValueError("warn_threshold cannot exceed fail_threshold")
        if any(not c.strip() for c in self.ignore_categories):
            raise ValueError("ignore_categories must contain nonempty exact category names")
        return self


class ValidatePolicy(PolicySection):
    require_completeness: StrictBool = True
    require_integrity: StrictBool = True
    minimum_assurance_level: Literal["declared", "observed", "verified"] = "declared"


class OutputPolicy(PolicySection):
    default_format: OutputFormat = "json"


class Policy(PolicySection):
    model_config = ConfigDict(
        extra="forbid", populate_by_name=True, strict=True, allow_inf_nan=False
    )
    version: Literal["1.0"] = "1.0"
    scan: ScanPolicy = Field(default_factory=ScanPolicy)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)
    validation: ValidatePolicy = Field(default_factory=ValidatePolicy, alias="validate")
    output: OutputPolicy = Field(default_factory=OutputPolicy)


def default_policy() -> Policy:
    return Policy()


def find_policy_path(project_root: Path) -> Path | None:
    """Locate the policy file in ``project_root`` itself; ancestors are never consulted.

    The policy is part of the checkout it governs. A file above the project root
    belongs to whoever controls that directory, not to the project.
    """
    current = project_root.resolve()
    if current.is_file():
        current = current.parent
    for name in (".nexus-symbiote.yaml", ".nexus-symbiote.yml"):
        candidate = current / name
        if candidate.is_symlink():
            raise PolicyError(f"policy must not be a symlink: {candidate}")
        if candidate.exists():
            return candidate
    return None


def load_policy(project_root: Path) -> Policy | None:
    path = find_policy_path(project_root)
    return None if path is None else _parse_policy(path)


def weakened_settings(policy: Policy) -> list[str]:
    """Name the settings under which this policy gates less strictly than the built-in defaults."""
    base = Policy()
    weaker: list[str] = []
    if not policy.validation.require_completeness:
        weaker.append("validate.require_completeness=false")
    if not policy.validation.require_integrity:
        weaker.append("validate.require_integrity=false")
    if policy.risk.fail_on_severity == "none":
        weaker.append("risk.fail_on_severity=none")
    if policy.risk.fail_threshold > base.risk.fail_threshold:
        weaker.append(f"risk.fail_threshold={policy.risk.fail_threshold:g}")
    if policy.risk.ignore_categories:
        weaker.append("risk.ignore_categories=" + ",".join(policy.risk.ignore_categories))
    if policy.scan.failure_mode == "report-only":
        weaker.append("scan.failure_mode=report-only")
    if set(policy.scan.scanners) < set(base.scan.scanners):
        weaker.append("scan.scanners=" + ",".join(policy.scan.scanners))
    return weaker


def nearest_policy_file(start: Path) -> Path | None:
    """Find the closest policy file at or above ``start`` so a caller can say it was not applied.

    Never use the result to load a policy: a file above the project, or beside an
    inventory written to a shared directory, belongs to whoever controls that directory.
    """
    for directory in (start, *start.parents):
        for name in (".nexus-symbiote.yaml", ".nexus-symbiote.yml"):
            candidate = directory / name
            try:
                if candidate.is_symlink() or candidate.exists():
                    return candidate
            except OSError:
                continue
    return None


def parse_yaml_mapping(text: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise PolicyError("PyYAML is required; install the declared dependencies") from exc

    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader: Any, node: Any) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, str) or key in data:
                raise PolicyError("YAML mapping keys must be unique strings")
            data[key] = loader.construct_object(value_node)
        return data

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        data = yaml.load(text, Loader=UniqueLoader)  # noqa: S506 - subclass of SafeLoader with unique-key enforcement
        if not isinstance(data, dict):
            raise PolicyError("configuration must be a nonempty YAML mapping")
        return data
    except (yaml.YAMLError, RecursionError) as exc:
        raise PolicyError("invalid YAML document") from exc


def _parse_policy(path: Path) -> Policy:
    from pydantic import ValidationError

    try:
        fd = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise PolicyError("policy must be a regular file no larger than 1 MiB")
            raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise PolicyError("policy exceeds 1 MiB")
        return Policy.model_validate(parse_yaml_mapping(raw.decode("utf-8")))
    except ValidationError as exc:
        locations = [".".join(map(str, e["loc"])) for e in exc.errors()]
        raise PolicyError(
            f"invalid policy {path}: invalid or unsupported settings: {', '.join(locations)}"
        ) from exc
    except (OSError, UnicodeError, ValueError) as exc:
        raise PolicyError(f"invalid policy {path}: {exc}") from exc


DEFAULT_POLICY_YAML = """\
# Nexus SymBiote policy; malformed or unsupported settings fail closed.
version: "1.0"
scan:
  scanners: ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]
  exclude_paths: ["node_modules", ".git", "__pycache__", ".venv"]
  failure_mode: "error"
risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  fail_on_severity: "critical"
  ignore_categories: []
validate:
  require_completeness: true
  require_integrity: true
  minimum_assurance_level: "declared"
output:
  default_format: "json"
"""
