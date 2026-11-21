"""Strict, fail-closed policy loading; absence alone selects defaults."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from nexus_symbiote import limits
from nexus_symbiote.core.models import MAX_REFERENCE_CHARS

ScannerName = Literal[
    "mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"
]
OutputFormat = Literal["json", "cyclonedx", "spdx", "sarif"]
POLICY_FILE_NAMES = (".nexus-symbiote.yaml", ".nexus-symbiote.yml")
DEFAULT_EXCLUDE_PATHS = ("node_modules", ".git", "__pycache__", ".venv")
_ALWAYS_EXCLUDED_NAMES = frozenset({*DEFAULT_EXCLUDE_PATHS, "venv"})
DEFAULT_WARN_THRESHOLD = 25.0
MAX_POLICY_LIST_ITEMS = 256
MAX_POLICY_SUPPRESSIONS = 1000
MAX_POLICY_ENTRY_CHARS = 1024
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class PolicyError(ValueError):
    """An existing policy cannot be interpreted without weakening its meaning."""


class PolicyListingError(PolicyError):
    """The project root could not be fully listed to locate its policy."""


class PolicySection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


def _default_scanners() -> list[ScannerName]:
    return ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]


class ScanPolicy(PolicySection):
    scanners: list[ScannerName] = Field(default_factory=_default_scanners, min_length=1)
    exclude_paths: list[str] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS), max_length=MAX_POLICY_LIST_ITEMS
    )
    failure_mode: Literal["error", "report-only"] = "error"

    @model_validator(mode="after")
    def valid_paths(self) -> ScanPolicy:
        if len(set(self.scanners)) != len(self.scanners):
            raise ValueError("scanners must be unique")
        if any(
            not p.strip()
            or len(p) > MAX_POLICY_ENTRY_CHARS
            or not Path(p).parts
            or Path(p).is_absolute()
            or ".." in Path(p).parts
            for p in self.exclude_paths
        ):
            raise ValueError("exclude_paths must be nonempty paths beneath the scan root")
        return self


class Suppression(PolicySection):
    """Accept one reviewed finding on one component, for a stated reason and period.

    Matching is exact: one component reference, one category and the fingerprint of
    the finding as it was reviewed, no wildcards. A finding whose severity, detail or
    component content digest has changed since no longer matches. An expired entry no
    longer suppresses anything and fails the risk gate until it is renewed or removed.
    """

    component_ref: str = Field(min_length=1, max_length=MAX_REFERENCE_CHARS)
    category: str = Field(min_length=1, max_length=256)
    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=2000)
    owner: str = Field(min_length=1, max_length=256)
    expires: date

    @field_validator("expires", mode="before")
    @classmethod
    def calendar_date(cls, value: object) -> object:
        # YAML reads an unquoted 2026-12-31 as a date; a quoted one arrives as text.
        if isinstance(value, datetime):
            raise ValueError("expires must be a calendar date (YYYY-MM-DD) without a time")
        if isinstance(value, str):
            if not _ISO_DATE.fullmatch(value):
                raise ValueError("expires must be a calendar date (YYYY-MM-DD)")
            return date.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def exact_and_accountable(self) -> Suppression:
        if any(not v.strip() for v in (self.component_ref, self.category, self.reason, self.owner)):
            raise ValueError("suppressions need a component_ref, category, reason and owner")
        if "*" in self.component_ref or "*" in self.category:
            raise ValueError(
                "suppressions match one exact component_ref and category; wildcards are not supported"
            )
        return self

    def label(self) -> str:
        return (
            f"{self.category} on {self.component_ref} ({self.fingerprint}) "
            f"until {self.expires.isoformat()} (owner {self.owner})"
        )


class RiskPolicy(PolicySection):
    fail_threshold: float = Field(default=50.0, gt=0)
    warn_threshold: float = Field(default=DEFAULT_WARN_THRESHOLD, ge=0)
    ignore_categories: list[str] = Field(default_factory=list, max_length=MAX_POLICY_LIST_ITEMS)
    fail_on_severity: Literal["critical", "high", "medium", "low", "info", "none"] = "critical"
    suppressions: list[Suppression] = Field(
        default_factory=list, max_length=MAX_POLICY_SUPPRESSIONS
    )

    @model_validator(mode="after")
    def valid_thresholds(self) -> RiskPolicy:
        if "warn_threshold" not in self.model_fields_set:
            # A stricter fail threshold alone must not trip the default warning threshold.
            # Writing __dict__ keeps the derived default out of model_fields_set, which
            # gate reports read as the keys the policy file itself set.
            self.__dict__["warn_threshold"] = min(DEFAULT_WARN_THRESHOLD, self.fail_threshold)
        if self.warn_threshold > self.fail_threshold:
            raise ValueError("warn_threshold cannot exceed fail_threshold")
        if any(not c.strip() or len(c) > 256 for c in self.ignore_categories):
            raise ValueError("ignore_categories must contain nonempty exact category names")
        keys = [
            (entry.component_ref, entry.category, entry.fingerprint) for entry in self.suppressions
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("each finding may be suppressed only once")
        return self


class ValidatePolicy(PolicySection):
    require_completeness: StrictBool = True
    require_integrity: StrictBool = True
    minimum_assurance_level: Literal["declared", "observed", "verified"] = "declared"
    # With --project, imported ShadowScan evidence must come from the exact report
    # bytes recorded in the BOM, signed as the operator signature policy requires.
    require_discovery_signature: StrictBool = False


class OutputPolicy(PolicySection):
    default_format: OutputFormat = "json"


class Policy(PolicySection):
    # Only the documented key `validate` names that section in a policy file.
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    version: Literal["1.0"] = "1.0"
    scan: ScanPolicy = Field(default_factory=ScanPolicy)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)
    validation: ValidatePolicy = Field(default_factory=ValidatePolicy, alias="validate")
    output: OutputPolicy = Field(default_factory=OutputPolicy)


def _policy_yaml_node_budget() -> int:
    """The YAML nodes of the largest policy the model accepts, in block or flow style.

    The root mapping, a key and a value node for every section and every setting,
    each distinct scanner, the two bounded string lists at their maximum length, and
    every permitted suppression as one mapping with a key and value per field.
    Comments, document markers and quoting add no node.
    """
    sections = (ScanPolicy, RiskPolicy, ValidatePolicy, OutputPolicy)
    settings = 1 + 2 * len(Policy.model_fields)
    settings += sum(2 * len(section.model_fields) for section in sections)
    lists = len(get_args(ScannerName)) + 2 * MAX_POLICY_LIST_ITEMS
    suppressions = MAX_POLICY_SUPPRESSIONS * (1 + 2 * len(Suppression.model_fields))
    return settings + lists + suppressions


# Larger documents are refused while composing, before any object is built.
MAX_POLICY_YAML_NODES = _policy_yaml_node_budget()


def default_policy() -> Policy:
    return Policy()


def find_policy_path(project_root: Path) -> Path | None:
    """Locate the policy file in ``project_root`` itself; ancestors are never consulted.

    The policy is part of the checkout it governs. A file above the project root
    belongs to whoever controls that directory, not to the project. Both file names
    at once are refused: either could silently shadow the other. The directory must
    fit the operator's entry bound before a policy is selected or defaults apply.
    """
    from nexus_symbiote.utils.confined import fold_name

    current = project_root.resolve()
    if current.is_file():
        current = current.parent
    entry_bound = limits.bound("entries")
    entries: list[str] = []
    try:
        with os.scandir(current) as stream:
            for item in stream:
                if len(entries) >= entry_bound.value:
                    raise PolicyListingError(f"project root {current}: {entry_bound.exceeded()}")
                entries.append(item.name)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        # A directory that cannot be listed may hold a policy, so it is not "no policy".
        raise PolicyListingError(
            f"project root {current} cannot be listed: {exc.strerror}"
        ) from None
    folded_targets = {fold_name(name): name for name in POLICY_FILE_NAMES}
    found: list[Path] = []
    variants: list[tuple[str, str]] = []
    for entry in sorted(entries):
        canonical = folded_targets.get(fold_name(entry))
        if canonical is None:
            continue
        candidate = current / entry
        if candidate.is_symlink():
            raise PolicyError(f"policy must not be a symlink: {candidate}")
        if entry in POLICY_FILE_NAMES:
            if candidate.exists():
                found.append(candidate)
        else:
            variants.append((entry, canonical))
    if variants:
        variant_name, canonical = variants[0]
        raise PolicyError(
            f"case-variant policy file {variant_name} in {current}; rename it to {canonical}"
        )
    if len(found) > 1:
        raise PolicyError(
            f"both {POLICY_FILE_NAMES[0]} and {POLICY_FILE_NAMES[1]} exist in {current}; "
            "keep one policy file"
        )
    return found[0] if found else None


def load_policy_file(project_root: Path) -> tuple[Policy, Path, str] | None:
    """Load the project policy with the path and SHA-256 of the exact bytes applied.

    The file is located once, so the reported source is always the policy applied.
    """
    path = find_policy_path(project_root)
    if path is None:
        return None
    policy, digest = _parse_policy_with_digest(path)
    return policy, path, digest


def load_policy(project_root: Path) -> Policy | None:
    loaded = load_policy_file(project_root)
    return None if loaded is None else loaded[0]


def nearest_policy_file(start: Path) -> Path | None:
    """Find the closest policy file at or above ``start`` so a caller can say it was not applied.

    Never use the result to load a policy: a file above the project, or beside an
    inventory written to a shared directory, belongs to whoever controls that directory.
    """
    for directory in (start, *start.parents):
        for name in POLICY_FILE_NAMES:
            candidate = directory / name
            try:
                if candidate.is_symlink() or candidate.exists():
                    return candidate
            except OSError:
                continue
    return None


def weakened_settings(policy: Policy) -> list[str]:
    """Name every setting that gates less strictly or changes reported results.

    Compared with the built-in policy: disabled validation, a relaxed severity cutoff
    or threshold, ignored categories, each suppression, report-only collection, fewer
    collectors, extra excluded paths, a raised warning threshold and an export format
    other than the native one, which changes what ``scan -o`` writes.
    """
    base = Policy()
    weaker: list[str] = []
    if not policy.validation.require_completeness:
        weaker.append("validate.require_completeness=false")
    if not policy.validation.require_integrity:
        weaker.append("validate.require_integrity=false")
    if policy.risk.fail_on_severity == "none":
        weaker.append("risk.fail_on_severity=none")
    if policy.risk.fail_threshold > base.risk.fail_threshold:
        weaker.append(f"risk.fail_threshold={policy.risk.fail_threshold!r}")
    if policy.risk.warn_threshold > base.risk.warn_threshold:
        weaker.append(f"risk.warn_threshold={policy.risk.warn_threshold!r}")
    if policy.risk.ignore_categories:
        weaker.append("risk.ignore_categories=" + ",".join(policy.risk.ignore_categories))
    weaker.extend(f"risk.suppressions: {entry.label()}" for entry in policy.risk.suppressions)
    if policy.scan.failure_mode == "report-only":
        weaker.append("scan.failure_mode=report-only")
    if set(policy.scan.scanners) < set(base.scan.scanners):
        weaker.append("scan.scanners=" + ",".join(policy.scan.scanners))
    extra = [path for path in policy.scan.exclude_paths if path not in _ALWAYS_EXCLUDED_NAMES]
    if extra:
        weaker.append("scan.exclude_paths=" + ",".join(extra))
    if policy.output.default_format != base.output.default_format:
        weaker.append(f"output.default_format={policy.output.default_format}")
    return weaker


def read_sexagesimal_integers_as_text(loader: type[Any]) -> None:
    """Make a SafeLoader subclass read ``1:30`` and ``12:30:45`` as text, as YAML 1.2 does.

    PyYAML builds a YAML 1.1 base-60 integer on ever larger integers, in time quadratic in
    its number of parts. A scalar tagged ``!!int`` that holds a colon is text too; every
    other integer is constructed as before.
    """
    loader.add_constructor("tag:yaml.org,2002:int", _integer_or_text)


def _integer_or_text(loader: Any, node: Any) -> Any:
    text = loader.construct_scalar(node)
    return text if ":" in text else loader.construct_yaml_int(node)


def _contains_lone_surrogate(value: str) -> bool:
    return any("\ud800" <= char <= "\udfff" for char in value)


def parse_yaml_mapping(text: str, *, max_nodes: int | None = None) -> dict[str, Any]:
    """Parse one YAML mapping with unique string keys, refusing anchors and aliases.

    ``max_nodes`` bounds the nodes composed; ``None`` sets no node budget, so callers
    bound the document themselves (pnpm lockfiles, scanner YAML and agent manifests
    by size and token count). Policy loading passes ``MAX_POLICY_YAML_NODES``.
    """
    if _contains_lone_surrogate(text):
        raise PolicyError("invalid YAML document")
    try:
        import yaml
    except ImportError as exc:
        raise PolicyError("PyYAML is required; install the declared dependencies") from exc

    class UniqueLoader(yaml.SafeLoader):
        def __init__(self, stream: Any) -> None:
            super().__init__(stream)
            self._nodes = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise PolicyError("YAML aliases are not supported in policy files")
            from typing import cast

            event = cast(Any, self).peek_event()
            if getattr(event, "anchor", None) is not None:
                raise PolicyError("YAML anchors are not supported in policy files")
            self._nodes += 1
            if max_nodes is not None and self._nodes > max_nodes:
                raise PolicyError("YAML complexity exceeds policy budget")
            return super().compose_node(parent, index)

        def construct_scalar(self, node: Any) -> str:
            value = str(super().construct_scalar(node))
            if _contains_lone_surrogate(value):
                raise PolicyError("YAML strings must not contain lone UTF-16 surrogates")
            return value

    def mapping(loader: Any, node: Any) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, str) or _contains_lone_surrogate(key) or key in data:
                raise PolicyError("YAML mapping keys must be unique strings")
            data[key] = loader.construct_object(value_node)
        return data

    def string_scalar(loader: Any, node: Any) -> str:
        value = str(loader.construct_yaml_str(node))
        if _contains_lone_surrogate(value):
            raise PolicyError("YAML strings must not contain lone UTF-16 surrogates")
        return value

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    UniqueLoader.add_constructor("tag:yaml.org,2002:str", string_scalar)
    read_sexagesimal_integers_as_text(UniqueLoader)
    try:
        data = yaml.load(text, Loader=UniqueLoader)  # noqa: S506 - subclass of SafeLoader with unique-key enforcement
        if not isinstance(data, dict):
            raise PolicyError("configuration must be a YAML mapping")
        return data
    except PolicyError:
        raise
    # OverflowError: PyYAML's YAML 1.1 base-60 float overflows from 175 parts on.
    # ValueError: Python 3.11+ int_max_str_digits rejects oversized integer scalars.
    except (yaml.YAMLError, RecursionError, OverflowError, ValueError) as exc:
        raise PolicyError("invalid YAML document") from exc


def _parse_policy_with_digest(path: Path) -> tuple[Policy, str]:
    from pydantic import ValidationError

    try:
        fd = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise PolicyError("policy must be a regular file no larger than 1 MiB")
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise PolicyError("policy exceeds 1 MiB")
        policy = Policy.model_validate(
            parse_yaml_mapping(raw.decode("utf-8"), max_nodes=MAX_POLICY_YAML_NODES)
        )
        return policy, "sha256:" + hashlib.sha256(raw).hexdigest()
    except ValidationError as exc:
        details = []
        for error in exc.errors():
            location = ".".join(map(str, error["loc"])) or "policy"
            # Messages of this module's own validators name no input value.
            if error["type"] == "value_error":
                location += " (" + str(error["msg"]).removeprefix("Value error, ") + ")"
            details.append(location)
        raise PolicyError(
            f"invalid policy {path}: invalid or unsupported settings: {', '.join(details)}"
        ) from exc
    except (OSError, UnicodeError, ValueError) as exc:
        raise PolicyError(f"invalid policy {path}: {exc}") from exc


DEFAULT_POLICY_YAML = """\
# Nexus SymBiote project policy. Every key is described in docs/policy-reference.md.
# Tightening settings apply automatically. An invalid file produces a warning and
# leaves the governing gates in effect. --accept-project-policy requires a valid
# file when present and accepts reviewed relaxations. --no-project-policy skips it.
version: "1.0"  # quote it: an unquoted 1.0 is a number and is refused
scan:
  # Removing a collector leaves coverage partial, which fails the gates.
  scanners: ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]
  # These four directories, and venv, are always skipped. Any other path listed here is a
  # recorded coverage gap, so the scan gate fails; use it only with report-only scans.
  exclude_paths: ["node_modules", ".git", "__pycache__", ".venv"]
  failure_mode: "error"  # or "report-only": never fail CI
risk:
  fail_threshold: 50.0  # aggregate score; lowering it is stricter
  warn_threshold: 25.0  # must not exceed fail_threshold
  fail_on_severity: "critical"  # critical, high, medium, low, info or none
  ignore_categories: []  # whole categories, everywhere; prefer suppressions
  # Accept one reviewed finding, with a reason, owner and expiry. Copy component_ref,
  # category and fingerprint from `risk --json-output`; a changed finding no longer matches.
  # suppressions:
  #   - component_ref: "model:tests/fixtures/firmware.bin"
  #     category: "serialization_format"
  #     fingerprint: "sha256:<64 hex digits from the finding>"
  #     reason: "Test fixture, never loaded"
  #     owner: "security@example.test"
  #     expires: 2027-01-31
  suppressions: []  # operator-approved decisions are managed in the operator policy
validate:
  require_completeness: true
  require_integrity: true
  minimum_assurance_level: "declared"  # or "observed"
  require_discovery_signature: false
output:
  default_format: "json"
"""
