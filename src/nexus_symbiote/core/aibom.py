"""The AIBOM document model — the top-level container for an AgentBOM."""

from __future__ import annotations

import errno
import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from nexus_symbiote import __version__
from nexus_symbiote.core.canonical import NAMESPACE, json_text
from nexus_symbiote.core.content_digest import inventory_content_digest
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import (
    CREDENTIAL_FORMAT_REFUSAL,
    CREDENTIAL_SPEC_VERSION_PATTERN,
    MAX_REFERENCE_CHARS,
    AIBOMMetadata,
    AnyComponent,
    CredentialComponent,
    UnsupportedSpecVersionError,
    admits_credentials,
    check_spec_version,
    credential_value_problem,
)

MAX_NATIVE_BYTES = 16 * 1024 * 1024
"""The largest native document any command reads, and therefore the largest one written."""

MAX_NATIVE_NESTING = 128
"""How many levels of arrays and objects a native document may nest, the root counted.

Twice the runtime snapshot budget (``runtime.MAX_BOM_DEPTH``), so a document the
snapshot cannot bind still loads and ``digest`` reports its missing canonical digest;
well below what pydantic serializes, which is where ``diff`` used to fail.
"""

SCHEMA_ID = (
    "https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/schemas/"
    "nexus-symbiote-aibom-1.0.schema.json"
)

UNDECLARED_SPEC_VERSION = "1.0.0"
"""The format of a native document that declares no version, as release 0.1.0 read it."""

Relationship = Literal[
    "invokes",
    "delegates-to",
    "retrieves-from",
    "acts-as-identity",
    "registered-as",
    "approved-under",
    "observed-using",
    "trained-on",
    "fine-tuned-from",
    "quantized-from",
    "merged-from",
    "depends-on",
    "configured-with",
    "provides-tool",
    "uses-model",
    "reads-instructions",
    "loads-skill",
    "uses-memory",
    "uses-guardrail",
]


class NativeFormatError(ValueError):
    """A native AgentBOM document cannot be read; the message never quotes its content."""


_SERIAL_UNDEFINED = (
    "Its serial number is derived from its content digest, which cannot be computed: the "
    "inventory records a value outside the I-JSON domain, such as a lone surrogate, or "
    "nests too deeply."
)
NO_CONTENT_SERIAL = f"Inventory not written. {_SERIAL_UNDEFINED}"


class ContentSerialError(ValueError):
    """The serial number cannot be derived because the content digest is undefined."""

    def __init__(self) -> None:
        super().__init__(NO_CONTENT_SERIAL)


class ExportCheckError(ValueError):
    """The inventory fails a check every export makes; the message is fixed text."""


def _open_failure(exc: OSError) -> str:
    """Why a native document could not be opened, without the operating system's text."""
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        return (
            "It is reached through a symbolic link or a path component that is not a "
            "directory; inventories are read without following links, so pass the real path."
        )
    if exc.errno is None:
        return (
            "It is not a regular file; FIFOs, devices, directories and standard input are refused."
        )
    if exc.errno == errno.ENOENT:
        return "It does not exist."
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return "It cannot be read: permission denied."
    return "It cannot be opened for reading."


def read_native_bytes(path: Path) -> bytes:
    """The bytes of a native document, read once without following links or blocking.

    At most ``MAX_NATIVE_BYTES``; every failure is a ``NativeFormatError``.
    """
    from nexus_symbiote.core.hashing import open_regular_file

    try:
        with open_regular_file(path) as stream:
            raw = stream.read(MAX_NATIVE_BYTES + 1)
    except OSError as exc:
        raise NativeFormatError(_open_failure(exc)) from exc
    if len(raw) > MAX_NATIVE_BYTES:
        raise NativeFormatError(
            f"It exceeds the {MAX_NATIVE_BYTES // (1024 * 1024)} MiB native inventory limit."
        )
    return raw


def _nested_deeper_than(value: Any, limit: int) -> bool:
    """Whether arrays and objects nest more than ``limit`` levels, checked without recursion."""
    pending: list[Iterator[Any]] = [iter((value,))]
    while pending:
        for item in pending[-1]:
            if isinstance(item, dict | list):
                if len(pending) > limit:
                    return True
                if item:
                    pending.append(iter(item.values() if isinstance(item, dict) else item))
                    break
        else:
            pending.pop()
    return False


def parse_native_bytes(raw: bytes) -> Any:
    """The JSON value of a native document's bytes: strict UTF-8 I-JSON or a NativeFormatError.

    Arrays and objects nest at most ``MAX_NATIVE_NESTING`` levels. The bound is checked
    without recursion, so what loads does not depend on the caller's stack, and every
    reader that walks the document recursively, pydantic included, stays within it.
    """
    from nexus_symbiote.core.hashing import parse_json_strict

    try:
        value = parse_json_strict(raw, max_bytes=MAX_NATIVE_BYTES)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise NativeFormatError(
            "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused."
        ) from exc
    if _nested_deeper_than(value, MAX_NATIVE_NESTING):
        raise NativeFormatError(f"inventory nests deeper than {MAX_NATIVE_NESTING} levels")
    return value


class DependencyEdge(BaseModel):
    """A typed relationship between two components."""

    model_config = ConfigDict(extra="forbid")

    source_ref: str = Field(max_length=MAX_REFERENCE_CHARS)
    target_ref: str = Field(max_length=MAX_REFERENCE_CHARS)
    relationship: Relationship = Field(description=", ".join(get_args(Relationship)))
    assurance_level: Literal["declared", "observed", "verified"] | None = None
    conditions: str | None = None


class AIBOM(BaseModel):
    """Agent Bill of Materials — a supply chain inventory.

    Its metadata.completeness claim says what it covers.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": SCHEMA_ID,
            # A credential component needs a format that defines it.
            "if": {
                "required": ["components"],
                "properties": {
                    "components": {
                        "contains": {
                            "type": "object",
                            "required": ["component_type"],
                            "properties": {"component_type": {"const": "credential"}},
                        }
                    }
                },
            },
            "then": {
                "required": ["metadata"],
                "properties": {
                    "metadata": {
                        "required": ["spec_version"],
                        "properties": {
                            "spec_version": {"pattern": CREDENTIAL_SPEC_VERSION_PATTERN}
                        },
                    }
                },
            },
        },
    )

    metadata: AIBOMMetadata = Field(default_factory=AIBOMMetadata)
    components: list[AnyComponent] = Field(default_factory=list)
    dependencies: list[DependencyEdge] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def undeclared_format_version(cls, data: Any) -> Any:
        """Read a metadata object that declares no spec_version as format 1.0.0.

        Objects built in process pass an AIBOMMetadata instance, or none, and keep the
        format this build writes. A document without metadata looks the same as such an
        object here, so documents are read with ``from_document``.
        """
        if isinstance(data, dict):
            metadata = data.get("metadata")
            if isinstance(metadata, dict) and "spec_version" not in metadata:
                return {**data, "metadata": {**metadata, "spec_version": UNDECLARED_SPEC_VERSION}}
        return data

    @model_validator(mode="after")
    def credentials_need_their_format(self) -> AIBOM:
        if not admits_credentials(self.metadata.spec_version) and any(
            c.component_type is ComponentType.CREDENTIAL for c in self.components
        ):
            raise ValueError(CREDENTIAL_FORMAT_REFUSAL)
        return self

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """The native schema, whose default is the version an undeclared document is read as."""
        schema = super().model_json_schema(*args, **kwargs)
        version = schema["$defs"]["AIBOMMetadata"]["properties"]["spec_version"]
        version["default"] = UNDECLARED_SPEC_VERSION
        return schema

    @model_validator(mode="after")
    def unique_components(self) -> AIBOM:
        refs = [component.bom_ref for component in self.components]
        if len(refs) != len(set(refs)):
            raise ValueError("Duplicate component references in AIBOM")
        return self

    def replace_component(self, component: AnyComponent) -> None:
        """Explicitly replace an existing component in an edited snapshot."""
        for index, existing in enumerate(self.components):
            if existing.bom_ref == component.bom_ref:
                self.components[index] = component
                return
        raise ValueError(f"No component with reference: {component.bom_ref}")

    def add_component(self, component: AnyComponent) -> None:
        for existing in self.components:
            if existing.bom_ref == component.bom_ref:
                if existing == component:
                    return
                raise ValueError(f"Duplicate component reference: {component.bom_ref}")
        self.components.append(component)

    def add_dependency(self, edge: DependencyEdge) -> None:
        self.dependencies.append(edge)

    def get_component(self, bom_ref: str) -> AnyComponent | None:
        for c in self.components:
            if c.bom_ref == bom_ref:
                return c
        return None

    def get_components_by_type(self, ctype: ComponentType) -> list[AnyComponent]:
        return [c for c in self.components if c.component_type == ctype]

    def get_all_risks(self) -> list[tuple[str, Any]]:
        results = []
        for c in self.components:
            if hasattr(c, "risks"):
                for risk in c.risks:
                    results.append((c.bom_ref, risk))
        return results

    def finalize(self) -> None:
        """Fill the deterministic tool stamp only.

        The serial number and the observation timestamp are export concerns
        owned by :func:`prepare`: the serial is a content-derived uuid5, and no
        wall-clock timestamp is stamped here, so two exports of the same inventory
        are identical. A timestamp set explicitly by a caller is preserved untouched.
        """
        if self.metadata.tool_version is None:
            self.metadata.tool_version = __version__

    def to_dict(self) -> dict[str, Any]:
        prepare(self)
        return native_document(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_native_json(self) -> str:
        """Render a document every reader accepts, or refuse with a ``NativeFormatError``.

        Indented output is preferred; a document that only fits without indentation is
        written compactly rather than being written in a form ``load`` rejects. The
        refusal names the limit or the check the inventory fails, never its content.
        """
        from nexus_symbiote.core.hashing import canonical_json

        try:
            payload = self.to_dict()
        except ContentSerialError as exc:
            raise NativeFormatError(_SERIAL_UNDEFINED) from exc
        except ExportCheckError as exc:
            raise NativeFormatError(
                f"It fails the native JSON export's consistency checks: {exc}."
            ) from exc
        if _nested_deeper_than(payload, MAX_NATIVE_NESTING):
            raise NativeFormatError(
                f"The inventory nests deeper than {MAX_NATIVE_NESTING} levels, which native "
                "readers refuse."
            )
        try:
            canonical_json(payload)
        except (TypeError, ValueError) as exc:
            raise NativeFormatError(
                "The inventory contains values outside strict I-JSON (such as nonfinite "
                "numbers or integers outside IEEE-754 exact range) that native readers reject."
            ) from exc
        text = json.dumps(payload, indent=2, default=str)
        if len(text.encode("utf-8")) <= MAX_NATIVE_BYTES:
            return text
        text = json.dumps(payload, separators=(",", ":"))
        if len(text.encode("utf-8")) <= MAX_NATIVE_BYTES:
            return text
        raise NativeFormatError(
            f"The inventory exceeds the {MAX_NATIVE_BYTES // (1024 * 1024)} MiB limit "
            "that native readers accept."
        )

    def save(self, path: Path) -> None:
        """Replace ``path`` atomically, never writing through a symbolic link."""
        from nexus_symbiote.utils.files import write_output_file

        write_output_file(path, self.to_native_json())

    @classmethod
    def from_document(cls, data: Any) -> AIBOM:
        """Read a parsed native document; one that declares no format version, with or
        without a metadata object, is read as format 1.0.0, as ``load`` reads it.

        Raises ``ValidationError`` when the document does not match the schema.
        """
        if isinstance(data, dict) and "metadata" not in data:
            data = {**data, "metadata": {}}
        return cls.model_validate(data)

    @classmethod
    def load(cls, path: Path) -> AIBOM:
        """Read a native document without following links or blocking on special files.

        Every failure is a ``NativeFormatError`` whose message names the class of
        problem and never quotes the document.
        """
        return cls.load_with_bytes(path)[0]

    @classmethod
    def load_with_bytes(cls, path: Path) -> tuple[AIBOM, bytes]:
        """Read like ``load`` and also return the bytes that were read.

        A digest of those bytes binds exactly the document that was validated, never a
        second read of a path that may have changed in between.
        """
        raw = read_native_bytes(path)
        return cls.from_native(parse_native_bytes(raw)), raw

    @classmethod
    def from_native(cls, data: Any) -> AIBOM:
        """Validate a parsed native document as ``load`` does, without changing ``data``.

        A document that declares no format version is read as format 1.0.0, with or
        without a metadata object (``from_document``); every failure is a
        ``NativeFormatError``.
        """
        metadata = data.get("metadata") if isinstance(data, dict) else None
        if isinstance(metadata, dict) and "spec_version" in metadata:
            try:
                check_spec_version(metadata["spec_version"])
            except UnsupportedSpecVersionError as exc:
                raise NativeFormatError(str(exc)) from exc
        try:
            return cls.from_document(data)
        except (ValidationError, RecursionError) as exc:
            raise NativeFormatError("It does not match the native AgentBOM schema.") from exc

    def summary(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for c in self.components:
            key = c.component_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        all_risks = self.get_all_risks()
        risk_counts: dict[str, int] = {}
        for _, risk in all_risks:
            sev = risk.severity.value if hasattr(risk.severity, "value") else str(risk.severity)
            risk_counts[sev] = risk_counts.get(sev, 0) + 1
        return {
            "total_components": len(self.components),
            "component_types": type_counts,
            "total_dependencies": len(self.dependencies),
            "total_risks": len(all_risks),
            "risk_breakdown": risk_counts,
            "completeness": (
                self.metadata.completeness.model_dump(mode="json", exclude_none=True)
                if self.metadata.completeness
                else None
            ),
        }


def prepare(bom: AIBOM) -> AIBOM:
    """Fill missing export metadata once; never reset an existing observation timestamp.

    A missing serial number becomes the uuid5, in ``core.canonical.NAMESPACE``, of the
    inventory content digest (``core.content_digest``) of the native document: the
    collection time, the observation times and the location an imported report was
    read from are not content, so collecting the same inventory at another time or
    from another checkout keeps the same serial, and anyone can recompute it from the
    native file with ``nexus-symbiote digest``. Two documents that differ only in
    those fields therefore share a serial by design. No wall-clock timestamp is
    stamped here, so two exports of the same inventory are byte-identical; a
    timestamp set explicitly by a caller (``SOURCE_DATE_EPOCH``) is preserved.
    Formats whose schema requires a timestamp (SPDX ``CreationInfo.created``) supply
    it at render time when the inventory has none.

    Raises ``ContentSerialError`` when the content digest is undefined for the inventory,
    and ``ExportCheckError`` for a timestamp without a timezone, a duplicate component
    reference, a dependency on an unknown component, or a credential that holds a value
    or a digest of one or that the declared format does not define. Validation alone
    cannot keep a value out: a record can be changed after it was built.
    """
    if bom.metadata.timestamp is not None and bom.metadata.timestamp.tzinfo is None:
        raise ExportCheckError("export timestamps must include a timezone")
    for component in bom.components:
        if isinstance(component, CredentialComponent):
            if not admits_credentials(bom.metadata.spec_version):
                raise ExportCheckError(CREDENTIAL_FORMAT_REFUSAL)
            problem = credential_value_problem(component)
            if problem is not None:
                raise ExportCheckError(problem)
    if bom.metadata.tool_version is None:
        bom.metadata.tool_version = __version__
    if bom.metadata.serial_number is None:
        try:
            digest = inventory_content_digest(native_document(bom))
        except (ValueError, RecursionError):
            raise ContentSerialError from None
        bom.metadata.serial_number = "urn:uuid:" + str(uuid.uuid5(NAMESPACE, digest))
    ids = [c.bom_ref for c in bom.components]
    if len(ids) != len(set(ids)):
        raise ExportCheckError("duplicate component references")
    known = set(ids)
    for edge in bom.dependencies:
        if edge.source_ref not in known or edge.target_ref not in known:
            raise ExportCheckError("dependency references an unknown component")
    return bom


def native_document(bom: AIBOM) -> dict[str, Any]:
    document = bom.model_dump(mode="json", exclude_none=True)
    document["components"] = sorted(document["components"], key=lambda c: c["bom_ref"])
    document["dependencies"] = sorted(document["dependencies"], key=json_text)
    return document
