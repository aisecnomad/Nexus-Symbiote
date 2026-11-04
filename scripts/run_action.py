"""GitHub Action entry point: inputs are data, and exports share one collection."""

from __future__ import annotations

import json
import math
import os
import secrets
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

SCANNERS = frozenset(
    {"shadowscan", "mcp", "model", "prompt", "rag", "registry", "a2a", "ide_agents"}
)
FORMATS = frozenset({"json", "cyclonedx", "spdx", "sarif"})


def _boolean(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError("boolean inputs must be true or false")
    return value == "true"


def _within(workspace: Path, value: str) -> Path:
    if not value or any(c in value for c in "\r\n\x00"):
        raise ValueError("paths must be nonempty and contain no newline or NUL")
    path = (workspace / value).absolute()
    if (
        ".." in path.parts
        or not path.is_relative_to(workspace)
        or not path.resolve().is_relative_to(workspace)
    ):
        raise ValueError("Action paths must stay within GITHUB_WORKSPACE")
    return path


@dataclass(frozen=True)
class Config:
    workspace: Path
    project: Path
    output: Path
    format: str
    scanners: tuple[str, ...]
    validate: bool
    risk_check: bool
    threshold: float
    sarif: bool

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        workspace = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
        project = _within(workspace, env.get("SYMBIOTE_SCAN_PATH", "."))
        if not project.is_dir():
            raise ValueError("scan-path must be an existing directory")
        output_value = env.get("SYMBIOTE_OUTPUT_FILE", "nexus-symbiote-aibom.json")
        if any(c in output_value for c in "*?[]!"):
            raise ValueError("output-file must be a literal artifact path without glob syntax")
        output = _within(workspace, output_value)
        fmt = env.get("SYMBIOTE_FORMAT", "json")
        if fmt not in FORMATS:
            raise ValueError("unsupported output format")
        scanners = tuple(
            s.strip() for s in env.get("SYMBIOTE_SCANNERS", "").split(",") if s.strip()
        )
        if len(scanners) != len(set(scanners)) or set(scanners) - SCANNERS:
            raise ValueError("scanners must be distinct supported names")
        threshold = float(env.get("SYMBIOTE_RISK_THRESHOLD", "50"))
        if not math.isfinite(threshold) or not 0 <= threshold <= 100:
            raise ValueError("risk-threshold must be finite and between 0 and 100")
        return cls(
            workspace,
            project,
            output,
            fmt,
            scanners,
            _boolean(env.get("SYMBIOTE_VALIDATE", "true")),
            _boolean(env.get("SYMBIOTE_RISK_CHECK", "true")),
            threshold,
            _boolean(env.get("SYMBIOTE_SARIF", "false")),
        )


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    # The executable is this interpreter; arguments never pass through a shell.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-m", "nexus_symbiote", *args],
        text=True,
        capture_output=True,
        check=False,
    )


def _echo_untrusted(text: str) -> None:
    # Collector output quotes repository text. The runner reads "::cmd::" at a line
    # start and the legacy "##[cmd]" anywhere in a line, so suspend workflow-command
    # processing while echoing it. The token is chosen after the text was produced.
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}", file=sys.stderr)
    print(text, file=sys.stderr)
    print(f"::{token}::", file=sys.stderr)


def _write(path: Path, content: str, *, root: Path | None = None) -> None:
    from nexus_symbiote.utils.files import write_output_file

    write_output_file(path, content, root=root, create_parents=True)


def _export(native: Path, output: Path, fmt: str, *, root: Path | None = None) -> None:
    if fmt == "json":
        _write(output, native.read_text(encoding="utf-8"), root=root)
        return
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.generators.sarif import SARIFGenerator
    from nexus_symbiote.generators.spdx import SPDXGenerator

    generators = {"cyclonedx": CycloneDXGenerator, "sarif": SARIFGenerator, "spdx": SPDXGenerator}
    _write(output, generators[fmt]().generate_json(AIBOM.load(native)), root=root)


def run(
    config: Config,
    *,
    command: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run,
    export: Callable[[Path, Path, str], None] | None = None,
    outputs: Path | None = None,
) -> int:
    def emit(**values: str) -> None:
        if outputs is not None:
            with outputs.open("a", encoding="utf-8") as stream:
                for name, value in values.items():
                    if any(c in value for c in "\r\n"):
                        raise ValueError("invalid multiline Action output")
                    stream.write(f"{name}={value}\n")

    def emit_export(native: Path, output: Path, fmt: str) -> None:
        if export is None:
            _export(native, output, fmt, root=config.workspace)
        else:
            export(native, output, fmt)

    emit(risk_score="", passed="skipped")
    with tempfile.TemporaryDirectory(prefix="nexus-symbiote-action-") as scratch:
        native = Path(scratch) / "native.json"
        args = [
            "scan",
            "--no-project-policy",
            "--report-only",
            "--format",
            "json",
            "--output",
            str(native),
        ]
        for scanner in config.scanners:
            args.extend(["--scanner", scanner])
        collected = command([*args, "--", str(config.project)])
        if collected.returncode != 0:
            _echo_untrusted(collected.stderr)
            return 1
        emit_export(native, config.output, config.format)
        emit(aibom_path=str(config.output))
        inventory = json.loads(native.read_text(encoding="utf-8"))
        if inventory.get("metadata", {}).get("completeness", {}).get("scan_failures"):
            print("Collection failed; review the partial inventory", file=sys.stderr)
            return 1
        if config.sarif:
            sarif = config.output.with_name(config.output.name + ".sarif")
            emit_export(native, sarif, "sarif")
            emit(sarif_path=str(sarif))
        if config.validate:
            validated = command(
                ["validate", "--no-project-policy", str(native), "--project", str(config.project)]
            )
            if validated.returncode != 0:
                _echo_untrusted(validated.stderr)
                return 1
        if config.risk_check and config.threshold != 0:
            scored = command(
                [
                    "risk",
                    "--no-project-policy",
                    str(native),
                    "--threshold",
                    str(config.threshold),
                    "--json-output",
                ]
            )
            if scored.returncode not in {0, 1}:
                raise ValueError("risk evaluation failed to run")
            report = json.loads(scored.stdout)
            score = report.get("overall_score")
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(score)
            ):
                raise ValueError("risk evaluation returned no finite numeric score")
            emit(risk_score=str(score), passed="true" if scored.returncode == 0 else "false")
            if scored.returncode != 0:
                return 1
    return 0


def main() -> int:
    try:
        config = Config.from_env(os.environ)
        output_path = Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None
        return run(config, outputs=output_path)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Nexus SymBiote action failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
