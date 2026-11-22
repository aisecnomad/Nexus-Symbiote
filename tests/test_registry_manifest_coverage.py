"""Manifest forms the registry collector cannot read are coverage gaps, not silence."""

from __future__ import annotations

import itertools
import json
import re
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import RegistryScanner
from tests.support import scaling_ratio

NOTHING_FOUND = "registry (no AI-related dependencies found)"


def _project(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text("# Agents\n\nUse the tests before committing.\n")
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _scan(project: Path, out: Path, *extra: str) -> tuple[int, dict]:
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(out), *extra]
    )
    document = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    return result.exit_code, document


@pytest.mark.parametrize(
    "line",
    [
        "-r more.txt",
        "--requirement more.txt",
        "--requirement=more.txt",
        "-rmore.txt",
        "--requirem more.txt",
        "-r reqs/base.txt",
        "-r ../x.txt",
        "-r a/../requirements.txt",
        "-r /requirements.txt",
        "-r ${REQUIREMENTS}",
        "-r https://h.example/r.txt",
        "--index-url https://pypi.org/simple -r ../shared/ai.txt",
        "-c constraints.txt",
        "--cons=constraints.txt",
        "-e git+https://github.com/openai/openai-python@v1.0.0#egg=openai",
        "-e ./vendor/x",
        "-e file:./vendor/x",
        "-r 'unbalanced",
        # optparse takes "--" as an option's value, so options continue after it.
        "--trusted-host -- -r more.txt",
        "-f -- -e ./vendor",
        "--extra-index-url -- -c c.txt",
        "-i -- -r more.txt",
        "--hash -- -r more.txt",
        "-C -- -r more.txt",
        # An option of another pip, which may take a value.
        "--global-option -- -r more.txt",
        # pip fills in ${NAME} before it reads the line.
        "${OPT} more.txt",
        "--pre ${OPT}",
        # pip installs the requirement itself as editable.
        "./vendor/openai -e .",
        "git+https://github.com/openai/openai-python@v1.0.0#egg=openai --editable=x",
    ],
)
def test_requirements_option_reaching_beyond_the_read_files_is_partial(tmp_path, line):
    project = _project(
        tmp_path / "proj", {"requirements.txt": f"{line}\n", "more.txt": "openai==1.0.0\n"}
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded and result.scan_failures == []
    assert all(gap.startswith("requirements.txt: ") for gap in result.surfaces_excluded)
    assert NOTHING_FOUND not in result.surfaces_scanned
    code, document = _scan(project, tmp_path / "a.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"
    code, _ = _scan(project, tmp_path / "b.json", "--report-only")
    assert code == 0


def test_hidden_include_fails_validate_and_risk(tmp_path):
    project = _project(
        tmp_path / "proj", {"requirements.txt": "-r more.txt\n", "more.txt": "openai==1.0.0\n"}
    )
    _scan(project, tmp_path / "a.json", "--report-only")
    runner = CliRunner()
    for command in ("validate", "risk"):
        result = runner.invoke(
            main,
            [command, str(tmp_path / "a.json"), "--project", str(project), "--no-project-policy"],
        )
        assert result.exit_code == 1, (command, result.output)


def test_include_gap_names_no_target(tmp_path):
    project = _project(
        tmp_path / "proj",
        {"requirements.txt": "openai==1.0.0\n-r https://alice:S3CR1@h.example/S3CR2/r.txt\n"},
    )
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        out = tmp_path / f"out.{fmt}"
        result = CliRunner().invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only", "-f", fmt]
            + ["-o", str(out)],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8") + result.output
        assert "S3CR" not in text and "alice" not in text, fmt


def test_one_gap_per_file_and_option(tmp_path):
    project = _project(
        tmp_path,
        {"requirements.txt": "-r a.txt\n-r b.txt\n-c c.txt\n-r requirements-ml.txt\n"},
    )
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "requirements.txt: requirements include not followed",
        "requirements.txt: constraints file not followed",
    ]


@pytest.mark.parametrize(
    "line",
    [
        "-r requirements.txt",
        "-r ./requirements.txt",
        "--requirement=.//requirements.txt",
        "-c requirements.txt",
        "-e .",
        "-e ./",
        "-e .[dev]",
        "-e file:.",
        "-e 'file:.[dev,test]'",
        "--index-url https://pypi.org/simple",
        "--extra-index-url https://${TOKEN}@h.example/simple --pre",
        "--hash=sha256:" + "0" * 64,
        "-- -r more.txt",
        "--pre -- -r more.txt",
        "--index-url=https://${TOKEN}@h.example/simple",
        "--trusted-host h.example --no-binary :all: --only-binary=:none:",
        "-f ./wheels -i https://pypi.org/simple --config-settings k=v --use-feature truststore",
        ". -e .",
    ],
)
def test_options_that_add_nothing_unread_stay_complete(tmp_path, line):
    project = _project(
        tmp_path,
        {"requirements.txt": "openai==1.0.0\n", "requirements-dev.txt": f"\ufeff{line}\n"},
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [c.name for c in result.components] == ["openai"]


@pytest.mark.parametrize(
    "line",
    ["${OPT} more.txt", "open${SUFFIX}==1.0.0", "--pre ${OPT}", "--${OPT}=more.txt"],
)
def test_environment_variable_that_decides_a_line_is_a_gap(tmp_path, line):
    project = _project(tmp_path, {"requirements.txt": f"{line}\n", "more.txt": "openai==1.0.0\n"})
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == ["requirements.txt: environment variable not resolved"]
    assert result.components == [] and result.scan_failures == []


@pytest.mark.parametrize(
    "declaration",
    ["# coding: utf-7", "# -*- coding: latin-1 -*-", "#!/bin/sh\n# vim: fileencoding=utf-16"],
)
def test_requirements_file_in_another_declared_encoding_is_not_read(tmp_path, declaration):
    # pip decodes by the declaration, so "+AC0-r more.txt" is "-r more.txt" in UTF-7.
    project = _project(
        tmp_path / "proj",
        {"requirements.txt": f"{declaration}\n+AC0-r more.txt\n", "more.txt": "openai==1.0.0\n"},
    )
    result = RegistryScanner().scan(project)
    assert result.scan_failures == [
        "requirements.txt: declared encoding other than UTF-8: not read"
    ]
    assert NOTHING_FOUND not in result.surfaces_scanned
    code, document = _scan(project, tmp_path / "a.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "failed"


@pytest.mark.parametrize(
    "declaration", ["# -*- coding: utf-8 -*-", "# coding=UTF8", "\ufeff# coding: utf-7"]
)
def test_utf8_declaration_is_read(tmp_path, declaration):
    # A byte order mark decides the encoding before any declaration.
    _project(tmp_path, {"requirements.txt": f"{declaration}\nopenai==1.0.0\n"})
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert [c.name for c in result.components] == ["openai"]


def test_editable_file_url_is_not_the_project_when_a_directory_shadows_it(tmp_path):
    # pip installs an existing directory named "file:." rather than the project.
    project = _project(tmp_path, {"requirements.txt": "-e file:.\n"})
    try:
        (project / "file:.").mkdir()
    except OSError:
        pytest.skip("file system rejects the name")
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "requirements.txt: editable install not followed"
    ]


WHEEL_URL = "https://files.pythonhosted.org/packages/x/openai-1.0.0-py3-none-any.whl"


@pytest.mark.parametrize(
    "line",
    [
        "./vendor/openai",
        "vendor/openai[extra]",
        "git+https://github.com/openai/openai-python@v1.0.0#egg=openai",
        "GIT+HTTPS://github.com/openai/openai-python@v1.0.0#egg=openai",
        WHEEL_URL,
        "file:vendor/openai",
        # pip keeps the extras in a file: URL, which names a directory ".[dev]".
        "file:.[dev]",
        "../openai",
        # pip normalises the path before it takes the extras off, so these name a
        # directory "..]".
        ".[/../..]",
        "./[x/../..]",
        # pip finds the scheme after it drops a tab, and reads a local archive.
        "git+ht\ttps://github.com/openai/openai-python#egg=openai",
        "dist/openai-1.0.0.tar.gz",
        f"{WHEEL_URL} --hash=sha256:{'0' * 64} --hash sha256:{'1' * 64}",
        "./vendor/openai ; python_version >= '3.8'",
        f"{WHEEL_URL} ; sys_platform == 'linux'",
    ],
)
def test_requirement_by_url_or_path_is_partial(tmp_path, line):
    # pip installs these without a PEP 508 name, so no component can stand for them.
    project = _project(
        tmp_path / "proj",
        {
            "requirements.txt": f"{line}\n",
            "vendor/openai/pyproject.toml": '[project]\nname = "openai"\nversion = "1.0.0"\n',
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [
        "requirements.txt: URL, VCS or path requirement not followed"
    ]
    assert result.components == [] and result.scan_failures == []
    assert NOTHING_FOUND not in result.surfaces_scanned
    code, document = _scan(project, tmp_path / "a.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


def test_requirement_by_archive_name_is_partial(tmp_path):
    # pip reads a name ending in an archive extension as a file, not a PyPI name.
    _project(tmp_path, {"requirements.txt": "openai-1.0.0-py3-none-any.whl\n"})
    assert RegistryScanner().scan(tmp_path).surfaces_excluded == [
        "requirements.txt: URL, VCS or path requirement not followed"
    ]


def test_url_requirement_gap_names_no_reference(tmp_path):
    project = _project(
        tmp_path / "proj",
        {
            "requirements.txt": "openai==1.0.0\n"
            "git+https://alice:S3CR1@github.com/org/S3CR2.git#egg=openai\n"
        },
    )
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        out = tmp_path / f"out.{fmt}"
        result = CliRunner().invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only", "-f", fmt]
            + ["-o", str(out)],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8") + result.output
        assert "S3CR" not in text and "alice" not in text, fmt
    assert "URL, VCS or path requirement not followed" in (tmp_path / "out.json").read_text()


@pytest.mark.parametrize(
    ("line", "directory"),
    [
        ("openai @ https://h.example/openai", "openai @ https:/h.example/openai"),
        # pip keeps both spaces in the path it looks for.
        (f"openai @ h  x/o --hash=sha256:{'0' * 64}", "openai @ h  x/o"),
    ],
)
def test_named_url_requirement_shadowed_by_a_directory_is_partial(tmp_path, line, directory):
    # pip reads the whole line as a relative path first and installs the directory
    # it finds there, under the name in its pyproject.toml.
    project = _project(tmp_path, {"requirements.txt": f"{line}\n"})
    shadow = project / directory
    try:
        shadow.mkdir(parents=True)
    except OSError:
        pytest.skip("file system rejects the name")
    (shadow / "pyproject.toml").write_text('[project]\nname = "other"\nversion = "1"\n')
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [
        "requirements.txt: URL, VCS or path requirement not followed"
    ]


@pytest.mark.parametrize(
    "line",
    [
        "openai @ x/../../evil",
        # The extras come off after normalisation, leaving "..".
        "openai @ x/../.. [z]",
    ],
)
def test_named_url_requirement_leaving_the_project_is_partial(tmp_path, line):
    # Normalised as a path, this names a directory outside the project.
    _project(tmp_path, {"requirements.txt": f"{line}\n"})
    assert RegistryScanner().scan(tmp_path).surfaces_excluded == [
        "requirements.txt: URL, VCS or path requirement not followed"
    ]


@pytest.mark.parametrize(
    ("line", "entry"),
    [
        # pip takes the last bracketed group and the white space before it off.
        ("foo @ x.tar.gz [y]", "foo @ x.tar.gz"),
        ("foo @ x[a.tar.gz[b]", "foo @ x[a.tar.gz"),
        # A backslash is a name character on POSIX and a separator on Windows.
        ("foo @ x\\..\\y.tar.gz", "foo @ x\\..\\y.tar.gz"),
        ("foo @ x\\..\\y/pkg", "foo @ x\\..\\y/pkg/"),
        ("openai @ x\\..\\y.tar.gz", "y.tar.gz"),
        # APFS finds a name in either Unicode normal form, HFS+ ignores a zero width
        # joiner, and NTFS ignores case, a trailing dot and a stream name and finds a
        # short name.
        ("foo @ caf\u00e9/pkg", "foo @ cafe\u0301/pkg/"),
        ("foo @ x\u200d/pkg", "foo @ x/pkg/"),
        ("FOO @ X./pkg", "foo @ x/pkg/"),
        ("foo @ x::$INDEX_ALLOCATION/pkg", "foo @ x/pkg/"),
        ("FOO@XY~1/pkg", "foo @ xyz/pkg/"),
    ],
)
def test_named_url_requirement_shadowed_by_a_local_path_is_partial(tmp_path, line, entry):
    project = _project(tmp_path, {"requirements.txt": f"{line}\n"})
    try:
        if entry.endswith("/"):
            (project / entry).mkdir(parents=True)
            (project / entry / "pyproject.toml").write_text(
                '[project]\nname = "other"\nversion = "1"\n'
            )
        else:
            (project / entry).write_bytes(b"")
    except OSError:
        pytest.skip("file system rejects the name")
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "requirements.txt: URL, VCS or path requirement not followed"
    ]


@pytest.mark.parametrize(
    "line",
    [
        "vendor.tar.gz [x]",
        "vendor.tar.gz\t[x]",
        f"vendor.zip [x] --hash=sha256:{'0' * 64}",
        "vendor.tar.gz\u00a0[x]; python_version > '3'",
        "vendor[a.zip[b]",
        "torch-2.3.1-py3-none-any.whl [x]",
    ],
)
def test_archive_requirement_with_extras_is_partial(tmp_path, line):
    # pip looks for the archive extension once the extras are off, as pip takes them.
    project = _project(tmp_path / "proj", {"requirements.txt": f"{line}\n"})
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [
        "requirements.txt: URL, VCS or path requirement not followed"
    ]
    code, document = _scan(project, tmp_path / "a.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


def test_extras_come_off_as_pip_strips_them():
    # pip 26.3's strip_extras, on a path below the directory pip runs in.
    for length in range(8):
        for letters in itertools.product("[]x \u00a0", repeat=length):
            text = "".join(letters)
            match = re.match(r"^(.+)(\[[^\]]+\])$", "/cwd/" + text)
            expected = match.group(1).rstrip() if match else "/cwd/" + text
            assert "/cwd/" + RegistryScanner._without_extras(text) == expected, repr(text)


def test_requirement_path_parsing_is_linear(tmp_path):
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / "requirements.txt").write_text(
            "".join(
                f"{prefix}{'[' * (250_000 * scale)}\n" for prefix in ("x", "openai @ ", "./", "x]")
            )
        )
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10
    result = RegistryScanner().scan(roots[4])
    assert result.surfaces_excluded == [
        "requirements.txt: URL, VCS or path requirement not followed"
    ]


@pytest.mark.parametrize(
    "line",
    [
        ".",
        "./",
        ".[dev]",
        # pip drops the space before the extras.
        ". [dev]",
        "file:.",
        ". ; python_version >= '3.8'",
        f". --hash=sha256:{'0' * 64}",
        f"openai @ {WHEEL_URL}",
        "openai[dev] @ git+https://github.com/openai/openai-python@v1.0.0",
    ],
)
def test_requirement_naming_the_project_or_a_package_stays_complete(tmp_path, line):
    # The project's own pyproject.toml is read, and "name @ URL" keeps its name.
    _project(
        tmp_path,
        {
            "requirements.txt": f"{line}\n",
            "pyproject.toml": '[project]\nname = "proj"\nversion = "1.0.0"\n'
            'dependencies = ["openai==1.0.0"]\n',
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [c.name for c in result.components] == ["openai"]


@pytest.mark.parametrize(
    ("dockerfile", "image", "risk"),
    [
        (
            "FROM --platform=linux/amd64 ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "ARG BUILDPLATFORM\nFROM --platform=$BUILDPLATFORM ollama/ollama:0.1.0 AS builder\n"
            "FROM builder\n",
            "ollama/ollama:0.1.0",
            "mutable_image_tag",
        ),
        ("from ollama/ollama:latest\n", "ollama/ollama:latest", "version_pinning"),
        ("FROM \\\n  ollama/ollama:latest\n", "ollama/ollama:latest", "version_pinning"),
        ("FROM ollama/\\\n# note\n\nollama:0.5.7\n", "ollama/ollama:0.5.7", "mutable_image_tag"),
        (
            "\ufeff# syntax=docker/dockerfile:1\nFrom   ollama/ollama:0.5.7\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        # BuildKit reads a heredoc's lines as its body, up to the terminator as written.
        (
            "FROM python:3.12-slim\nRUN <<'EOF\\'\necho hello\nEOF\\\nFROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "RUN <<'#EOF'\necho hello \\\n#EOF\nFROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "RUN <<-EOF\n\tFROM ollama/ollama:1\n\tEOF\nFROM ollama/ollama:0.5.7\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        (
            "RUN <<A <<B\nA\nFROM ollama/ollama:1\nB\nFROM ollama/ollama:0.5.7\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        (
            "RUN <<EOF\r\nFROM ollama/ollama:1\r\nEOF\r\r\nFROM ollama/ollama:0.5.7\r\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        (
            "LABEL a=<<EOF\nFROM ollama/ollama:0.5.7\nEOF\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        (
            'RUN ["<<EOF"]\nFROM ollama/ollama:0.5.7\nEOF\n',
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        (
            "RUN echo a<<EOF\nFROM ollama/ollama:0.5.7\nEOF\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        (
            "ONBU\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}LD RUN <<'EOF\\'\nx\nEOF\\\n"
            "FROM ollama/ollama:0.5.7\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
        # An escaped backslash does not continue a line, and every CR before LF goes.
        (
            "RUN echo foo\\\\\nFROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        # BuildKit parity, pinned: an escaped backslash after a stage does not hide the
        # next FROM, and BuildKit reads `<<- EOF` as no heredoc.
        (
            "FROM python:3\nRUN echo foo\\\\\nFROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "FROM python:3\nRUN cat <<- EOF\nFROM ollama/ollama:latest\nEOF\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        ("FROM \\\r\r\nollama/ollama:latest\r\n", "ollama/ollama:latest", "version_pinning"),
        # Go's unicode.IsSpace has no \x1c-\x1f.
        (
            "RUN echo \\\n\x1c\nFROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "RUN echo \\\n\x1c# x\nFROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        # BuildKit trims the joined instruction, so a line holding only a backslash
        # does not hide the indented FROM it continues onto.
        (
            "FROM python:3.12-slim\n\\\n    FROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "FROM python:3.12-slim\n\\\n\tFROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "FROM python:3.12-slim\n\\\n# note\n    FROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "FROM python:3.12-slim\n\\\n\n    FROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        (
            "FROM python:3.12-slim\n  \\ \n\xa0\u2000FROM ollama/ollama:latest\n",
            "ollama/ollama:latest",
            "version_pinning",
        ),
        # BuildKit trims the end of the instruction too, so the tag is still latest.
        ("FROM ollama/ollama:latest\xa0\n", "ollama/ollama:latest", "version_pinning"),
        ("FROM ollama/ollama:latest\u3000\x85\r\n", "ollama/ollama:latest", "version_pinning"),
        (
            "FROM ollama/ollama:0.5.7 AS ollama\u2028\nFROM ollama\n",
            "ollama/ollama:0.5.7",
            "mutable_image_tag",
        ),
    ],
)
def test_dockerfile_from_forms_name_the_image(tmp_path, dockerfile, image, risk):
    (tmp_path / "Dockerfile").write_bytes(dockerfile.encode())
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [(c.bom_ref, [r.category for r in c.risks]) for c in result.components] == [
        (f"registry:docker/{image}", [risk])
    ]


@pytest.mark.parametrize(
    "dockerfile",
    [
        "FROM python:3\nRUN <<EOF\nFROM ollama/ollama:1\nEOF\n",
        "FROM python:3\nRUN cat << EOF\nFROM ollama/ollama:1\nEOF\n",
        "FROM python:3\nCOPY <<EOF /etc/x\nFROM ollama/ollama:1\nEOF\n",
        "FROM python:3\nONBUILD RUN <<EOF\nFROM ollama/ollama:1\nEOF\n",
        "FROM python:3\nRUN 3<<EOF cat\nFROM ollama/ollama:1\nEOF\n",
        "FROM python:3\nRUN <<E\\OF\nFROM ollama/ollama:1\nEOF\n",
        'FROM python:3\nRUN <<"E O"\nFROM ollama/ollama:1\nE O\n',
        "FROM python:3\nRUN <<EOF \\\n  && echo\nFROM ollama/ollama:1\nEOF\n",
        # The instruction word is found after the space BuildKit trims.
        "FROM python:3\n\\\n\xa0RUN <<EOF\nFROM ollama/ollama:1\nEOF\n",
    ],
)
def test_heredoc_body_is_not_an_instruction(tmp_path, dockerfile):
    (tmp_path / "Dockerfile").write_bytes(dockerfile.encode())
    result = RegistryScanner().scan(tmp_path)
    assert result.components == [] and result.surfaces_excluded == []


def test_stage_reference_is_not_an_image(tmp_path):
    (tmp_path / "Dockerfile.agent").write_text(
        "FROM python:3.12-slim AS Model-Builder\nRUN pip install vllm\nFROM model-builder\n"
        "FROM --platform=linux/arm64 vllm/vllm-openai:v0.4.0 AS serve\n"
    )
    assert [c.bom_ref for c in RegistryScanner().scan(tmp_path).components] == [
        "registry:docker/vllm/vllm-openai:v0.4.0"
    ]


def test_text_outside_a_from_instruction_is_not_an_image(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n# FROM ollama/ollama:1\nRUN echo FROM ollama/ollama:2\n"
        "LABEL image: ollama/ollama:3\n"
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.components == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    ("dockerfile", "gap", "collected"),
    [
        (
            "ARG BASE=ollama/ollama:0.1.0\nFROM $BASE\n",
            "FROM image substitution not resolved",
            [],
        ),
        (
            "ARG V=0.1.0\nFROM ollama/ollama:${V}\n",
            "FROM image substitution not resolved",
            ["ollama/ollama:${V}"],
        ),
        ("FROM --platform=linux/amd64\n", "FROM instruction not parsed", []),
        ('FROM --platform="linux/amd64 x" ollama/ollama:1\n', "FROM instruction not parsed", []),
        ("# escape=`\nFROM ollama/ollama:latest\n", "escape parser directive not followed", []),
        (
            "#\x0cescape=`\nRUN echo \\\nFROM ollama/ollama:1\n",
            "escape parser directive not followed",
            [],
        ),
        ("RUN <<EOF\nFROM ollama/ollama:1\n", "heredoc not parsed", []),
        (
            "RUN echo ${X:-a} <<EOF\nFROM ollama/ollama:1\nEOF\n",
            "heredoc not parsed",
            ["ollama/ollama:1"],
        ),
        (
            "RUN echo 'it <<EOF\nFROM ollama/ollama:1\nEOF\n",
            "heredoc not parsed",
            ["ollama/ollama:1"],
        ),
        # BuildKit's lexer removes quotes and escapes from the image it pulls.
        ('FROM oll""ama/oll""ama:latest\n', "FROM image quoting not resolved", []),
        ("FROM ol\\lama/ol\\lama:latest\n", "FROM image quoting not resolved", []),
        (
            "FROM 'ollama/ollama:latest'\n",
            "FROM image quoting not resolved",
            ["'ollama/ollama:latest'"],
        ),
    ],
)
def test_unresolved_from_is_partial(tmp_path, dockerfile, gap, collected):
    (tmp_path / "Dockerfile").write_bytes(dockerfile.encode())
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [f"Dockerfile: {gap}"]
    assert [c.name for c in result.components] == collected
    out = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(out)]
    )
    assert scanned.exit_code == 1, scanned.output
    status = json.loads(out.read_text())["metadata"]["completeness"]["scanner_status"]
    assert status["registry"] == "partial"


def test_tag_change_behind_a_from_flag_is_drift(tmp_path):
    project = _project(tmp_path / "proj", {})
    dockerfile = project / "Dockerfile"
    runner = CliRunner()
    for tag, out in (("0.1.0", "a.json"), ("0.5.7", "b.json")):
        dockerfile.write_text(f"FROM --platform=linux/amd64 ollama/ollama:{tag}\n")
        scanned = runner.invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only"]
            + ["-o", str(tmp_path / out)],
        )
        assert scanned.exit_code == 0, scanned.output
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "ollama/ollama:0.5.7" in diff.output


def test_dockerfile_parsing_is_linear(tmp_path):
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / "Dockerfile").write_text("FROM" + " " * (1_000_000 * scale))
        # Just under the 4 MiB read limit at the larger size: a file over it is refused
        # unread, and a ratio over input that is never parsed measures nothing.
        (roots[scale] / "Dockerfile.agent").write_text(
            "FROM a AS b \\\n" * (74_000 * scale) + "RUN x\n"
        )
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10
    result = RegistryScanner().scan(roots[4])
    assert not result.scan_failures
    assert result.surfaces_excluded == ["Dockerfile: FROM instruction not parsed"]


def test_heredoc_parsing_is_linear(tmp_path):
    roots = {}
    for scale in (1, 4):
        root = roots[scale] = tmp_path / f"scale-{scale}"
        root.mkdir()
        (root / "Dockerfile").write_text('RUN <<EOF "' + "a" * 375_000 * scale + "\n")
        (root / "Dockerfile.agent").write_text(
            "RUN <<A <<B\nx\nA\nB\n" * 12_500 * scale + "FROM ollama/ollama:1\n"
        )
    # Four times the input: about four times the work if linear, sixteen if quadratic.
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10
    result = RegistryScanner().scan(roots[1])
    assert result.surfaces_excluded == ["Dockerfile: heredoc not parsed"]
    assert [c.name for c in result.components] == ["ollama/ollama:1"]


POETRY = '[tool.poetry]\nname = "agent"\nversion = "0.1.0"\n[tool.poetry.dependencies]\npython = "^3.11"\n'


def _poetry(root: Path, body: str) -> RegistryScanner:
    _project(root, {"pyproject.toml": POETRY + body})
    return RegistryScanner()


@pytest.mark.parametrize(
    ("constraint", "specifier"),
    [
        ("2.3.1", "==2.3.1"),
        ("=2.3.1", "==2.3.1"),
        ("2.3.*", "==2.3.*"),
        ("*", ""),
        ("", ""),
        ("^1.2.3", ">=1.2.3,<2"),
        ("^1.2", ">=1.2,<2"),
        ("^1", ">=1,<2"),
        ("^0.2.3", ">=0.2.3,<0.3"),
        ("^0.0.3", ">=0.0.3,<0.0.4"),
        ("^0.0", ">=0.0,<0.1"),
        ("^0", ">=0,<1"),
        ("~1.2.3", ">=1.2.3,<1.3"),
        ("~1.2", ">=1.2,<1.3"),
        ("~1", ">=1,<2"),
        ("~=2.3", "~=2.3"),
        (">= 2.3, < 3.0", ">= 2.3,< 3.0"),
        ("^2.3,!=2.4.1", ">=2.3,<3,!=2.4.1"),
        ("^2.3 || ^3.0", None),
        (">=1.2 <1.5", None),
        ("^1.0.0a1", None),
        ("^" + "9" * 70, None),
        ("https://h.example/t.whl", None),
    ],
)
def test_poetry_constraints_translate_to_pep440(constraint, specifier):
    from nexus_symbiote.scanners.registry import _poetry_specifier

    assert _poetry_specifier(constraint) == specifier


@pytest.mark.parametrize(
    "line", ['torch = "2.3.1"', 'torch = {version = "2.3.1", optional = true}']
)
def test_poetry_bare_version_is_an_exact_pin(tmp_path, line):
    result = _poetry(tmp_path, line + "\n").scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert component.bom_ref == "registry:pypi/torch"
    assert component.package_url == "pkg:pypi/torch@2.3.1" and component.risks == []


@pytest.mark.parametrize(
    ("value", "version"),
    [('"^2.3"', "<3,>=2.3"), ('"^0.2.3"', "<0.3,>=0.2.3"), ('"~2.3"', "<2.4,>=2.3"), ('"*"', None)],
)
def test_poetry_caret_tilde_and_wildcard_are_not_failures(tmp_path, value, version):
    result = _poetry(tmp_path, f"torch = {value}\n").scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert [(c.bom_ref, c.version) for c in result.components] == [("registry:pypi/torch", version)]
    code, _ = _scan(tmp_path, tmp_path / "bom.json")
    assert code == 0


def test_poetry_sources_are_recorded_by_name_as_a_gap(tmp_path):
    body = (
        'torch = {git = "https://alice:S3CR1@github.com/pytorch/S3CR2.git", rev = "v2.3.1"}\n'
        'openai = {url = "https://alice:S3CR1@h.example/S3CR2/openai.whl"}\n'
        'langchain = {path = "../vendor/S3CR2", develop = true}\n'
        'tokenizers = [{version = "0.19.1", platform = "linux"}, {version = "0.19.0", platform = "darwin"}]\n'
    )
    project = tmp_path / "proj"
    result = _poetry(project, body).scan(project)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [
        "pyproject.toml: Poetry git, path or URL dependency not translated"
    ]
    by_ref = {c.bom_ref: c for c in result.components}
    assert sorted(by_ref) == [
        "registry:pypi/langchain",
        "registry:pypi/openai",
        "registry:pypi/tokenizers",
        "registry:pypi/torch",
    ]
    assert by_ref["registry:pypi/torch"].package_url is None
    tokenizers = by_ref["registry:pypi/tokenizers"]
    assert tokenizers.version == '==0.19.1; sys_platform == "linux"'
    assert tokenizers.package_url is None
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        out = tmp_path / f"out.{fmt}"
        scanned = CliRunner().invoke(
            main,
            ["scan", str(project), "--no-project-policy", "--report-only", "-f", fmt]
            + ["-o", str(out)],
        )
        assert scanned.exit_code == 0, scanned.output
        text = out.read_text(encoding="utf-8") + scanned.output
        assert "S3CR" not in text and "alice" not in text, fmt


def test_poetry_markers_do_not_become_an_unconditional_pin(tmp_path):
    body = 'torch = {version = "==2.3.1", markers = "sys_platform == \'linux\'"}\n'
    (component,) = _poetry(tmp_path, body).scan(tmp_path).components
    assert component.package_url is None
    assert "sys_platform" in component.version
    assert "sys_platform" in component.properties["requested_requirement"]


def test_poetry_groups_and_dev_dependencies_are_read(tmp_path):
    body = (
        'torch = "2.3.1"\n[tool.poetry.group.ml.dependencies]\ncohere = "5.5.0"\ntorch = "2.2.0"\n'
        '[tool.poetry.dev-dependencies]\nopenai = "1.30.1"\n'
    )
    result = _poetry(tmp_path, body).scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    by_name = {c.name: c for c in result.components}
    assert by_name["cohere"].package_url == "pkg:pypi/cohere@5.5.0"
    assert by_name["openai"].package_url == "pkg:pypi/openai@1.30.1"
    assert by_name["torch"].risks == []


@pytest.mark.parametrize(
    "line",
    ['torch = "^2.3 || ^3.0"', 'torch = {version = "2.3.1", python = "^3.11"}'],
)
def test_untranslatable_poetry_condition_is_partial(tmp_path, line):
    result = _poetry(tmp_path, line + "\n").scan(tmp_path)
    assert result.surfaces_excluded == [
        "pyproject.toml: Poetry dependency condition not translated"
    ]
    assert result.scan_failures == []
    assert [(c.bom_ref, c.package_url) for c in result.components] == [
        ("registry:pypi/torch", None)
    ]
    code, document = _scan(tmp_path, tmp_path / "bom.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


@pytest.mark.parametrize(
    "line",
    [
        'torch = "https://h.example/t.whl"',
        "torch = 5",
        'torch = {version = "2.3.1", markers = "((("}',
        '"torch==2" = "*"',
    ],
)
def test_invalid_poetry_dependency_is_a_failure_without_a_mangled_name(tmp_path, line):
    result = _poetry(tmp_path, line + "\n").scan(tmp_path)
    assert result.scan_failures == ["pyproject.toml: invalid or unsupported Poetry dependency"]
    assert {c.bom_ref for c in result.components} <= {"registry:pypi/torch"}


def test_poetry_dependency_from_another_source_is_not_a_pypi_pin(tmp_path):
    body = (
        'torch = {version = "2.3.1", source = "cu121"}\n'
        'openai = {version = "1.0.0", source = "PyPI"}\n'
        '[[tool.poetry.source]]\nname = "cu121"\n'
        'url = "https://download.pytorch.org/whl/cu121"\npriority = "explicit"\n'
    )
    result = _poetry(tmp_path, body).scan(tmp_path)
    assert result.surfaces_excluded == [
        "pyproject.toml: Poetry dependency from a source other than PyPI not translated"
    ]
    by_ref = {c.bom_ref: c for c in result.components}
    assert by_ref["registry:pypi/torch"].package_url is None
    assert by_ref["registry:pypi/openai"].package_url == "pkg:pypi/openai@1.0.0"


def test_poetry_python_key_is_not_a_package(tmp_path):
    result = _poetry(tmp_path, "").scan(tmp_path)
    assert result.components == [] and result.scan_failures == []


def test_poetry_pin_change_is_a_version_change(tmp_path):
    project = _project(tmp_path / "proj", {})
    runner = CliRunner()
    for version, out in (("2.3.1", "a.json"), ("2.3.2", "b.json")):
        (project / "pyproject.toml").write_text(POETRY + f'torch = "{version}"\n')
        _scan(project, tmp_path / out, "--report-only")
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "==2.3.1 \u2192 ==2.3.2" in diff.output and "torch2" not in diff.output


# The patterns BuildKit's parser and this collector used before; the hand-written
# readers that replace them must give the same answers in linear time.
OLD_DIRECTIVE = re.compile(
    r"#[\t\n\f\r ]*([A-Za-z][A-Za-z0-9]*)[\t\n\f\r ]*=[\t\n\f\r ]*(.+?)[\t\n\f\r ]*"
)
OLD_HEREDOC = re.compile(r"[0-9]*<<(-?)[\t\n\f\r ]*([^<]*)")


def test_directive_reader_matches_buildkits_pattern():
    for length in range(8):
        for letters in itertools.product("#a1= \x0b", repeat=length):
            line = "".join(letters)
            old = OLD_DIRECTIVE.fullmatch(line)
            expected = (old.group(1), old.group(2)) if old else None
            assert RegistryScanner._directive(line) == expected, repr(line)


def test_heredoc_word_reader_matches_the_heredoc_pattern():
    for length in range(9):
        for letters in itertools.product("<-1a ", repeat=length):
            word = "".join(letters)
            old = OLD_HEREDOC.fullmatch(word)
            expected = (old.group(1) == "-", old.group(2)) if old else None
            assert RegistryScanner._heredoc_word(word) == expected, repr(word)


def test_directive_and_heredoc_reading_is_linear_at_the_read_limit(tmp_path):
    # Both shapes made the old patterns backtrack quadratically: about half a day
    # each at the read limit, which the larger size reaches.
    roots = {}
    for scale in (1, 4):
        blank = " " * (1_000_000 * scale)
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / "Dockerfile").write_text(f"# a=x{blank}y\nFROM ollama/ollama:1\n")
        (roots[scale] / "Dockerfile.agent").write_text(f"RUN <<{blank}a<b\nFROM ollama/ollama:2\n")
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10
    result = RegistryScanner().scan(roots[4])
    assert [c.name for c in result.components] == ["ollama/ollama:1", "ollama/ollama:2"]


def test_pyproject_dotted_keys_are_bounded_before_parsing(tmp_path):
    # tomllib keeps every prefix of a dotted key: about 3.5 MB for 900 parts.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        root.mkdir()
        (root / "pyproject.toml").write_text(
            "".join(f"k{i}." + ".".join(["a"] * 900) + " = 1\n" for i in range(30 * scale))
        )
        roots[scale] = root

    def run(scale: int) -> None:
        result = RegistryScanner().scan(roots[scale])
        assert result.scan_failures == [
            "pyproject.toml: dotted key exceeds the length limit: not read"
        ]

    assert scaling_ratio(run) < 10


@pytest.mark.parametrize(
    "key",
    ['"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s" = 1', "a . b . c = 1", "[tool.a.b.c.d]"],
)
def test_dots_in_strings_comments_and_short_keys_are_not_counted(tmp_path, key):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18"\n'
        'description = """' + "One. Two. " * 50 + '""""\n'
        'dependencies = ["openai==1.0.0"]  # a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s\n'
        "[tool.x]\nt = '''" + "a." * 40 + "'''\n" + key + "\n"
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert [c.name for c in result.components] == ["openai"]


@pytest.mark.parametrize(
    "hidden",
    [
        # A string ends at the last three of a run of quotes; up to two belong to it.
        'x = {y = """a"""", ' + ".".join(["a"] * 40) + " = 1}\n",
        "x = {y = '''a'''', " + ".".join(["a"] * 40) + " = 1}\n",
        'x = "a\\"", ' + ".".join(["a"] * 40) + " = 1\n",
    ],
)
def test_a_long_dotted_key_cannot_hide_behind_a_string_end(tmp_path, hidden):
    (tmp_path / "pyproject.toml").write_text(hidden)
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "pyproject.toml: dotted key exceeds the length limit: not read"
    ]


TOO_LONG = ["pyproject.toml: dotted key exceeds the length limit: not read"]


@pytest.mark.parametrize(
    "key",
    [
        # A quoted part, even an empty one, is one part of the key.
        "k" + '.""' * 20 + " = 1",
        "k" + ".'a'" * 20 + " = 1",
        "k" + '."a"' * 20 + " = 1",
        "k" + ' . "a\\"b"' * 20 + " = 1",
        "x = {k" + ".'''a'''" * 20 + " = 1}",
        "[tool" + '."b"' * 20 + "]",
        "[[tool" + ".'b'" * 20 + "]]",
    ],
)
def test_quoted_parts_count_toward_the_dotted_key_bound(tmp_path, key):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agent"\ndependencies = ["openai==1.0.0"]\n' + key + "\n"
    )
    assert RegistryScanner().scan(tmp_path).scan_failures == TOO_LONG


def test_a_long_key_of_quoted_parts_is_refused_before_parsing(tmp_path):
    # tomllib keeps every prefix of a dotted key: 7.5 s and 2.3 GB for this one.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        root.mkdir()
        (root / "pyproject.toml").write_text(
            '[project]\nname = "agent"\ndependencies = ["openai==1.0.0"]\n[tool.x]\nk'
            + '.""' * (5_000 * scale)
            + " = 1\n"
        )
        roots[scale] = root

    def run(scale: int) -> None:
        assert RegistryScanner().scan(roots[scale]).scan_failures == TOO_LONG

    assert scaling_ratio(run) < 10


def test_a_large_pyproject_is_not_parsed(tmp_path):
    (tmp_path / "pyproject.toml").write_text("x = 1\n" * 50_000)
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "pyproject.toml: exceeds the size limit: not read"
    ]


def test_an_integer_too_long_to_convert_fails_only_pyproject(tmp_path):
    # tomllib raises a plain ValueError past CPython's limit on decimal digits; it
    # used to fail the whole collector and drop the npm and image components.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "a"\nversion = "1"\ndependencies = ["anthropic==0.40.0"]\n'
        "[tool.x]\nn = " + "1" * 5_000 + "\n"
    )
    (tmp_path / "package.json").write_text('{"dependencies": {"openai": "4.52.0"}}')
    (tmp_path / "Dockerfile").write_text("FROM ollama/ollama:0.5.7\n")
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(sys.int_info.default_max_str_digits)
    try:
        result = RegistryScanner().scan(tmp_path)
    finally:
        sys.set_int_max_str_digits(previous)
    assert result.scan_failures == ["pyproject.toml: invalid TOML"]
    assert sorted(c.bom_ref for c in result.components) == [
        "registry:docker/ollama/ollama:0.5.7",
        "registry:npm/openai",
    ]


def test_long_quoted_option_text_is_not_split_and_is_a_gap(tmp_path):
    # shlex grows a token one character at a time: minutes for a 4 MiB quoted word.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        root.mkdir()
        word = "'" + "a" * (375_000 * scale) + "'"
        (root / "requirements.txt").write_text(f"openai==1.0.0 --hash {word}\n-i {word}\n")
        roots[scale] = root

    def run(scale: int) -> None:
        result = RegistryScanner().scan(roots[scale])
        assert result.surfaces_excluded == ["requirements.txt: option line not parsed"]
        assert [c.name for c in result.components] == ["openai"]

    assert scaling_ratio(run) < 10


def test_a_deeply_nested_marker_fails_its_line_and_keeps_the_rest(tmp_path):
    # packaging parses markers by recursion; the RecursionError used to end the
    # collector and discard every component it had built.
    (tmp_path / "requirements.txt").write_text(
        "openai ; " + "(" * 600 + "python_version > '3'" + ")" * 600 + "\nanthropic==0.30.0\n"
    )
    (tmp_path / "package.json").write_text('{"dependencies": {"@anthropic-ai/sdk": "0.30.1"}}')
    (tmp_path / "Dockerfile").write_text("FROM ollama/ollama:0.5.7\n")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == ["requirements.txt: invalid or unsupported PyPI requirement"]
    assert sorted(c.bom_ref for c in result.components) == [
        "registry:docker/ollama/ollama:0.5.7",
        "registry:npm/@anthropic-ai/sdk",
        "registry:pypi/anthropic",
        "registry:pypi/openai",
    ]
