"""Human-readable output prints inventory text literally: no markup, no terminal controls."""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import click
import pytest
from click.testing import CliRunner, Result
from hypothesis import given, settings
from hypothesis import strategies as st

from nexus_symbiote.cli import _RootGroup, main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import (
    MAX_REFERENCE_CHARS,
    CompletenessClaim,
    MCPServerComponent,
    PromptComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.scanners import live_mcp
from nexus_symbiote.utils.terminal import json_text, neutralize, safe_line
from tests.support import scaling_ratio
from tests.test_live_mcp import (
    ENDPOINT,
    ORIGIN,
    FixtureTransport,
    notification_accepted,
    rpc_result,
    tool,
)
from tests.test_verify_live_scope import launcher

pytestmark = pytest.mark.usefixtures("nonisolated_pinned_fixtures")


MARKUP = "[link=https://attacker.example/approve]docs[/link][conceal]"
CONTROLS = "\x1b]8;;https://attacker.example\x07x\x1b]8;;\x07\x1b[1A\x1b[2K\rfake\u202egpj.exe"


def test_hostile_component_names_cannot_hide_a_critical_alert(tmp_path):
    server = MCPServerComponent(
        bom_ref="mcp:pay", name="payments", endpoint_url="https://trusted.example"
    )
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(AIBOM(components=[server]).to_json())
    new.write_text(
        AIBOM(
            components=[
                server.model_copy(update={"endpoint_url": "https://attacker.example"}),
                PromptComponent(bom_ref="prompt:1", name=MARKUP),
                PromptComponent(bom_ref="prompt:2", name=CONTROLS),
            ]
        ).to_json()
    )
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    output = result.output
    assert "[CRITICAL] Critical change in 'payments'" in output
    assert MARKUP in output
    for character in ("\x1b", "\x07", "\r", "\u202e"):
        assert character not in output


def test_validate_shows_the_component_each_issue_belongs_to(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"tickets": {"type": "http", "url": "https://mcp.example.com/mcp"}}}
        )
    )
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    assert (
        runner.invoke(main, ["scan", str(project), "--report-only", "-o", str(bom)]).exit_code == 0
    )
    result = runner.invoke(
        main, ["validate", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert "[mcp-server:" in result.output, result.output


def test_validate_prints_dangling_graph_references_literally(tmp_path):
    hostile = "tool:" + MARKUP + CONTROLS
    server = MCPServerComponent(bom_ref="mcp:docs", name="docs", tool_refs=[hostile])
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM(components=[server]).to_json())
    result = CliRunner().invoke(main, ["validate", str(bom), "--no-project-policy"])
    assert "ERROR:" in result.output, result.output
    assert MARKUP in result.output
    for character in ("\x1b", "\x07", "\r", "\u202e"):
        assert character not in result.output


def test_risk_project_failure_reasons_print_without_terminal_controls(tmp_path):
    # File names are project data; reconciliation reasons quote the component ref.
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    hostile = "evil\x1b[1A\x1b[2K\rfake\u202egpj"
    sample = Path(__file__).parents[1] / "examples/demo-agent/models/intent-classifier.safetensors"
    (project / "models" / f"{hostile}.safetensors").write_bytes(sample.read_bytes())
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM(components=[]).to_json())
    result = CliRunner().invoke(
        main, ["risk", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert result.exit_code == 1, result.output
    assert "Project reconciliation failed." in result.output
    assert "evil" in result.output and "fake" in result.output
    for character in ("\x1b", "\r", "\u202e"):
        assert character not in result.output


WORKFLOW_COMMAND = "x\n::error title=Spoofed::All checks passed\n::add-mask::CRITICAL\u2028y"


# A runner acts on "::" at the start of a line and on "##name[" anywhere in one.
LOG_COMMAND = re.compile(r"##[A-Za-z]*\[")


def _injected_lines(output: str) -> list[str]:
    return [
        line
        for line in output.splitlines()
        if line.lstrip().startswith("::") or LOG_COMMAND.search(line)
    ]


def test_line_breaks_in_inventory_text_cannot_forge_output_lines(tmp_path):
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(AIBOM().to_json())
    new.write_text(
        AIBOM(components=[PromptComponent(bom_ref="prompt:1", name=WORKFLOW_COMMAND)]).to_json()
    )
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    assert not _injected_lines(result.output)
    assert (
        "x\ufffd::error title=Spoofed::All checks passed\ufffd::add-mask::CRITICAL\ufffdy"
        in result.output
    )


def test_validate_prints_hostile_collection_paths_on_one_line(tmp_path):
    bom = AIBOM(components=[PromptComponent(bom_ref="prompt:1", name="CLAUDE.md")])
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        surfaces_scanned=["."],
        scan_failures=[WORKFLOW_COMMAND + ".pkl: nonregular file excluded"],
    )
    path = tmp_path / "bom.json"
    path.write_text(bom.to_json())
    result = CliRunner().invoke(main, ["validate", str(path), "--no-project-policy"])
    assert result.exit_code == 1
    assert "::error title=Spoofed" in result.output
    assert not _injected_lines(result.output)


def test_supplied_failure_text_cannot_start_a_line_when_reconciliation_fails(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="repository", scan_failures=["::error title=forged::supplied text"]
    )
    path = tmp_path / "forged.json"
    path.write_text(bom.to_json())
    result = CliRunner().invoke(
        main, ["risk", str(path), "--project", str(project), "--no-project-policy"]
    )
    assert result.exit_code == 1
    # The reconciliation report is a result, so it is printed on standard output.
    assert "::error title=forged::supplied text" in result.stdout
    assert not _injected_lines(result.output)


def test_invalid_policy_keys_cannot_forge_output_lines(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    inventory = tmp_path / "bom.json"
    runner = CliRunner()
    scanned = runner.invoke(
        main, ["scan", str(project), "-o", str(inventory), "--no-project-policy"]
    )
    assert scanned.exit_code == 0, scanned.output
    (project / ".nexus-symbiote.yaml").write_text(
        'risk:\n  "x\\e[2K\\r\\n::error title=Policy::forged by checkout\\n": 1\n'
    )
    for args in (
        ["scan", str(project), "--accept-project-policy", "-o", str(tmp_path / "again.json")],
        ["validate", str(inventory), "--project", str(project), "--accept-project-policy"],
        [
            "risk",
            str(inventory),
            "--project",
            str(project),
            "--accept-project-policy",
            "--json-output",
        ],
    ):
        result = runner.invoke(main, args)
        assert result.exit_code == 1, args
        assert "invalid policy" in result.stderr and "\ufffd" in result.stderr
        assert not _injected_lines(result.output)
        assert "\x1b" not in result.output and "\r" not in result.output


def _kind() -> click.Option:
    return click.Option(["--kind"], type=click.Choice(["snapshot", "model"]), required=True)


@pytest.mark.parametrize(
    "error",
    [
        lambda: click.MissingParameter("x\n::warning::forged", param=_kind()),
        lambda: click.MissingParameter(param=_kind(), param_hint="x\n::warning::forged"),
        lambda: click.MissingParameter(param=_kind(), param_type="x\n::warning::forged"),
        lambda: click.BadParameter("x\n::warning::forged ##[error]y", param=_kind()),
    ],
    ids=["message", "hint", "type-name", "bad-parameter"],
)
def test_click_errors_worded_by_code_or_input_stay_one_neutralized_line(error):
    # Only Click's own missing-parameter text keeps its line breaks; any error that
    # carries a message, hint or type name, which code may build from input, does not.
    group = _RootGroup()

    @group.command()
    def hostile() -> None:
        raise error()

    result = CliRunner().invoke(group, ["hostile"])
    assert result.exit_code == 2
    assert "forged" in result.output
    assert not _injected_lines(result.output)


def test_every_format_control_and_line_break_character_is_neutralized():
    # Every such character in this Python's Unicode database, not a sample: a later
    # Unicode version that adds one makes this fail until UNSAFE_TEXT covers it. A tab
    # becomes one space, which keeps a file name readable; every other one is replaced.
    characters = "".join(
        chr(code)
        for code in range(0x110000)
        if unicodedata.category(chr(code)) in {"Cf", "Cc", "Zl", "Zp"}
    )
    assert "\t" in characters
    assert neutralize(characters) == "".join(
        " " if character == "\t" else "\ufffd" for character in characters
    )


def test_a_tab_cannot_line_text_up_under_a_column_and_noncharacters_are_replaced():
    assert neutralize("ok\t\t\tGate: PASSED") == "ok   Gate: PASSED"
    assert "\t" not in safe_line("  - ", "a\tb")
    assert neutralize("a\ufffeb\uffffc") == "a\ufffdb\ufffdc"


@pytest.mark.parametrize(
    "text",
    [
        "##[set-output name=sarif_path]/etc/hostname",
        "x ##[error title=Nexus SymBiote]All gates passed",
        "##vso[task.setvariable variable=x]y",
        "##teamcity[buildStatus text='ok']",
        "###[add-mask]secret",
        "##\u200b[warning]x",
    ],
)
def test_ci_log_command_introducers_are_broken_anywhere_in_a_line(text):
    shown = neutralize(text)
    assert not LOG_COMMAND.search(shown)
    assert shown.replace("\ufffd", "") == text.replace("\u200b", "")


@given(st.lists(st.text(alphabet="#[]:abvsoxetcmity \n\r\u2028\x1b", max_size=12), max_size=6))
@settings(max_examples=300, deadline=None)
def test_fragments_cannot_assemble_a_command_or_start_a_line(parts):
    line = safe_line("  - ", *parts)
    assert not LOG_COMMAND.search(line)
    assert "\n" not in line and "\r" not in line and not line.lstrip().startswith("::")
    assert line.startswith("  - ")


def test_an_output_line_needs_a_visible_fixed_prefix():
    with pytest.raises(ValueError):
        safe_line("  ", "::error::forged")


def test_json_on_standard_output_parses_to_the_same_value_without_a_command():
    value = {"name": "x ##[set-output name=aibom_path]/etc/passwd ###vso[y] \\##[z"}
    text = json_text(json.dumps(value, indent=2))
    assert not LOG_COMMAND.search(text)
    assert json.loads(text) == value


def _bom_with_names(path: Path, *names: str, reference_chars: int = MAX_REFERENCE_CHARS) -> Path:
    # A reference is capped at MAX_REFERENCE_CHARS; a name is not, so a long name keeps
    # its length and, by default, its reference is the longest one allowed.
    path.write_text(
        AIBOM(
            components=[
                ToolComponent(bom_ref=f"tool:{name}"[:reference_chars], name=name) for name in names
            ]
        ).to_json()
    )
    return path


LEGACY = "x ##[set-output name=sarif_path]/home/runner/work/_temp/**/*%0A"


def test_legacy_workflow_commands_in_inventory_text_reach_no_output_line(tmp_path):
    bom = _bom_with_names(tmp_path / "bom.json", LEGACY, "##", "#[error]split", "::notice::x")
    old = tmp_path / "old.json"
    old.write_text(AIBOM().to_json())
    runner = CliRunner()
    commands = [
        ["validate", str(bom), "--no-project-policy"],
        ["validate", str(bom), "--no-project-policy", "--json-output"],
        ["risk", str(bom), "--no-project-policy"],
        ["risk", str(bom), "--no-project-policy", "--json-output"],
        ["diff", str(old), str(bom)],
        ["diff", str(old), str(bom), "--json-output"],
        ["summary", str(bom), "--json-output"],
        ["vex", str(bom)],
    ]
    for args in commands:
        result = runner.invoke(main, args)
        assert result.exception is None or isinstance(result.exception, SystemExit), args
        assert not _injected_lines(result.output), (args, _injected_lines(result.output))
    shown = runner.invoke(main, ["diff", str(old), str(bom)]).output
    assert "x ##\ufffd[set-output name=sarif_path]/home/runner/work/_temp/**/*%0A" in shown


def test_live_commands_print_server_and_inventory_text_without_a_log_command(monkeypatch, tmp_path):
    # The live commands print what a server or an inventory supplied under the same
    # rules: their JSON parses to the same value, and no line carries a log command.
    real_discover = live_mcp.discover_tools
    hostile_tool = tool(LEGACY, description=LEGACY)
    hello = {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": LEGACY, "version": "1"},
    }

    def served(endpoint, **kwargs):
        replies = [
            rpc_result(1, hello),
            notification_accepted(),
            rpc_result(2, {"tools": [hostile_tool]}),
        ]
        return real_discover(endpoint, transport=FixtureTransport(replies), **kwargs)

    monkeypatch.setattr("nexus_symbiote.live_cli.discover_tools", served)
    project, operator = tmp_path / "checkout", tmp_path / "operator"
    project.mkdir()
    operator.mkdir()
    bom, pinned_bom = project / "bom.json", project / "pinned.json"
    AIBOM(
        components=[
            MCPServerComponent(bom_ref=f"mcp:{LEGACY}", name=LEGACY, transport="stdio"),
            MCPServerComponent(
                bom_ref=f"mcp:remote {LEGACY}",
                name=LEGACY,
                transport="streamable-http",
                endpoint_url="https://mcp.example.com",
            ),
            RegistryEntryComponent(bom_ref=f"registry:{LEGACY}", name="x", registry_type="cargo"),
        ]
    ).save(bom)
    AIBOM(
        components=[MCPServerComponent(bom_ref="mcp:weather", name="weather", transport="stdio")]
    ).save(pinned_bom)
    policy, pinned = operator / "launch-policy.json", operator / "pinned-policy.json"
    policy.write_text("{}")
    pinned.write_text(json.dumps(launcher(operator, tools=[hostile_tool])))
    discover = ["--live", "discover-mcp", ENDPOINT, "--allowed-origin", ORIGIN]
    verify = ["--live", "verify-live", str(bom), "--project", str(project)]
    record = ["--live", "verify-live", str(pinned_bom), "--project", str(project), "--record"]
    shown = LEGACY.replace("##", "##\ufffd")
    runner = CliRunner()
    for args, document, line in (
        (discover, True, None),
        ([*discover, "--record"], True, None),
        ([*verify, "--launch-policy", str(policy)], False, f"Server mcp:{shown}: missing"),
        ([*verify, "--launch-policy", str(policy), "--json-output"], True, None),
        ([*record, "--launch-policy", str(pinned)], True, f"mcp:weather: new tool {shown}"),
        (["advisories", str(bom), "--dry-run"], True, None),
    ):
        result = runner.invoke(main, args)
        assert result.exception is None or isinstance(result.exception, SystemExit), args
        assert not _injected_lines(result.output), (args, _injected_lines(result.output))
        if document:
            assert LEGACY in json.dumps(json.loads(result.stdout)), args
        assert line is None or line in result.stderr, (args, result.stderr)


def test_risk_reconciliation_reasons_never_start_a_line(tmp_path):
    # A supplied BOM's scan_failures become reasons verbatim; they used to be printed
    # as whole lines, so "::error ..." became a workflow command.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    bom = AIBOM(components=[PromptComponent(bom_ref="prompt:1", name="AGENTS.md")])
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        surfaces_scanned=["."],
        scan_failures=["::error title=x::y", "##[add-mask]CRITICAL"],
    )
    path = tmp_path / "bom.json"
    path.write_text(bom.to_json())
    result = CliRunner().invoke(
        main, ["risk", str(path), "--project", str(project), "--no-project-policy"]
    )
    assert result.exit_code == 1
    assert "  - ::error title=x::y" in result.output.splitlines()
    assert not _injected_lines(result.output)


def test_a_symlink_named_as_a_command_never_starts_a_line(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "::notice::x").symlink_to(project / "AGENTS.md")
    (project / "##[warning]y").symlink_to(project / "AGENTS.md")
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    scanned = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert scanned.exit_code == 1 and "::notice::x: symlink target is absolute" in scanned.output
    reconciled = runner.invoke(
        main, ["risk", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert reconciled.exit_code == 1
    for result in (scanned, reconciled):
        assert not _injected_lines(result.output)


STAGED = "Unsigned baseline staged for review: "


@pytest.mark.parametrize(
    "directory,output",
    [
        ("##[set-output name=approved]true", None),
        ("x\n::error title=Forged::All gates passed\n::add-mask::CRITICAL", None),
        ("esc\x1b]0;pwned-title\x07\x1b[2K\rFORGED", None),
        ("agent", "##[warning]dir/base.json"),
        ("agent", "##vso[task.setvariable variable=APPROVED]true/base.json"),
        ("agent", "##teamcity[buildStatus status='SUCCESS' text='forged']/base.json"),
        ("agent", "x\n::error title=Forged::All gates passed/base.json"),
    ],
)
def test_baseline_prints_its_output_path_on_one_inert_line(
    tmp_path, monkeypatch, directory, output
):
    # Workflows that loop over agent directories derive both the working directory and
    # the -o name from checkout names.
    project = tmp_path / directory
    project.mkdir()
    (project / "CLAUDE.md").write_text("Use the configured tools.\n")
    (project / "agent.yaml").write_text("name: Demo\ninstructions: [CLAUDE.md]\n")
    monkeypatch.chdir(project)
    args = ["baseline", ".", "--no-project-policy"]
    if output is not None:
        (project / output).parent.mkdir()
        args += ["-o", output]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    target = project / (output or ".nexus-symbiote-baseline.json")
    assert target.is_file()
    assert result.stdout.splitlines() == [safe_line(STAGED, target)]
    assert not _injected_lines(result.output)
    for character in ("\x1b", "\x07", "\r"):
        assert character not in result.output


def test_an_ordinary_baseline_path_is_printed_unchanged(tmp_path, monkeypatch):
    project = tmp_path / "agents" / "billing"
    project.mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Use the configured tools.\n")
    (project / "agent.yaml").write_text("name: Demo\ninstructions: [CLAUDE.md]\n")
    monkeypatch.chdir(project)
    result = CliRunner().invoke(main, ["baseline", ".", "--no-project-policy"])
    assert result.exit_code == 0, result.output
    assert result.stdout == f"{STAGED}{project / '.nexus-symbiote-baseline.json'}\n"


def test_a_long_scan_root_is_printed_on_one_line(tmp_path):
    # Rich used to wrap the path at 80 columns, so text at that column started a line.
    project = tmp_path / ("p" * (78 - len(str(tmp_path)) % 80)) / "::notice::wrapped"
    project.mkdir(parents=True)
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    assert f"Scanning {project}" in result.output.splitlines()
    assert not _injected_lines(result.output)


@pytest.mark.parametrize("ref", ["tool:x[conceal", "tool:x[/", "tool:x[bold red", "tool:\\[x]"])
def test_markup_and_emoji_codes_are_printed_literally(tmp_path, ref):
    bom = tmp_path / "bom.json"
    bom.write_text(
        AIBOM(
            components=[ToolComponent(bom_ref=ref, name="mcp-source:a.ts:x:100:7 :warning:")]
        ).to_json()
    )
    result = CliRunner().invoke(main, ["validate", str(bom), "--no-project-policy"])
    assert result.exit_code == 1 and result.exception.__class__ is SystemExit
    assert f"WARNING [{ref}] Component 'mcp-source:a.ts:x:100:7 :warning:'" in result.output


# Each name a quarter of the length this test always used, times ``scale``.
_LONG_NAMES = {
    "quote-and-digits": lambda scale: "'" + "1" * (50_000 * scale),
    "letters": lambda scale: "a" * (50_000 * scale),
    "backslashes": lambda scale: "\\" * (50_000 * scale),
    "inner-spaces": lambda scale: "x" + " " * (50_000 * scale) + "y",
    "angle-brackets": lambda scale: "<" * (50_000 * scale),
}


@pytest.mark.parametrize("shape", sorted(_LONG_NAMES))
def test_long_inventory_names_print_in_linear_time(tmp_path, shape):
    # Rich's markup, highlighter and wrapping regexes took hours on such names.
    names = {scale: _LONG_NAMES[shape](scale) for scale in (1, 4)}
    # validate prints each name beside its reference, so the reference grows with the
    # scale too, to the longest one allowed: otherwise the text printed grows less.
    boms = {
        scale: _bom_with_names(
            tmp_path / f"bom-{scale}.json",
            names[scale],
            reference_chars=MAX_REFERENCE_CHARS // 4 * scale,
        )
        for scale in names
    }
    old = tmp_path / "old.json"
    old.write_text(AIBOM().to_json())
    runner = CliRunner()

    def validate(scale: int) -> Result:
        return runner.invoke(main, ["validate", str(boms[scale]), "--no-project-policy"])

    def diff(scale: int) -> Result:
        return runner.invoke(main, ["diff", str(old), str(boms[scale])])

    for command in (validate, diff):
        assert scaling_ratio(command) < 10, command.__name__
        assert names[4] in command(4).output


def test_a_tab_is_replaced_with_a_space_in_neutralized_text():
    from nexus_symbiote.utils.terminal import neutralize

    assert neutralize("name\tvalue") == "name value"
