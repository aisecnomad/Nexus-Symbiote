"""Adversarial and positive regression tests for retro Bundle E (confinement, secrets, parsers)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from nexus_symbiote.policy import MAX_YAML_FLOW_DEPTH, PolicyError, check_yaml_flow_depth
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.source_binding import whatwg_form
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.files import create_staging_file, write_output_file
from nexus_symbiote.utils.secrets import REDACTED, redact_descriptor, redact_keyed_text, redact_text
from nexus_symbiote.utils.toml import TOMLBoundsError
from nexus_symbiote.utils.toml import loads as toml_loads
from tests.support import scaling_ratio


class _DummyScanner(Scanner):
    name = "dummy"

    def scan(self, project_root: Path) -> ScanResult:
        return ScanResult(scanner_name=self.name)


# --- R-HIGH-03 & Muse RAIL-01: credential_files.py ---


@pytest.mark.parametrize(
    "directory",
    ["secrets", "credentials", ".aws", ".ssh", ".kube", ".docker", ".vault", ".config/gh"],
)
def test_regular_files_under_credential_directories_are_withheld(
    tmp_path: Path, directory: str
) -> None:
    target_dir = tmp_path / directory
    target_dir.mkdir(parents=True)
    (target_dir / "config.yml").write_text("models: []\n", encoding="utf-8")
    (target_dir / "main.co").write_text("define flow f\n  bot say 'x'\n", encoding="utf-8")
    (target_dir / "rag_config.yaml").write_text(
        "sources:\n  - name: s\n    source_uris: ['https://kb.example']\n", encoding="utf-8"
    )

    rag = RAGScanner().scan(tmp_path)
    assert not rag.components
    assert any(f"{directory}/config.yml" in entry for entry in rag.surfaces_excluded)
    assert any(f"{directory}/rag_config.yaml" in entry for entry in rag.surfaces_excluded)


@pytest.mark.parametrize(
    ("target_dir", "target_name"),
    [
        ("aws", "creds.co"),
        (".config", "gh.co"),
        ("ssh", "keys.co"),
        ("kube", "prod.co"),
        ("docker", "auth.co"),
        ("gh", "hosts.co"),
        ("oci", "profile.co"),
        ("sops", "age.co"),
    ],
)
def test_colang_symlinks_into_undotted_and_xdg_stores_are_withheld(
    tmp_path: Path, target_dir: str, target_name: str
) -> None:
    nemo = tmp_path / "nemo"
    nemo.mkdir()
    (nemo / "config.yml").write_text("rails: {}\n", encoding="utf-8")
    (nemo / "safe.co").write_text("define flow safe\n  bot say 'ok'\n", encoding="utf-8")
    store = tmp_path / target_dir
    store.mkdir(parents=True)
    (store / target_name).write_text("define flow s\n  bot say 'secret'\n", encoding="utf-8")
    (nemo / "linked.co").symlink_to(Path("..") / target_dir / target_name)

    result = RAGScanner().scan(tmp_path)
    assert len(result.components) == 1
    assert "linked.co" not in result.components[0].properties["rail_files"]
    assert "safe.co" in result.components[0].properties["rail_files"]
    assert any("nemo/linked.co" in entry for entry in result.surfaces_excluded)


def test_markdown_and_non_store_directories_remain_permitted() -> None:
    assert not credential_shaped("docs/secrets-handling.md")
    assert not credential_shaped("vault-tools/check_secrets.co", colang_source=True)
    assert not credential_shaped("ssh-handlers/config.yml")
    assert not credential_shaped(".config/mcp.json")
    assert not credential_shaped(".config/agent.yaml")
    assert not credential_shaped(".config/opencode/opencode.json")
    assert not credential_shaped(".config/guardrails/config.yml")
    assert credential_shaped(".aws/config.yml")
    assert credential_shaped("secrets/agent.json")
    assert credential_shaped(".config/gh/hosts.yml")
    assert credential_shaped(".config/gcloud/credentials.json")
    assert credential_shaped(".config/sops/age/keys.txt")


def test_a2a_regular_card_under_dot_aws_is_withheld(tmp_path: Path) -> None:
    card_dir = tmp_path / ".aws" / ".well-known"
    card_dir.mkdir(parents=True)
    (card_dir / "agent.json").write_text(
        '{"name": "a", "url": "https://a.example", "skills": []}', encoding="utf-8"
    )
    result = A2AScanner().scan(tmp_path)
    assert not result.components
    assert any(".aws/.well-known/agent.json" in entry for entry in result.surfaces_excluded)


@pytest.mark.parametrize("store_dir", [".secrets", ".credentials", ".config/gh"])
def test_a2a_well_known_under_dotted_or_xdg_store_remains_withheld(
    tmp_path: Path, store_dir: str
) -> None:
    card_dir = tmp_path / store_dir / ".well-known"
    card_dir.mkdir(parents=True)
    (card_dir / "agent-card.json").write_text(
        '{"name": "a", "url": "https://a.example", "skills": []}', encoding="utf-8"
    )
    result = A2AScanner().scan(tmp_path)
    assert not result.components
    assert any(
        f"{store_dir}/.well-known/agent-card.json" in entry for entry in result.surfaces_excluded
    )


def test_a2a_well_known_symlink_into_secrets_remains_withheld(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "creds.json").write_text(
        '{"name": "a", "url": "https://a.example", "skills": []}', encoding="utf-8"
    )
    card_dir = tmp_path / "services" / "credentials" / ".well-known"
    card_dir.mkdir(parents=True)
    (card_dir / "agent-card.json").symlink_to("../../../secrets/creds.json")
    result = A2AScanner().scan(tmp_path)
    assert not result.components
    assert any(
        "services/credentials/.well-known/agent-card.json" in entry
        for entry in result.surfaces_excluded
    )


# --- R-HIGH-04: source_binding.py whatwg_form & rag.py ---


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ht\ttp://evil.example/api", "http://evil.example/api"),
        ("\x01\x1fhttp://evil.example/api\x00", "http://evil.example/api"),
        ("ht\r\ntp:evil.example/api", "http://evil.example/api"),
        ("http:///evil.example/api", "http://evil.example/api"),
        ("http://\\evil.example/api", "http://evil.example/api"),
        ("ws\t://evil.example/stream", "ws://evil.example/stream"),
        ("https://safe.example/v1", "https://safe.example/v1"),
        ("http:", "http:"),
        ("http:   spaced", "http:   spaced"),
        ("data/plain.csv", "data/plain.csv"),
    ],
)
def test_whatwg_form_normalizes_c0_tabs_newlines_and_slashes(raw: str, expected: str) -> None:
    assert whatwg_form(raw) == expected


@pytest.mark.parametrize(
    "obfuscated",
    [
        "ht\ttp://evil.example/api",
        "\x01http://evil.example/api",
        "ht\ttp:evil.example/api",
        "http:///evil.example/api",
    ],
)
def test_rag_detects_cleartext_http_with_whatwg_whitespace_and_c0(
    tmp_path: Path, obfuscated: str
) -> None:
    (tmp_path / "rag_config.json").write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "name": "kb",
                        "type": "vector-store",
                        "source_uris": [obfuscated],
                        "vector_store": {"endpoint": obfuscated},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = RAGScanner().scan(tmp_path)
    assert len(result.components) == 1
    comp = result.components[0]
    assert comp.properties["endpoint_origins"] == ["http://evil.example"]
    high_risks = [
        r for r in comp.risks if r.category == "data_integrity" and r.severity.value == "high"
    ]
    assert len(high_risks) == 2


# --- R-HIGH-19 & policy_exclusions_recorded: confined.py ---


def test_coexisting_case_variants_fail_closed_for_claude_and_prompts(tmp_path: Path) -> None:
    # Skip only if filesystem is genuinely case-insensitive.
    probe = tmp_path / "CaseProbe"
    probe.mkdir()
    if (tmp_path / "caseprobe").exists():
        pytest.skip("needs a case-sensitive file system to hold both spellings")

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text('{"permissions": {}}', encoding="utf-8")
    (tmp_path / ".CLAUDE").mkdir()
    (tmp_path / ".CLAUDE" / "settings.json").write_text(
        '{"permissions": {"allow": ["Bash(*)"]}}', encoding="utf-8"
    )
    (tmp_path / ".claude" / "rules").mkdir()
    (tmp_path / ".claude" / "rules" / "safe.md").write_text("# safe\n", encoding="utf-8")
    (tmp_path / ".CLAUDE" / "rules").mkdir()
    (tmp_path / ".CLAUDE" / "rules" / "evil.md").write_text("# evil\n", encoding="utf-8")

    ide_result = IDEAgentScanner().scan(tmp_path)
    assert any(".CLAUDE/settings.json" in f for f in ide_result.scan_failures)

    prompt_result = PromptScanner().scan(tmp_path)
    assert any(".CLAUDE/rules" in f for f in prompt_result.scan_failures)


def test_coexisting_case_variant_respects_variants_read(tmp_path: Path) -> None:
    probe = tmp_path / "CaseProbe"
    probe.mkdir()
    if (tmp_path / "caseprobe").exists():
        pytest.skip("needs a case-sensitive file system to hold both spellings")

    (tmp_path / "codex.md").write_text("# a\n", encoding="utf-8")
    (tmp_path / "CODEX.md").write_text("# b\n", encoding="utf-8")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert (
            files.read_text("codex.md", missing_ok=True, variants_read={"codex.md", "CODEX.md"})
            == "# a\n"
        )
    assert failures == []


def test_policy_exclusions_recorded_distinguishes_default_from_policy_excludes(
    tmp_path: Path,
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (tmp_path / "blocked").mkdir()
    (tmp_path / "blocked" / "a.txt").write_text("x", encoding="utf-8")
    (tmp_path / "ok.txt").write_text("y", encoding="utf-8")

    failures: list[str] = []
    exclusions: list[str] = []
    with ConfinedCollection(tmp_path, failures, exclusions) as files:
        assert list(files.iter_files()) == [Path("blocked/a.txt"), Path("ok.txt")]
        assert files.exclusions_recorded > 0
        assert files.policy_exclusions_recorded == 0

    exclusions2: list[str] = []
    with ConfinedCollection(tmp_path, failures, exclusions2, exclude_paths=["blocked"]) as files:
        assert list(files.iter_files()) == [Path("ok.txt")]
        assert files.policy_exclusions_recorded >= 1


# --- R-MED-15: per-entry OSError scoping in _walk ---


def test_walk_unreadable_sibling_does_not_abort_remaining_siblings(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory mode 0o000")
    locked = tmp_path / "000_locked"
    locked.mkdir()
    (locked / "hidden.txt").write_text("x", encoding="utf-8")
    readable = tmp_path / "zzz_readable"
    readable.mkdir()
    (readable / "ok.txt").write_text("ok", encoding="utf-8")
    locked.chmod(0o000)
    try:
        failures: list[str] = []
        with ConfinedCollection(tmp_path, failures) as files:
            walked = list(files.iter_files())
        assert Path("zzz_readable/ok.txt") in walked
        assert any("000_locked" in f for f in failures)
        assert not any(f.startswith(".:") for f in failures)
    finally:
        locked.chmod(0o700)


# --- R-HIGH-26, R-MED-18, Muse R-RES-01: utils/secrets.py ---


def test_redact_descriptor_masks_top_level_credential_keys_while_keeping_identifier() -> None:
    raw = {
        "name": "sk-learn-classifier",
        "description": "Classifies text safely",
        "api_key": "plain-secret-value",
        "password": "hunter2",
        "Authorization": "Bearer customsecretvalue",
        "Cookie": 'session="QuotedSecretVal99"; Path=/',
        "secret_MyKnownSecretVal": "nested-plain",
        "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string", "default": "drop-me"}},
        },
    }
    safe = redact_descriptor(raw, secrets=["MyKnownSecretVal"])
    assert safe["name"] == "sk-learn-classifier"
    assert safe["description"] == "Classifies text safely"
    assert safe["api_key"] == REDACTED
    assert safe["password"] == REDACTED
    assert safe["Authorization"] == f"Bearer {REDACTED}"
    assert "QuotedSecretVal99" not in safe["Cookie"]
    assert "Path=/" in safe["Cookie"]
    assert "MyKnownSecretVal" not in str(safe)
    assert "nested-plain" not in str(safe)
    assert "default" not in safe["inputSchema"]["properties"]["q"]


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('Cookie: session="SecretCookieValue123"; other=SecretTwo456', "SecretCookieValue123"),
        ('Cookie: session="SecretCookieValue123"; other=SecretTwo456', "SecretTwo456"),
        ('Cookie: a="1"; session=SecretSession789', "SecretSession789"),
        ('Set-Cookie: sid="QuotedSecretVal99"; Path=/; HttpOnly', "QuotedSecretVal99"),
        (r"{\"Cookie\": \"sid=EscapedCookie99\", \"note\": \"ok\"}", "EscapedCookie99"),
        ("Cookie: sid='SingleQuotedSecret99'; theme=dark", "SingleQuotedSecret99"),
        (r"{\"password\": \"hunter2\"}", "hunter2"),
        (r"{\"password\": \"hunter 2\"}", "hunter"),
        (r"{\"password\": \"hunter 2\"}", "2"),
        (r"{\"password\": \"val \\\"inner\\\" secretend\"}", "secretend"),
        (r"password=\"spaced secret99\"", "secret99"),
        (r'https://h/?api_key=\\"SuperSecretValue99\\"', "SuperSecretValue99"),
        (r'https://h/?api_key=\\"Super Secret 99\\"', "Secret"),
        (r"https://h/?api_key=\\\"Super Secret 99\\\"", "Secret"),
        ('https://h/?api_key="Super Secret 99"', "Secret"),
    ],
)
def test_secrets_redacts_quoted_cookies_escaped_json_and_url_end_backslashes(
    text: str, secret: str
) -> None:
    out = redact_text(text)
    assert secret not in out, f"leaked {secret!r} in {out!r}"


def test_secrets_preserves_benign_cookie_attributes_and_adjacent_json() -> None:
    out = redact_text('{"Cookie": "sid=SecretVal123; Path=/", "label": "theme=light"}')
    assert "SecretVal123" not in out
    assert "Path=/" in out
    assert '"label": "theme=light"' in out

    keyed = redact_keyed_text("Cookie", 'sid="SecretVal99"; theme="light"; Path="/"')
    assert "SecretVal99" not in keyed
    assert 'theme="light"' in keyed
    assert 'Path="/"' in keyed


def test_secrets_cookie_and_escape_scanning_stay_linear_on_adversarial_inputs() -> None:
    assert scaling_ratio(lambda scale: redact_text('Cookie: "' * (500 * scale))) < 10
    assert (
        scaling_ratio(
            lambda scale: redact_text(
                "password=" + "\\" * (500 * scale) + '"' + "a" * (500 * scale)
            )
        )
        < 10
    )


# --- R-MED-14: YAML flow-nesting DoS guard ---


def test_check_yaml_flow_depth_blocks_deep_flow_and_allows_safe_constructs() -> None:
    deep_seq = "[" * (MAX_YAML_FLOW_DEPTH + 1) + "]" * (MAX_YAML_FLOW_DEPTH + 1)
    with pytest.raises(PolicyError):
        check_yaml_flow_depth(deep_seq)

    deep_map = "{" * (MAX_YAML_FLOW_DEPTH + 1)
    with pytest.raises(PolicyError):
        check_yaml_flow_depth(deep_map)

    # Strings, comments, CRLF, and indented block scalars must not trigger false positives.
    safe_yaml = (
        'quoted: "' + "[" * 200 + '\\""\r\n'
        "single: '" + "{" * 200 + "''" + "'\r\n"
        "# " + "[" * 200 + "\n"
        "url: https://example.com/#frag\n"
        "stray: ]\n"
        "block: | # comment\n"
        "  " + "[" * 200 + "\n"
        "\n"
        "  " + "{" * 200 + "\n"
        "after: [1, 2, 3]\n"
        "trailing: [1, # comment inside flow\n2]\n"
        "# trailing eof comment without newline"
    )
    check_yaml_flow_depth(safe_yaml)
    check_yaml_flow_depth('unterminated: "abc')
    check_yaml_flow_depth("unterminated: 'abc")

    # Unindented deep flow immediately after a block scalar header must still be caught.
    escaped_block = "block: |\n" + "[" * (MAX_YAML_FLOW_DEPTH + 1) + "\n"
    with pytest.raises(PolicyError):
        check_yaml_flow_depth(escaped_block)

    # All block-scalar bypass vectors must still fail closed.
    deep = "[" * (MAX_YAML_FLOW_DEPTH + 1) + "]" * (MAX_YAML_FLOW_DEPTH + 1)
    for bypass in (
        f"? foo |\n : {deep}\n",
        f"a: foo |\nb: {deep}\n",
        f"a: |2\n {deep}\n",
        f"  a: |2\n   {deep}\n",
        f"- a: |2\n   {deep}\n",
        f"|2\n {deep}\n",
        f"a: |\n    hi\n {deep}\n",
        f"a: |\n   \n  {deep}\n",
        f"a: |\r{deep}\r",
    ):
        with pytest.raises(PolicyError):
            check_yaml_flow_depth(bypass)

    # Legitimate explicit-indent and property-annotated block scalars remain allowed.
    check_yaml_flow_depth(f"a: |2\n  {deep}\n")
    check_yaml_flow_depth(f"  - a: &x !str |2-\n      {deep}\n")
    check_yaml_flow_depth(f"--- |\n  {deep}\n")


def test_rag_and_base_yaml_parsers_reject_flow_nesting_dos_in_linear_time(tmp_path: Path) -> None:
    dos_payload = "[" * 4000
    (tmp_path / "rag_config.yaml").write_text(dos_payload, encoding="utf-8")
    rag = RAGScanner().scan(tmp_path)
    assert any("rag_config.yaml" in f for f in rag.scan_failures)

    result = ScanResult(scanner_name="dummy")
    parsed = _DummyScanner()._parse_yaml_mapping(Path("x.yaml"), dos_payload, result)
    assert parsed is None
    assert any("x.yaml" in f for f in result.scan_failures)

    def run_depth(scale: int) -> None:
        text = (
            "items: " + "[1, " * (MAX_YAML_FLOW_DEPTH // 2) + "1" + "]" * (MAX_YAML_FLOW_DEPTH // 2)
        )
        check_yaml_flow_depth((text + "\n") * (200 * scale))

    assert scaling_ratio(run_depth) < 10


# --- R-CQ-03: utils/toml.py bracket depth cap ---


def test_toml_loads_rejects_deep_bracket_and_brace_nesting_before_tomllib() -> None:
    from nexus_symbiote.utils.toml import _MAX_BRACKET_DEPTH

    at_limit_array = "a = " + "[" * _MAX_BRACKET_DEPTH + "1" + "]" * _MAX_BRACKET_DEPTH + "\n"
    assert toml_loads(at_limit_array) is not None

    deep_array = "a = " + "[" * (_MAX_BRACKET_DEPTH + 1) + "]" * (_MAX_BRACKET_DEPTH + 1) + "\n"
    with pytest.raises(TOMLBoundsError):
        toml_loads(deep_array)

    deep_table = (
        "a = " + "{x = " * (_MAX_BRACKET_DEPTH + 1) + "1" + "}" * (_MAX_BRACKET_DEPTH + 1) + "\n"
    )
    with pytest.raises(TOMLBoundsError):
        toml_loads(deep_table)

    # Strings and comments holding many brackets stay valid.
    benign = 's = "' + "[" * 200 + '"\n# ' + "{" * 200 + "\n[[items]]\nx = [1, [2, 3]]\n"
    parsed = toml_loads(benign)
    assert parsed["items"] == [{"x": [1, [2, 3]]}]


# --- R-CQ-05: case-insensitive Colang .CO detection ---


def test_rag_reports_uppercase_colang_suffix_as_case_variant_failure(tmp_path: Path) -> None:
    nemo = tmp_path / "nemo"
    nemo.mkdir()
    (nemo / "config.yml").write_text("rails: {}\n", encoding="utf-8")
    (nemo / "MAIN.CO").write_text("define flow main\n  bot say 'hi'\n", encoding="utf-8")

    result = RAGScanner().scan(tmp_path)
    assert not result.components
    assert any("nemo/MAIN.CO" in f and "case variant" in f for f in result.scan_failures)

    (nemo / "safe.co").write_text("define flow safe\n  bot say 'ok'\n", encoding="utf-8")
    result2 = RAGScanner().scan(tmp_path)
    assert len(result2.components) == 1
    assert "safe.co" in result2.components[0].properties["rail_files"]
    assert any("nemo/MAIN.CO" in f for f in result2.scan_failures)


# --- R-LOW-05: utils/files.py 0111 traverse-only ancestor ---


def test_write_output_file_and_staging_work_under_traverse_only_ancestor(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory mode 0o111")
    locked = tmp_path / "traverse_only"
    child = locked / "out"
    child.mkdir(parents=True)
    locked.chmod(0o111)
    try:
        dest = child / "report.json"
        if getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0):
            write_output_file(dest, '{"ok": true}\n')
            assert dest.read_text(encoding="utf-8") == '{"ok": true}\n'

            staged = create_staging_file(dest, ".stage-")
            assert staged.exists()
            staged.unlink()

            dest2 = child / "sub" / "report2.json"
            write_output_file(dest2, '{"nested": true}\n', create_parents=True)
            assert dest2.read_text(encoding="utf-8") == '{"nested": true}\n'

            # Missing directory directly below a 0o311 (write+exec, no read) ancestor.
            locked.chmod(0o311)
            dest3 = locked / "created_child" / "report3.json"
            with pytest.raises(FileNotFoundError):
                write_output_file(dest3, "x", create_parents=False)
            write_output_file(dest3, '{"created": true}\n', create_parents=True)
            assert dest3.read_text(encoding="utf-8") == '{"created": true}\n'

            # Symlink beneath traverse-only ancestor is still refused descriptor-relatively.
            target_dir = tmp_path / "outside"
            target_dir.mkdir()
            link_dir = locked / "link_dir"
            link_dir.symlink_to(target_dir)
            locked.chmod(0o111)
            with pytest.raises(OSError):
                write_output_file(link_dir / "escape.json", "nope")
            with pytest.raises(PermissionError):
                write_output_file(locked / "leaf.json", "denied")

        # Without O_PATH or O_SEARCH, _parent must fail closed rather than drop dir_fd confinement.
        locked.chmod(0o111)
        with (
            mock.patch.object(os, "O_PATH", 0, create=True),
            mock.patch.object(os, "O_SEARCH", 0, create=True),
            pytest.raises(PermissionError),
        ):
            write_output_file(child / "no_opath.json", "nope")
    finally:
        locked.chmod(0o700)


def test_check_yaml_flow_depth_blocks_mid_scalar_quotes_and_unicode_linebreaks() -> None:
    deep = "[" * (MAX_YAML_FLOW_DEPTH + 10)
    for bypass in (
        f"a: don't\nb: {deep}",
        f'a: foo"bar\nb: {deep}',
        f"a: {{x:'y, z: {deep}",
        f"a: {{x\":'y, z: {deep}",
        f"# comment\u2028{deep}",
        f"# comment\x85{deep}",
        f"a: |\n  hi\u2028b: {deep}",
        f"a: |\n  hi\u2029b: {deep}",
        f'a: foo\n  "not a quote\nb: {deep}\nc: "ok"\n',
        f"a: foo\n  'not a quote\nb: {deep}\n",
        f'[foo\n  "not a quote, {deep}]\n',
    ):
        with pytest.raises(PolicyError, match="flow nesting"):
            check_yaml_flow_depth(bypass)

    # Legitimate apostrophes, JSON-like flow keys, BOM quotes, and multi-line quoted keys stay allowed.
    for benign in (
        f"a: don't\nb: '{deep}'\n",
        f"a: {{\"x\":'{deep}'}}\n",
        f'a: {{"x" :"{deep}"}}\n',
        f"a: {{[1]:'{deep}'}}\n",
        f"\ufeff'{deep}'\n",
        f'"{deep}"\n',
        f"['{deep}','{deep}']\n",
        f'"k1\nk2": |\n  {deep}\n',
    ):
        check_yaml_flow_depth(benign)


def test_secrets_redacts_double_json_cookies_auth_and_trailing_backslashes() -> None:
    double_cookie = json.dumps(json.dumps({"Cookie": 'session="SecretCookie123"; Path=/'}))
    redacted_cookie = redact_text(double_cookie)
    assert "SecretCookie123" not in redacted_cookie
    assert "Path=/" in redacted_cookie

    esc_single_cookie = r"Cookie: session=\'SingleEscSecret99\'; Path=/"
    redacted_single = redact_text(esc_single_cookie)
    assert "SingleEscSecret99" not in redacted_single
    assert "Path=/" in redacted_single

    double_pw_bs = json.dumps(json.dumps({"password": "my secret value\\"}))
    assert "secret value" not in redact_text(double_pw_bs)

    raw_esc_pw_bs = r"password=\"my secret value\\\""
    assert "secret value" not in redact_text(raw_esc_pw_bs)

    double_pw_inner_q = json.dumps(json.dumps({"password": 'my "secret" value', "user": "alice"}))
    redacted_inner = redact_text(double_pw_inner_q)
    assert "secret" not in redacted_inner
    assert "alice" in redacted_inner

    double_bearer = json.dumps(json.dumps({"Authorization": "Bearer supersecretval"}))
    assert "supersecretval" not in redact_text(double_bearer)

    double_nego = json.dumps(json.dumps({"Authorization": "Negotiate YIIsecretToken99"}))
    assert "YIIsecretToken99" not in redact_text(double_nego)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("re\tdis://evil.example:6379", "redis://evil.example:6379"),
        ("\x01redis://evil.example:6379", "redis://evil.example:6379"),
        ("ld\tap://evil.example:389", "ldap://evil.example:389"),
        ("git+ht\ttp://evil.example/repo", "git+http://evil.example/repo"),
        ("fi\tle:///etc/passwd", "file:///etc/passwd"),
        ("fi\tle:/etc/passwd", "file:/etc/passwd"),
        ("C:/Windows/System32", "C:/Windows/System32"),
    ],
)
def test_whatwg_form_normalizes_non_special_schemes_too(raw: str, expected: str) -> None:
    assert whatwg_form(raw) == expected


def test_rag_detects_obfuscated_cleartext_redis_url(tmp_path: Path) -> None:
    (tmp_path / "rag_config.json").write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "name": "cache",
                        "type": "vector-store",
                        "vector_store": {"endpoint": "re\tdis://cache.evil.example:6379"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = RAGScanner().scan(tmp_path)
    assert len(result.components) == 1
    comp = result.components[0]
    assert comp.properties["endpoint_origins"] == ["redis://cache.evil.example:6379"]
    assert any(r.category == "data_integrity" for r in comp.risks)


def test_rag_colang_fold_variants_dedup_and_withheld_order(tmp_path: Path) -> None:
    nemo = tmp_path / "nemo"
    nemo.mkdir()
    (nemo / "config.yml").write_text("rails: {}\n", encoding="utf-8")
    (nemo / "config.yaml").write_text("rails: {}\n", encoding="utf-8")
    (nemo / "MAIN.CO").write_text("define flow a\n", encoding="utf-8")
    (nemo / "trailing.co.").write_text("define flow b\n", encoding="utf-8")
    (nemo / "Guardrails.co").write_text("define flow ok\n", encoding="utf-8")

    result = RAGScanner().scan(tmp_path)
    main_failures = [f for f in result.scan_failures if "nemo/MAIN.CO" in f]
    trailing_failures = [f for f in result.scan_failures if "nemo/trailing.co." in f]
    assert len(main_failures) == 1
    assert len(trailing_failures) == 1
    assert any("Guardrails.co" in c.properties.get("rail_files", {}) for c in result.components)

    # Withheld config.yml must not emit spurious sibling rail failures.
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "config.yml").write_text("rails: {}\n", encoding="utf-8")
    (secret_dir / "BAD.CO").write_text("define flow bad\n", encoding="utf-8")
    res_withheld = RAGScanner().scan(tmp_path)
    assert not any("secrets/BAD.CO" in f for f in res_withheld.scan_failures)
    assert any("secrets/config.yml" in e for e in res_withheld.surfaces_excluded)


def test_registry_toml_reports_exact_nesting_depth_bounds_error(tmp_path: Path) -> None:
    from nexus_symbiote.scanners.registry import RegistryScanner
    from nexus_symbiote.utils.toml import _MAX_BRACKET_DEPTH

    deep = "a = " + "[" * (_MAX_BRACKET_DEPTH + 2) + "1" + "]" * (_MAX_BRACKET_DEPTH + 2) + "\n"
    (tmp_path / "pyproject.toml").write_text(deep, encoding="utf-8")
    result = RegistryScanner().scan(tmp_path)
    assert any("TOML nesting exceeds the depth limit" in f for f in result.scan_failures)
    assert not any("dotted key exceeds" in f for f in result.scan_failures)
