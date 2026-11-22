"""Free-text redaction must cover credential names, schemes and token formats."""

from __future__ import annotations

import time

import pytest

from nexus_symbiote.utils.secrets import (
    REDACTED,
    SecretScrubber,
    holds_token_shape,
    redact_descriptor,
    redact_metadata,
    redact_text,
    secret_like,
)
from tests.support import scaling_ratio

SECRET = "s3cr3tValue9"  # noqa: S105 - synthetic fixture


@pytest.mark.parametrize(
    "name",
    [
        "token",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "x-api-key",
        "client_secret",
        "AWS_SECRET_ACCESS_KEY",
        "SECRET_KEY",
        "private_key",
        "DB_PASSWORD",
        "mytoken",
        "ENCRYPTION_KEY",
        "MASTER_KEY",
        "signing-key",
        "session_key",
    ],
)
@pytest.mark.parametrize("operator", ["=", ": "])
def test_credential_assignment_value_is_redacted(name, operator):
    text = f"--env {name}{operator}{SECRET} --other"
    redacted = redact_text(text)
    assert SECRET not in redacted
    assert f"{name}{operator}{REDACTED}" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "max_tokens=4096",
        "tokenizer=bert",
        "keyword=value",
        "monkey=banana",
        "mode=fast",
        "turkey=dinner",
        "key=C major",
    ],
)
def test_unrelated_assignments_are_unchanged(text):
    assert redact_text(text) == text


def test_long_adversarial_input_stays_fast():
    text = "token " * 100_000 + "a" * 1_000_000
    started = time.monotonic()
    redact_text(text)
    assert time.monotonic() - started < 5


# Spelled in parts so the source never holds a token-shaped literal, which secret scanners
# rightly refuse; the value is the public example token from Discord's documentation.
DISCORD_SHAPED_TOKEN = ".".join(
    ("MTk4NjIyNDgzNDcxOTI1MjQ4", "Cl2FMQ", "ZnCjm1XVW7vRze4b7Cq4se7kKWs")
)


@pytest.mark.parametrize(
    "text,kept",
    [
        ("Authorization: Bearer abc.DEF-123", "Authorization: Bearer"),
        ("authorization: bearer eyJhbGciOi.payload_x", "authorization: bearer"),
        ("basic dXNlcjpwYXNz", "basic"),
        ("Basic dXNlcjpwYXNzd29yZA==", "Basic"),
        ("Authorization: token ghp_0123456789abcdefABCDEF0123456789abcd", "Authorization: token"),
        (f"Bot {DISCORD_SHAPED_TOKEN}", "Bot"),
    ],
)
def test_authorization_scheme_credentials_are_redacted(text, kept):
    credential = text.split()[-1]
    redacted = redact_text(text)
    assert credential not in redacted
    assert redacted == f"{kept} {REDACTED}"


@pytest.mark.parametrize(
    "text,kept",
    [
        ("Authorization: Basic 00000000000A", "Authorization: Basic"),
        ('{"Authorization": "Basic abcdefgh', '{"Authorization": "Basic'),
        ("-H 'Proxy-Authorization: bearer abcdefgh", "-H 'Proxy-Authorization: bearer"),
        ("authorization=Token abcdefgh", "authorization=Token"),
        ("Authorization: Negotiate YIIGhgYGKwYBBQUCoIIGejCCBnag", "Authorization: Negotiate"),
        ("-H 'Proxy-Authorization: NTLM TlRMTVNTUAABAAAAB4IIog==", "-H 'Proxy-Authorization: NTLM"),
        ('{"Authorization": "negotiate abcdefgh', '{"Authorization": "negotiate'),
    ],
)
def test_any_scheme_value_after_an_authorization_header_is_redacted(text, kept):
    # A header value is a credential whatever its shape; the shape checks are for prose.
    credential = text.split()[-1]
    redacted = redact_text(text)
    assert credential not in redacted
    assert redacted == f"{kept} {REDACTED}"


@pytest.mark.parametrize(
    "text",
    [
        "Provides basic arithmetic",
        "Basic Auth is supported",
        "Uses a Bearer token for auth",
        "Bearer authentication",
        "a token for the session",
        "We negotiate content-type with the server",
        "Authorization: Negotiate",
    ],
)
def test_authorization_scheme_words_in_prose_survive(text):
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "name",
    [
        "DB_PASSWORD_PROD",
        "SECRET_KEY_BASE",
        "API_KEY_OPENAI",
        "AWS_ACCESS_KEY_ID",
        "token2",
        "AccountKey",
        "Pwd",
        "client_credentials",
        "x_sig",
        '"password"',
    ],
)
def test_credential_names_with_suffixes_and_quotes_are_redacted(name):
    text = f"{name}={SECRET} rest" if not name.startswith('"') else f'{name}: "{SECRET}" rest'
    redacted = redact_text(text)
    assert SECRET not in redacted and redacted.endswith(" rest")


def test_quoted_value_is_redacted_whole():
    assert redact_text('password="two words" next') == f"password={REDACTED} next"


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"password": "Pa\\"ss-secret-tail"} next', f'{{"password": {REDACTED}}} next'),
        ("password='it\\'s-a-secret-tail' next", f"password={REDACTED} next"),
        ('password="ends in a backslash\\\\" next', f"password={REDACTED} next"),
    ],
)
def test_an_escaped_quote_does_not_end_a_quoted_value(text, expected):
    assert redact_text(text) == expected


@pytest.mark.parametrize(
    "token",
    [
        "ghp_" + "a1" * 18,
        "github_pat_" + "B2" * 20,
        "glpat-" + "c3" * 10,
        "xoxb-" + "1234567890-abcdef",
        "sk-proj-" + "d4" * 12,
        "sk_live_" + "e5" * 10,
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "AIza" + "f6" * 17 + "g",
        "npm_" + "h7" * 18,
        "SG." + "i8" * 11 + "." + "j9" * 14,
        "dckr_pat_" + "k0" * 12,
        "shpat_" + "abcd1234" * 4,
        "SK" + "0123456789abcdef" * 2,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
    ],
)
def test_known_token_formats_in_free_text_are_redacted(token):
    redacted = redact_text(f"example call with {token} inside")
    assert token not in redacted and redacted == f"example call with {REDACTED} inside"


def test_private_key_blocks_are_redacted_and_certificates_kept():
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----"
    assert redact_text(f"key: {key} done") == f"key: {REDACTED} done"
    assert redact_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE truncated") == REDACTED
    certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    assert redact_text(certificate) == certificate


def test_a_private_key_whose_begin_closes_another_label_is_redacted():
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----"
    prose = "Keys start with -----BEGIN, for example: "
    assert redact_text(prose + key) == prose + REDACTED
    assert redact_text("-----BEGIN-----BEGIN-----" + key) == "-----BEGIN-----BEGIN-----" + REDACTED


def test_a_url_whose_authority_holds_a_backslash_is_withheld():
    # Browsers read the host as attacker.example; urlsplit reads docs.trusted.example.
    text = "Send the file to https://attacker.example\\@docs.trusted.example/upload"
    assert redact_text(text) == "Send the file to [redacted-url]"


def test_identifiers_keep_names_that_resemble_token_formats():
    name = "sk-learn-classifier-tool-v2"
    assert redact_text(name, identifier=True) == name
    descriptor = redact_descriptor({"name": name, "description": f"Runs {name}"})
    assert descriptor["name"] == name and descriptor["description"] == f"Runs {REDACTED}"


# Assembled at run time so the source holds no token-shaped literal.
AWS_ID = "".join(("AK", "IA", "IOSFODNN7EXAMPLE"))
GITLAB = "".join(("gl", "pat-", "Xy9fakeFAKEfake12345"))
GITHUB = "".join(("gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"))


@pytest.mark.parametrize(
    "name,kept",
    [
        (f"AWS_{AWS_ID}", "AWS_"),
        (f"UV_{AWS_ID}", "UV_"),
        (f"X_{GITLAB}", "X_"),
        (f"x-{GITHUB}", "x-"),
        (f"{AWS_ID}_PROD", None),
    ],
)
@pytest.mark.parametrize("identifier", [False, True])
def test_a_token_inside_a_name_is_redacted(name, kept, identifier):
    redacted = redact_text(name, identifier=identifier)
    assert AWS_ID not in redacted and GITLAB not in redacted and GITHUB not in redacted
    assert REDACTED in redacted and redacted.startswith(kept or "")


@pytest.mark.parametrize("token", [GITHUB, GITLAB, AWS_ID])
def test_an_identifier_that_is_a_token_is_redacted(token):
    assert redact_text(token, identifier=True) == REDACTED
    assert redact_descriptor({"name": token})["name"] == REDACTED


@pytest.mark.parametrize(
    "name",
    [
        "GITHUB_TOKEN",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "OPENAI_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITLAB_PAT",
        "SLACK_BOT_TOKEN",
        "NPM_TOKEN",
        "PYPI_API_TOKEN",
        "REGION_ASIAPACIFICSOUTHEAST1",
        "X_ASIA_REGION",
        "run_sk-learn-classifier-model",
        "my-sk-learn-classifier-tool-v2",
        "npm_config_registry",
        "github_pat_rotation_policy",
        "glpat-rotation",
        "ya29-client",
        "xoxb-bot",
    ],
)
@pytest.mark.parametrize("identifier", [False, True])
def test_ordinary_names_near_token_formats_are_kept(name, identifier):
    assert redact_text(name, identifier=identifier) == name


@pytest.mark.parametrize(
    "unit", ["_eyJ", "_eyJaaaaaaaaa.", "_glpat-a.", "_AKIA", "_ghp_a", "_github_pat_", "-xoxb-a."]
)
def test_tokens_inside_names_are_found_in_linear_time(unit):
    def run(scale: int) -> None:
        text = unit * (250_000 // len(unit) * scale)
        redact_text(text)
        redact_text(text, identifier=True)

    assert scaling_ratio(run) < 10


@pytest.mark.parametrize("unit", ["sk-", "eyJ", "eyJaaaaaaaaa", "x-sk-eyJ1."])
def test_a_glued_token_shape_is_looked_for_in_linear_time(unit):
    # Each start of a JWT or sk- form read to the end of the run; retried at every start
    # of "sk-" * n that was quadratic.
    def run(scale: int) -> None:
        assert not holds_token_shape(unit * (12_000 // len(unit) * scale))

    assert scaling_ratio(run) < 10


@pytest.mark.parametrize(
    "text",
    [
        "prod-sk-ant-" + "a" * 20,
        "x-eyJabcdefgh.ijklmnopq",
        "sk-sk-a1a1a1a1a1a1a1a1a1",
        "eyJeyJabcdefgh.ijklmnopq",
        "1AKIA" + "A" * 16,
    ],
)
def test_a_token_shape_glued_to_other_text_is_still_found(text):
    assert holds_token_shape(text)


@pytest.mark.parametrize(
    "name,value,expected",
    [
        ("DEBUG", "1", False),
        ("LANG", "en", False),
        ("PORT", "8443", False),
        ("NODE_ENV", "production", False),
        ("MCP_HOST", "mcp.vendor.example", False),
        ("AUTH_ISSUER", "https://auth.example.test", False),
        ("API_TOKEN", "short", False),
        ("API_TOKEN", "mcp.vendor.example", True),
        ("GITHUB_PAT", "0123456789", True),
        ("UNRELATED", "ghp_" + "a" * 36, True),
        ("DATABASE_URL", "postgres://user:pw@db.example/app", True),
    ],
)
def test_secret_like_values_need_a_credential_name_or_shape(name, value, expected):
    assert secret_like(name, value) is expected


def test_scrubber_replaces_longest_values_first_and_skips_short_texts():
    scrubber = SecretScrubber(["abcdefgh", "abcdefgh-ijkl", ""])
    assert scrubber.scrub("x abcdefgh-ijkl y abcdefgh") == f"x {REDACTED} y {REDACTED}"
    assert scrubber.contains("..abcdefgh..") and not scrubber.contains("abc")
    assert scrubber.scrub("short") == "short"
    assert not SecretScrubber() and SecretScrubber().scrub("anything") == "anything"


@pytest.mark.parametrize(
    ("head", "unit", "count"),
    [
        ("", "eyJ", 400_000),
        ("", "-----BEGIN", 200_000),
        ("", "Bearer ", 300_000),
        ("", "password=", 300_000),
        ("DB_PASSWORD", "_X", 400_000),
        ("", "ghp_", 300_000),
    ],
)
def test_new_patterns_stay_linear_on_adversarial_input(head, unit, count):
    # The largest text is the size this test always used. A ratio, unlike a fixed
    # number of seconds, holds on a slow runner and under coverage tracing: linear work
    # grows about 8 times from one eighth of it, quadratic work about 64 times.
    step = count // 8
    assert scaling_ratio(lambda scale: redact_text(head + unit * (step * scale)), factor=8) < 16


def test_prepared_scrubber_is_linear_in_values_and_strings():
    scrubber = SecretScrubber(f"credential-{i:05d}" for i in range(256))
    metadata = {"examples": [f"value {i} credential-00007" for i in range(20_000)]}
    redacted = redact_metadata(metadata, scrubber)
    assert "credential-00007" not in str(redacted)

    def run(scale: int) -> object:
        examples = [f"value {i} credential-00007" for i in range(2_000 * scale)]
        return redact_metadata({"examples": examples}, scrubber)

    # CONTRIBUTING: show linear work with a ratio, not a duration the runner sets.
    assert scaling_ratio(run) < 10


@pytest.mark.parametrize(
    "text,kept",
    [
        ("Authorization: Bearer abcdefghijklmnopqrstuv", "Authorization: Bearer"),
        ("Token ABCDEFGHIJKLMNOPQRST", "Token"),
        ("ApiKey qwertyuiopasdfghjk", "ApiKey"),
        ("Bearer abc123", "Bearer"),
        ("Bot aBcDeFgH", "Bot"),
    ],
)
def test_long_or_shaped_scheme_values_are_redacted_whatever_their_letters(text, kept):
    assert redact_text(text) == f"{kept} {REDACTED}"


@pytest.mark.parametrize(
    "text", ["Send a Bearer Tokens header", "Token Validation failed", "Bearer scheme"]
)
def test_capitalised_prose_after_a_scheme_word_survives(text):
    assert redact_text(text) == text


# Vendor formats with a fixed prefix, assembled at run time like the tokens above. A
# Doppler body that opens in lowercase letters and digits, as a service token's config
# name does, must still be read as the token.
DOPPLER_BODY = "".join(("a1b2", "C3d4E5f6G7h8" * 3, "J9k"))
VENDOR_TOKENS = {
    "databricks": "".join(("da", "pi", "0123456789abcdef" * 2)),
    "slack-app": "".join(("xa", "pp-", "1-A0B1C2D3E4-1234567890-", "c" * 24)),
    "shopify-private-app": "".join(("sh", "ppa_", "0123456789abcdef" * 2)),
    "postman": "".join(("PM", "AK-", "a" * 24, "-", "b" * 34)),
    "doppler-personal": "".join(("dp", ".pt.", DOPPLER_BODY)),
    "doppler-cli": "".join(("dp", ".ct.", DOPPLER_BODY)),
    "doppler-service": "".join(("dp", ".st.", DOPPLER_BODY)),
    "doppler-service-lowercase": "".join(("dp", ".st.", "0123456789abcdef" * 2, "0123456789ab")),
    "doppler-service-config": "".join(("dp", ".st.", "dev.", DOPPLER_BODY)),
    "doppler-service-branch-config": "".join(("dp", ".st.", "prd_api-2.", DOPPLER_BODY)),
    "doppler-service-account": "".join(("dp", ".sa.", DOPPLER_BODY)),
    "doppler-scim": "".join(("dp", ".scim.", DOPPLER_BODY)),
    "doppler-audit": "".join(("dp", ".audit.", DOPPLER_BODY)),
    "anthropic": "".join(("sk-ant-", "api03-", "0123456789abcdefABCDEF0123456789")),
    "anthropic-admin": "".join(("sk-ant-", "admin01-", "0123456789abcdefABCDEF0123456789")),
}


@pytest.mark.parametrize("token", VENDOR_TOKENS.values(), ids=VENDOR_TOKENS.keys())
@pytest.mark.parametrize("identifier", [False, True])
def test_vendor_token_formats_are_redacted(token, identifier):
    redacted = redact_text(f"call with {token} inside", identifier=identifier)
    assert token not in redacted and redacted == f"call with {REDACTED} inside"
    assert secret_like("CONFIG", token)


@pytest.mark.parametrize(
    "name",
    [
        "SG.config",
        "dapi-client",
        "dapi-docs",
        "xapp-bot",
        "shpat_rotation",
        "shppa_rotation",
        "PMAK-docs",
        "dp.pt.cfg",
        "dp.st.dev",
        "dp.st.dev.integrations.secrets_manager.client_factory",
        "dp.pt.load_pretrained_weights_from_checkpoint_directory",
        "sk-ant-docs",
        "sk-ant-adapter",
    ],
)
@pytest.mark.parametrize("identifier", [False, True])
def test_ordinary_names_near_vendor_token_formats_are_kept(name, identifier):
    assert redact_text(name, identifier=identifier) == name
