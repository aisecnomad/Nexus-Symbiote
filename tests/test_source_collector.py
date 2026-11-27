"""The source collector: the model identifiers a project's Python code gives an SDK.

Each rule has a fixture that must be read and one that must not be. A declaration
is never executed, and no value the collector may not export leaves the file.
"""

from __future__ import annotations

import json
import pickle
import tracemalloc
from pathlib import Path, PurePosixPath

import pytest

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import is_source_reference
from nexus_symbiote.core.enums import AssuranceLevel, SerializationSafety
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.scanners import source_python, source_references
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.source import SourceScanner, eligible
from nexus_symbiote.scanners.source_references import (
    Declarations,
    environment_name,
    model_identifier,
    split_route,
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.integrity import IntegrityValidator

PLANTED = "sk-proj-" + "Zq7" * 16
UNREAD = "bound to a value the collector cannot read as a model; not inventoried"
GIVEN = "given to a callee the project defines, which is not followed; not inventoried"


def unread(path: str, line: int, count: int = 1) -> str:
    subject = "a model argument is" if count == 1 else f"{count} model arguments are"
    return f"{path}:{line}: {subject} {UNREAD}"


CUT = (
    "Python source binds more names or values than the collector follows; "
    "some declarations were not read"
)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def scan(root: Path, files: dict[str, str]) -> ScanResult:
    return SourceScanner().scan(write(root, files))


def models(result: ScanResult) -> dict[str, ModelComponent]:
    return {c.name: c for c in result.components if isinstance(c, ModelComponent)}


def exported(result: ScanResult) -> str:
    return json.dumps(
        [c.model_dump(mode="json") for c in result.components]
        + list(result.surfaces_excluded)
        + list(result.scan_failures)
    )


CLIENT = '''\
"""Example in a docstring: client.chat.completions.create(model="gpt-3.5-turbo")"""
import os

from openai import OpenAI

# client.chat.completions.create(model="gpt-4-turbo", messages=[])
FAMILY = "claude"
REVIEW_MODEL = f"{FAMILY}-sonnet-4-5"
CHAT_MODEL = os.getenv("CHAT_MODEL", "gpt-4o-mini")
client = OpenAI()


def answer(question: str, careful: bool) -> str:
    model = REVIEW_MODEL if careful else CHAT_MODEL
    reply = client.chat.completions.create(model=model, messages=[])
    client.embeddings.create(model="text-embedding-3-small", input=question)
    return reply
'''


@pytest.fixture
def client(tmp_path: Path) -> ScanResult:
    return scan(tmp_path, {"app/client.py": CLIENT})


def test_a_model_argument_is_followed_to_the_values_bound_to_it(client: ScanResult):
    found = models(client)
    assert set(found) == {"claude-sonnet-4-5", "gpt-4o-mini", "text-embedding-3-small"}
    mini = found["gpt-4o-mini"]
    assert mini.bom_ref == "model:source:gpt-4o-mini"
    assert mini.assurance_level is AssuranceLevel.DECLARED
    assert mini.properties == {
        "collection_mode": "static-source-reference",
        "method": "python-ast",
        "declaration_line": 15,
        "reference_path": "app/client.py",
        "environment_variables": ["CHAT_MODEL"],
    }
    claim = mini.claims["source_reference"]
    assert (claim.locator, claim.collector, claim.assurance) == (
        "app/client.py:15",
        "source",
        AssuranceLevel.DECLARED,
    )
    # A weight file is what ``source_path`` names on a model; a reference has none.
    assert mini.source_path is None and mini.hashes == {} and mini.provider is None
    assert found["text-embedding-3-small"].model_type == "embedding"
    assert not client.surfaces_excluded and not client.scan_failures


def test_a_docstring_and_a_comment_declare_nothing(client: ScanResult):
    assert not {"gpt-3.5-turbo", "gpt-4-turbo"} & set(models(client))


def test_the_surfaces_say_what_was_and_was_not_read(client: ScanResult):
    assert client.surfaces_scanned == [
        "source: declarations in application source (static)",
        "source: tests, documentation, examples, benchmarks and build output are not read",
    ]


@pytest.mark.parametrize(
    ("argument", "expected"),
    [
        ('"gpt-4o"', ["gpt-4o"]),
        ('"gpt-" + "4o"', ["gpt-4o"]),
        ('os.environ.get("M", "gpt-4o")', ["gpt-4o"]),
        ('os.environ.get("M") or "gpt-4o"', ["gpt-4o"]),
        ('str("gpt-4o")', ["gpt-4o"]),
        ('" gpt-4o ".strip()', ["gpt-4o"]),
        ('"gpt-4o" if fast else "o4-mini"', ["gpt-4o", "o4-mini"]),
        ("(chosen := NAME)", ["gpt-4.1"]),
        ('f"{PREFIX}-4.1"', ["gpt-4.1"]),
        ("ALIAS", ["gpt-4.1"]),
        ("unknown_name", []),
        ("build_name()", []),
        ('f"{unknown_name}-4.1"', []),
        ("42", []),
    ],
)
def test_what_a_model_argument_can_stand_for(tmp_path: Path, argument: str, expected: list[str]):
    result = scan(
        tmp_path,
        {
            "run.py": f"""\
import os
from openai import OpenAI

PREFIX = "gpt"
NAME = "gpt-4.1"
ALIAS = NAME
fast = True
OpenAI().chat.completions.create(model={argument}, messages=[])
"""
        },
    )
    assert sorted(models(result)) == sorted(expected)


def test_a_parameter_default_and_the_nearest_binding_are_what_a_name_stands_for(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from openai import OpenAI

MODEL = "gpt-4o"


def outer(client, model="o4-mini", *, fallback="gpt-4.1-nano"):
    client.chat.completions.create(model=model, messages=[])
    client.chat.completions.create(model=fallback, messages=[])

    def inner():
        MODEL = "gpt-4.1"
        return OpenAI().chat.completions.create(model=MODEL, messages=[])

    return inner


class Settings:
    MODEL = "never-read-from-a-method"

    def call(self, client):
        return client.chat.completions.create(model=MODEL, messages=[])
"""
        },
    )
    assert set(models(result)) == {"o4-mini", "gpt-4.1-nano", "gpt-4.1", "gpt-4o"}


def test_names_bound_by_unpacking_and_with_are_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from openai import OpenAI

FAST, CAREFUL = "gpt-4o-mini", "o3"
[EMBED] = ["text-embedding-3-large"]
client = OpenAI()
client.chat.completions.create(model=FAST, messages=[])
client.chat.completions.create(model=CAREFUL, messages=[])
client.embeddings.create(model=EMBED, input="x")
with OpenAI() as scoped:
    scoped.chat.completions.create(model="gpt-4.1", messages=[])
"""
        },
    )
    assert set(models(result)) == {
        "gpt-4o-mini",
        "o3",
        "text-embedding-3-large",
        "gpt-4.1",
    }


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'from langchain.chat_models import init_chat_model\ninit_chat_model("openai:gpt-4.1")\n',
            {"gpt-4.1": "openai"},
        ),
        (
            'from sentence_transformers import SentenceTransformer\nSentenceTransformer("BAAI/bge-m3")\n',
            {"BAAI/bge-m3": None},
        ),
        (
            'from transformers import AutoModel\nAutoModel.from_pretrained("openai/whisper-large-v3")\n',
            {"openai/whisper-large-v3": None},
        ),
        (
            'import dspy\ndspy.LM("anthropic/claude-sonnet-4-5")\n',
            {"claude-sonnet-4-5": "anthropic"},
        ),
        (
            'from agno.models.openai import OpenAIChat\nOpenAIChat(id="gpt-4.1-mini")\n',
            {"gpt-4.1-mini": None},
        ),
        (
            'from langchain_huggingface import HuggingFaceEndpoint\nHuggingFaceEndpoint(repo_id="mistralai/Mistral-7B-Instruct-v0.3")\n',
            {"mistralai/Mistral-7B-Instruct-v0.3": None},
        ),
        (
            'from huggingface_hub import hf_hub_download\nhf_hub_download(repo_id="acme/rules-dataset")\n',
            {},
        ),
        (
            'from langchain.chat_models import init_chat_model\ninit_chat_model("ignored", model="gpt-4o")\n',
            {"gpt-4o": None},
        ),
        (
            'import boto3\nboto3.client("bedrock-runtime").converse(modelId="anthropic.claude-3-5-haiku-20241022-v1:0")\n',
            {"anthropic.claude-3-5-haiku-20241022-v1:0": None},
        ),
        ('from crewai import LLM\nLLM(model="ollama/llama3.1:8b")\n', {"llama3.1:8b": "ollama"}),
    ],
)
def test_which_arguments_hold_a_model(tmp_path: Path, source: str, expected: dict[str, str | None]):
    result = scan(tmp_path, {"run.py": source})
    assert {name: model.provider for name, model in models(result).items()} == expected


def test_a_routed_identifier_keeps_the_text_as_written(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "a.py": 'import litellm\nlitellm.completion(model="anthropic/claude-sonnet-4-5")\n',
            "b.py": 'import litellm\nlitellm.completion(model="bedrock/claude-sonnet-4-5")\n'
            'litellm.completion(model="ollama/llama3.2")\n',
        },
    )
    found = models(result)
    sonnet = found["claude-sonnet-4-5"]
    assert sonnet.provider is None and sonnet.model_type is None
    assert sonnet.properties["providers"] == ["anthropic", "aws-bedrock"]
    assert sonnet.properties["requested_aliases"] == [
        "anthropic/claude-sonnet-4-5",
        "bedrock/claude-sonnet-4-5",
    ]
    assert sonnet.claims["source_reference"].evidence_refs == ["a.py:2", "b.py:2"]
    local = found["llama3.2"]
    # A runtime that serves weights on the machine is no hosted service.
    assert (local.provider, local.model_type, local.requested_alias) == (
        "ollama",
        None,
        "ollama/llama3.2",
    )


def test_one_component_names_every_place_up_to_the_listing_bound(tmp_path: Path):
    files = {
        f"pkg/m{index:02}.py": 'from openai import OpenAI\nOpenAI().responses.create(model="gpt-4.1")\n'
        for index in range(20)
    }
    model = models(scan(tmp_path, files))["gpt-4.1"]
    assert len(model.claims["source_reference"].evidence_refs) == 16
    assert model.properties["references_unlisted"] == 4
    assert model.properties["reference_path"] == "pkg/m00.py"


def test_a_secret_written_into_source_never_reaches_the_inventory(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "bot.py": f"""\
import os
from openai import OpenAI

client = OpenAI(api_key="{PLANTED}")
client.chat.completions.create(model="{PLANTED}", messages=[])
client.chat.completions.create(model="openai/{PLANTED}", messages=[])
client.chat.completions.create(model=os.getenv("{PLANTED}", "gpt-4o"), messages=[])
client.chat.completions.create(model=os.environ["{PLANTED}"], messages=[])
"""
        },
    )
    assert PLANTED not in exported(result) and "Zq7Zq7" not in exported(result)
    found = models(result)
    assert set(found) == {"gpt-4o"}
    assert "environment_variables" not in found["gpt-4o"].properties


def test_nothing_in_the_project_is_executed(tmp_path: Path):
    marker = tmp_path / "ran"
    scan(
        tmp_path / "project",
        {
            "boot.py": f"""\
from pathlib import Path
from openai import OpenAI

Path({str(marker)!r}).write_text("ran")
OpenAI().chat.completions.create(model="gpt-4o", messages=[])
""",
            "setup.py": f"open({str(marker)!r}, 'w').write('ran')\n",
        },
    )
    assert not marker.exists()


def test_the_same_tree_gives_the_same_records(tmp_path: Path):
    first = scan(tmp_path / "a", {"app/client.py": CLIENT})
    second = scan(tmp_path / "b", {"app/client.py": CLIENT})
    assert exported(first) == exported(second)


def test_a_file_that_imports_no_sdk_declares_nothing(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "shop/models.py": """\
from django.db import models

class Order(models.Model):
    def render(self, model="claude-sonnet-4-5"):
        return call(model=model)
""",
            "notes.py": 'TEXT = "we moved off openai last year"\nrender(model="gpt-4o")\n',
        },
    )
    assert result.components == []
    assert not result.surfaces_excluded


def test_part_of_a_namespace_that_is_not_an_sdk_declares_nothing(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "store.py": 'from google.cloud import storage\nstorage.Client().get(model="gpt-4o")\n',
            "chat.py": 'from google import genai\ngenai.Client().models.generate_content(model="gemini-2.5-flash")\n',
        },
    )
    assert set(models(result)) == {"gemini-2.5-flash"}


@pytest.mark.parametrize("layout", ["openai.py", "openai/__init__.py", "src/openai.py"])
def test_a_project_module_named_like_an_sdk_is_not_the_sdk(tmp_path: Path, layout: str):
    result = scan(
        tmp_path,
        {
            layout: "class OpenAI:\n    def create(self, **options): ...\n",
            "main.py": 'from openai import OpenAI\n\nOpenAI().create(model="gpt-4o")\n',
        },
    )
    assert result.components == []
    # Whether the project's module is the one imported depends on how it is run.
    assert list(result.surfaces_excluded) == [
        "main.py:1: imports an SDK by a name that a module of the project also has; "
        "not read as the SDK"
    ]


def test_a_shadowing_module_counts_even_when_it_cannot_be_read(tmp_path: Path):
    write(tmp_path, {"main.py": 'from openai import OpenAI\n\nOpenAI().create(model="gpt-4o")\n'})
    (tmp_path / "openai.py").write_bytes(b"NAME = '\xe9'\n")
    result = SourceScanner().scan(tmp_path)
    assert result.components == []
    assert (
        len(result.surfaces_excluded) == 1 and "not read as the SDK" in result.surfaces_excluded[0]
    )


def test_a_second_sdk_is_read_and_a_call_into_the_shadowing_module_is_a_gap(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "openai.py": "class OpenAI: ...\n",
            "main.py": "import litellm\nfrom openai import OpenAI\n\n"
            'OpenAI().create(model="gpt-4o")\nlitellm.completion(model="gpt-4.1")\n',
        },
    )
    # The project's own OpenAI is not the SDK's, so what it is given is not a model.
    assert set(models(result)) == {"gpt-4.1"}
    assert list(result.surfaces_excluded) == [f"main.py:4: a model argument is {GIVEN}"]


def test_results_kept_for_one_file_are_not_read_for_the_next(tmp_path: Path):
    # Many small files of the same shape: a result kept by the identity of a freed
    # syntax node would be read back for a node of a later file.
    files = {
        f"pkg/m{index:03}.py": "from openai import OpenAI\n"
        f'NAME = "gpt-4o-{index}"\nOpenAI().responses.create(model=NAME)\n'
        for index in range(120)
    }
    found = models(scan(tmp_path, files))
    assert set(found) == {f"gpt-4o-{index}" for index in range(120)}
    for index in range(120):
        assert found[f"gpt-4o-{index}"].properties["reference_path"] == f"pkg/m{index:03}.py"


def test_a_name_read_twice_in_a_chain_is_read_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Read afresh at each use, eight doublings are 2 ** 8 readings of the first name,
    # which this allowance does not cover; read once each, they are a few dozen.
    monkeypatch.setattr(source_python.PythonReader, "_allowance", staticmethod(lambda module: 150))
    chain = "\n".join(f"n{index + 1} = n{index} + n{index}" for index in range(8))
    result = scan(
        tmp_path,
        {
            "run.py": f'from openai import OpenAI\nn0 = "g"\n{chain}\n'
            "OpenAI().responses.create(model=n8)\n"
        },
    )
    # 2 ** 8 letters were read within the allowance, and are no identifier.
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("run.py", 11)]


def test_text_joined_to_itself_does_not_grow_without_bound(tmp_path: Path):
    # Unbounded, eleven doublings of 20,000 characters build 40 MB of text for one
    # small file, and forty doublings of one character more memory than any host has.
    wide = "g" * 20_000
    chain = "\n".join(f"n{index + 1} = n{index} + n{index}" for index in range(11))
    formatted = "\n".join(f'f{index + 1} = f"{{f{index}}}{{f{index}}}"' for index in range(11))
    write(
        tmp_path,
        {
            "run.py": f'from openai import OpenAI\nn0 = "{wide}"\nf0 = "h"\n{chain}\n{formatted}\n'
            "OpenAI().responses.create(model=n11)\nOpenAI().responses.create(model=f11)\n"
            'OpenAI().responses.create(model="x" * 3)\n'
            f'OpenAI().responses.create(model="{"y" * 600}")\n'
        },
    )
    tracemalloc.start()
    try:
        result = SourceScanner().scan(tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 16 * 2**20
    assert result.components == []
    # Text the reader gave up on is not text it read: the three arguments built by
    # joining or repeating are a gap, and the one long constant is plainly no model.
    assert list(result.surfaces_excluded) == [unread("run.py", 26, 3)]


def test_a_short_name_built_from_parts_is_still_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "from openai import OpenAI\n"
            'FAMILY = "gpt-4o"\nSIZE = "mini"\nNAME = FAMILY + "-" + SIZE\n'
            'OpenAI().responses.create(model=NAME)\nOpenAI().responses.create(model=f"{FAMILY}-audio")\n'
        },
    )
    assert set(models(result)) == {"gpt-4o-mini", "gpt-4o-audio"}


def test_words_that_name_no_model_are_not_models(tmp_path: Path):
    arguments = ["default", "auto", "weights/llama.gguf", "https://x.example/v1", "two words", "x"]
    calls = "\n".join(f"client.chat.completions.create(model={word!r})" for word in arguments)
    result = scan(tmp_path, {"run.py": f"from openai import OpenAI\nclient = OpenAI()\n{calls}\n"})
    assert result.components == []


def test_a_model_only_the_environment_sets_is_a_named_gap(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
import os
from os import environ, getenv
from openai import OpenAI

client = OpenAI()
client.chat.completions.create(model=os.environ["CHAT_MODEL"], messages=[])
client.chat.completions.create(model=getenv("CHAT_MODEL"), messages=[])
client.chat.completions.create(model=environ.get("TUNED_MODEL", "gpt-4.1"), messages=[])
client.chat.completions.create(model=environ["TUNED_MODEL"], messages=[])
"""
        },
    )
    assert set(models(result)) == {"gpt-4.1"}
    # One gap for the variable, at its first use; a variable with a value elsewhere is none.
    assert list(result.surfaces_excluded) == [
        "run.py:6: model set by environment variable CHAT_MODEL, which no file of the project "
        "gives a value; not inventoried"
    ]


UNFOLLOWED = """\
import os
from openai import OpenAI
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel

client = OpenAI()


def ask(model, settings, table, fallback="gpt-4.1"):
    client.responses.create(model=model)
    client.responses.create(model=settings.model)
    client.responses.create(model=table["chat"])
    client.responses.create(model=f"gpt-{model}")
    client.responses.create(model=unbound)
    client.responses.create(model=os.environ[model])
    client.responses.create(model="gpt-4o" if settings.fast else model)
    client.responses.create(model=fallback)
    again = again
    client.responses.create(model=again)
    twice = fallback or fallback
    client.responses.create(model=twice)
    client.responses.create(model=None)
    client.responses.create(model=pick())
    Agent(model=OpenAIChatModel("gpt-4o-mini"))
    settings.client.responses.create(model=model)
    record(model=model)
"""


def test_a_model_argument_the_reader_cannot_follow_is_one_gap_for_its_file(tmp_path: Path):
    result = scan(tmp_path, {"app/ask.py": UNFOLLOWED})
    # A value that was read is recorded, whatever else the argument can hold.
    assert set(models(result)) == {"gpt-4o", "gpt-4.1", "gpt-4o-mini"}
    # A parameter, with or without a default, an attribute, a subscript, text built from
    # a parameter, a name the file does not bind, a variable named by a parameter, one
    # side of a conditional, a name bound only to itself, a call the reader cannot give
    # the result of, and the arguments of two callees it cannot name: thirteen. Nothing
    # and a model's own object, which is read where it is built, are not counted.
    assert list(result.surfaces_excluded) == [unread("app/ask.py", 10, 13)]


def test_one_unfollowed_argument_is_named_alone(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "one.py": "from anthropic import Anthropic\n\n\ndef ask(model):\n"
            "    Anthropic().messages.create(model=model)\n"
            "    Anthropic().messages.create(\n        model=model\n    )\n"
        },
    )
    assert list(result.surfaces_excluded) == [unread("one.py", 5, 2)]
    single = scan(
        tmp_path / "single",
        {
            "one.py": "from anthropic import Anthropic\n\n\ndef ask(model):\n"
            "    Anthropic().messages.create(model=model)\n"
        },
    )
    assert list(single.surfaces_excluded) == [unread("one.py", 5)]


FOLLOWED = "model argument is bound in another module of the project, which the collector could not follow; not inventoried"


def test_a_model_bound_in_another_module_of_the_project_is_followed(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "app/settings.py": 'MODEL = "gpt-4o"\nfrom .defaults import FALLBACK\n',
            "app/defaults.py": 'FALLBACK = "o3"\n',
            "app/__init__.py": "",
            "app/run.py": """\
from openai import OpenAI
from . import settings
from .settings import FALLBACK, MODEL
import app.settings as configured

OpenAI().chat.completions.create(model=MODEL, messages=[])
OpenAI().chat.completions.create(model=settings.MODEL, messages=[])
OpenAI().chat.completions.create(model=configured.FALLBACK, messages=[])
OpenAI().chat.completions.create(model=FALLBACK, messages=[])
""",
        },
    )
    found = models(result)
    assert set(found) == {"gpt-4o", "o3"}
    # The place recorded is the argument that gives the model, in the analysed file.
    assert found["gpt-4o"].claims["source_reference"].evidence_refs == [
        "app/run.py:6",
        "app/run.py:7",
    ]
    assert not result.surfaces_excluded


@pytest.mark.parametrize(
    ("files", "why"),
    [
        ({"app/settings.py": "MODEL = (\n"}, "unparsable"),
        ({"app/settings.py": b"MODEL = '\xe9'\n"}, "not UTF-8"),
        ({"tests/settings.py": 'MODEL = "gpt-4o"\n'}, "a test module"),
        ({"app/settings.py": "from .elsewhere import *\n"}, "not bound there"),
    ],
)
def test_a_model_bound_in_a_module_the_collector_cannot_follow_is_a_gap(
    tmp_path: Path, files: dict[str, str | bytes], why: str
):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        data = text if isinstance(text, bytes) else text.encode()
        (tmp_path / name).write_bytes(data)
    caller = "app/run.py" if "tests/settings.py" not in files else "app/run.py"
    module = "tests.settings" if "tests/settings.py" in files else "app.settings"
    result = scan(
        tmp_path,
        {
            caller: f"from openai import OpenAI\nfrom {module} import MODEL\n\nOpenAI().responses.create(model=MODEL)\n"
        },
    )
    assert result.components == [], why
    assert list(result.surfaces_excluded) == [f"app/run.py:4: {FOLLOWED}"], why


ATTRIBUTES = """\
from openai import OpenAI


class Assistant:
    tier = "gpt-4o-mini"

    def __init__(self):
        self.client = OpenAI()
        self.model = "gpt-4.1"
        self.helper = Settings()

    def ask(self):
        def inner():
            return self.client.responses.create(model=self.model)

        self.client.responses.create(model=self.tier)
        self.client.responses.create(model=self.helper.chat)
        return inner()


class Settings:
    chat = "o3"
    embed: str = "text-embedding-3-small"


def run(settings: Settings, client=OpenAI()):
    client.embeddings.create(model=settings.embed)
    client.responses.create(model=Settings.chat)
"""


def test_attributes_of_self_of_a_class_and_of_its_objects_are_followed(tmp_path: Path):
    result = scan(tmp_path, {"assistant.py": ATTRIBUTES})
    found = models(result)
    assert set(found) == {"gpt-4.1", "gpt-4o-mini", "o3", "text-embedding-3-small"}
    # What the client on ``self`` is decides that this is an embeddings call.
    assert found["text-embedding-3-small"].model_type == "embedding"
    assert not result.surfaces_excluded


ITEMS_AND_RETURNS = """\
import os
from openai import OpenAI

MODELS = {"chat": "gpt-4o", "embed": "text-embedding-3-large", **os.environ}
PLAIN = {"chat": "o3"}


def pick():
    if os.environ.get("FAST"):
        return "gpt-4o-mini"
    return MODELS["chat"]


def make_client():
    return OpenAI()


choose = lambda: "o1"  # noqa: E731
client = make_client()
client.responses.create(model=pick())
client.responses.create(model=choose())
client.responses.create(model=PLAIN["chat"])
client.responses.create(model=PLAIN.get("embed", "gpt-4.1"))
client.responses.create(model=MODELS["embed"])
client.responses.create(model=os.environ.get("CHAT_MODEL", "gpt-4.1-mini"))
client.responses.create(model=settings.get("chat", "gpt-4.1-nano"))
"""


def test_items_of_literal_dictionaries_and_returned_values_are_followed(tmp_path: Path):
    result = scan(tmp_path, {"items.py": ITEMS_AND_RETURNS})
    found = models(result)
    assert set(found) == {
        "gpt-4o",
        "gpt-4o-mini",
        "o1",
        "o3",
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4.1-nano",
        "text-embedding-3-large",
    }
    # A dictionary it unpacks may hold any key; an unknown holder may hold any value.
    assert list(result.surfaces_excluded) == [unread("items.py", 20, 3)]


def test_a_client_made_in_another_module_is_that_client(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "app/clients.py": "from openai import OpenAI\n\nclient = OpenAI()\n\n\n"
            "def make():\n    return OpenAI()\n",
            "app/run.py": "import openai\nfrom app import clients\nfrom app.clients import client, make\n\n"
            'client.embeddings.create(model="text-embedding-3-small")\n'
            'clients.client.responses.create(model="gpt-4o")\n'
            'make().responses.create(model="o3")\n',
        },
    )
    found = models(result)
    assert set(found) == {"text-embedding-3-small", "gpt-4o", "o3"}
    assert found["text-embedding-3-small"].model_type == "embedding"
    # Each call is the SDK's, not a callee the project defines.
    assert not result.surfaces_excluded


FOLLOWING_EDGES = """\
from openai import OpenAI

PLAIN = {"chat": "o3"}


def helper(): ...


def outside(self):
    OpenAI().responses.create(model=self.model)


OpenAI().responses.create(model=PLAIN.get("chat"))
OpenAI().responses.create(model=PLAIN.get("missing"))
OpenAI().responses.create(model=helper.model)
for client in clients:
    client.responses.create(model="gpt-4o")
"""


def test_what_following_cannot_reach_is_unread_and_what_it_rules_out_is_not(tmp_path: Path):
    result = scan(tmp_path, {"edges.py": FOLLOWING_EDGES})
    # A loop variable's client is unknown, so its model keyword is still read.
    assert set(models(result)) == {"o3", "gpt-4o"}
    # ``self`` outside a class and an attribute of a function are unread; a missing key
    # of a literal dictionary gives ``None``, which names no model.
    assert list(result.surfaces_excluded) == [unread("edges.py", 10, 2)]


def test_reading_many_keys_of_one_dictionary_costs_its_size_once(tmp_path: Path):
    # Scanned again at each read, the keys would spend the file's allowance.
    table = ", ".join(f'"k{index}": "m-{index}"' for index in range(1000))
    reads = "\n".join(f'OpenAI().responses.create(model=T["k{index}"])' for index in range(1000))
    result = scan(tmp_path, {"t.py": f"from openai import OpenAI\nT = {{{table}}}\n{reads}\n"})
    assert len(models(result)) == 1000
    assert not result.surfaces_excluded


def test_a_name_imported_from_outside_the_project_is_unread(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "app/run.py": "from openai import OpenAI\nfrom company_settings import MODEL\n\n"
            "OpenAI().responses.create(model=MODEL)\n"
        },
    )
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("app/run.py", 4)]


def test_modules_that_import_each_other_are_read_once(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "app/a.py": "from app.b import B\nA = B\n",
            "app/b.py": "from app.a import A\nB = A\n",
            "app/run.py": "from openai import OpenAI\nfrom app.a import A\n\n"
            "OpenAI().responses.create(model=A)\n",
        },
    )
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("app/run.py", 4)]


def test_source_that_names_an_sdk_and_cannot_be_read_is_a_gap(tmp_path: Path):
    write(tmp_path, {"broken.py": "from openai import OpenAI\n\ndef (:\n", "plain.py": "def (:\n"})
    (tmp_path / "latin.py").write_bytes(b"from openai import OpenAI\nNAME = '\xe9'\n")
    (tmp_path / "other.py").write_bytes(b"NAME = '\xe9'\n")
    result = SourceScanner().scan(tmp_path)
    assert sorted(result.surfaces_excluded) == [
        "broken.py:1: Python source could not be parsed; not read",
        "latin.py: source file is not UTF-8; declarations in it were not read",
    ]


def test_a_file_over_the_syntax_limit_is_a_gap_only_when_it_names_an_sdk(tmp_path: Path):
    padding = "# padding\n" * 40
    write(
        tmp_path,
        {
            "big.py": f'from openai import OpenAI\n{padding}OpenAI().responses.create(model="gpt-4o")\n',
            "plain.py": padding,
        },
    )
    with limits.applied(limits.resolve(["syntax-bytes=256"], {})):
        result = SourceScanner().scan(tmp_path)
    assert result.components == []
    assert list(result.surfaces_excluded) == [
        "big.py: source file is larger than the syntax-bytes limit; declarations in it were "
        "not read"
    ]


def test_a_file_over_the_node_limit_is_a_gap(tmp_path: Path):
    write(tmp_path, {"wide.py": "from openai import OpenAI\n" + "x = 1\n" * 200})
    with limits.applied(limits.resolve(["python-nodes=100"], {})):
        result = SourceScanner().scan(tmp_path)
    assert list(result.surfaces_excluded) == [
        "wide.py:1: Python source has more syntax nodes than the python-nodes limit; not read"
    ]


def test_source_past_the_scan_budget_is_one_named_failure(tmp_path: Path):
    body = 'from openai import OpenAI\nOpenAI().responses.create(model="gpt-4o")\n'
    write(tmp_path, {"a.py": body, "b.py": body, "c.py": body})
    with limits.applied(limits.resolve([f"source-scan-bytes={len(body) + 1}"], {})):
        result = SourceScanner().scan(tmp_path)
    assert len(result.scan_failures) == 1
    assert "source declarations exceed the combined size limit" in result.scan_failures[0]


def test_a_name_bound_in_terms_of_itself_costs_no_more_than_its_length(tmp_path: Path):
    rebinds = "\n".join(f'text = text.replace("{index}", "x")' for index in range(400))
    result = scan(
        tmp_path,
        {
            "loop.py": f'from openai import OpenAI\n\ntext = "gpt-4o"\n{rebinds}\n'
            "OpenAI().chat.completions.create(model=text, messages=[])\n"
        },
    )
    # The first sixteen bindings were followed, which is not all of them, and what
    # ``replace`` gives back is not read: the text as first written is not the last.
    assert set(models(result)) == {"gpt-4o"}
    assert list(result.surfaces_excluded) == [unread("loop.py", 404), f"loop.py:1: {CUT}"]


def test_following_stops_at_its_bounds_and_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    chain = "\n".join(f"n{index + 1} = n{index}" for index in range(40))
    files = {
        "deep.py": f'from openai import OpenAI\nn0 = "gpt-4o"\n{chain}\n'
        "OpenAI().chat.completions.create(model=n40, messages=[])\n"
    }
    deep = scan(tmp_path / "depth", files)
    assert deep.components == []
    assert list(deep.surfaces_excluded) == [unread("deep.py", 43), f"deep.py:1: {CUT}"]
    monkeypatch.setattr(source_python.PythonReader, "_allowance", staticmethod(lambda module: 5))
    starved = scan(tmp_path / "steps", files)
    assert starved.components == []
    # Past the allowance an argument is unread, and the file says some were not read.
    assert list(starved.surfaces_excluded) == [unread("deep.py", 43), f"deep.py:1: {CUT}"]


def test_a_name_bound_more_often_than_is_followed_is_read_in_part_and_says_so(tmp_path: Path):
    bound = "\n".join(f'NAME = "gpt-4o-{index}"' for index in range(20))
    result = scan(
        tmp_path,
        {"many.py": f"from openai import OpenAI\n{bound}\nOpenAI().responses.create(model=NAME)\n"},
    )
    assert set(models(result)) == {f"gpt-4o-{index}" for index in range(16)}
    assert list(result.surfaces_excluded) == [f"many.py:1: {CUT}"]


def test_a_long_dotted_name_behind_a_short_alias_is_not_followed(tmp_path: Path):
    # Followed, each read of the alias would cost the length of the name it stands for.
    package = ".".join(["part"] * 60)
    reads = "\n".join('m.Client().responses.create(model="gpt-4o")' for _ in range(3))
    result = scan(
        tmp_path,
        {
            "long.py": f"import openai\nimport openai.{package} as m\n"
            f"from openai.{package} import Client as short\n{reads}\n"
            'short("gpt-4.1")\n'
        },
    )
    # What the alias calls is unknown, and a model keyword is still read by its name.
    assert set(models(result)) == {"gpt-4o"}
    assert list(result.surfaces_excluded) == [f"long.py:1: {CUT}"]


def test_a_dotted_name_grown_past_its_bound_is_not_followed(tmp_path: Path):
    steps = ".".join("a" * 30 for _ in range(9))
    source = (
        "import sentence_transformers as st\n"
        'st.SentenceTransformer("all-MiniLM-L6-v2")\n'
        f'st.{steps}.SentenceTransformer("all-mpnet-base-v2")\n'
    )
    result = scan(tmp_path, {"grown.py": source})
    assert set(models(result)) == {"all-MiniLM-L6-v2"}
    assert list(result.surfaces_excluded) == [f"grown.py:1: {CUT}"]


def test_a_module_is_looked_for_in_the_nearest_directories_above_the_importer(tmp_path: Path):
    source = 'from openai import OpenAI\n\nOpenAI().responses.create(model="gpt-4o")\n'
    near = "/".join(f"d{index}" for index in range(30))
    far = "/".join(f"d{index}" for index in range(40))
    shadowed = scan(
        tmp_path / "near", {"top/openai.py": "", f"top/{near}/main.py": source, "pad.py": ""}
    )
    assert shadowed.components == [] and len(shadowed.surfaces_excluded) == 1
    distant = scan(tmp_path / "far", {"top/openai.py": "", f"top/{far}/main.py": source})
    assert set(models(distant)) == {"gpt-4o"} and not distant.surfaces_excluded


def test_looking_for_modules_is_within_the_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(source_python.PythonReader, "_allowance", staticmethod(lambda module: 40))
    imports = "\n".join(f"import openai.part{index} as p{index}" for index in range(30))
    result = scan(
        tmp_path,
        {"wide.py": f'{imports}\np0.Client().responses.create(model="gpt-4o")\n', "openai.py": ""},
    )
    # The allowance ran out before the reader could say which module each name is.
    assert result.components == []
    assert list(result.surfaces_excluded) == [f"wide.py:1: {CUT}"]


def test_an_expression_is_read_once_however_many_names_read_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[int] = []
    keywords = source_python._keywords

    def counted(call):  # type: ignore[no-untyped-def]
        calls.append(1)
        return keywords(call)

    monkeypatch.setattr(source_python, "_keywords", counted)
    reads = "\n".join("OpenAI().responses.create(model=NAME)" for _ in range(300))
    result = scan(
        tmp_path,
        {
            "once.py": "import os\nfrom openai import OpenAI\n"
            f'NAME = os.getenv("CHAT_MODEL", default="gpt-4o")\n{reads}\n'
        },
    )
    assert set(models(result)) == {"gpt-4o"}
    # One reading for each of the 600 calls into the SDK, and one of the default; the
    # call that reads the environment is not one whose arguments name models.
    assert len(calls) == 601


def test_text_built_from_itself_is_read_as_far_as_it_is_written(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "grow.py": "from openai import OpenAI\n"
            'NAME = "gpt-4o"\nNAME = NAME + "-mini"\nOpenAI().responses.create(model=NAME)\n'
        },
    )
    assert set(models(result)) == {"gpt-4o", "gpt-4o-mini"}
    assert not result.surfaces_excluded


def test_what_a_name_bound_many_times_calls_is_worked_out_once_from_all_of_them(
    tmp_path: Path,
):
    bound = "\n".join("loader = SentenceTransformer" for _ in range(40))
    mixed = "\n".join(["other = SentenceTransformer"] * 30 + ["other = OpenAI"])
    result = scan(
        tmp_path,
        {
            "often.py": "from openai import OpenAI\n"
            "from sentence_transformers import SentenceTransformer\n"
            f'{bound}\n{mixed}\nloader("all-MiniLM-L6-v2")\nother("all-mpnet-base-v2")\n'
            'text = ""\n' + "\n".join('text = text.replace("a", "b")' for _ in range(40))
        },
    )
    # Every binding of ``loader`` is the loader, so its first argument is a model; one
    # binding of ``other`` is not, so what it calls is unknown and no positional
    # argument is read. A name that only carries text through many steps is no gap.
    assert set(models(result)) == {"all-MiniLM-L6-v2"}
    assert not result.surfaces_excluded


@pytest.mark.parametrize(
    ("argument", "kept"),
    [
        (" or ".join(f"a{index}" for index in range(20)), 16),
        ('f"{left}-{right}"', 8),
    ],
    ids=["candidates", "joined"],
)
def test_more_values_than_are_kept_for_one_argument_says_so(
    tmp_path: Path, argument: str, kept: int
):
    names = "\n".join(f'a{index} = "gpt-4o-{index}"' for index in range(20))
    result = scan(
        tmp_path,
        {
            "wide.py": f"from openai import OpenAI\n{names}\n"
            "left = a0 or a1 or a2 or a3\nright = a4 or a5 or a6 or a7\n"
            f"OpenAI().responses.create(model={argument})\n"
        },
    )
    assert len(models(result)) == kept
    assert list(result.surfaces_excluded) == [f"wide.py:1: {CUT}"]


def test_many_bindings_read_many_times_cost_their_sum_not_their_product(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # 2,000 bindings read 2,000 times: followed in full at each read that is four
    # million steps; within the bound it is a few more than the values kept per read.
    walked: list[int] = []
    follow = source_python.PythonReader._follow_into

    def counted(self, value, out, seen, depth):  # type: ignore[no-untyped-def]
        walked.append(1)
        follow(self, value, out, seen, depth)

    monkeypatch.setattr(source_python.PythonReader, "_follow_into", counted)
    bound = "\n".join('NAME = "gpt-4o"' for _ in range(2000))
    reads = "\n".join("OpenAI().responses.create(model=NAME)" for _ in range(2000))
    result = scan(tmp_path, {"big.py": f"from openai import OpenAI\n{bound}\n{reads}\n"})
    assert set(models(result)) == {"gpt-4o"}
    assert list(result.surfaces_excluded) == [f"big.py:1: {CUT}"]
    assert len(walked) < 2000 * (source_python.MAX_CANDIDATES + 4)


def test_a_wide_expression_read_at_many_places_costs_its_bound_at_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    walked: list[int] = []
    follow = source_python.PythonReader._follow_into

    def counted(self, value, out, seen, depth):  # type: ignore[no-untyped-def]
        walked.append(1)
        follow(self, value, out, seen, depth)

    monkeypatch.setattr(source_python.PythonReader, "_follow_into", counted)
    wide = " or ".join(f'"gpt-4o-{index}"' for index in range(400))
    reads = "\n".join("OpenAI().responses.create(model=W)" for _ in range(400))
    result = scan(tmp_path, {"wide.py": f"from openai import OpenAI\nW = {wide}\n{reads}\n"})
    assert len(models(result)) == source_python.MAX_CANDIDATES
    assert list(result.surfaces_excluded) == [f"wide.py:1: {CUT}"]
    # Walked in full at each read this is 400 x 400 steps.
    assert len(walked) < 400 * (source_python.MAX_CANDIDATES + 4)


def test_what_a_callee_is_decides_how_its_arguments_are_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from openai import AsyncOpenAI, OpenAI
from sentence_transformers import SentenceTransformer

TABLE = {"fast": "gpt-4o-mini"}
a = b
b = a


def local_loader(name):
    return SentenceTransformer(name)


def embed(client: OpenAI, text):
    return client.embeddings.create(model="acme-search-v2", input=text)


async def reply(make):
    client = await make()
    scoped = await AsyncOpenAI().with_options(timeout=5)
    await scoped.chat.completions.create(model="gpt-4.1", messages=[])
    await client.chat.completions.create(model=TABLE["fast"], messages=[])
    a(model="gpt-4o")
    local_loader("openai/gpt-4.1-nano")
    return SentenceTransformer("openai/" + ("clip" + ("-vit" + ("-base" + "-patch32"))))
"""
        },
    )
    found = models(result)
    # An item of a literal dictionary is followed; the argument of a project function is
    # not read here, but where the function hands it to an SDK.
    assert set(found) == {
        "acme-search-v2",
        "gpt-4.1",
        "gpt-4o",
        "gpt-4o-mini",
        "openai/clip-vit-base-patch32",
    }
    # The annotated parameter is an OpenAI client, so the call is an embeddings call.
    assert found["acme-search-v2"].model_type == "embedding"


def test_text_nested_past_the_depth_bound_is_not_read(tmp_path: Path):
    nested = '"o"'
    for _ in range(source_python.MAX_DEPTH + 2):
        nested = f'("g" + {nested})'
    result = scan(
        tmp_path,
        {"run.py": f"from openai import OpenAI\nOpenAI().responses.create(model={nested})\n"},
    )
    assert result.components == []


@pytest.mark.parametrize(
    ("path", "read"),
    [
        ("app/agent.py", True),
        ("agent.py", True),
        ("tests/test_agent.py", False),
        ("app/test_agent.py", False),
        ("app/agent_test.py", False),
        ("app/conftest.py", False),
        ("examples/agent.py", False),
        ("docs/snippets/agent.py", False),
        ("benchmarks/cases/agent.py", False),
        ("build/lib/agent.py", False),
        ("app/agent.ts", False),
        ("app/config.yaml", False),
        ("README.md", False),
    ],
)
def test_which_files_are_read(path: str, read: bool):
    assert eligible(PurePosixPath(path)) is read


def test_a_file_too_large_to_read_is_a_gap_whatever_it_holds(tmp_path: Path):
    padding = "# padding\n" * 40
    write(
        tmp_path,
        {
            "app/llm.py": 'from openai import OpenAI\nOpenAI().responses.create(model="x-1")\n'
            + padding,
            "app/plain.py": padding,
            "app/small.py": 'from openai import OpenAI\nOpenAI().responses.create(model="o3")\n',
        },
    )
    with limits.applied(limits.resolve(["file-bytes=256"], {})):
        result = SourceScanner().scan(tmp_path)
    # Without reading a file, whether it names an SDK is unknown.
    assert set(models(result)) == {"o3"}
    assert list(result.surfaces_excluded) == [
        "app/llm.py: source file is larger than the file-bytes limit; not read",
        "app/plain.py: source file is larger than the file-bytes limit; not read",
    ]


def test_a_source_file_that_cannot_be_read_is_a_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    write(tmp_path, {"app/client.py": CLIENT})
    monkeypatch.setattr(ConfinedCollection, "read_bytes", lambda self, path, **options: None)
    result = SourceScanner().scan(tmp_path)
    assert result.components == []
    assert list(result.surfaces_excluded) == [
        "app/client.py: source file could not be read; not read"
    ]


def test_a_link_is_read_only_when_it_reaches_a_file_the_collector_reads(tmp_path: Path):
    body = 'from openai import OpenAI\n\nOpenAI().responses.create(model="{}")\n'
    write(
        tmp_path,
        {
            "config/secrets.py": body.format("from-secrets"),
            "tests/helper.py": body.format("from-tests"),
            "app/real.py": body.format("through-a-link"),
        },
    )
    (tmp_path / "app" / "llm.py").symlink_to("../config/secrets.py")
    (tmp_path / "app" / "prod.py").symlink_to("../tests/helper.py")
    (tmp_path / "app" / "alias.py").symlink_to("real.py")
    result = SourceScanner().scan(tmp_path)
    assert set(models(result)) == {"through-a-link"}
    reference = models(result)["through-a-link"].claims["source_reference"]
    assert reference.evidence_refs == ["app/alias.py:3", "app/real.py:3"]
    assert not result.surfaces_excluded


BINDINGS = """\
import os
from openai import OpenAI

client = OpenAI()
name = "claude"
name += "-sonnet-4-5"
client.responses.create(model=name)
size = "gpt-4o"
size *= 2
client.responses.create(model=size)
looped = "gpt-4.1"
for looped in os.environ:
    client.responses.create(model=looped)
inner = "module-level-thing"
[client.responses.create(model=inner) for inner in os.environ]
paired, other = os.environ.popitem()
paired = "o3"
client.responses.create(model=paired)
try:
    pass
except ValueError as caught:
    client.responses.create(model=caught)
with open(__file__) as (first, second):
    client.responses.create(model=first)
match os.environ:
    case {"MODEL": captured}:
        client.responses.create(model=captured)
"""


def test_a_name_with_a_binding_the_reader_cannot_give_is_a_gap(tmp_path: Path):
    result = scan(tmp_path, {"bind.py": BINDINGS})
    # ``+=`` joins; every other binding below the first is one the reader cannot give:
    # ``*=``, a loop and a comprehension variable, a name unpacked from a call, an
    # exception, a name unpacked from a context and a pattern capture. Every value the
    # reader could give is still recorded, and a comprehension's own variable is not
    # the module's name of the same spelling.
    assert set(models(result)) == {"claude", "claude-sonnet-4-5", "gpt-4o", "gpt-4.1", "o3"}
    assert list(result.surfaces_excluded) == [unread("bind.py", 10, 7)]


def test_a_callee_cut_short_by_depth_is_worked_out_again_nearer_the_top(tmp_path: Path):
    chain = "\n".join(f"st{index + 1} = st{index}" for index in range(5))
    deep = "st5" + ".part" * 25
    result = scan(
        tmp_path,
        {
            "deep.py": "from sentence_transformers import SentenceTransformer\n"
            f'st0 = SentenceTransformer\n{chain}\n{deep}()\nst5("all-MiniLM-L6-v2")\n'
        },
    )
    # Under 25 attributes, what ``st5`` is lies past the depth bound. Read directly it
    # is within it, and what was cut short before is worked out again.
    assert set(models(result)) == {"all-MiniLM-L6-v2"}
    assert list(result.surfaces_excluded) == [f"deep.py:1: {CUT}"]


def test_bindings_past_the_bound_are_not_skipped_in_silence(tmp_path: Path):
    bound = "\n".join(["NAME = NAME"] * 16 + ['NAME = "gpt-4o"', 'NAME = "o3"'])
    result = scan(
        tmp_path,
        {"rest.py": f"from openai import OpenAI\n{bound}\nOpenAI().responses.create(model=NAME)\n"},
    )
    # Bindings of the name to itself spend the depth bound; what is left is a gap.
    assert set(models(result)) == {"gpt-4o"}
    assert list(result.surfaces_excluded) == [unread("rest.py", 20), f"rest.py:1: {CUT}"]


def test_conditionals_nested_past_the_depth_bound_say_so(tmp_path: Path):
    nested = '"m-0"'
    for index in range(1, 30):
        nested = f'("m-{index}" if flag else {nested})'
    result = scan(
        tmp_path,
        {
            "cond.py": f"from openai import OpenAI\nflag = 1\nOpenAI().responses.create(model={nested})\n"
        },
    )
    found = set(models(result))
    assert "m-29" in found and "m-0" not in found
    assert list(result.surfaces_excluded) == [f"cond.py:1: {CUT}"]


NOT_AN_SDK = """\
import logging
from openai import OpenAI
from prometheus_client import Counter

REQUESTS = Counter("requests", "Requests", ["model"])
log = logging.getLogger(__name__)


def render(**fields): ...


REQUESTS.labels(model="fallback")
log.info("routed", model="primary-pool")
render(model="OrderInvoice")
dict(model="Customer")
"{model}".format(model="Template")
OpenAI().responses.create(model="gpt-4o")
"""


def test_a_call_into_another_library_or_a_builtin_is_not_read(tmp_path: Path):
    result = scan(tmp_path, {"app.py": NOT_AN_SDK})
    assert set(models(result)) == {"gpt-4o"}
    # A function of the project may hand its argument to an SDK, which is not followed.
    assert list(result.surfaces_excluded) == [f"app.py:14: a model argument is {GIVEN}"]


TEXT_CALLS = """\
import os
from dataclasses import field
from openai import OpenAI
from pydantic import Field

CHAT = Field(default="gpt-4o-mini")
EMBED = field(default="text-embedding-3-small")
client = OpenAI()
client.responses.create(model=CHAT)
client.embeddings.create(model=EMBED)
client.responses.create(model=Field("gpt-4.1"))
client.responses.create(model=str("o3"))
client.responses.create(model="GPT-4O".lower())
client.responses.create(model=cfg.field("llm-tier"))
client.responses.create(model="{}-{}".format("gpt", "4o"))
client.responses.create(model=os.getenv("M"))
client.responses.create(model="my model v2")
client.responses.create(model="weights/final.pickle")
client.responses.create(model="default")
"""


def test_text_a_call_gives_back_is_read_only_where_its_callee_is_known(tmp_path: Path):
    result = scan(tmp_path, {"text.py": TEXT_CALLS})
    assert set(models(result)) == {
        "gpt-4o-mini",
        "text-embedding-3-small",
        "gpt-4.1",
        "o3",
        "gpt-4o",
    }
    # A field of anything else, a format, a variable named so it is not exported, text
    # that is no identifier and a weight file are unread; ``default`` names none.
    assert list(result.surfaces_excluded) == [unread("text.py", 14, 5)]


def test_positional_models_of_common_entry_points_are_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "import litellm\nimport ollama\nfrom pydantic_ai import Agent\n\n"
            'Agent("openai:gpt-4o")\nlitellm.completion("gpt-4o-mini", [])\n'
            'ollama.chat("llama3.2", messages=[])\n'
        },
    )
    found = models(result)
    assert set(found) == {"gpt-4o", "gpt-4o-mini", "llama3.2"}
    assert found["gpt-4o"].provider == "openai"


def test_a_reference_another_collector_contradicts_is_not_vouched_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = write(
        tmp_path,
        {
            "app/client.py": 'from openai import OpenAI\n\nOpenAI().responses.create(model="gpt-4o")\n',
            "CLAUDE.md": "Be brief.\n",
        },
    )
    (root / "weights.pkl").write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
    # The two collectors name different subjects by one reference.
    monkeypatch.setattr(source_references, "model_ref", lambda name: "model:weights.pkl")
    report = CompletenessValidator().validate_against_project(AIBOM(components=[]), root)
    assert any(
        "Conflicting local reference: model:weights.pkl" in i.description for i in report.issues
    )
    assert report.bound_references == frozenset()


EDGES = """\
import os
from openai import OpenAI

client = OpenAI()
first, *rest = ["gpt-4o", "o3"]
client.responses.create(model=rest)
[(chosen := "gpt-4.1") for _ in range(1)]
client.responses.create(model=chosen)
client.responses.create(model=f"{'gpt-4o'!r}")
client.responses.create(model=f"{'gpt':>8}")
client.responses.create(model="ft:gpt-4o-mini:acme::abc123")
match {"MODEL": "o1"}:
    case {"MODEL": _, **others}:
        client.responses.create(model=others)
"""


def test_the_rules_at_the_edges_of_a_binding(tmp_path: Path):
    result = scan(tmp_path, {"edges.py": EDGES})
    found = models(result)
    # An assignment expression in a comprehension binds the name around it.
    assert set(found) == {"gpt-4.1", "ft:gpt-4o-mini:acme::abc123"}
    assert found["ft:gpt-4o-mini:acme::abc123"].model_type == "fine-tuned"
    # A starred name, a converted or formatted value and a pattern's rest are unread.
    assert list(result.surfaces_excluded) == [unread("edges.py", 6, 4)]


def test_more_texts_than_one_argument_keeps_say_so(tmp_path: Path):
    names = "\n".join(f'A{index} = "gpt-4o-{index}"' for index in range(10))
    choose = "A = " + " or ".join(f"A{index}" for index in range(10))
    halves = 'L = "a" or "b" or "c" or "d"\nR = "e" or "f"\n'
    joined = "\n".join('N = f"{L}-{R}"' for _ in range(3))
    result = scan(
        tmp_path,
        {
            "many.py": f"import os\nfrom openai import OpenAI\n{names}\n{choose}\n{halves}"
            f"{joined}\n"
            'OpenAI().responses.create(model=os.getenv("CHAT_MODEL", A))\n'
            "OpenAI().responses.create(model=N)\n"
        },
    )
    # Eight of the ten defaults, and sixteen of the twenty-four joined texts.
    assert len(models(result)) == 8 + 8
    assert list(result.surfaces_excluded) == [f"many.py:1: {CUT}"]


def test_only_text_is_recorded_as_a_model():
    declarations = Declarations(ScanResult(scanner_name="source"))
    assert declarations.model(3, "a.py", 1, method="python-ast") is None
    assert declarations.model("gpt-4o", "a.py", 1, method="python-ast") == "model:source:gpt-4o"


def test_a_file_named_for_credentials_is_not_read(tmp_path: Path):
    body = 'from openai import OpenAI\n\nOpenAI().chat.completions.create(model="gpt-4o")\n'
    result = scan(tmp_path, {"secrets.py": body, "config/secrets/client.py": body})
    assert result.components == [] and not result.surfaces_excluded


def test_an_excluded_path_is_not_read(tmp_path: Path):
    body = 'from openai import OpenAI\n\nOpenAI().chat.completions.create(model="gpt-4o")\n'
    write(tmp_path, {"vendor/client.py": body, "app/client.py": body.replace("gpt-4o", "o3")})
    scanner = SourceScanner()
    scanner.configure(exclude_paths=["vendor"])
    assert set(models(scanner.scan(tmp_path))) == {"o3"}


@pytest.mark.parametrize(
    ("literal", "accepted"),
    [
        ("gpt-4o", True),
        (" gpt-4o ", True),
        ("anthropic.claude-3-5-sonnet-20241022-v2:0", True),
        ("BAAI/bge-small-en-v1.5", True),
        ("ft:gpt-4o-mini-2024-07-18:acme:support:AbCd1234", True),
        ("", False),
        ("x", False),
        ("1234", False),
        ("model", False),
        ("two words", False),
        ("./models/llama", False),
        ("~/models/llama", False),
        ("weights.safetensors", False),
        ("https://api.example.com/v1", False),
        ("a" * 129, False),
        (PLANTED, False),
        (42, False),
        (None, False),
    ],
)
def test_what_can_be_recorded_as_a_model_identifier(literal: object, accepted: bool):
    assert (model_identifier(literal) is not None) is accepted


@pytest.mark.parametrize(
    ("literal", "weights", "expected"),
    [
        ("openai/gpt-4o", False, ("gpt-4o", "openai")),
        ("anthropic:claude-sonnet-4-5", False, ("claude-sonnet-4-5", "anthropic")),
        (
            "bedrock/anthropic.claude-3-haiku-20240307-v1:0",
            False,
            ("anthropic.claude-3-haiku-20240307-v1:0", "aws-bedrock"),
        ),
        ("llama3.1:8b", False, ("llama3.1:8b", None)),
        ("openai/", False, ("openai/", None)),
        ("openai/x", False, ("openai/x", None)),
        ("openai/whisper-large-v3", False, ("openai/whisper-large-v3", None)),
        ("openai/gpt-4o", True, ("openai/gpt-4o", None)),
        ("mistralai/Mistral-7B-Instruct-v0.3", False, ("mistralai/Mistral-7B-Instruct-v0.3", None)),
        ("mistralai:mistral-large-latest", False, ("mistral-large-latest", "mistral")),
        ("meta-llama/Llama-3.3-70B-Instruct", False, ("meta-llama/Llama-3.3-70B-Instruct", None)),
    ],
)
def test_a_routing_prefix_is_split_from_the_identifier(
    literal: str, weights: bool, expected: tuple[str, str | None]
):
    assert split_route(literal, weights=weights) == expected


@pytest.mark.parametrize(
    ("name", "accepted"),
    [
        ("CHAT_MODEL", True),
        ("model", True),
        ("1MODEL", False),
        ("has space", False),
        (PLANTED, False),
        (7, False),
    ],
)
def test_which_names_are_exported_as_environment_variables(name: object, accepted: bool):
    assert (environment_name(name) is not None) is accepted


def test_the_number_of_model_identifiers_is_bounded(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(source_references, "MAX_RECORDS", 3)
    result = ScanResult(scanner_name="source")
    found = Declarations(result)
    for index in range(6):
        found.model(f"gpt-4o-{index}", "a.py", index + 1, method="python-ast")
    assert found.model("gpt-4o-0", "b.py", 1, method="python-ast") == "model:source:gpt-4o-0"
    assert len(found.components()) == 3
    assert list(result.scan_failures) == [
        "source: more than 3 model identifiers; the rest were not recorded"
    ]


def run_scan(runner, root: Path, *extra: str) -> tuple[AIBOM, Path]:
    out = root.parent / f"{root.name}.json"
    result = runner.invoke(
        main,
        ["scan", str(root), "--no-project-policy", "-o", str(out), *extra],
        catch_exceptions=False,
    )
    assert out.exists(), result.output
    return AIBOM.model_validate_json(out.read_text(encoding="utf-8")), out


def test_a_scan_records_the_collector_and_relates_its_models_to_the_repository(
    runner, tmp_path: Path
):
    bom, _ = run_scan(runner, write(tmp_path / "project", {"app/client.py": CLIENT}))
    claim = bom.metadata.completeness
    assert claim.scanner_status["source"] == "complete"
    assert "source" in claim.collectors_requested and "source" in claim.collectors_completed
    model = next(c for c in bom.components if c.bom_ref == "model:source:gpt-4o-mini")
    repository = next(c for c in bom.components if c.bom_ref.startswith("agent:repository:"))
    assert model.bom_ref in repository.model_refs
    assert {
        (edge.relationship, edge.assurance_level)
        for edge in bom.dependencies
        if edge.source_ref == repository.bom_ref and edge.target_ref == model.bom_ref
    } == {("uses-model", "declared")}
    assert model.claims["repository_presence"].collector == "source"


def test_only_the_source_collector_can_be_selected(runner, tmp_path: Path):
    bom, _ = run_scan(
        runner, write(tmp_path / "project", {"app/client.py": CLIENT}), "--scanner", "source"
    )
    assert bom.metadata.completeness.collectors_requested == ["source"]
    assert {c.name for c in bom.components if isinstance(c, ModelComponent)} == {
        "claude-sonnet-4-5",
        "gpt-4o-mini",
        "text-embedding-3-small",
    }


def test_a_reference_read_again_from_source_validates_and_a_changed_one_does_not(
    runner, tmp_path: Path
):
    # An instruction file gives the inventory one digest that validation can verify.
    root = write(tmp_path / "project", {"app/client.py": CLIENT, "CLAUDE.md": "Be brief.\n"})
    _, out = run_scan(runner, root)
    reconciled = runner.invoke(
        main, ["validate", str(out), "--project", str(root), "--no-project-policy"]
    )
    assert reconciled.exit_code == 0, reconciled.output
    assert (
        "INFO [model:source:gpt-4o-mini] Model identifier declared in source, with no artifact: "
        "Model artifact digest is unavailable" in reconciled.output
    )
    # Without the project, nothing read the reference again: its artifact stays unknown.
    alone = runner.invoke(main, ["validate", str(out), "--no-project-policy"])
    assert alone.exit_code == 1 and "UNKNOWN [model:source:gpt-4o-mini]" in alone.output
    (root / "app" / "client.py").write_text(CLIENT.replace("gpt-4o-mini", "gpt-4.1"), "utf-8")
    drifted = runner.invoke(
        main, ["validate", str(out), "--project", str(root), "--no-project-policy"]
    )
    assert drifted.exit_code == 1
    assert "model:source:gpt-4o-mini" in drifted.output


def test_only_a_reconciled_reference_without_an_artifact_is_reported_as_information():
    reference = ModelComponent(
        bom_ref="model:source:gpt-4o",
        name="gpt-4o",
        properties={"collection_mode": "static-source-reference"},
    )
    weights = reference.model_copy(update={"hashes": {"sha256": "0" * 64}})
    located = reference.model_copy(update={"source_path": "models/weights.bin"})
    other = reference.model_copy(update={"properties": {"collection_mode": "static-config"}})
    # Each of these claims something only an artifact can establish.
    claimed = [
        reference.model_copy(update={name: value})
        for name, value in [
            ("serialization_safety", SerializationSafety.SAFE),
            ("tokenizer_hash", "sha256:" + "1" * 64),
            ("chat_template_hash", "sha256:" + "2" * 64),
            ("trust_remote_code", False),
            ("signing_status", "verified"),
        ]
    ]
    assert is_source_reference(reference)
    assert not any(is_source_reference(c) for c in (weights, located, other, *claimed))

    def severities(component: ModelComponent, bound: frozenset[str]) -> set[str]:
        report = IntegrityValidator().validate(
            AIBOM(components=[component]), bound_references=bound
        )
        return {i.severity for i in report.issues if i.component_ref == component.bom_ref}

    bound = frozenset({reference.bom_ref})
    assert severities(reference, bound) == {"info"}
    assert severities(reference, frozenset()) == {"unknown"}
    # A supplied record that only claims the mode, and has what an artifact gives, is
    # judged as any model is.
    for record in (weights, located, other, *claimed):
        assert "info" not in severities(record, bound), record


def test_an_unsafe_format_claim_on_a_reference_still_fails(tmp_path: Path):
    reference = ModelComponent(
        bom_ref="model:source:gpt-4o",
        name="gpt-4o",
        trust_remote_code=True,
        properties={"collection_mode": "static-source-reference"},
    )
    report = IntegrityValidator().validate(
        AIBOM(components=[reference]), bound_references=frozenset({reference.bom_ref})
    )
    assert "critical" in {issue.severity for issue in report.issues}
    assert not report.is_valid


def test_a_project_without_ai_source_gains_no_component(runner, tmp_path: Path):
    bom, _ = run_scan(
        runner, write(tmp_path / "project", {"app.py": "print('hello')\n", "README.md": "# x\n"})
    )
    assert [c for c in bom.components if ":source:" in c.bom_ref] == []
    assert bom.metadata.completeness.scanner_status["source"] == "complete"
