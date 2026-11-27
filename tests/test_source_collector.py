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
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.integrity import IntegrityValidator
from tests.support import load_script

PLANTED = "sk-proj-" + "Zq7" * 16
UNREAD = "bound to a value the collector cannot read as a model; not inventoried"
GIVEN = "given to a callee the project defines, which is not followed; not inventoried"


def unread_gap(path: str, line: int, count: int = 1) -> str:
    return unread(path, line, count)


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
from openai import OpenAI

# client.chat.completions.create(model="gpt-4-turbo", messages=[])
client = OpenAI()


def answer(question: str) -> str:
    reply = client.chat.completions.create(model="gpt-4o-mini", messages=[])
    client.embeddings.create(model="text-embedding-3-small", input=question)
    return reply
'''


@pytest.fixture
def client(tmp_path: Path) -> ScanResult:
    return scan(tmp_path, {"app/client.py": CLIENT})


def test_a_literal_model_argument_is_recorded_with_where_it_was_read(client: ScanResult):
    found = models(client)
    assert set(found) == {"gpt-4o-mini", "text-embedding-3-small"}
    mini = found["gpt-4o-mini"]
    assert mini.bom_ref == "model:source:gpt-4o-mini"
    assert mini.assurance_level is AssuranceLevel.DECLARED
    assert mini.properties == {
        "collection_mode": "static-source-reference",
        "method": "python-ast",
        "declaration_line": 9,
        "reference_path": "app/client.py",
    }
    claim = mini.claims["source_reference"]
    assert (claim.locator, claim.collector, claim.assurance) == (
        "app/client.py:9",
        "source",
        AssuranceLevel.DECLARED,
    )
    # A weight file is what ``source_path`` names on a model; a reference has none.
    assert mini.source_path is None and mini.hashes == {} and mini.provider is None
    assert found["text-embedding-3-small"].model_type == "embedding"
    assert not client.surfaces_excluded and not client.scan_failures


@pytest.mark.parametrize(
    ("argument", "expected", "unread"),
    [
        ('"gpt-4o"', ["gpt-4o"], 0),
        ("42", [], 0),
        ("None", [], 0),
        ('"default"', [], 0),
        ('"my model v2"', [], 1),
        ("NAME", ["gpt-4.1"], 0),
        ('f"{NAME}"', ["gpt-4.1"], 0),
        ('os.getenv("CHAT_MODEL", "gpt-4o")', ["gpt-4o"], 0),
        # The variable that may override the default is named so it is not exported.
        ('os.getenv("M", "gpt-4o")', ["gpt-4o"], 1),
        ("OpenAIChatModel('gpt-4.1')", ["gpt-4.1"], 0),
        ("get_peft_model(base)", [], 0),
        ("[NAME]", [], 1),
        ("DEFAULT_MODEL", [], 1),
        ("pydantic_ai.DEFAULT", [], 1),
        # What another library makes, such as configuration it reads, may be any text.
        ("yaml.safe_load(TEXT)", [], 1),
    ],
)
def test_text_a_value_spells_is_read_and_any_other_value_is_unread_unless_a_library_builds_it(
    tmp_path: Path, argument: str, expected: list[str], unread: int
):
    result = scan(
        tmp_path,
        {
            "run.py": f"""\
import os
import pydantic_ai
import yaml
from openai import OpenAI
from peft import get_peft_model
from pydantic_ai.models.openai import OpenAIChatModel
from shared_defaults import DEFAULT_MODEL

NAME = "gpt-4.1"
OpenAI().chat.completions.create(model={argument}, messages=[])
"""
        },
    )
    # An object an SDK makes is no text; a library's name, attribute or value may be.
    assert sorted(models(result)) == sorted(expected)
    assert list(result.surfaces_excluded) == ([unread_gap("run.py", 10)] if unread else [])


def test_a_docstring_and_a_comment_declare_nothing(client: ScanResult):
    assert not {"gpt-3.5-turbo", "gpt-4-turbo"} & set(models(client))


def test_the_surfaces_say_what_was_and_was_not_read(client: ScanResult):
    assert client.surfaces_scanned == [
        "source: declarations in application source (static)",
        "source: tests, documentation, examples, benchmarks and build output are not read",
    ]


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
    # A literal that holds a token shape is no model. A variable named with one is not
    # exported: its default is recorded, and what it may set instead is unread.
    assert set(models(result)) == {"gpt-4o"}
    assert list(result.surfaces_excluded) == [unread("bot.py", 5, 4)]


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
        + "not read as the SDK"
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


def test_words_that_name_no_model_are_not_models(tmp_path: Path):
    arguments = ["default", "auto", "weights/llama.gguf", "https://x.example/v1", "two words", "x"]
    calls = "\n".join(f"client.chat.completions.create(model={word!r})" for word in arguments)
    result = scan(tmp_path, {"run.py": f"from openai import OpenAI\nclient = OpenAI()\n{calls}\n"})
    assert result.components == []


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


def test_a_model_bound_in_another_module_of_the_project_is_a_gap(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "app/settings.py": 'MODEL = "gpt-4o"\n',
            "app/run.py": """\
from openai import OpenAI
from . import settings
from .settings import MODEL

OpenAI().chat.completions.create(model=MODEL, messages=[])
OpenAI().chat.completions.create(model=settings.MODEL, messages=[])
""",
        },
    )
    assert result.components == []
    gap = (
        "model argument is bound in another module of the project, which the collector does "
        "not follow; not inventoried"
    )
    assert list(result.surfaces_excluded) == [f"app/run.py:5: {gap}", f"app/run.py:6: {gap}"]


def test_source_that_names_an_sdk_and_cannot_be_read_is_a_gap(tmp_path: Path):
    write(tmp_path, {"broken.py": "from openai import OpenAI\n\ndef (:\n", "plain.py": "def (:\n"})
    (tmp_path / "latin.py").write_bytes(b"from openai import OpenAI\nNAME = '\xe9'\n")
    (tmp_path / "other.py").write_bytes(b"NAME = '\xe9'\n")
    result = SourceScanner().scan(tmp_path)
    assert sorted(result.surfaces_excluded) == [
        "broken.py:1: Python source could not be parsed; not read",
        "latin.py: source file cannot be decoded as its encoding declares; declarations in it "
        + "were not read",
    ]


def test_source_is_decoded_as_its_coding_line_declares(tmp_path: Path):
    (tmp_path / "latin.py").write_bytes(
        b"# -*- coding: latin-1 -*-\nfrom openai import OpenAI\nNOTE = '\xe9'\n"
        b'OpenAI().responses.create(model="gpt-4o")\n'
    )
    result = SourceScanner().scan(tmp_path)
    assert set(models(result)) == {"gpt-4o"} and not result.surfaces_excluded


@pytest.mark.parametrize(
    "content",
    [
        b"# graphics that phi may name\nprint 'Python 2'\n",
        b"# -*- coding: latin-1 -*-\ncamelCase = '\xe9'\nprint 'Python 2'\n",
        b"from google.protobuf import descriptor\n" + b"x = 1\n" * 40,
        b"text = 'import openai'\nprint 'Python 2'\n",
    ],
    ids=["word", "word-latin", "protobuf", "string"],
)
def test_a_file_that_imports_no_sdk_is_not_parsed_whatever_words_it_holds(
    tmp_path: Path, content: bytes
):
    (tmp_path / "plain.py").write_bytes(content)
    with limits.applied(limits.resolve(["syntax-bytes=256"], {})):
        result = SourceScanner().scan(tmp_path)
    assert result.components == [] and not result.surfaces_excluded


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
        + "not read"
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
    # Past the directories looked in, a shadowing module may still be there: it says so.
    assert set(models(distant)) == {"gpt-4o"}
    assert list(distant.surfaces_excluded) == [f"top/{far}/main.py:1: {CUT}"]


def test_a_directory_inside_a_package_is_no_import_root(tmp_path: Path):
    source = 'from agents import Agent\n\nAgent(name="a", model="gpt-4.1")\n'
    result = scan(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/agents/__init__.py": "class Agent: ...\n",
            "main.py": source,
            "app/run.py": "from agents.researcher import Researcher\n",
            "agents_project/agents/researcher.py": "class Researcher: ...\n",
        },
    )
    # ``app`` is a package, so ``app/agents`` does not shadow the SDK for ``main.py``.
    assert set(models(result)) == {"gpt-4.1"}
    assert not result.surfaces_excluded


def test_a_module_path_that_only_the_project_has_is_the_projects(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "agents/__init__.py": "",
            "agents/researcher.py": "class Researcher: ...\n",
            "main.py": "from agents.researcher import Researcher\n\nResearcher()\n",
        },
    )
    assert result.components == [] and not result.surfaces_excluded


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
    assert set(found) == {"acme-search-v2", "gpt-4.1", "gpt-4o", "openai/clip-vit-base-patch32"}
    # The annotated parameter is an OpenAI client, so the call is an embeddings call.
    assert found["acme-search-v2"].model_type == "embedding"
    # A parameter and an item of a dictionary are unread; joined text is read. The
    # project's own loader is given no model argument the reader knows of, but where it
    # hands its parameter to the SDK, that is unread.
    assert list(result.surfaces_excluded) == [unread("run.py", 10, 2)]


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
    (tmp_path / "app" / "text.py").symlink_to("real.txt")
    (tmp_path / "app" / "real.txt").write_text(body.format("through-a-text-file"))
    result = SourceScanner().scan(tmp_path)
    # A file named for credentials is read like any other. A test is not, and a link from
    # the application to one may hide what it runs, so it is a gap.
    assert set(models(result)) == {"through-a-link", "from-secrets", "through-a-text-file"}
    reference = models(result)["through-a-link"].claims["source_reference"]
    assert reference.evidence_refs == ["app/alias.py:3", "app/real.py:3"]
    assert list(result.surfaces_excluded) == [
        "app/prod.py: source file links to a file the collector does not read; not read"
    ]


def test_a_link_that_changes_after_it_was_checked_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    body = 'from openai import OpenAI\n\nOpenAI().responses.create(model="{}")\n'
    write(tmp_path, {"app/real.py": body.format("o3"), "tests/helper.py": body.format("x")})
    (tmp_path / "app" / "alias.py").symlink_to("real.py")
    monkeypatch.setattr(
        ConfinedCollection,
        "link_target",
        lambda self, path: "tests/helper.py" if str(path).endswith("alias.py") else None,
    )
    result = SourceScanner().scan(tmp_path)
    assert models(result)["o3"].claims["source_reference"].locator == "app/real.py:3"
    assert not result.components[0].claims["source_reference"].evidence_refs


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


def test_only_text_is_recorded_as_a_model():
    declarations = Declarations(ScanResult(scanner_name="source"))
    assert declarations.model(3, "a.py", 1, method="python-ast") is None
    assert declarations.model("gpt-4o", "a.py", 1, method="python-ast") == "model:source:gpt-4o"


def test_a_file_named_for_credentials_is_read_and_its_values_are_not_exported(tmp_path: Path):
    body = (
        f'from openai import OpenAI\n\nOpenAI(api_key="{PLANTED}").chat.completions.create('
        'model="gpt-4o")\n'
    )
    result = scan(tmp_path, {"secrets.py": body, "config/secrets/client.py": body})
    assert set(models(result)) == {"gpt-4o"} and not result.surfaces_excluded
    assert PLANTED not in exported(result)


FRAMEWORK = """\
import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import Request
from flask import g
from langchain_openai import ChatOpenAI
from openai import OpenAI

sync_client = OpenAI()


async def chat(request: Request):
    client = request.app.state.openai
    await client.chat.completions.create(model="gpt-4o")


def ask(client: Any, other: object):
    client.chat.completions.create(model="o3")
    other.chat.completions.create(model="o3-mini")
    g.llm.chat.completions.create(model="o1")


functools.partial(sync_client.chat.completions.create, model="gpt-4o-mini")
asyncio.to_thread(sync_client.chat.completions.create, model="o4-mini")
with ThreadPoolExecutor() as pool:
    pool.submit(sync_client.chat.completions.create, model="gpt-4.1")


class Tuned(ChatOpenAI):
    def __init__(self):
        super().__init__(model="gpt-4.1-mini")


REQUEST = {"model": "gpt-4.1-nano"}
sync_client.chat.completions.create(**REQUEST)
sync_client.chat.completions.create(model="gpt-4o", **{"temperature": 0})
"""


def test_a_client_reached_through_a_framework_or_a_forwarder_is_read(tmp_path: Path):
    result = scan(tmp_path, {"framework.py": FRAMEWORK})
    # A framework's state, an untyped parameter, ``partial``, ``to_thread``, an
    # executor and ``super()`` in a subclass of an SDK class all lead to a model.
    assert set(models(result)) == {
        "gpt-4o",
        "o3",
        "o3-mini",
        "o1",
        "gpt-4o-mini",
        "o4-mini",
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4.1-nano",
    }
    # A dict the file only spreads is read; beside a model keyword, ``**`` gives none.
    assert not result.surfaces_excluded


def test_a_client_a_project_function_or_module_makes_is_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/llm.py": "from openai import OpenAI\n\nclient = OpenAI()\n",
            "app/run.py": """\
import functools

from openai import OpenAI

from app.llm import client


@functools.lru_cache
def get_client():
    return OpenAI()


class Wrapper:
    def create(self, **options): ...


get_client().chat.completions.create(model="gpt-4o")
client.chat.completions.create(model="o3")
Wrapper().create(model="gpt-4.1")
""",
        },
    )
    # A method of an object of a project class is the project's to give.
    assert set(models(result)) == {"gpt-4o", "o3"}
    assert list(result.surfaces_excluded) == [f"app/run.py:19: a model argument is {GIVEN}"]


def test_names_bound_in_other_ways_still_tell_what_a_callee_is(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
import google.genai
from openai import *

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = None

loader = None


def configure():
    global loader
    loader = SentenceTransformer


google.genai.Client().models.generate_content(model="gemini-2.5-flash", contents="hi")
OpenAI().responses.create(model="gpt-4o")
SentenceTransformer("all-MiniLM-L6-v2")
loader("all-mpnet-base-v2")
SentenceTransformer(*ARGS)
"""
        },
    )
    # An unaliased namespace import, a star import, an optional import's fallback and a
    # ``global`` binding are each read; a starred positional argument is unread.
    assert set(models(result)) == {
        "gemini-2.5-flash",
        "gpt-4o",
        "all-MiniLM-L6-v2",
        "all-mpnet-base-v2",
    }
    assert list(result.surfaces_excluded) == [unread("run.py", 21)]


BOUND_AGAIN = {
    "with-tuple": 'with OpenAI() as (client, other):\n    pass\nclient.create(model="gpt-4o")\n',
    "keyword-only-default": "def run(*, client: logging.Logger = OpenAI()):\n"
    '    client.create(model="gpt-4o")\n',
    "nonlocal-from-a-method": "def outer():\n"
    '    client = logging.getLogger("y")\n\n'
    "    class Holder:\n"
    "        def set(self):\n"
    "            nonlocal client\n"
    "            client = OpenAI()\n\n"
    "    Holder().set()\n"
    '    client.create(model="gpt-4o")\n',
    "assignment-expression-in-a-comprehension": "clients = [(client := OpenAI()) for _ in range(1)]\n"
    'client.create(model="gpt-4o")\n',
    "starred-target": 'first, *client = make()\nclient.create(model="gpt-4o")\n',
    "match-mapping-rest": "match make():\n"
    '    case {"kind": "chat", **client}:\n'
    '        client.create(model="gpt-4o")\n',
}


@pytest.mark.parametrize("bound", list(BOUND_AGAIN.values()), ids=list(BOUND_AGAIN))
def test_a_name_bound_again_in_any_form_is_not_taken_for_a_library_alone(
    tmp_path: Path, bound: str
):
    # Each name is first a logger. If the second binding were missed, the call would be
    # skipped as a method of a standard-library object, silently.
    source = 'import logging\nfrom openai import OpenAI\n\nclient = logging.getLogger("x")\n'
    result = scan(tmp_path, {"run.py": source + bound})
    assert set(models(result)) == {"gpt-4o"}


def test_a_starred_parameter_is_the_functions_own_name(tmp_path: Path):
    source = (
        "import logging\nfrom openai import OpenAI\n\n"
        'log = logging.getLogger("x")\n\n\n'
        "def run(*log, **clients):\n"
        '    log.create(model="gpt-4o")\n'
        '    clients.create(model="o3")\n\n\n'
        'clients = logging.getLogger("y")\n'
    )
    result = scan(tmp_path, {"run.py": source})
    # Inside ``run`` neither name is the module's logger, so the calls are not skipped.
    assert set(models(result)) == {"gpt-4o", "o3"}


def test_a_method_of_what_python_builds_is_not_read(tmp_path: Path):
    source = (
        "import logging\nfrom openai import OpenAI\n\n"
        'client = logging.getLogger("x")\n'
        'client.create(model="gpt-4o")\n'
        'line = "Using {model}".format(model="gpt-4o")\n'
        "params = {}\n"
        'params.update(model="gpt-4o")\n'
        "OpenAI().responses.create(**params)\n"
    )
    result = scan(tmp_path, {"run.py": source})
    # A logger's, a string's and a dict's methods take no model; what the SDK call is
    # given through ``**params`` is unread.
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("run.py", 9)]


def test_an_sdk_imported_only_with_a_star_is_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {"run.py": 'from openai import *\n\nOpenAI().responses.create(model="gpt-4o")\n'},
    )
    assert set(models(result)) == {"gpt-4o"}


def test_an_sdk_imported_by_its_full_dotted_name_alone_is_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "gem.py": "import google.genai\n\n"
            'google.genai.Client().models.generate_content(model="gemini-2.5-flash", contents="x")\n'
        },
    )
    assert set(models(result)) == {"gemini-2.5-flash"}


def test_a_class_attribute_of_the_same_module_is_unread_not_another_modules(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "import enum\nfrom openai import OpenAI\n\n\nclass Model(enum.Enum):\n"
            '    FAST = "gpt-4o-mini"\n\n\nOpenAI().responses.create(model=Model.FAST)\n'
        },
    )
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("run.py", 9)]


def test_a_model_that_runs_its_own_code_is_not_a_bare_reference(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "load.py": "from transformers import AutoModelForCausalLM\n\n"
            'AutoModelForCausalLM.from_pretrained("someorg/custom-7b", trust_remote_code=True)\n'
            'AutoModelForCausalLM.from_pretrained("someorg/plain-7b")\n'
        },
    )
    found = models(result)
    assert found["someorg/custom-7b"].trust_remote_code is True
    assert found["someorg/plain-7b"].trust_remote_code is None
    # So validation judges it as any model with an artifact to verify.
    assert not is_source_reference(found["someorg/custom-7b"])
    assert is_source_reference(found["someorg/plain-7b"])


@pytest.mark.parametrize(
    "value",
    ["0123456789abcdef0123456789abcdef", "admin:hunter22@db.internal", "wJalrXUtnFEMI" * 4],
)
def test_a_value_shaped_like_a_secret_is_no_model_and_is_not_exported(tmp_path: Path, value: str):
    result = scan(
        tmp_path,
        {"run.py": f'from openai import OpenAI\n\nOpenAI().responses.create(model="{value}")\n'},
    )
    assert result.components == [] and value not in exported(result)
    assert list(result.surfaces_excluded) == [unread("run.py", 3)]


def test_a_file_that_cannot_be_opened_is_a_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    write(tmp_path, {"app/client.py": CLIENT})
    monkeypatch.setattr(ConfinedCollection, "regular_file", lambda self, path: None)
    result = SourceScanner().scan(tmp_path)
    assert result.components == []
    assert list(result.surfaces_excluded) == [
        "app/client.py: source file could not be read; not read"
    ]


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
        "gpt-4o-mini",
        "text-embedding-3-small",
    }


def test_a_project_without_ai_source_gains_no_component(runner, tmp_path: Path):
    bom, _ = run_scan(
        runner, write(tmp_path / "project", {"app.py": "print('hello')\n", "README.md": "# x\n"})
    )
    assert [c for c in bom.components if ":source:" in c.bom_ref] == []
    assert bom.metadata.completeness.scanner_status["source"] == "complete"


# -- the third review -------------------------------------------------------------------


def test_an_import_in_a_function_binds_there_and_nowhere_else(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from sentence_transformers import SentenceTransformer


def helper():
    from mylib import SentenceTransformer

    return SentenceTransformer("not-a-model-here")


def loader():
    from ollama import Client

    return Client().chat(model="llama3")


SentenceTransformer("all-MiniLM-L6-v2")
"""
        },
    )
    # The module's name is still the SDK's, and the function's own import is its own.
    assert set(models(result)) == {"all-MiniLM-L6-v2", "llama3"}
    assert not result.surfaces_excluded


@pytest.mark.parametrize(
    "source",
    [
        "try: import openai\nexcept ImportError: pass\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING: from openai import OpenAI\n\n\n"
        + "def ask(client: OpenAI):\n    client.responses.create(model='gpt-4o')\n",
        "import os; import openai\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
        "from \\\n    openai import OpenAI\nOpenAI().responses.create(model='gpt-4o')\n",
        "import os\r# one\rimport openai\ropenai.OpenAI().responses.create(model='gpt-4o')\r",
        "\fimport openai\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
        "import os, \\\n    openai\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
        "import \uff4f\uff50\uff45\uff4e\uff41\uff49\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
    ],
    ids=[
        "try",
        "type-checking",
        "semicolon",
        "continued",
        "carriage-return",
        "form-feed",
        "continued-list",
        "compatibility-spelling",
    ],
)
def test_every_import_statement_python_runs_is_found(tmp_path: Path, source: str):
    (tmp_path / "run.py").write_bytes(source.encode())
    assert set(models(SourceScanner().scan(tmp_path))) == {"gpt-4o"}


def test_a_codec_the_reader_does_not_follow_is_a_gap(tmp_path: Path):
    # In UTF-7, ``+AGk-`` is ``i``: the import is there only once the text is decoded.
    (tmp_path / "seven.py").write_bytes(
        b"# coding: utf-7\n+AGk-mport openai\nopenai.OpenAI().responses.create(model='gpt-4o')\n"
    )
    result = SourceScanner().scan(tmp_path)
    assert result.components == []
    assert list(result.surfaces_excluded) == [
        "seven.py: source file cannot be decoded as its encoding declares; declarations in it "
        + "were not read"
    ]


def test_a_google_cloud_import_of_vertex_is_found(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "from google.cloud import aiplatform\n"
            'aiplatform.Endpoint("projects/p").predict(model="text-bison")\n'
        },
    )
    assert set(models(result)) == {"text-bison"}


def test_a_method_of_an_object_the_reader_cannot_tell_is_read_where_named_as_sdk_calls_are(
    tmp_path: Path,
):
    result = scan(
        tmp_path,
        {
            "run.py": """\
import mlflow
from django.contrib.contenttypes.models import ContentType
from openai import OpenAI


class Agent:
    @classmethod
    def create(cls, model):
        return OpenAI().responses.create(model=model)


def handle(metric, client, store, settings):
    metric.labels(model="thermostat-v2").inc()
    store.put(model="customer")
    settings.usage.objects.filter(model="invoice")
    ContentType.objects.get(app_label="blog", model="post")
    mlflow.pyfunc.log_model("x", model="summariser")
    client.chat.completions.create(model="gpt-4o")
    settings.llm.invoke("hi", model="o3")
    Agent.create(model="planner")
"""
        },
    )
    # A label, a store, a query and a logging call take no model; an SDK call does. What
    # a method of a project class is given is the project's to give.
    assert set(models(result)) == {"gpt-4o", "o3"}
    assert list(result.surfaces_excluded) == [
        unread("run.py", 9),
        f"run.py:20: a model argument is {GIVEN}",
    ]


@pytest.mark.parametrize(
    "client",
    [
        "from typing import Any\n\ndef ask(client: Any):\n    client.converse(modelId='nova')\n",
        "def ask(client: object):\n    client.chat(model='nova')\n",
        "from typing import cast, Any\nimport ollama\n\ncast(Any, ollama.Client()).chat(model='nova')\n",
        "CLIENTS = {}\nCLIENTS.get('x').chat(model='nova')\n",
        "from contextvars import ContextVar\nCURRENT = ContextVar('c')\nCURRENT.get().chat(model='nova')\n",
        "from mypy_boto3_bedrock_runtime import BedrockRuntimeClient\n\n"
        + "def ask(client: BedrockRuntimeClient):\n    client.converse(modelId='nova')\n",
    ],
    ids=["any", "object", "cast", "container", "context-variable", "type-stub"],
)
def test_an_object_typed_as_anything_is_read_as_one_the_reader_cannot_tell(
    tmp_path: Path, client: str
):
    result = scan(tmp_path, {"run.py": "import openai\n" + client})
    assert set(models(result)) == {"nova"}


def test_an_executor_and_a_mixin_lead_to_the_sdk(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from concurrent.futures import Executor
from langchain_openai import ChatOpenAI
from openai import OpenAI


class Logged:
    pass


class Tuned(Logged, ChatOpenAI):
    def __init__(self):
        super().__init__(model="gpt-4.1-mini")


def ask(pool: Executor):
    pool.submit(OpenAI().responses.create, model="o4-mini")
"""
        },
    )
    assert set(models(result)) == {"gpt-4.1-mini", "o4-mini"}


@pytest.mark.parametrize(
    "flag",
    [
        "trust_remote_code=TRUST",
        "trust_remote_code=args.trust",
        "model_kwargs={'trust_remote_code': True}",
    ],
    ids=["name", "attribute", "model-kwargs"],
)
def test_remote_code_that_is_not_a_false_literal_is_recorded(tmp_path: Path, flag: str):
    result = scan(
        tmp_path,
        {
            "run.py": "from transformers import AutoModel\nTRUST = True\n"
            f'AutoModel.from_pretrained("someorg/custom-7b", {flag})\n'
        },
    )
    model = models(result)["someorg/custom-7b"]
    assert model.trust_remote_code is True and not is_source_reference(model)


@pytest.mark.parametrize(
    ("directory", "imported"),
    [
        ("pkg", "a1.a2.a3.a4.a5.a6.a7.a8.a9"),
        ("/".join(f"d{index}" for index in range(34)), "helpers"),
    ],
    ids=["dotted-name", "directories"],
)
def test_a_bound_reached_through_a_kept_answer_is_a_gap_in_every_file(
    tmp_path: Path, directory: str, imported: str
):
    body = f'import openai\nfrom {imported} import run\nrun(model="gpt-4o")\n'
    result = scan(tmp_path, {f"{directory}/one.py": body, f"{directory}/two.py": body})
    assert sorted(result.surfaces_excluded) == [
        f"{directory}/one.py:1: {CUT}",
        f"{directory}/two.py:1: {CUT}",
    ]


def test_a_submodule_imported_from_a_project_package_is_the_projects(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "agents/__init__.py": "",
            "agents/researcher.py": "class Researcher: ...\n",
            "main.py": "from agents import researcher\n\nresearcher.Researcher()\n",
        },
    )
    assert result.components == [] and not result.surfaces_excluded


def test_a_relative_import_past_the_top_package_binds_nothing(tmp_path: Path):
    result = scan(
        tmp_path,
        {"app/run.py": "from .... import OpenAI\nimport openai\nOpenAI().create(model='gpt-4o')\n"},
    )
    assert set(models(result)) == {"gpt-4o"}


@pytest.mark.parametrize(
    ("literal", "recorded", "gap"),
    [
        ("C:/Users/alice/models/minilm", False, True),
        ("\\\\\\\\share\\\\models\\\\minilm", False, True),
        ("/opt/models/minilm", False, True),
        ("./checkpoints/final", False, False),
        ("model.safetensors", False, False),
        ("key-" + "0123456789abcdef" * 2, False, True),
        ("0123456789abcdef0123456789abcd-" + "0123456789abcdef0123456789abcd", False, True),
        ("anthropic:claude-3-5-sonnet@20240620", True, False),
        ("stability-ai/sdxl:" + "39ed52f2a78e934b" * 4, True, False),
    ],
    ids=[
        "drive",
        "share",
        "absolute",
        "relative",
        "weight-file",
        "hex-key",
        "split-hex",
        "versioned",
        "pinned",
    ],
)
def test_a_path_or_a_key_is_never_a_model_and_a_project_file_is_no_gap(
    tmp_path: Path, literal: str, recorded: bool, gap: bool
):
    result = scan(
        tmp_path,
        {
            "run.py": "from sentence_transformers import SentenceTransformer\n"
            f"SentenceTransformer({literal!r})\n"
        },
    )
    assert bool(result.components) is recorded
    assert (literal in exported(result)) is recorded
    assert bool(result.surfaces_excluded) is gap


def test_each_file_is_read_as_it_is_given_and_only_the_first_places_are_kept(tmp_path: Path):
    found = Declarations(ScanResult(scanner_name="source"))
    reader = source_python.PythonReader(found, frozenset({"a.py", "b.py"}))
    calls = "\n".join('OpenAI().responses.create(model="gpt-4o")' for _ in range(40))
    reader.add("a.py", f"from openai import OpenAI\n{calls}\n")
    # Read as it was given, before any other file.
    assert [component.name for component in found.components()] == ["gpt-4o"]
    reader.add("b.py", "from openai import OpenAI\n" + calls.replace("\n", "\n\n") + "\n")
    (model,) = found.components()
    assert model.properties["references_unlisted"] == 80 - 16
    assert len(model.claims["source_reference"].evidence_refs) == 16
    assert len(found._models["gpt-4o"].locations) == 16


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


def test_the_staged_policy_gate_validates_a_reference_as_validate_does(tmp_path: Path):
    staged = load_script("verify_staged_policy")
    project = write(tmp_path / "checkout", {"app/client.py": CLIENT, "CLAUDE.md": "Be brief.\n"})
    operator = tmp_path / "policy.yaml"
    operator.write_text("version: '1.0'\n")
    code, text = staged.run_staged_gate(project, operator, allow_unsigned=True)
    assert code == 0, text


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


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'from langchain.chat_models import init_chat_model\ninit_chat_model("openai:gpt-4.1")\n',
            {"openai:gpt-4.1"},
        ),
        (
            'from sentence_transformers import SentenceTransformer\nSentenceTransformer("BAAI/bge-m3")\n',
            {"BAAI/bge-m3"},
        ),
        (
            'from transformers import AutoModel\nAutoModel.from_pretrained("openai/whisper-large-v3")\n',
            {"openai/whisper-large-v3"},
        ),
        ('import dspy\ndspy.LM("anthropic/claude-sonnet-4-5")\n', {"anthropic/claude-sonnet-4-5"}),
        (
            'from agno.models.openai import OpenAIChat\nOpenAIChat(id="gpt-4.1-mini")\n',
            {"gpt-4.1-mini"},
        ),
        (
            'from langchain_huggingface import HuggingFaceEndpoint\nHuggingFaceEndpoint(repo_id="mistralai/Mistral-7B-Instruct-v0.3")\n',
            {"mistralai/Mistral-7B-Instruct-v0.3"},
        ),
        (
            'from huggingface_hub import hf_hub_download\nhf_hub_download(repo_id="acme/rules-dataset")\n',
            set(),
        ),
        (
            'from langchain.chat_models import init_chat_model\ninit_chat_model("ignored", model="gpt-4o")\n',
            {"gpt-4o"},
        ),
        (
            'import boto3\nboto3.client("bedrock-runtime").converse(modelId="anthropic.claude-3-5-haiku-20241022-v1:0")\n',
            {"anthropic.claude-3-5-haiku-20241022-v1:0"},
        ),
        ('from crewai import LLM\nLLM(model="ollama/llama3.1:8b")\n', {"ollama/llama3.1:8b"}),
    ],
)
def test_which_arguments_hold_a_model(tmp_path: Path, source: str, expected: set[str]):
    result = scan(tmp_path, {"run.py": source})
    # An identifier is recorded as written; no provider is read from it here.
    assert set(models(result)) == expected
    assert all(model.provider is None for model in models(result).values())


def test_positional_models_of_common_entry_points_are_read(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "import litellm\nimport ollama\nfrom pydantic_ai import Agent\n\n"
            'Agent("openai:gpt-4o")\nlitellm.completion("gpt-4o-mini", [])\n'
            'ollama.chat("llama3.2", messages=[])\n'
        },
    )
    assert set(models(result)) == {"openai:gpt-4o", "gpt-4o-mini", "llama3.2"}


def test_more_entry_points_name_their_models(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "import replicate\nfrom llama_cpp import Llama\n\n"
            'replicate.run("meta/meta-llama-3-8b-instruct", input={})\n'
            'Llama.from_pretrained(repo_id="Qwen/Qwen2-0.5B-Instruct-GGUF", filename="*q8_0.gguf")\n'
        },
    )
    assert set(models(result)) == {"meta/meta-llama-3-8b-instruct", "Qwen/Qwen2-0.5B-Instruct-GGUF"}


# -- following a model argument within its file ---------------------------------------

FOLLOWED = '''\
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


def test_a_model_argument_is_followed_to_the_values_bound_to_it(tmp_path: Path):
    result = scan(tmp_path, {"app/client.py": FOLLOWED})
    found = models(result)
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
    assert "environment_variables" not in found["claude-sonnet-4-5"].properties
    assert not result.surfaces_excluded and not result.scan_failures


@pytest.mark.parametrize(
    ("argument", "expected", "unread"),
    [
        ('"gpt-" + "4o"', ["gpt-4o"], 0),
        ('os.environ.get("CHAT_MODEL", "gpt-4o")', ["gpt-4o"], 0),
        ('os.environ.get("CHAT_MODEL") or "gpt-4o"', ["gpt-4o"], 0),
        ('os.environ.get("CHAT_MODEL", "") or "gpt-4o"', ["gpt-4o"], 0),
        ('str("gpt-4o")', ["gpt-4o"], 0),
        ('" gpt-4o ".strip()', ["gpt-4o"], 0),
        ('"gpt-4o" if fast else "o4-mini"', ["gpt-4o", "o4-mini"], 0),
        ("(chosen := NAME)", ["gpt-4.1"], 0),
        ('f"{PREFIX}-4.1"', ["gpt-4.1"], 0),
        ("ALIAS", ["gpt-4.1"], 0),
        ("unknown_name", [], 1),
        ("build_name()", [], 1),
        ('f"{unknown_name}-4.1"', [], 1),
        ("42", [], 0),
        # What can be read of a partly unknown value is recorded; the rest is a gap.
        ('"gpt-4o" if fast else build_name()', ["gpt-4o"], 1),
        ('"gpt-4o-" + ("mini" if fast else build_name())', ["gpt-4o-mini"], 1),
    ],
)
def test_what_a_model_argument_can_stand_for(
    tmp_path: Path, argument: str, expected: list[str], unread: int
):
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
    assert list(result.surfaces_excluded) == ([unread_gap("run.py", 8)] if unread else [])


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
    # A caller may pass any value in place of a default.
    assert list(result.surfaces_excluded) == [unread("run.py", 7, 2)]


def test_a_default_is_read_in_the_scope_around_its_function(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "from openai import OpenAI\n\n"
            'model = "gpt-4o"\n\n\n'
            "def run(model=model):\n"
            "    OpenAI().responses.create(model=model)\n"
        },
    )
    # ``model=model`` takes the module's value when the function is made.
    assert set(models(result)) == {"gpt-4o"}
    assert list(result.surfaces_excluded) == [unread("run.py", 7)]


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
    assert set(models(result)) == {"gpt-4o-mini", "o3", "text-embedding-3-large", "gpt-4.1"}
    assert not result.surfaces_excluded


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
    # joining or repeating are a gap, and so is the long constant, which is no model.
    assert list(result.surfaces_excluded) == [unread("run.py", 26, 4)]


def test_a_long_chain_of_joined_text_ends_at_the_depth_bound(tmp_path: Path):
    chain = " + ".join(['"g"'] * 3000)
    result = scan(
        tmp_path,
        {"run.py": f"from openai import OpenAI\nOpenAI().responses.create(model={chain})\n"},
    )
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("run.py", 2), f"run.py:1: {CUT}"]


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
    assert not result.surfaces_excluded


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
    assert models(result)["gpt-4.1"].properties["environment_variables"] == ["TUNED_MODEL"]
    # One gap for each variable a read needs, at its first such read in the file: a
    # default another read gives does not stand for this one.
    assert list(result.surfaces_excluded) == [
        "run.py:6: model set only by environment variable CHAT_MODEL; not inventoried",
        "run.py:9: model set only by environment variable TUNED_MODEL; not inventoried",
    ]


def test_a_variable_read_with_no_default_falls_through_to_what_or_gives(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
import os
from openai import OpenAI

SET = os.environ.get("CHAT_MODEL")
CHOSEN = SET or "gpt-4o"
OpenAI().responses.create(model=CHOSEN)
OpenAI().responses.create(model=os.getenv("FAST_MODEL") or os.getenv("SMALL_MODEL") or "o3")
OpenAI().responses.create(model=os.environ["STRICT_MODEL"] or "o4-mini")
"""
        },
    )
    found = models(result)
    # When the variable is unset, ``or`` gives the text after it, which it may override.
    assert found["gpt-4o"].properties["environment_variables"] == ["CHAT_MODEL"]
    assert found["o3"].properties["environment_variables"] == ["FAST_MODEL", "SMALL_MODEL"]
    # Indexing ``os.environ`` raises when the variable is unset, so nothing falls through.
    assert "environment_variables" not in found["o4-mini"].properties
    assert list(result.surfaces_excluded) == [
        "run.py:8: model set only by environment variable STRICT_MODEL; not inventoried"
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


def test_text_built_from_itself_is_read_as_far_as_it_is_written_and_the_rest_is_a_gap(
    tmp_path: Path,
):
    result = scan(
        tmp_path,
        {
            "grow.py": "from openai import OpenAI\n"
            'NAME = "gpt-4o"\nNAME = NAME + "-mini"\nOpenAI().responses.create(model=NAME)\n'
        },
    )
    # Run again, as in a loop, the second binding would grow the text further.
    assert set(models(result)) == {"gpt-4o", "gpt-4o-mini"}
    assert list(result.surfaces_excluded) == [unread("grow.py", 4)]


def test_text_built_in_a_cycle_reads_the_same_whichever_name_is_read_first(tmp_path: Path):
    body = 'from openai import OpenAI\nA = "gpt-4o"\nB = "o3"\nA = B + "-a"\nB = A + "-b"\n'
    first = scan(
        tmp_path / "first",
        {
            "run.py": body
            + "OpenAI().responses.create(model=A)\nOpenAI().responses.create(model=B)\n"
        },
    )
    second = scan(
        tmp_path / "second",
        {
            "run.py": body
            + "OpenAI().responses.create(model=B)\nOpenAI().responses.create(model=A)\n"
        },
    )
    assert (
        set(models(first))
        == set(models(second))
        == {
            "gpt-4o",
            "o3",
            "o3-a",
            "gpt-4o-b",
            "gpt-4o-b-a",
            "o3-a-b",
        }
    )
    assert (
        list(first.surfaces_excluded) == list(second.surfaces_excluded) == [unread("run.py", 6, 2)]
    )


@pytest.mark.parametrize(
    ("argument", "kept"),
    [
        (" or ".join(f"a{index}" for index in range(20)), 16),
        ('f"{left}-{right}"', 16),
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
            "left = a0 or a1 or a2 or a3 or a4\nright = a5 or a6 or a7 or a8\n"
            f"OpenAI().responses.create(model={argument})\n"
        },
    )
    assert len(models(result)) == kept
    assert list(result.surfaces_excluded) == [f"wide.py:1: {CUT}"]


def test_three_by_three_joined_values_are_all_kept(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": "from openai import OpenAI\n"
            'SIZE = "a" if x else ("b" if y else "c")\n'
            'TIER = "1" if x else ("2" if y else "3")\n'
            'OpenAI().responses.create(model=f"{SIZE}-{TIER}")\n'
        },
    )
    assert set(models(result)) == {f"{size}-{tier}" for size in "abc" for tier in "123"}
    assert not result.surfaces_excluded


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


def test_text_nested_past_the_depth_bound_is_not_read(tmp_path: Path):
    nested = '"o"'
    for _ in range(source_python.MAX_DEPTH + 2):
        nested = f'("g" + {nested})'
    result = scan(
        tmp_path,
        {"run.py": f"from openai import OpenAI\nOpenAI().responses.create(model={nested})\n"},
    )
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("run.py", 2), f"run.py:1: {CUT}"]


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
    # ``+=`` joins, and may join again; every other binding below the first is one the
    # reader cannot give: ``*=``, a loop and a comprehension variable, a name unpacked
    # from a call, an exception, a name unpacked from a context and a pattern capture.
    # Every value the reader could give is still recorded, and a comprehension's own
    # variable is not the module's name of the same spelling.
    assert set(models(result)) == {"claude", "claude-sonnet-4-5", "gpt-4o", "gpt-4.1", "o3"}
    assert list(result.surfaces_excluded) == [unread("bind.py", 7, 8)]


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
    assert list(result.surfaces_excluded) == [unread("cond.py", 3), f"cond.py:1: {CUT}"]


TEXT_CALLS = """\
import os
from openai import OpenAI

client = OpenAI()
client.responses.create(model=str("o3"))
client.responses.create(model="GPT-4O".lower())
client.responses.create(model=" gpt-4.1 ".strip())
client.responses.create(model=cfg.field("llm-tier"))
client.responses.create(model="{}-{}".format("gpt", "4o"))
client.responses.create(model=os.getenv("M"))
client.responses.create(model="my model v2")
client.responses.create(model="weights/final.pickle")
client.responses.create(model="default")
"""


def test_text_a_call_gives_back_is_read_only_where_its_callee_is_known(tmp_path: Path):
    result = scan(tmp_path, {"text.py": TEXT_CALLS})
    assert set(models(result)) == {"o3", "gpt-4o", "gpt-4.1"}
    # A call of anything else, a format, a variable named so it is not exported and text
    # that is no identifier are unread; ``default`` and a weight file name no hosted model.
    assert list(result.surfaces_excluded) == [unread("text.py", 8, 4)]


def test_a_token_is_not_exported_through_a_change_of_case(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": f'from openai import OpenAI\nKEY = "{PLANTED}"\n'
            "OpenAI().responses.create(model=KEY.upper())\n"
            "OpenAI().responses.create(model=KEY.lower())\n"
            'OpenAI().responses.create(model=(" " + KEY).strip())\n'
        },
    )
    assert result.components == []
    assert PLANTED.upper() not in exported(result) and "Zq7Zq7".lower() not in exported(result)
    assert list(result.surfaces_excluded) == [unread("run.py", 3, 3)]


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
    # All ten defaults, and the eight texts each of the three bindings joins to, of which
    # sixteen are kept for the argument.
    assert len(models(result)) == 10 + 8
    assert list(result.surfaces_excluded) == [f"many.py:1: {CUT}"]


def test_a_dict_spread_into_a_call_is_read_where_nothing_else_may_change_it(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from openai import OpenAI

client = OpenAI()
client.responses.create(**{"model": "superseded", "model": "gpt-4o"})
client.responses.create(**dict(model="o3"))
REQUEST = {"model": "gpt-4.1"}
client.responses.create(**REQUEST)
CHANGED = {"model": "gpt-4.1-mini"}
CHANGED["model"] = pick()
client.responses.create(**CHANGED)
PASSED = {"model": "gpt-4.1-nano"}
log(PASSED)
client.responses.create(**PASSED)
BASE = {"temperature": 0}
client.responses.create(**{**BASE})
TWICE = {"model": "o1"}
TWICE = {"temperature": 0}
client.responses.create(**TWICE)


def run(**options):
    client.responses.create(**options)
"""
        },
    )
    # A dict written out, there or bound once to a name the file only spreads, is read,
    # and of a key written twice, the value Python keeps.
    # One changed, handed on, spread from another or bound twice may hold anything, and
    # so may a parameter.
    assert set(models(result)) == {"gpt-4o", "o3", "gpt-4.1"}
    assert list(result.surfaces_excluded) == [unread("run.py", 10, 5)]


def test_an_object_a_library_makes_is_no_gap_wherever_it_is_bound(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from langchain_openai import ChatOpenAI
from pydantic_ai import Agent

llm = ChatOpenAI(model="gpt-4o")
fallback = llm if fast else ChatOpenAI(model="o3")
Agent(model=llm)
Agent(model=fallback)
"""
        },
    )
    assert set(models(result)) == {"gpt-4o", "o3"}
    assert not result.surfaces_excluded


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


def test_joining_text_is_charged_to_the_allowance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(source_python.PythonReader, "_allowance", staticmethod(lambda module: 200))
    left = " or ".join(f'"{"l" * 199}{index:x}"' for index in range(16))
    right = " or ".join(f'"{"r" * 99}{index:x}"' for index in range(16))
    result = scan(
        tmp_path,
        {
            "run.py": f"from openai import OpenAI\nL = {left}\nR = {right}\n"
            'OpenAI().responses.create(model=f"{L}{R}")\n'
        },
    )
    # No joined text is short enough to keep, yet each of the 256 was made and is a
    # step, which this allowance does not cover.
    assert list(result.surfaces_excluded) == [unread("run.py", 4), f"run.py:1: {CUT}"]


def test_a_default_in_one_file_does_not_stand_for_a_read_another_file_needs(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "a.py": "import os\nfrom openai import OpenAI\n"
            'OpenAI().responses.create(model=os.getenv("CHAT_MODEL", "gpt-4o"))\n',
            "b.py": "import os\nfrom openai import OpenAI\n"
            'OpenAI().responses.create(model=os.environ["CHAT_MODEL"])\n',
        },
    )
    assert set(models(result)) == {"gpt-4o"}
    assert list(result.surfaces_excluded) == [
        "b.py:3: model set only by environment variable CHAT_MODEL; not inventoried"
    ]
