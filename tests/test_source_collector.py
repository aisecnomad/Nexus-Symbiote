"""The source collector: the model identifiers a project's Python code gives an SDK.

Each rule has a fixture that must be read and one that must not be. A declaration
is never executed, and no value the collector may not export leaves the file.
"""

from __future__ import annotations

import json
import pickle
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
        ("NAME", [], 1),
        ('f"{NAME}"', [], 1),
        ('os.getenv("M", "gpt-4o")', [], 1),
        ("OpenAIChatModel('gpt-4.1')", ["gpt-4.1"], 0),
        ("get_peft_model(base)", [], 0),
        ("[NAME]", [], 1),
        ("DEFAULT_MODEL", [], 1),
        ("pydantic_ai.DEFAULT", [], 1),
        # What another library makes, such as configuration it reads, may be any text.
        ("yaml.safe_load(TEXT)", [], 1),
    ],
)
def test_a_literal_is_read_and_any_other_value_is_unread_unless_a_library_builds_it(
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
    # A literal that holds a token shape is no model; the other two are not literals.
    assert models(result) == {}
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
    assert set(found) == {"acme-search-v2", "gpt-4.1", "gpt-4o"}
    # The annotated parameter is an OpenAI client, so the call is an embeddings call.
    assert found["acme-search-v2"].model_type == "embedding"
    # A parameter, an item of a dictionary and joined text are not literals. The
    # project's own loader is given no model argument the reader knows of, but where it
    # hands its parameter to the SDK, that is unread.
    assert list(result.surfaces_excluded) == [unread("run.py", 10, 3)]


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
    }
    # What ``**`` gives may be the model, unless a model keyword is there too.
    assert list(result.surfaces_excluded) == [unread("framework.py", 37)]


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
        ("ft:gpt-4o-mini-2024-07-18:acme:a:9wXyZ12", True),
        ("", False),
        ("x", False),
        ("1234", False),
        ("model", False),
        ("two words", False),
        ("./models/llama", False),
        ("~/models/llama", False),
        ("local:/home/alice/models/minilm", False),
        ("C:Users/alice/models/minilm", False),
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
        "import x\u0301y, openai\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
        "import os . path, openai\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
        "import os\\\n.path as p, openai\nopenai.OpenAI().responses.create(model='gpt-4o')\n",
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
        "combining-mark-in-an-earlier-name",
        "spaced-dots-in-an-earlier-name",
        "continued-dots-in-an-earlier-name",
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


@pytest.mark.parametrize(
    "statement",
    [
        "from google.cloud import aiplatform",
        "from google . cloud import aiplatform",
        "from google \\\n    .cloud import aiplatform",
        "import google . cloud . aiplatform as aiplatform",
        "import google.\\\ncloud.aiplatform as aiplatform",
    ],
    ids=["dotted", "spaced", "continued", "spaced-import", "continued-import"],
)
def test_a_google_cloud_import_of_vertex_is_found(tmp_path: Path, statement: str):
    result = scan(
        tmp_path,
        {"run.py": f'{statement}\naiplatform.Endpoint("projects/p").predict(model="text-bison")\n'},
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
        "from types_boto3_bedrock_runtime import BedrockRuntimeClient\n\n"
        + "def ask(client: BedrockRuntimeClient):\n    client.converse(modelId='nova')\n",
        "from typing_extensions import cast, Any\nimport ollama\n\n"
        + "cast(Any, ollama.Client()).chat(model='nova')\n",
        "import ollama\nCLIENTS = {}\nCLIENTS.setdefault('h', ollama.Client()).chat(model='nova')\n",
        "import random\nPOOL = []\nrandom.choice(POOL).chat(model='nova')\n",
        "from botocore.client import BaseClient\n\n"
        + "def ask(client: BaseClient):\n    client.converse(modelId='nova')\n",
        "import itertools, ollama\nPOOL = itertools.cycle([ollama.Client()])\nnext(POOL).chat(model='nova')\n",
        "import copy, ollama\nBASE = ollama.Client()\ncopy.copy(BASE).chat(model='nova')\n",
        "import ollama\nCLIENTS = [ollama.Client()]\nmin(CLIENTS, key=id).chat(model='nova')\n",
        "import collections, ollama\nQ = collections.deque([ollama.Client()])\nQ.popleft().chat(model='nova')\n",
    ],
    ids=[
        "any",
        "object",
        "cast",
        "container",
        "context-variable",
        "type-stub",
        "other-type-stub",
        "backported-cast",
        "set-default",
        "random-choice",
        "service-client-base",
        "next",
        "copy",
        "min",
        "pop-left",
    ],
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
        ("local:/home/alice/models/minilm", False, True),
        ("huggingface:C:/Users/alice/models/minilm", False, True),
        ("C:Users/alice/models/minilm", False, True),
        ("file:/home/alice/models/minilm", False, True),
        (".\\checkpoints\\final", False, False),
        ("hosted_vllm//home/alice/models/Meta-Llama-3-8B-Instruct", False, True),
        ("openai//models/Meta-Llama-3-8B-Instruct", False, True),
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
        "prefixed-root",
        "prefixed-drive",
        "drive-relative",
        "one-slash-file-scheme",
        "windows-relative",
        "root-behind-a-slash-route",
        "root-after-a-slash-route",
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


def test_a_folded_import_statement_longer_than_a_slice_is_found(tmp_path: Path):
    names = ", ".join(f"m{index}" for index in range(1500))
    (tmp_path / "run.py").write_text(
        f"import {names}, \uff4f\uff50\uff45\uff4e\uff41\uff49\n"
        + "openai.OpenAI().responses.create(model='gpt-4o')\n",
        encoding="utf-8",
    )
    # Folded a slice at a time, the statement's start and the SDK's name are in different
    # slices; the name alone admits the file, and the syntax tree decides.
    assert set(models(SourceScanner().scan(tmp_path))) == {"gpt-4o"}


REMOTE = "a model is loaded with options the collector cannot read; whether it may run its own code is not known"


@pytest.mark.parametrize(
    ("call", "remote", "gap"),
    [
        ('VLLM(model="someorg/custom-7b", trust_remote_code=True)', True, False),
        ('LLM(model="someorg/custom-7b", trust_remote_code=True)', True, False),
        (
            'SentenceTransformer("someorg/custom-7b", model_kwargs=dict(trust_remote_code=True))',
            True,
            False,
        ),
        ('SentenceTransformer("someorg/custom-7b", model_kwargs=OPTIONS)', None, True),
        ('SentenceTransformer("someorg/custom-7b", model_kwargs={**OPTIONS})', None, True),
        ('SentenceTransformer("someorg/custom-7b", model_kwargs=dict(OPTIONS))', None, True),
        ('AutoModel.from_pretrained("someorg/custom-7b", **OPTIONS)', None, True),
        ('LLM("someorg/custom-7b", **OPTIONS)', None, True),
        ('SentenceTransformer("someorg/custom-7b", model_kwargs={"device": "cpu"})', None, False),
        ('SentenceTransformer("someorg/custom-7b", model_kwargs=None)', None, False),
        ('litellm.completion("someorg/custom-7b", messages=[], **OPTIONS)', None, False),
        (
            'HuggingFaceLocalChatGenerator(model="someorg/custom-7b", '
            'huggingface_pipeline_kwargs={"trust_remote_code": True})',
            True,
            False,
        ),
        (
            'HuggingFaceLocalChatGenerator(model="someorg/custom-7b", huggingface_pipeline_kwargs='
            '{"device_map": "auto", "model_kwargs": {"trust_remote_code": True}})',
            True,
            False,
        ),
        (
            'SentenceTransformer("someorg/custom-7b", tokenizer_kwargs={"trust_remote_code": 1})',
            True,
            False,
        ),
    ],
    ids=[
        "wrapper-of-a-weights-library",
        "weights-library-of-its-own",
        "dict-call",
        "name",
        "spread-in-a-dict",
        "dict-of-a-name",
        "spread",
        "spread-to-a-weights-library-of-its-own",
        "readable-options",
        "no-options",
        "hosted-call",
        "another-options-dict",
        "options-nested-in-options",
        "tokenizer-options",
    ],
)
def test_remote_code_is_read_on_every_sdk_call_and_options_it_cannot_read_are_a_gap(
    tmp_path: Path, call: str, remote: bool | None, gap: bool
):
    result = scan(
        tmp_path,
        {
            "run.py": "import litellm\nfrom langchain_community.llms import VLLM\n"
            "from sentence_transformers import SentenceTransformer\n"
            "from transformers import AutoModel\nfrom vllm import LLM\n"
            "from haystack.components.generators.chat import HuggingFaceLocalChatGenerator\n"
            f"OPTIONS = load_options()\n{call}\n"
        },
    )
    assert models(result)["someorg/custom-7b"].trust_remote_code is remote
    assert list(result.surfaces_excluded) == ([f"run.py:8: {REMOTE}"] if gap else [])


def test_a_wrapper_that_hands_on_what_it_was_given_is_no_model_call(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
import functools

import openai


def retry(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


def run(hook, context):
    hook(**context)


openai.OpenAI().responses.create(**PARAMS)
"""
        },
    )
    # A spread given to an SDK call may hold the model; one a wrapper hands on, to a
    # callee it was given, is not known to be a model call.
    assert list(result.surfaces_excluded) == [unread("run.py", 18)]


@pytest.mark.parametrize("sdk_first", [True, False], ids=["sdk-first", "sdk-last"])
def test_of_two_imports_of_one_name_in_a_module_the_sdks_is_read(tmp_path: Path, sdk_first: bool):
    imports = ["from langchain_openai import ChatOpenAI as Chat", "from my_company_llm import Chat"]
    first, second = imports if sdk_first else imports[::-1]
    source = f"import os\n\nif os.environ.get('P'):\n    {first}\nelse:\n    {second}\n"
    result = scan(tmp_path, {"run.py": source + "Chat(model='gpt-4o')\n"})
    assert set(models(result)) == {"gpt-4o"}


def test_weights_libraries_name_their_models_by_position_and_by_keyword(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from diffusers import DiffusionPipeline
from peft import AutoPeftModelForCausalLM, PeftModel
from sentence_transformers import SentenceTransformer
from transformers import AutoModel
from vllm import LLM

base = AutoModel.from_pretrained(pretrained_model_name_or_path="someorg/base-7b")
PeftModel.from_pretrained(base, "someorg/adapter")
AutoPeftModelForCausalLM.from_pretrained("someorg/peft-7b")
DiffusionPipeline.from_pretrained("stabilityai/sdxl-base")
LLM("facebook/opt-125m")
SentenceTransformer(model_name_or_path="someorg/embedder")
"""
        },
    )
    assert set(models(result)) == {
        "someorg/base-7b",
        "someorg/adapter",
        "someorg/peft-7b",
        "stabilityai/sdxl-base",
        "facebook/opt-125m",
        "someorg/embedder",
    }
    assert list(result.surfaces_excluded) == []


def test_text_an_sdk_function_returns_is_unread_not_an_object_it_made(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
import boto3
from huggingface_hub import snapshot_download
from langchain_core.utils import get_from_env
from langchain_openai import ChatOpenAI
from transformers import AutoModel

AutoModel.from_pretrained(snapshot_download(repo_id="meta-llama/Llama-3.1-8B"))
ChatOpenAI(model=get_from_env("model", "OPENAI_MODEL"))
secrets = boto3.client("secretsmanager")
ChatOpenAI(model=secrets.get_secret_value(SecretId="m").get("SecretString"))
ChatOpenAI(model=ChatOpenAI().model_name)
ChatOpenAI(model=get_from_env("model", "OPENAI_MODEL").strip())
ChatOpenAI(model=ChatOpenAI().model_name.lower())
"""
        },
    )
    assert result.components == []
    assert list(result.surfaces_excluded) == [unread("run.py", 7, 6)]


def test_a_method_reached_through_a_class_is_the_classs_and_no_sdk_call(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import models
from openai import OpenAI


class Car(models.Model):
    make = models.CharField(max_length=40)


def record(client):
    ContentType.objects.create(app_label="blog", model="post")
    Car.objects.create(make="Toyota", model="Corolla")
    settings.LLM_CLIENT.chat.completions.create(model="o3")
    client.chat.completions.create(model="gpt-4o")
"""
        },
    )
    # A row of an ORM's class names no model: a library's is not read, and what a
    # project class is given is the project's to give. A constant of a library may still
    # hold an SDK's client.
    assert set(models(result)) == {"gpt-4o", "o3"}
    assert list(result.surfaces_excluded) == [f"run.py:13: a model argument is {GIVEN}"]


def test_a_text_longer_than_any_identifier_is_judged_and_not_kept():
    found = Declarations(ScanResult(scanner_name="source"))
    assert found.model("x" * 300, "run.py", 1, method="python-ast") is None
    assert found.model("gpt-4o", "run.py", 2, method="python-ast") == "model:source:gpt-4o"
    assert list(found._written) == ["gpt-4o"]


def test_the_answers_kept_across_files_are_bounded(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(source_python, "MAX_CACHED", 10)
    files = {
        f"app/m{index}.py": "".join(
            f"from openai import sub{index}_{part}\nsub{index}_{part}.chat(model='gpt-4o')\n"
            for part in range(20)
        )
        for index in range(5)
    }
    reader = source_python.PythonReader(
        Declarations(ScanResult(scanner_name="source")), frozenset(files)
    )
    kept = []
    for path, text in sorted(files.items()):
        reader.add(path, text)
        kept.append(len(reader._resolved) + len(reader._local))
    # Each file asks of its own imports; what earlier files kept is let go past the bound.
    assert max(kept) == kept[0] and kept[0] > 10


@pytest.mark.parametrize(
    "chosen",
    [
        "Chat = ChatAnthropic if CONFIG['provider'] == 'anthropic' else ChatOpenAI",
        "Chat = PROVIDERS[CONFIG['provider']]",
    ],
    ids=["class-chosen-by-a-branch", "class-chosen-from-a-table"],
)
def test_an_sdk_class_chosen_at_run_time_and_given_a_spread_is_a_gap(tmp_path: Path, chosen: str):
    result = scan(
        tmp_path,
        {
            "run.py": "import yaml\nfrom langchain_anthropic import ChatAnthropic\n"
            "from langchain_openai import ChatOpenAI\n\nCONFIG = yaml.safe_load(open('llm.yaml'))\n"
            "PROVIDERS = {'openai': ChatOpenAI, 'anthropic': ChatAnthropic}\n"
            f"{chosen}\nllm = Chat(**CONFIG['llm'])\n"
        },
    )
    # Only a function a wrapper was given, and calls with what it was handed, is no SDK call.
    assert list(result.surfaces_excluded) == [unread("run.py", 8)]


def test_a_constant_holding_a_client_is_read_and_a_class_of_the_file_is_the_projects(
    tmp_path: Path,
):
    result = scan(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/clients.py": "from openai import OpenAI\n\nOPENAI_CLIENT = OpenAI()\n",
            "app/service.py": "import openai\nfrom app.clients import OPENAI_CLIENT\n\n\n"
            "class LLM:\n    @classmethod\n    def create(cls, model):\n        return model\n\n\n"
            'OPENAI_CLIENT.chat.completions.create(model="gpt-4o-mini", messages=[])\n'
            'LLM.create(model="planner")\n',
        },
    )
    assert set(models(result)) == {"gpt-4o-mini"}
    assert list(result.surfaces_excluded) == [f"app/service.py:12: a model argument is {GIVEN}"]


def test_a_method_of_a_loaded_model_given_a_spread_is_no_load_with_unread_options(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from huggingface_hub import InferenceClient
from transformers import AutoModelForCausalLM, AutoTokenizer
from vllm import LLM, SamplingParams

tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-0.5B-Instruct")
model = AutoModelForCausalLM.from_pretrained("Qwen/Qwen2.5-0.5B-Instruct")
out = model.generate(**tok("hello", return_tensors="pt"), max_new_tokens=32)
GEN = {"temperature": 0.2}
LLM(model="Qwen/Qwen2.5-7B-Instruct").generate(["hi"], SamplingParams(**GEN))
InferenceClient("Qwen/Qwen2.5-7B-Instruct").text_generation("hi", model="Qwen/QwQ-32B", **GEN)
"""
        },
    )
    # Generating text loads no model, so options it cannot read do not say how one loads.
    assert not any("loaded with options" in gap for gap in result.surfaces_excluded)


@pytest.mark.parametrize("project_first", [True, False], ids=["project-first", "library-first"])
def test_of_a_librarys_and_the_projects_import_of_one_name_the_projects_is_read(
    tmp_path: Path, project_first: bool
):
    imports = ["from app.router import Router", "from llm_toolkit import Router"]
    first, second = imports if project_first else imports[::-1]
    result = scan(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/router.py": "def Router(**kw):\n    return kw\n",
            "app/main.py": f"import openai\n\ntry:\n    {first}\nexcept ImportError:\n    {second}\n"
            "Router(model='gpt-4o')\n",
        },
    )
    assert list(result.surfaces_excluded) == [f"app/main.py:7: a model argument is {GIVEN}"]


def test_a_parameter_typed_as_an_sdks_model_names_holds_text_not_an_object(tmp_path: Path):
    result = scan(
        tmp_path,
        {
            "run.py": """\
from openai import OpenAI
from openai.types import ChatModel
from pydantic_ai.models import KnownModelName

client = OpenAI()


def ask(prompt: str, model: ChatModel):
    return client.chat.completions.create(model=model, messages=[])


def plan(model: KnownModelName):
    return client.responses.create(model=model, input="hi")
"""
        },
    )
    # An SDK's data types and its type of model names are text a caller may give.
    assert list(result.surfaces_excluded) == [unread("run.py", 9, 2)]
