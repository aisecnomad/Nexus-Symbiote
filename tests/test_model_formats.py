"""The bounded ONNX and GGUF readers follow the formats and fail closed on what they cannot read."""

from __future__ import annotations

import io
import os
import random
import re
import subprocess
import sys
import time

import pytest

from nexus_symbiote.utils import model_formats
from nexus_symbiote.utils.model_formats import (
    GGUF_LIMIT,
    GGUF_UNREADABLE,
    ONNX_LIMIT,
    ONNX_UNEXPLAINED,
    ONNX_UNREADABLE,
    FormatError,
    InspectionBudget,
    gguf_metadata,
    onnx_external_data,
    template_escape_markers,
)
from tests.support import scaling_ratio


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def tag(number: int, wire: int) -> bytes:
    return varint(number << 3 | wire)


def message(number: int, payload: bytes) -> bytes:
    return tag(number, 2) + varint(len(payload)) + payload


def number(field: int, value: int) -> bytes:
    return tag(field, 0) + varint(value)


def entry(key: bytes, value: bytes) -> bytes:
    return message(1, key) + message(2, value)


def external(location: bytes) -> bytes:
    """A TensorProto stored as EXTERNAL at ``location``."""
    return message(8, b"w") + message(13, entry(b"location", location)) + number(14, 1)


def graph(*fields: bytes) -> bytes:
    return number(1, 8) + message(7, b"".join(fields))


def read(data: bytes) -> tuple[str, ...]:
    return onnx_external_data(io.BytesIO(data).read)


def test_tensors_in_attributes_subgraphs_sparse_and_functions_are_followed():
    attribute = message(5, external(b"attribute.bin"))
    subgraph = message(6, message(5, external(b"subgraph.bin")))
    node = message(1, message(5, attribute) + message(5, subgraph))
    sparse = message(15, message(1, external(b"sparse.bin")))
    function = message(25, message(7, message(5, message(10, external(b"function.bin")))))
    data = graph(node, sparse) + function
    assert read(data) == ("attribute.bin", "function.bin", "sparse.bin", "subgraph.bin")


def test_fixed_width_fields_and_groups_are_skipped_like_protobuf_does():
    group = tag(30, 3) + number(1, 5) + tag(31, 3) + tag(31, 4) + tag(30, 4)
    fixed = tag(40, 1) + b"\0" * 8 + tag(41, 5) + b"\0" * 4
    assert read(graph(group, fixed, message(5, external(b"data.bin")))) == ("data.bin",)


def test_a_non_minimal_key_encoding_is_still_attributed():
    key = tag(1, 2) + b"\x88\x00" + b"location"
    tensor = message(13, key + message(2, b"data.bin")) + number(14, 1)
    assert read(graph(message(5, tensor))) == ("data.bin",)


@pytest.mark.parametrize(
    "broken",
    [
        tag(5, 6),
        tag(5, 7),
        tag(0, 0) + b"\0",
        tag(9, 4),
        tag(9, 3) + tag(8, 4),
        tag(5, 0) + b"\xff" * 11,
        tag(5, 2) + varint(1000) + b"short",
    ],
)
def test_malformed_wire_data_fails_only_when_a_location_key_exists(broken):
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, external(b"data.bin"))) + broken)
    assert read(number(1, 8) + broken) == ()


# Key encodings protobuf's C++ parser accepts: it keeps the low 32 bits of a tag and
# the low 64 bits of a length, from varints of up to ten bytes.
OVERLONG_TAGS = [
    bytes([0x8A, 0x80, 0x80, 0x80, 0x10]),
    bytes([0x8A, 0x80, 0x80, 0x80, 0xF0, 0x80, 0x80, 0x80, 0x80, 0x01]),
]
OVERLONG_LENGTH = bytes([0x88] + [0x80] * 8 + [0x02])


@pytest.mark.parametrize("key_tag", OVERLONG_TAGS)
def test_a_key_tag_beyond_32_bits_fails_closed(key_tag):
    key = key_tag + b"\x08location"
    tensor = message(8, b"w") + message(13, key + message(2, b"data.bin")) + number(14, 1)
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, tensor)))


@pytest.mark.parametrize(
    "key",
    [
        *(key_tag + b"\x08location" for key_tag in OVERLONG_TAGS),
        tag(1, 2) + OVERLONG_LENGTH + b"location",
    ],
)
def test_keys_in_any_accepted_encoding_count_in_skipped_fields(key):
    hidden = message(99, message(13, key + message(2, b"data.bin")))
    with pytest.raises(FormatError, match=ONNX_UNEXPLAINED):
        read(graph(message(5, external(b"model.bin"))) + hidden)


def place(data: bytes, start: int) -> bytes:
    """Prefix ``data`` with a doc string so its first ``location`` starts at ``start``."""
    padded = message(6, b"x" * (start - data.index(b"location") - 4)) + data
    assert padded.index(b"location") == start
    return padded


@pytest.mark.parametrize("shift", [-28, -21, -20, -9, -8, -7, -4, -1, 0, 1])
def test_keys_across_read_boundaries_are_counted_once(shift):
    # The reader reads 64 KiB at a time; a key may straddle any boundary.
    parsed = graph(message(5, external(b"data.bin")))
    assert read(place(parsed, 65536 + shift)) == ("data.bin",)
    for key_tag in [tag(1, 2), *OVERLONG_TAGS]:
        hidden = message(99, message(13, key_tag + b"\x08location" + message(2, b"x")))
        with pytest.raises(FormatError, match=ONNX_UNEXPLAINED):
            read(place(hidden + number(1, 8), 65536 + shift))


def test_a_length_beyond_64_bits_is_read_as_protobuf_reads_it():
    key = tag(1, 2) + OVERLONG_LENGTH + b"location"
    tensor = message(8, b"w") + message(13, key + message(2, b"data.bin")) + number(14, 1)
    assert read(graph(message(5, tensor))) == ("data.bin",)


def test_an_unreadable_file_fails_on_the_key_bytes_alone():
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(number(1, 8) + b"\x7f location")
    assert read(number(1, 8) + b"\x7f locator") == ()


def test_names_spelled_location_are_not_external_data_keys():
    named = [
        message(11, message(1, b"location")),
        message(1, message(1, b"location") + message(4, b"Relu")),
        message(1, message(5, message(1, b"location") + number(3, 1)) + message(4, b"Relu")),
        message(5, message(1, b"location") + message(8, b"w")),
    ]
    opset = message(8, message(1, b"location") + number(2, 1))
    assert read(graph(*named) + opset) == ()


def test_nesting_beyond_the_depth_limit_fails_closed():
    nested = message(5, external(b"deep.bin"))
    for _ in range(40):
        nested = message(6, message(1, message(5, nested)))
    with pytest.raises(FormatError, match=ONNX_LIMIT):
        read(graph(message(1, message(5, nested))))


@pytest.mark.parametrize("location", [b"x" * 5000, b"\xff\xfe.bin"])
def test_unusable_locations_fail_closed(location):
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, external(location))))


# protobuf merges repeated occurrences of a singular message field, so a tensor
# split across two of them is EXTERNAL with the location the first one carries.
STORED = message(8, b"w") + message(13, entry(b"location", b"data.bin"))
EXTERNAL = number(14, 1)


def node_attribute(*fields: bytes) -> bytes:
    return message(1, message(5, b"".join(fields)))


@pytest.mark.parametrize(
    "split",
    [
        node_attribute(message(5, STORED), message(5, EXTERNAL)),
        node_attribute(message(5, EXTERNAL), message(5, STORED)),
        node_attribute(message(22, message(1, STORED) + message(1, EXTERNAL))),
        node_attribute(message(22, message(2, STORED) + message(2, EXTERNAL))),
        node_attribute(message(22, message(1, STORED)), message(22, message(1, EXTERNAL))),
        message(15, message(1, STORED) + message(1, EXTERNAL)),
    ],
    ids=[
        "attribute-t",
        "attribute-t-reversed",
        "attribute-sparse-values",
        "attribute-sparse-indices",
        "attribute-sparse-tensor",
        "sparse-initializer-values",
    ],
)
def test_a_tensor_split_across_a_singular_field_fails_closed(split):
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(split))


def test_repeated_tensor_fields_are_read_one_tensor_each():
    attribute = message(10, external(b"first.bin")) + message(10, external(b"second.bin"))
    initializers = message(5, external(b"third.bin")) + message(5, external(b"fourth.bin"))
    data = graph(node_attribute(attribute), initializers)
    assert read(data) == ("first.bin", "fourth.bin", "second.bin", "third.bin")
    keyless = message(8, b"w")
    assert read(graph(node_attribute(message(5, keyless), message(5, keyless)))) == ()


def test_location_without_a_value_fails_only_for_external_tensors():
    keyless = message(13, message(1, b"location"))
    with pytest.raises(FormatError, match=ONNX_UNREADABLE):
        read(graph(message(5, keyless + number(14, 1))))
    assert read(graph(message(5, keyless))) == ()


# protobuf reads data_location (an enum) as int32 and, for ONNX's proto2 closed
# enum, keeps a value it does not define as an unknown field, so it never replaces
# an earlier EXTERNAL; upb and pure-Python protobuf read these cases so.
@pytest.mark.parametrize(
    ("data_location", "is_external"),
    [
        (number(14, 1), True),
        (tag(14, 0) + bytes([0x81, 0x80, 0x80, 0x80, 0x10]), True),
        (number(14, 1) + number(14, 2), True),
        (number(14, 1) + tag(14, 0) + b"\xff" * 9 + b"\x01", True),
        (number(14, 1) + number(14, 0), False),
        (number(14, 2), False),
        (tag(14, 0) + bytes([0x80, 0x80, 0x80, 0x80, 0x10]), False),
        (tag(14, 2) + varint(1) + b"\x01", False),
    ],
)
def test_data_location_is_read_as_protobuf_reads_the_enum(data_location, is_external):
    tensor = message(8, b"w") + message(13, entry(b"location", b"data.bin")) + data_location
    assert read(graph(message(5, tensor))) == (("data.bin",) if is_external else ())


# The forward form of the reader's marker pattern: a key tag, a length of 8, the key.
FORWARD_MARKER = re.compile(
    rb"(?:\x0a|\x8a(?:\x80{0,2}\x00|\x80{3}[\x00\x10\x20\x30\x40\x50\x60\x70]"
    rb"|\x80{3}[\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0][\x80-\xff]{0,4}[\x00-\x7f]))"
    rb"(?:\x08|\x88(?:\x80{0,7}\x00|\x80{8}[\x00-\x7f]))location"
)


def test_markers_are_counted_exactly_across_reads():
    pieces = [
        b"location",
        b"\x0a\x08location",
        b"\x8a\x80\x80\x80\x10\x08location",
        b"\x8a\x80\x80\x80\x90\x81\x00\x88\x80\x00location",
        b"\x88\x80\x80location",
        b"\x8a",
        b"\x80",
        b"\x00",
        b"\x08",
        b"\x88",
    ]
    generator = random.Random(7)  # noqa: S311 - a reproducible corpus, not a secret
    for _ in range(300):
        data = b"".join(generator.choice(pieces) for _ in range(generator.randint(1, 40)))
        # Shift the data across the reader's 64 KiB read boundary.
        data = b"\x01" * generator.randint(65536 - 40, 65536) + data
        reader = model_formats._OnnxReader(io.BytesIO(data).read)
        reader.drain()
        assert reader.markers == len(FORWARD_MARKER.findall(data))
        assert reader.occurrences == data.count(b"location")


def test_marker_search_costs_the_same_whatever_the_filler():
    # A search that may start at any byte of a set retries at each such byte, so
    # filler of those bytes would cost far more than other bytes of the same size.
    def cost(filler: bytes) -> float:
        window = (filler * 65536)[: 65536 - 8] + b"location"
        data = number(1, 8) + message(100, window * 64)
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            assert read(data) == ()
            best = min(best, time.perf_counter() - started)
        return best

    assert cost(b"\x8a") < 3 * cost(b"\x00") + 0.05


def test_an_exhausted_budget_fails_files_that_name_external_data():
    data = graph(message(5, external(b"data.bin")))
    budget = InspectionBudget(3)
    with pytest.raises(FormatError, match=ONNX_LIMIT):
        onnx_external_data(io.BytesIO(data).read, budget)
    assert onnx_external_data(io.BytesIO(number(1, 8)).read, budget) == ()


def gguf_string(text: bytes) -> bytes:
    return len(text).to_bytes(8, "little") + text


def gguf(*entries: tuple[bytes, int, bytes], version: int = 3) -> bytes:
    header = b"GGUF" + version.to_bytes(4, "little") + (0).to_bytes(8, "little")
    header += len(entries).to_bytes(8, "little")
    return header + b"".join(
        gguf_string(key) + kind.to_bytes(4, "little") + value for key, kind, value in entries
    )


def array(item: int, values: list[bytes]) -> bytes:
    return item.to_bytes(4, "little") + len(values).to_bytes(8, "little") + b"".join(values)


def test_gguf_named_templates_and_nested_arrays_are_read():
    nested = array(9, [array(4, [(1).to_bytes(4, "little")]), array(8, [gguf_string(b"x")])])
    data = gguf(
        (b"general.architecture", 8, gguf_string(b"llama")),
        (b"tokenizer.ggml.merges", 9, nested),
        (b"general.flag", 7, b"\x01"),
        (b"tokenizer.chat_template.tool_use", 8, gguf_string(b"{{ tools }}")),
    )
    metadata = gguf_metadata(io.BytesIO(data).read)
    assert metadata.architecture == "llama"
    assert metadata.chat_templates == (("tokenizer.chat_template.tool_use", b"{{ tools }}"),)


def test_gguf_template_names_with_control_characters_are_named_by_position():
    data = gguf(
        (b"tokenizer.chat_template", 8, gguf_string(b"{{ a }}")),
        (b"tokenizer.chat_template.\x1b[31mx", 8, gguf_string(b"{{ b }}")),
    )
    names = [name for name, _ in gguf_metadata(io.BytesIO(data).read).chat_templates]
    assert names == ["tokenizer.chat_template", "tokenizer.chat_template.#1"]


def test_gguf_template_keys_end_at_a_nul_as_llama_cpp_reads_them():
    data = gguf(
        (b"tokenizer.chat_template\0hidden", 8, gguf_string(b"{{ x.__class__ }}")),
        (b"tokenizer.chat_template", 8, gguf_string(b"{{ a }}")),
        (b"tokenizer.chat_template.tool_use\0", 8, gguf_string(b"{{ b }}")),
    )
    assert gguf_metadata(io.BytesIO(data).read).chat_templates == (
        ("tokenizer.chat_template.#0", b"{{ x.__class__ }}"),
        ("tokenizer.chat_template", b"{{ a }}"),
        ("tokenizer.chat_template.#2", b"{{ b }}"),
    )


def test_gguf_architecture_must_be_a_plain_name():
    data = gguf((b"general.architecture", 8, gguf_string(b"Llama\n::warning::x")))
    assert gguf_metadata(io.BytesIO(data).read).architecture is None


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"GGUF" + (1).to_bytes(4, "little"), GGUF_UNREADABLE),
        (b"NOPE" + (3).to_bytes(4, "little"), GGUF_UNREADABLE),
        (gguf((b"k", 13, b"")), GGUF_UNREADABLE),
        (gguf((b"k", 9, array(9, [array(9, [array(4, [])])]))), GGUF_LIMIT),
        (gguf((b"k", 8, (1 << 40).to_bytes(8, "little"))), GGUF_LIMIT),
        (gguf((b"k", 9, (8).to_bytes(4, "little") + (1 << 40).to_bytes(8, "little"))), GGUF_LIMIT),
        (
            b"GGUF" + (3).to_bytes(4, "little") + b"\0" * 8 + (1 << 20).to_bytes(8, "little"),
            GGUF_LIMIT,
        ),
        (gguf((b"k", 8, gguf_string(b"abc")))[:-2], GGUF_UNREADABLE),
    ],
)
def test_gguf_metadata_outside_the_format_or_its_bounds_is_refused(data, reason):
    with pytest.raises(FormatError, match=reason):
        gguf_metadata(io.BytesIO(data).read)


def test_gguf_budget_is_shared():
    data = gguf(*[(b"k%d" % i, 4, b"\0" * 4) for i in range(10)])
    with pytest.raises(FormatError, match=GGUF_LIMIT):
        gguf_metadata(io.BytesIO(data).read, InspectionBudget(5))


@pytest.mark.parametrize(
    ("template", "escapes"),
    [
        (b"{{ messages[0]['content'] }}", False),
        (b"{{ '<__media__>' }}", False),
        (b"{{ getattr(x, 'y') }}", False),
        (b"{{ x.__class__ }}", True),
        (b"{{ x['__globals__'] }}", True),
        (b"{{ x|attr('a') }}", True),
        # Dunder names can be built from more than two literal pieces.
        (b"{{ x['_' ~ '_' ~ 'class' ~ '_' ~ '_'] }}", True),
        (b"{{ x['_' + '_' + 'class' + '_' + '_'] }}", True),
        (b"{{ x['_' '_' 'class' '_' '_'] }}", True),
        (b"{{ x['\\x5f' ~ '_' ~ 'class' ~ '_' ~ '\\u005f'] }}", True),
        (b"{{ x|map(attribute='_'~'_'~'class'~'_'~'_') }}", True),
        (b"{{ x['_' ~ 'class' ~ '_'] }}", False),
        (b"Text '_' ~ '_' ~ 'class' ~ '_' ~ '_'", False),
        (b"{{ x['_'] ~ x['_'] ~ 'class' ~ x['_'] ~ x['_'] }}", False),
        # Jinja skips Unicode whitespace between tokens and decodes string escapes.
        ("{{ ''.\u00a0__class__ }}".encode(), True),
        ("{{ ''.\u3000__class__ }}".encode(), True),
        (b"{{ ''.\x1c__class__ }}", True),
        ("{{ ''[\u00a0'__class__'] }}".encode(), True),
        ("{{ ''|attr\u00a0('__class__') }}".encode(), True),
        (b"{{ ''['\\x5f\\x5fclass\\x5f\\x5f'] }}", True),
        (b"{{ ''['\\u005f_class__'] }}", True),
        (b"{{ ''['\\137\\137class__'] }}", True),
        (b"{{ ''['\\N{LOW LINE}_class__'] }}", True),
        (b"{{ ['']|map(attribute='__class__')|list }}", True),
        (b"{{ x|selectattr('__class__') }}", True),
        (b"{{ x|sort(attribute='a.__class__') }}", True),
        # Jinja removes a backslash before a line break, of any kind, in a string.
        (b"{{ ''['__cl\\\nass__'] }}", True),
        (b"{{ ''['__cl\\\r\nass__'] }}", True),
        (b"{{ ''['__cl\\\rass__'] }}", True),
        (b"{{ x|map(attribute='_\\\n_class__') }}", True),
        # An escaped backslash is consumed whole, as Jinja reads it.
        (b"{{ '\\\\x5f\\x5fclass\\x5f\\x5f' }}", False),
        (b"{{ ''['__cl\\\\\nass__'] }}", False),
        (b"{{ '\\N{NO SUCH NAME}\\UFFFFFFFF\\x5' }}", False),
        (b"{{ '\xff__class__' }}", False),
        # Audit P1-M10: Python-mangled private names reach the render context.
        (b"{{ self._TemplateReference__context }}", True),
        (b"{{ self. _TemplateReference__context.environment }}", True),
        (b"{{ self['_TemplateReference__context'] }}", True),
        (b'{{ self|attr("_TemplateReference__context") }}', True),
        (b"{{ self._TemplateReference_context }}", False),
        (b"{{ message._content }}", False),
        # Audit P1-M10: underscores repeated by string multiplication.
        (b"{{ ('_'*2) ~ 'class' ~ ('_'*2) }}", True),
        (b"{{ ''[('_' * 2) ~ 'class' ~ (2 * \"_\")] }}", True),
        (b"{{ ''[('\\x5f'*2)~'class'~('\\x5f'*2)] }}", True),
        (b"{{ '-' * 80 }}", False),
        (b"{{ 'a_' * 2 }}", False),
    ],
)
def test_template_escape_heuristic(template, escapes):
    assert template_escape_markers(template) is escapes


def test_template_escape_check_stays_linear_on_near_misses():
    # Near-misses of the mangled-name and multiplication shapes, which a backtracking
    # pattern could make quadratic.
    unit = "._a" + "b_" * 40 + " '_" + "c" * 40 + "_' '" + "_" * 40 + " * '_ " + ". " * 8
    text = unit.encode()

    def run(scale: int) -> None:
        assert not template_escape_markers(text * 2_000 * scale)

    assert scaling_ratio(run) < 10


def test_simple_template_marker_short_circuits_joined_literal_analysis(monkeypatch):
    def unexpected(_: str) -> bool:
        raise AssertionError("a direct marker should not need joined-literal analysis")

    monkeypatch.setattr(model_formats, "_joined_literal_marker", unexpected)
    assert template_escape_markers(b"{{ x.__class__ }}")
    assert template_escape_markers(b"{{ x['\\x5f\\x5fclass\\x5f\\x5f'] }}")


def test_joined_literal_stream_matches_dunder_pattern():
    rng = random.Random(42)  # noqa: S311 - deterministic parser test data
    for _ in range(2_000):
        pieces = ["".join(rng.choices("_abc01!", k=rng.randrange(12))) for _ in range(4)]
        template = "{{ " + " ~ ".join(f"'{piece}'" for piece in pieces) + " }}"
        assert model_formats._joined_literal_marker(template) is bool(
            re.search(r"__[A-Za-z0-9_]+__", "".join(pieces))
        )


# The peak is measured in a child process: tracemalloc counts every thread's allocations, so
# in a pytest-xdist worker under coverage the I/O thread and the tracer land in the window.
_JOINED_LITERAL_PEAK = """
import tracemalloc
from nexus_symbiote.utils import model_formats
template = "{{ " + "'a'~" * 100_000 + "'b' }}"
model_formats._joined_literal_marker("{{ 'a' ~ 'b' }}")
tracemalloc.start()
before, _ = tracemalloc.get_traced_memory()
tracemalloc.reset_peak()
assert not model_formats._joined_literal_marker(template)
_, peak = tracemalloc.get_traced_memory()
print(peak - before)
"""


def test_long_joined_literal_chain_uses_bounded_auxiliary_memory():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV_CORE_", "COVERAGE"))}
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", _JOINED_LITERAL_PEAK],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=True,
    )
    assert int(result.stdout) < 100_000
