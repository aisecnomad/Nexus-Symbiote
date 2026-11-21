"""The in-process evaluator and the isolated worker agree on output preflight."""

import pytest

from nexus_symbiote import runtime_validation as validation
from tests.test_runtime_validation_in_process import dialects as dialects
from tests.test_runtime_validation_in_process import in_process

SHARED_RULES = {
    "type": "object",
    "$defs": {"label": {"type": "string", "pattern": "^[a-z]+$"}},
    "properties": {"title": {"$ref": "#/$defs/label"}},
    "patternProperties": {"^alias_": {"$ref": "#/$defs/label"}},
    "dependentSchemas": {"published": {"required": ["title"]}},
    "if": {"required": ["title"]},
    "then": {"allOf": [{"type": "object"}, {"properties": {"active": {"type": "boolean"}}}]},
    "else": {"not": {"required": ["active"]}},
}


def test_shared_subschemas_apply_to_both_their_fields(dialects):
    assert in_process(dialects, SHARED_RULES, None) == "valid"
    with validation.prepare_output_validation(SHARED_RULES) as validate:
        for result in ({"title": "sample", "alias_one": "copy", "active": True}, {}):
            assert in_process(dialects, SHARED_RULES, result) == "valid"
            validate(result)
        for result in ({"alias_one": 4}, {"published": True}, {"active": True}):
            assert in_process(dialects, SHARED_RULES, result) == "arguments-invalid"
            with pytest.raises(validation.ValidationBudgetError) as refused:
                validate(result)
            assert refused.value.reason == "arguments-invalid"


@pytest.mark.parametrize(
    ("schema", "accepted"),
    [
        ({"$vocabulary": {"https://json-schema.org/draft/2020-12/vocab/core": True}}, True),
        ({"$vocabulary": {"https://example.invalid/extra-vocabulary": False}}, True),
        ({"$vocabulary": {"https://example.invalid/extra-vocabulary": True}}, False),
        ({"properties": {"entry": {"$vocabulary": {}}}}, False),
        ({"properties": {"entry": {"$ref": "#/$defs/missing"}}}, False),
        ({"$defs": {"allow": True}, "$ref": "#/$defs/allow"}, True),
        (
            {
                "$schema": "https://json-schema.org/draft/2019-09/schema",
                "allOf": [{"contains": {"type": "integer"}}],
                "unevaluatedItems": False,
            },
            False,
        ),
    ],
)
def test_preflight_reports_the_same_supported_semantics_in_both_workers(dialects, schema, accepted):
    assert in_process(dialects, schema, None) == ("valid" if accepted else "schema-invalid")
    if accepted:
        with validation.prepare_output_validation(schema) as validate:
            validate({})
    else:
        with (
            pytest.raises(validation.ValidationBudgetError) as refused,
            validation.prepare_output_validation(schema),
        ):
            pytest.fail("unsupported schema passed preflight")
        assert refused.value.reason == "schema-invalid"
