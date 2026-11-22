"""Exercise static runner arguments without launching their commands."""

import pytest

from nexus_symbiote.control_plane_audit import _extract_local_script_target
from nexus_symbiote.utils.confined import ConfinedCollection


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (["npx", "tsx", "--watch", "./example.ts"], "example.ts"),
        (["uvx", "example-runner", "--quiet", "./example.py"], "example.py"),
        (["npx", "tsx", "--watch", "@catalog/tasks/example.ts"], "@catalog/tasks/example.ts"),
        (["npx", "tsx", "--tsconfig", "./profile.ts"], None),
        (["npx", "tsx", "--tsconfig", "./profile.ts", "--watch", "./example.ts"], "example.ts"),
        (["npx", "--package", "tsx", "--", "tsx", "--watch", "./example.ts"], "example.ts"),
        (["npx", "tsx", "@catalog/formatter"], None),
        (["npx", "tsx", "~/example.ts"], None),
        (["npx", "tsx", "${CUSTOM_DIR}/example.ts"], None),
        (["npx", "tsx", "${CLAUDE_PROJECT_DIR}/example.ts"], "example.ts"),
    ],
)
def test_runner_script_operand_respects_known_argument_arity(tokens, expected):
    assert _extract_local_script_target(tokens) == expected


def test_sparse_directory_is_recognized_inside_the_project(tmp_path):
    (tmp_path / "empty").mkdir()
    (tmp_path / "linked").symlink_to("empty", target_is_directory=True)
    failures = []

    with ConfinedCollection(tmp_path, failures) as files:
        for name in ("empty", "linked"):
            args = ["npx", "@modelcontextprotocol/server-filesystem", f"./{name}"]
            assert _extract_local_script_target(args, files=files) is None

    assert not failures
