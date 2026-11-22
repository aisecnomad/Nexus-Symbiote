"""Check tracked source conflicts, doc links and anchors, versions and vendor digests offline."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
import unicodedata
from collections import Counter
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

VENDOR = Path("src/nexus_symbiote/generators/schemas/vendor")
MAX_FILE_BYTES = 2 * 1024 * 1024
LINK = re.compile(r'!?\[[^\]\n]*\]\((<[^>\n]+>|[^)\s]+)(?:\s+"[^"\n]*")?\)')
# The outer target of an image used as a link, [![alt](image)](target), and a reference
# definition, [label]: target, which LINK does not reach.
WRAPPED_LINK = re.compile(
    r"\[!\[[^\]\n]*\]\([^)\n]*\)\]\((<[^>\n]+>|[^)\s]+)(?:\s+\"[^\"\n]*\")?\)"
)
REFERENCE_LINK = re.compile(r"^ {0,3}\[[^\]\n]+\]:[ \t]*(<[^>\n]+>|\S+)")
HTML_LINK = re.compile(r"""<(?:a|img)\b[^>]*?\b(?:href|src)=["']([^"'\s]+)["']""", re.I)
HTML_ANCHOR = re.compile(r"""<a\b[^>]*?\b(?:id|name)=["']([^"']+)["']""", re.I)
HEADING = re.compile(r"^ {0,3}#{1,6}[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$")
LINE_FRAGMENT = re.compile(r"L\d+(?:-L\d+)?")
MARKER = re.compile(r"^(?:<{7}|>{7}|\|{7})(?: .*)?$", re.M)
# Absolute links must stay absolute where the README doubles as the package-index
# description, so they need their own check against the tracked tree.
SELF_BLOB = r"https://github\.com/{owner}/{repository}/(?:blob|tree)/main/([^\s()\"'<>?#]+)(?:\?[^\s()\"'<>#]*)?(?:#([^\s()\"'<>]+))?"
SELF_RAW = r"https://raw\.githubusercontent\.com/{owner}/{repository}/main/([^\s()\"'<>?#]+)()"
PROJECT_URL = re.compile(r"https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)")
# A slug may end in .git, as a clone URL does, or before the full stop of a sentence.
_SLUG_END = r"(?:\.git)?(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9])"
# Anchored so a longer URL path cannot look like an owner: the project's own
# PyPI URL ends in /p/<name>, and GitHub URLs are matched by PROJECT_URL.
OWNER_SLUG = "(?<![A-Za-z0-9._/-])([A-Za-z0-9._-]+)/{0}" + _SLUG_END
# The paths where an owner/repo slug follows a slash: the REST API, raw file URLs,
# a github.com URL without its scheme, and badge services.
EMBEDDED_SLUG = (
    r"(?:\brepos|github\.com|githubusercontent\.com|/github/[a-z-]+)/([A-Za-z0-9._-]+)/{0}"
    + _SLUG_END
)
OWNER_TEXT_SUFFIXES = frozenset({".md", ".yml", ".yaml", ".cff", ".toml"})
# Test and benchmark data hold the characters the collectors must detect, and benchmark
# results record other tools' output verbatim. Their Python is code CI runs, so it is
# checked like any other source outside a fixtures directory.
HIDDEN_EXEMPT_PREFIXES = (Path("tests"), Path("benchmarks"))
HIDDEN_SUFFIXES = frozenset(
    {".py", ".md", ".toml", ".yml", ".yaml", ".cff", ".cfg", ".txt", ".json", ".sh", ".lock"}
)
HIDDEN_NAMES = frozenset({"Dockerfile", "Makefile", "CODEOWNERS"})
_BLANK = frozenset({0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0})
# Dated audits record what was inspected under the owner live at the time.
# Rewriting their links would falsify the record rather than fix a stale one.
OWNER_EXEMPT_PREFIXES = (Path("docs/audits"),)
# Type identifiers minted under an earlier owner. Signed evidence binds to them, so
# a transfer keeps them; documents quote them verbatim and are not stale links.
STABLE_IDENTIFIERS = ((Path("src/nexus_symbiote/attestation.py"), "PREDICATE_TYPE"),)
# v0.1.0 was published while the Hunzee-VC organization owned the repository, and its
# attestation certificate names that repository and workflow. The README's verified
# install of that release must pass the same identity, or verification cannot succeed.
# Only the fenced verify command that names that release's wheel may carry it, so a
# later release verified under the old identity is reported as stale.
SIGNED_RELEASE_IDENTITIES = {
    Path("README.md"): (
        "nexus_symbiote-0.1.0-py3-none-any.whl",
        (
            "--repo Hunzee-VC/Nexus-Symbiote",
            "--signer-workflow Hunzee-VC/Nexus-Symbiote/.github/workflows/release.yml",
        ),
    ),
}


def read_file(root: Path, relative: Path) -> bytes:
    path = root / relative
    if relative.is_absolute() or ".." in relative.parts or path.is_symlink():
        raise ValueError("unsafe tracked path")
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("tracked file is missing or outside the repository")
    with path.open("rb") as stream:
        value = stream.read(MAX_FILE_BYTES + 1)
    if len(value) > MAX_FILE_BYTES:
        raise ValueError("file exceeds the hygiene check byte limit")
    return value


def prose_lines(text: str) -> Iterator[str]:
    """Yield Markdown lines outside fenced code blocks."""
    fence = ""
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            marker = stripped[:3]
            fence = "" if fence == marker else fence if fence else marker
            continue
        if not fence:
            yield line


def heading_anchors(text: str) -> set[str]:
    """Return the fragment identifiers GitHub renders for a Markdown document."""
    anchors: set[str] = set()
    seen: Counter[str] = Counter()
    for line in prose_lines(text):
        anchors.update(HTML_ANCHOR.findall(line))
        heading = HEADING.match(line)
        if heading is None:
            continue
        label = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading[1])
        label = re.sub(r"<[^>]*>|[`*]", "", label)
        slug = re.sub(r"[^\w\- ]", "", label.lower()).replace(" ", "-")
        anchors.add(f"{slug}-{seen[slug]}" if seen[slug] else slug)
        seen[slug] += 1
    return anchors


def _anchor_issue(
    root: Path, relative: Path, target: Path, fragment: str, link: str, cache: dict[Path, set[str]]
) -> list[str]:
    if not fragment or target.suffix != ".md" or LINE_FRAGMENT.fullmatch(fragment):
        return []
    # Normalize lexically so read_file still refuses a symlinked document.
    name = Path(os.path.normpath(target.relative_to(root)))
    if name not in cache:
        try:
            cache[name] = heading_anchors(read_file(root, name).decode("utf-8"))
        except (OSError, ValueError, UnicodeError):
            return [f"{relative}: linked document is unavailable or unsafe: {link}"]
    if unquote(fragment) in cache[name]:
        return []
    return [f"{relative}: link to a missing heading: {link}"]


def source_issues(root: Path, files: list[Path]) -> list[str]:
    errors = []
    anchors: dict[Path, set[str]] = {}
    for relative in files:
        if relative.suffix not in {".py", ".md", ".toml", ".yml", ".yaml"}:
            continue
        if "fixtures" in relative.parts or VENDOR in relative.parents:
            continue
        try:
            text = read_file(root, relative).decode("utf-8")
        except (OSError, ValueError, UnicodeError):
            errors.append(f"{relative}: source is unavailable or unsafe")
            continue
        if MARKER.search(text):
            errors.append(f"{relative}: unresolved merge conflict marker")
        if relative.suffix != ".md":
            continue
        for line in prose_lines(text):
            for link in _line_links(line):
                parsed = urlsplit(link)
                if parsed.scheme or parsed.netloc:
                    continue
                if not parsed.path:
                    errors.extend(
                        _anchor_issue(
                            root, relative, root / relative, parsed.fragment, link, anchors
                        )
                    )
                    continue
                local = unquote(parsed.path)
                target = (
                    root / local.lstrip("/")
                    if local.startswith("/")
                    else root / relative.parent / local
                )
                if not target.resolve().is_relative_to(root.resolve()) or not target.exists():
                    errors.append(f"{relative}: missing or escaping inline local link: {link}")
                    continue
                errors.extend(_anchor_issue(root, relative, target, parsed.fragment, link, anchors))
    return errors


def _hidden(character: str) -> bool:
    """Whether a reader cannot see this character: format, separator, selector or blank filler."""
    point = ord(character)
    return (
        unicodedata.category(character) in {"Cf", "Zl", "Zp"}
        or point in _BLANK
        or 0x180B <= point <= 0x180F
        or 0xFE00 <= point <= 0xFE0F
        or 0xE0100 <= point <= 0xE01EF
    )


def hidden_character_issues(root: Path, files: list[Path]) -> list[str]:
    """Reject invisible characters in tracked source and documentation.

    Bidirectional controls, zero-width characters and their kind make text read
    differently from how it is processed, in a review as in an instruction file. Code
    that needs one writes it as an escape such as ``\\u202e``.
    """
    errors = []
    for relative in files:
        if relative.suffix not in HIDDEN_SUFFIXES and relative.name not in HIDDEN_NAMES:
            continue
        if VENDOR in relative.parents:
            continue
        if any(prefix in relative.parents for prefix in HIDDEN_EXEMPT_PREFIXES) and (
            relative.suffix != ".py" or "fixtures" in relative.parts
        ):
            continue
        try:
            data = read_file(root, relative)
        except (OSError, ValueError):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            # Skipping it would let one invalid byte hide every character below.
            errors.append(f"{relative}: not valid UTF-8; invisible characters were not checked")
            continue
        # Not splitlines: it would consume the separators this check reports.
        for number, line in enumerate(text.split("\n"), 1):
            found = sorted({f"U+{ord(character):04X}" for character in line if _hidden(character)})
            if found:
                errors.append(
                    f"{relative}:{number}: invisible character {', '.join(found)}; "
                    "write it as an escape"
                )
    return errors


def canonical_repository(root: Path) -> tuple[str, str]:
    """Derive the canonical owner/repository from the declared project homepage."""
    homepage = tomllib.loads(read_file(root, Path("pyproject.toml")).decode())["project"]["urls"][
        "Homepage"
    ]
    match = PROJECT_URL.fullmatch(str(homepage).rstrip("/"))
    if match is None:
        raise ValueError("project Homepage is not a GitHub repository URL")
    return match[1], match[2]


def stable_identifiers(root: Path) -> list[str]:
    """The string constants named in STABLE_IDENTIFIERS, read without importing the package."""
    values = []
    for relative, name in STABLE_IDENTIFIERS:
        try:
            module = ast.parse(read_file(root, relative).decode("utf-8"))
        except (OSError, ValueError, SyntaxError, UnicodeError):
            continue
        for node in module.body:
            if (
                isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value
            ):
                values.append(node.value.value)
    return values


def without_signed_release_identities(text: str, wheel: str, identities: tuple[str, ...]) -> str:
    """Blank ``identities`` on the lines of a fenced ``gh attestation verify`` command
    that names ``wheel``, its backslash continuations included.

    Outside a fence or in one that never closes, on another command in the same block,
    in a comment that names the wheel, or in a block that verifies any other artifact,
    the identities stay in the text and the owner check reports them as stale.
    """
    verifies = re.compile(
        r"^[ \t]*gh attestation verify[ \t]+(?:\S*/)?" + re.escape(wheel) + r"(?!\S)"
    )

    def blanked(lines: list[str]) -> list[str]:
        command = False
        kept = []
        for line in lines:
            if not command:
                command = verifies.match(line) is not None
            if command:
                for identity in identities:
                    line = line.replace(identity, " ")
                command = line.rstrip().endswith("\\")
            kept.append(line)
        return kept

    output: list[str] = []
    block: list[str] = []
    fence = ""
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            marker = stripped[:3]
            if fence == marker:
                output.extend(blanked(block))
                block = []
                fence = ""
            elif not fence:
                fence = marker
            else:
                block.append(line)
                continue
            output.append(line)
            continue
        (block if fence else output).append(line)
    output.extend(block)
    return "".join(output)


def owner_issues(root: Path, files: list[Path]) -> list[str]:
    """Reject links to this repository under a stale owner.

    Absolute GitHub URLs are deliberately skipped by the inline local-link
    check, so a repository transfer can leave them pointing at the previous
    owner and survive review on redirects alone. The exact type identifiers in
    STABLE_IDENTIFIERS are not links and may keep the owner they were minted under,
    and SIGNED_RELEASE_IDENTITIES may name the identity a release was signed under.
    """
    try:
        owner, repository = canonical_repository(root)
    except (OSError, ValueError, KeyError, TypeError):
        return ["canonical repository owner could not be determined"]
    identifiers = stable_identifiers(root)
    errors = []
    for relative in files:
        if relative.suffix not in OWNER_TEXT_SUFFIXES:
            continue
        if any(prefix in relative.parents for prefix in OWNER_EXEMPT_PREFIXES):
            continue
        try:
            text = read_file(root, relative).decode("utf-8")
        except (OSError, ValueError, UnicodeError):
            errors.append(f"{relative}: source is unavailable or unsafe")
            continue
        for identifier in identifiers:
            text = text.replace(identifier, " ")
        if relative in SIGNED_RELEASE_IDENTITIES:
            text = without_signed_release_identities(text, *SIGNED_RELEASE_IDENTITIES[relative])
        # The bare owner/repo slug is matched too: a transfer leaves it stale in
        # command examples, where it is an argument rather than a link.
        name = re.escape(repository)
        owners = {
            match[1]
            for pattern in (OWNER_SLUG, EMBEDDED_SLUG)
            for match in re.finditer(pattern.format(name), text, re.I)
        }
        owners.update(
            match[1]
            for match in PROJECT_URL.finditer(text)
            if match[2].lower().rstrip(".").removesuffix(".git") == repository.lower()
        )
        stale = {value for value in owners if value.lower() != owner.lower()}
        errors.extend(
            f"{relative}: links to {value}/{repository} instead of {owner}/{repository}"
            for value in sorted(stale)
        )
    return errors


def self_link_issues(root: Path, files: list[Path]) -> list[str]:
    """Require absolute links into this repository's main branch to resolve locally."""
    try:
        owner, repository = canonical_repository(root)
    except (OSError, ValueError, KeyError, TypeError):
        # owner_issues already reports an undeterminable canonical repository.
        return []
    names = {"owner": re.escape(owner), "repository": re.escape(repository)}
    patterns = [re.compile(value.format(**names), re.I) for value in (SELF_BLOB, SELF_RAW)]
    errors: list[str] = []
    anchors: dict[Path, set[str]] = {}
    for relative in files:
        if relative.suffix not in OWNER_TEXT_SUFFIXES:
            continue
        if any(prefix in relative.parents for prefix in OWNER_EXEMPT_PREFIXES):
            continue
        try:
            text = read_file(root, relative).decode("utf-8")
        except (OSError, ValueError, UnicodeError):
            errors.append(f"{relative}: source is unavailable or unsafe")
            continue
        for pattern in patterns:
            for match in pattern.finditer(text):
                target = root / unquote(match[1]).rstrip(".,/")
                if not target.resolve().is_relative_to(root.resolve()) or not target.exists():
                    errors.append(
                        f"{relative}: links to a path missing from this repository: {match[0]}"
                    )
                    continue
                errors.extend(_anchor_issue(root, relative, target, match[2], match[0], anchors))
    return errors


def _line_links(line: str) -> list[str]:
    """Every link target on a line of prose: inline, image-wrapped, reference and HTML."""
    links = [
        match[1].strip("<>")
        for pattern in (LINK, WRAPPED_LINK, REFERENCE_LINK)
        for match in pattern.finditer(line)
    ]
    return [*links, *HTML_LINK.findall(line)]


def readme_link_issues(root: Path) -> list[str]:
    """Reject relative links in the README that doubles as the package-index description.

    twine does not render Markdown descriptions, so no build check notices a
    relative link or image that will not resolve on the package index.
    """
    try:
        project = tomllib.loads(read_file(root, Path("pyproject.toml")).decode())["project"]
        readme = project["readme"]
        relative = Path(readme if isinstance(readme, str) else readme["file"])
        text = read_file(root, relative).decode("utf-8")
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        return ["package-index README could not be determined or read"]
    errors = []
    for line in prose_lines(text):
        for link in _line_links(line):
            parsed = urlsplit(link)
            if not parsed.scheme and not parsed.netloc and parsed.path:
                errors.append(
                    f"{relative}: relative link will not resolve on the package index: {link}"
                )
    return errors


def version_issues(root: Path) -> list[str]:
    try:
        project = tomllib.loads(read_file(root, Path("pyproject.toml")).decode())["project"][
            "version"
        ]
        module = ast.parse(read_file(root, Path("src/nexus_symbiote/__init__.py")).decode())
        versions = [
            ast.literal_eval(node.value)
            for node in module.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
        ]
        if not isinstance(project, str) or versions != [project]:
            return ["distribution and package versions disagree"]
    except (OSError, ValueError, KeyError, SyntaxError, UnicodeError):
        return ["distribution or package version could not be checked"]
    return citation_issues(root, project)


def citation_issues(root: Path, version: str) -> list[str]:
    """CITATION.cff must cite the version being released, with a real release date."""
    try:
        citation = yaml.safe_load(read_file(root, Path("CITATION.cff")).decode("utf-8"))
    except (OSError, ValueError, UnicodeError, yaml.YAMLError):
        return ["CITATION.cff could not be read"]
    if not isinstance(citation, dict) or str(citation.get("version")) != version:
        return ["CITATION.cff cites another version than pyproject.toml"]
    released = citation.get("date-released")
    if isinstance(released, str):
        try:
            released = date.fromisoformat(released)
        except ValueError:
            released = None
    if not isinstance(released, date):
        return ["CITATION.cff needs the release date as date-released: YYYY-MM-DD"]
    return []


def vendor_issues(root: Path) -> list[str]:
    errors = []
    try:
        records = json.loads(read_file(root, VENDOR / "SOURCES.json"))["files"]
        if not isinstance(records, list) or not records:
            raise ValueError("missing schema provenance")
        seen = set()
        for record in records:
            name, expected = record["file"], record["sha256"]
            relative = Path(name)
            if name in seen or relative.is_absolute() or ".." in relative.parts:
                raise ValueError("invalid or duplicate vendor path")
            seen.add(name)
            if not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected):
                raise ValueError("invalid digest")
            if hashlib.sha256(read_file(root, VENDOR / relative)).hexdigest() != expected:
                errors.append(f"{VENDOR / relative}: differs from its reviewed provenance digest")
        actual = {
            p.relative_to(root / VENDOR).as_posix()
            for p in (root / VENDOR).rglob("*.json*")
            if p.name != "SOURCES.json"
        }
        if actual != seen:
            errors.append("vendored schema files and provenance entries disagree")
    except (OSError, ValueError, KeyError, TypeError):
        errors.append("vendored schema provenance is unavailable or invalid")
    return errors


_COST_BOUND_NAME_WORDS = frozenset({"fast", "linear", "linearly", "bounded", "scales", "scaling"})
_WALL_CLOCK_FUNCS = frozenset({"monotonic", "perf_counter"})


def _is_wall_clock_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return (
            isinstance(func.value, ast.Name)
            and func.value.id == "time"
            and func.attr in _WALL_CLOCK_FUNCS
        )
    return isinstance(func, ast.Name) and func.id in _WALL_CLOCK_FUNCS


def _is_wall_clock_diff(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Sub)
        and _is_wall_clock_call(node.left)
    )


def _is_numeric_constant(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, (int, float))
        and not isinstance(node.value, bool)
    )


def _has_deadline_comment(lines: list[str], start_line: int, end_line: int) -> bool:
    """True if the assertion lines or the immediately preceding comment line names a deadline."""
    for idx in range(max(0, start_line - 2), min(len(lines), end_line)):
        line = lines[idx]
        if "#" in line and "deadline" in line.split("#", 1)[1].lower():
            return True
    return False


def wall_clock_cost_bound_issues(root: Path, files: list[Path]) -> list[str]:
    """Reject absolute wall-clock cost bounds in performance/linearity tests.

    Tests whose names signal cost or linearity (``fast``, ``linear``, ``bounded``, ``scales``)
    must use relative growth bounds such as ``tests.support.scaling_ratio`` instead of fixed
    wall-clock ceilings, unless explicitly marked as a product timeout deadline check.
    """
    errors: list[str] = []
    for relative in files:
        if relative.suffix != ".py" or not relative.parts or relative.parts[0] != "tests":
            continue
        try:
            text = read_file(root, relative).decode("utf-8")
            tree = ast.parse(text, filename=str(relative))
        except (OSError, ValueError, SyntaxError, UnicodeError):
            continue
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            words = set(node.name.lower().split("_"))
            if "deadline" in words or not (words & _COST_BOUND_NAME_WORDS):
                continue
            elapsed_vars: set[str] = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and _is_wall_clock_diff(child.value):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            elapsed_vars.add(target.id)
                elif (
                    isinstance(child, ast.AnnAssign)
                    and child.value is not None
                    and _is_wall_clock_diff(child.value)
                    and isinstance(child.target, ast.Name)
                ):
                    elapsed_vars.add(child.target.id)

            def _is_elapsed(expr: ast.AST, tracked: set[str] = elapsed_vars) -> bool:
                return _is_wall_clock_diff(expr) or (
                    isinstance(expr, ast.Name) and expr.id in tracked
                )

            for child in ast.walk(node):
                if not isinstance(child, ast.Assert):
                    continue
                end_line = child.end_lineno or child.lineno
                for sub in ast.walk(child.test):
                    if not isinstance(sub, ast.Compare):
                        continue
                    operands = [sub.left, *sub.comparators]
                    is_bound = any(
                        (
                            isinstance(op, (ast.Lt, ast.LtE))
                            and _is_elapsed(left)
                            and _is_numeric_constant(right)
                        )
                        or (
                            isinstance(op, (ast.Gt, ast.GtE))
                            and _is_numeric_constant(left)
                            and _is_elapsed(right)
                        )
                        for left, op, right in zip(operands, sub.ops, sub.comparators, strict=False)
                    )
                    if is_bound and not _has_deadline_comment(lines, child.lineno, end_line):
                        errors.append(
                            f"{relative}:{child.lineno}: {node.name} uses an absolute wall-clock "
                            "cost bound; use tests.support.scaling_ratio or mark a product timeout "
                            "with a '# deadline' comment"
                        )
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        git = shutil.which("git")
        if git is None:
            raise OSError("Git is unavailable")
        result = subprocess.run(  # noqa: S603 - fixed read-only Git operation
            [git, "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=10,
        )
        files = [Path(value) for value in result.stdout.decode().split("\0") if value]
        errors = [
            *source_issues(root, files),
            *hidden_character_issues(root, files),
            *owner_issues(root, files),
            *self_link_issues(root, files),
            *readme_link_issues(root),
            *version_issues(root),
            *vendor_issues(root),
            *wall_clock_cost_bound_issues(root, files),
        ]
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Repository hygiene could not inspect the tracked source.")
        return 1
    for error in errors:
        print(error)
    if not errors:
        print(f"Repository hygiene passed for {len(files)} tracked paths.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
