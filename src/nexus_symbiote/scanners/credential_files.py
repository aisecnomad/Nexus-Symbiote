"""File names that say a file holds credentials, which no collector reads or digests."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nexus_symbiote.utils.confined import ConfinedCollection

MARKDOWN_SUFFIXES = frozenset({".md", ".mdc", ".markdown"})
# Names that hold credentials wherever they appear. A memory file names what to
# import, and a checked-in symlink what an instruction, skill or model configuration
# file holds, so `@.env`
# or `CLAUDE.md -> .env` would otherwise direct an unkeyed digest of the file into the
# inventory, which anyone holding it could confirm guesses against.
_CREDENTIAL_SUFFIXES = frozenset(
    {".pem", ".key", ".p12", ".pfx", ".der", ".jks", ".keystore", ".token"}
)
_CREDENTIAL_MARKERS = ("secret", "credential", "password", "apikey", "api_key", "api-key")
_CREDENTIAL_NAMES = frozenset({".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ecdsa", "id_ed25519"})
# A checked-in `.env` template lists the names to set and holds no values.
_ENV_TEMPLATE_SUFFIXES = frozenset({".example", ".sample", ".template"})
# A program named for the credential it handles, such as `rotate_api_key.py`, is code a
# skill runs, not a store of values: dropping it would take what the agent executes out
# of the inventory. One named only for what it holds, such as `secrets.py`, is a store
# written as a program and stays a credential file, as the names and suffixes above do.
_PROGRAM_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".mts",
        ".cts",
        ".tsx",
        ".rb",
        ".go",
    }
)
# Directories named for what the files in them hold, such as `secrets/`. Only a whole
# name counts, so a skill named `secret-scanner` keeps its scripts.
_CREDENTIAL_DIRECTORIES = frozenset(
    marker + plural for marker in _CREDENTIAL_MARKERS for plural in ("", "s")
)
_RAIL_LINK_CREDENTIAL_STORES = frozenset(
    {".aws", ".ssh", ".gnupg", ".kube", ".docker", ".azure", ".gcloud", ".vault", "vault"}
)


def credential_shaped(path: str, *, colang_source: bool = False) -> bool:
    """Whether a file that is not Markdown is named as one that holds credentials, by its
    own name or by a directory on its path, such as ``secrets/token.txt``.

    A Markdown file is an instruction surface whatever its name, such as
    ``docs/secrets-handling.md``.
    """
    if PurePosixPath(path).suffix.lower() in MARKDOWN_SUFFIXES:
        return False
    directories = PurePosixPath(path).parts[:-1]
    if any(part.lower().lstrip(".") in _CREDENTIAL_DIRECTORIES for part in directories):
        return True
    name = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(name).suffix
    if name in _CREDENTIAL_NAMES:
        return True
    if suffix not in _ENV_TEMPLATE_SUFFIXES and (
        name.startswith(".env")
        # `prod.env` and `app.env.local` hold values as `.env` does; `jest.env.js` is a
        # program, and a template still falls through to the marker checks below.
        or ((name.endswith(".env") or ".env." in name) and suffix not in _PROGRAM_SUFFIXES)
    ):
        return True
    if suffix in _CREDENTIAL_SUFFIXES:
        return True
    if suffix in _PROGRAM_SUFFIXES or (colang_source and suffix == ".co"):
        # `.secrets.py` has stem `.secrets`. Directories already strip a leading dot.
        return PurePosixPath(name).stem.lstrip(".") in _CREDENTIAL_DIRECTORIES
    return any(marker in name for marker in _CREDENTIAL_MARKERS)


def credential_gap(path: str, target: str | None) -> str | None:
    """Why the file at ``path`` is not read, or None: its name, or the name of
    ``target``, the in-root file a symlink at ``path`` leads to, says it holds
    credentials."""
    if credential_shaped(path):
        return "its name says it holds credentials"
    return link_gap(target)


def link_gap(target: str | None, *, colang_rail: str | None = None) -> str | None:
    """Why a symlink that leads to ``target`` is not followed, or None."""
    if target is None:
        return None
    if colang_rail is not None and any(
        part.casefold() in _RAIL_LINK_CREDENTIAL_STORES for part in PurePosixPath(target).parts[:-1]
    ):
        return "symlink leads into a credential directory"
    # A transparent rail link keeps its declared name and program role. A
    # renamed target can be a credential store presented under a rail alias.
    same_rail = (
        colang_rail is not None and PurePosixPath(colang_rail).name == PurePosixPath(target).name
    )
    if credential_shaped(target, colang_source=same_rail):
        return f"a symlink leads to {target}, whose name says it holds credentials"
    return None


def withheld(
    files: ConfinedCollection, path: str, excluded: list[str], *, colang_source: bool = False
) -> bool:
    """Record credential-name refusals for RAG, guardrail and A2A inputs.

    Known collector files use their own names. The NeMo collector can designate a
    Colang rail as a program. A same-name link preserves that role for the target.
    """
    relative = PurePosixPath(path)
    reason: str | None
    if credential_shaped(relative.name, colang_source=colang_source):
        reason = "its name says it holds credentials"
    else:
        linked = files.in_root_target(path)
        resolved = None if linked is None else linked.as_posix()
        reason = (
            None
            if resolved == relative.as_posix()
            else link_gap(resolved, colang_rail=path if colang_source else None)
        )
    if reason is None:
        return False
    message = f"{path}: {reason}; not read or inventoried"
    if message not in excluded:
        excluded.append(message)
    return True


def relinked(files: ConfinedCollection, path: str, *, colang_source: bool = False) -> bool:
    """Whether the read of ``path`` followed a symlink to a file named as holding
    credentials: one replaced after ``withheld`` checked it."""
    followed = files.link_target(path)
    return link_gap(followed, colang_rail=path if colang_source else None) is not None
