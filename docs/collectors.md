# Collector reference

Every path each built-in collector reads, and what the `ide_agents` collector records from coding-agent settings. The [registry collector](registry-collector.md) and [model integrity](model-integrity.md) pages describe those two collectors in full, and the [known limitations](known-limitations.md) list what each collector leaves out. A test checks that the `prompt`, `rag`, `a2a` and `ide_agents` rows below name every path those collectors read.

## What each collector reads

Every path is relative to the project root. Each collector also bounds what it reads; see [collection limits](collection-limits.md).

| Collector | Reads |
| --- | --- |
| `mcp` | At the root: `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `.claude/mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.roo/mcp.json`, `.kiro/settings/mcp.json`, `.amazonq/mcp.json`, `.windsurf/mcp.json`, `.cline/mcp.json`, `.codex/config.toml`, `.zed/settings.json` (`context_servers`), `opencode.json` and `opencode.jsonc` (`mcp`), `.continue/config.yaml` (`mcpServers`), the `.yaml` and `.yml` files directly in `.continue/mcpServers` (each a block holding `mcpServers`), in `.continue/agents`, `.continue/assistants` and `.continue/configs` (Continue's local agent files, in the `config.yaml` format), `.junie/mcp/mcp.json` and `.continuerc.json` (read only for a gap when it declares `experimental.modelContextProtocolServers`). At any depth: files named `.mcp.json`, `mcp.json`, `mcp-config.json`, `mcp_config.json`, `mcp-servers.json`, `claude_desktop_config.json` and `cline_mcp_settings.json`, and a nested copy of a root path, such as `pkg/.gemini/settings.json`, `pkg/opencode.json` or `pkg/.continue/mcpServers/x.yaml`, read as that root path's dialect, also through a directory symlink such as `pkg/.gemini -> ../shared/gemini`; another spelling of one of them, or of the client directory that holds it, such as `pkg/.MCP.json`, `pkg/.VSCode/mcp.json` or `pkg/.Kiro/mcp.json`, and of a root path at any depth, such as `.Gemini/settings.json`, is a collection failure, beside the exact spelling too. In `.gemini/settings.json`, the server that `mcpServerCommand` or `mcp.serverCommand` starts, named `mcp`. A server with neither a command nor an endpoint, such as a Zed server that an editor extension provides, is inventoried with an unknown launcher, opencode's `{env:NAME}` and `{file:PATH}` are unresolved references, and a file in `.continue/mcpServers` or a Continue agent directory that the collector does not read there is a gap ([known limitations](known-limitations.md#mcp-servers-and-tools)). The root resolver settings that apply to launchers: `.npmrc`, `bunfig.toml`, `.yarnrc.yml`, `.yarnrc`, `.env.yarn`, `deno.json`, `deno.jsonc`, `uv.toml` and `pyproject.toml`. Python files, and TypeScript and JavaScript files (`.ts`, `.mts`, `.cts`, `.tsx`, `.js`, `.mjs`, `.cjs` and `.jsx`), that name an MCP SDK or, in Python, a supported agent framework, outside directories named `tests`, `test`, `dist`, `build`, `docs`, `benchmarks` or `examples` unless a configured server launches the file ([which files](collection-limits.md#source-files-the-mcp-collector-searches)) |
| `model` | `.safetensors`, `.gguf`, `.ggml`, `.onnx`, Keras (`.h5`, `.hdf5`, `.keras`), `.tflite`, `.mlmodel`, `.pte`, `saved_model.pb`, `saved_model.pbtxt` and pickle-family files ([full list](model-integrity.md#model-files-and-references)), with ONNX external data, SavedModel variables, shard indexes, configuration, tokenizer files, chat templates and declared custom code |
| `prompt` | At the root: `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `AGENTS.override.md`, `.github/AGENTS.md`, `GEMINI.md`, `CODEX.md`, `codex.md`, `.codex/instructions.md`, `.github/copilot-instructions.md`, `.cursorrules`, `.clinerules` (a file or a directory), `.windsurfrules`, `system_prompt.md` and `system_prompt.txt`. At any depth: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` and `.cursorrules`; another spelling of one of them, such as `pkg/claude.md`, is a collection failure unless a subagent, rule, prompt, skill or command directory inventories it. Every file under `.claude/rules`, `.cursor/rules`, `.windsurf/rules`, `.roo/rules`, `.kiro/steering`, `.github/instructions`, `.github/prompts`, `.claude/output-styles`, `.claude/agents` and `.github/agents`, and under the skill and command directories `.claude/skills`, `.claude/commands`, `skills`, `.agents/skills`, `.github/skills`, `.cursor/skills`, `.gemini/skills`, `.cursor/commands` and `.gemini/commands`, including a skill's bundled scripts, and under the hook script directories `.claude/hooks` and `.cursor/hooks`, recorded as skill resources. Every text file under a directory named exactly `prompts` at any depth (not `Prompts`), one whose name has no suffix and is not a dotfile, such as `LICENSE`, or ends in `.md`, `.mdc`, `.mdx`, `.markdown`, `.txt`, `.yaml`, `.yml`, `.json`, `.toml`, `.j2`, `.jinja`, `.jinja2`, `.tmpl`, `.tpl`, `.hbs`, `.mustache` or `.prompt`, and every file named `*.prompt.md`, `*.prompt.yaml` or `*.prompt.yml` at any depth, a suffix matched in any case, such as `src/Review.PROMPT.MD`, recorded as `prompt-template` components with `prompt_type` `template`, except under `tests`, `test`, `dist`, `build`, `docs`, `benchmarks`, `examples`, `node_modules` and `vendor`, the names the mcp collector's source search skips, and except where a walk of the directories above reaches the file, also through a directory symlink, which inventories it under its own kind; up to the [`prompt-files`](collection-limits.md#limits) limit. Other files under `prompts`, such as code or images, are not read; a text file there that is not UTF-8 or is larger than `file-bytes` is a failure and one named as holding credentials is a gap, as in a rule directory, so such a new file fails a scan that passed before; templates are read after every other file, so skills keep their `total-bytes` budget; without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, templates without a content hash share one low completeness finding; and a directory symlink under which a file would be a prompt template that no walk inventories, such as `agent -> examples/agent`, is a gap. A file a memory file imports, also through a directory symlink, is recorded once, as that import, and another spelling of a nested instruction name, such as `pkg/prompts/claude.md`, stays a failure. What a JSON, YAML or TOML prompt template, or the YAML front matter of a Markdown one, decodes to is checked for hidden characters as well as its raw text ([known limitations](known-limitations.md#instructions-and-ide-settings)). `llms.txt` is not read. Files that the root `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md` and `GEMINI.md`, and every nested `CLAUDE.md` and `GEMINI.md`, import with `@path`, to five hops. A file named as holding credentials, or a symlink to one, is not read ([known limitations](known-limitations.md#instructions-and-ide-settings)) |
| `rag` | At any depth: `rag_config.json`, `rag_config.yaml`, `rag_config.yml`, `retrieval_config.json`, `vector_store_config.json`, `kb_config.json` and `knowledge_base.json`. At the root: `.env`, `.env.local` and `.env.example`, for key names only. Python files, for vector-store imports. Guardrail and evaluation configuration at any depth, by name and never parsed: `promptfooconfig.yaml`, `promptfooconfig.yml` and `promptfooconfig.json` (recorded with `guardrail_type` `evaluation`), `guardrails.yaml`, `guardrails.yml` and `guardrails.json` (`policy`), and a `config.yml` or `config.yaml` with at least one `.co` file in the same directory (`policy`, with the digest of each `.co` file in `rail_files`). Each is a `guardrail-policy` component whose `config_hash` is the SHA-256 of the file's bytes or, for the directory, the RFC 8785 digest of the map from each file name to its digest; another spelling of one of these names, such as `Guardrails.yaml`, is a collection failure. A configuration or Colang file whose own path or symlink target lies in a credential directory or store (including `.aws/`, `.ssh/`, `.gnupg/`, `.kube/`, `.docker/`, `.azure/`, `.gcloud/`, `.vault/`, `vault/`, and `.config/<store>/`), or whose name says it holds credentials, is a coverage gap and is not read or hashed; a direct `.co` rail or same-name rail symlink in an ordinary project directory is treated as a program, as a `.py` file is (so a direct `secrets.co` is withheld as `secrets.py` is, while `guardrails/secret_disclosure.co` is bound). If a Colang symlink leads to a credential file, the NeMo record binds the configuration and the other `.co` files. A configuration URL value such as `http:host/x` or `ht\ttp://host/x`, which WHATWG parsers normalise by stripping leading/trailing C0 controls and internal ASCII tabs/newlines, is checked and exported as that normalised URL; `source_uris` are not normalised |
| `registry` | At the root only: `package.json` with one lockfile (`npm-shrinkwrap.json` or `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock`); `requirements*.txt`; `pyproject.toml`, with `uv.lock` or `poetry.lock`; `Dockerfile`, `Dockerfile.agent` and `Containerfile`; and the Compose files and override files Compose reads by default. For inventoried packages, also the registry and index settings of the root `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `bunfig.toml`, `pip.conf`, `pip.ini` and `uv.toml`, and those in requirements files and `pyproject.toml` ([registry and index settings](registry-collector.md#registry-and-index-settings)). [What it reads](registry-collector.md#what-it-reads) gives the fields, and [coverage gaps](registry-collector.md#coverage-gaps) the gaps, including those in [requirements files](registry-collector.md#requirements-files) and [Dockerfiles](registry-collector.md#dockerfiles) |
| `a2a` | `agent.json` and `agent-card.json` in any `.well-known` directory and in the root, and `a2a/agent.json`. At the root, client configuration in `a2a.json`, `a2a.yaml`, `a2a.yml` or `a2a_config.json`. Python files outside directories named `tests`, `test`, `dist`, `build`, `docs`, `benchmarks` or `examples`, for SDK references. A card or client configuration that is a symlink to a file whose name or directory says it holds credentials (including `.aws/`, `.ssh/`, `.gnupg/`, `.kube/`, `.docker/`, `.azure/`, `.gcloud/`, `.vault/`, `vault/`, and `.config/<store>/`), or a regular file inside a dotted or XDG credential store, is a coverage gap and is not read; a regular `.well-known` card under a plain service directory such as `services/credentials/.well-known/agent-card.json` remains inventoried. A card's `url` or `endpoint`, or an interface URL, such as `http:host/x` or `ht\ttp://host/x` is checked and exported as `http://host/x`, as WHATWG parsers read it; client configuration URLs and a security scheme's `tokenUrl` are not normalised |
| `ide_agents` | Marker files and settings of Claude Code (also `.claude` settings in subdirectories, plugin manifests and the hook files `.claude-plugin/plugin.json` names in `hooks`, and the `hooks` front matter of project subagents in `.claude/agents` and skills in `.claude/skills`), Codex (`.codex/config.toml` and `.codex/config.json`), Cursor (including `.cursor/hooks.json` and `.cursor/cli.json`), Gemini CLI (`.gemini/settings.json`), Windsurf, Cline, Copilot (`.github/copilot-extensions.json`), Antigravity and xAI; `.vscode/extensions.json`, for recommended AI extensions |
| `shadowscan` | A report at `.shadowscan/report.json`, `shadowscan-report.json` or `shadowscan.json`; reports at more than one of them are a failure |
| `source` | At any depth, outside directories named `tests`, `test`, `__tests__`, `dist`, `build`, `docs`, `benchmarks` and `examples`: Python files other than `test_*.py`, `*_test.py` and `conftest.py`, and a link only when what it reaches is not one of these. A file named as one that holds credentials is read: the collector exports no value but a model identifier that passes its checks |

An optional [`agent.yaml` manifest](agent-manifest.md) at the project root names the agent and declares further instruction files and models.

## Declarations in application source

The `source` collector reads the model identifiers that a project's Python code gives
an SDK. It never imports, runs or contacts anything. A file is decoded as CPython
decodes it and parsed to a syntax tree only when an import statement in it, however it
is spelled, may name a known SDK; the tree then decides. A module of the project at an
import root named like an SDK, such as its own `agents` package, is not taken for the
SDK, and a path only the project has, such as `agents.researcher`, is the project's.

It reads the model arguments of a call (`model=` and its variants, a deployment name,
`llm=`, and `repo_id=` or `id=` where they name a model) and the first argument of an
entry point such as `init_chat_model`, `SentenceTransformer` or `litellm.completion`. What
a callee is comes from the names, attributes and calls it is reached through, each
import in the scope it binds: a client made in the file, a parameter annotated with an
SDK class, a method handed to `functools.partial`, `asyncio.to_thread` or an executor,
and `super()` in a subclass of an SDK class. A call into a known SDK is read. A function
of another library or of Python, such as a logger, and a method of what one returns are
not. Of an object the reader cannot tell, such as an untyped or `Any` parameter or a
framework's state, a call is read when it is named as SDK calls are (`create`, `chat`,
`completions`, `invoke`, `generate_content` and the like), so a metrics label or an
ORM query is not. A call of a name the reader cannot tell, such as a class chosen at run
time, is read, though not a `**` spread a wrapper hands on that way. A method reached
through a class, as an ORM's manager is, is the class's: a library's is not read, and a
project's is a gap.

A model argument is followed within its file, to each text it can hold: through names
and `:=`, conditionals (`if`/`else`, `or`, `and`), an environment variable's default
(`os.getenv`, `os.environ.get`, `decouple.config`), joined text (`+`, `+=` and
f-strings), `str()`, `.lower()`, `.upper()` and `.strip()`, and a dict spread with `**`
that is written out there or bound once to a name the file reads only to spread it. A
dict of `model_kwargs` or `config_kwargs` is read the same way. A name is looked up as Python looks it up: in its function, honouring `global` and
`nonlocal`, then in the scopes around it, skipping a class body from its methods. A
parameter's default and a decorator, annotation or base class are read in the scope
around their function or class. In `or`, a variable read with no default falls
through to what follows when it is unset, so `os.environ.get("CHAT_MODEL") or
"gpt-4o"` gives `gpt-4o`.

Each model identifier becomes one `model` component for the project at `declared`
assurance. Its `source_reference` claim names the file and the line of the argument,
up to 16 places, and `references_unlisted` counts the rest. The environment variables
that may give a model in place of a value read are listed in `environment_variables`.
The identifier is kept as written, routing prefix and all, and no provider is recorded.
Any `trust_remote_code` but a false literal, given to a call or in its `model_kwargs` or
`config_kwargs`, records that the model may run its own code. A relative path or a
weight file names a file in the project, which the model collector reads.

What the reader knows is there and cannot read is a coverage gap:

- a file it cannot open, read or decode, one larger than `file-bytes`, and a link to a
  test, documentation or build output, whatever they hold;
- a file that may import an SDK and cannot be parsed, is larger than `syntax-bytes` or
  holds more syntax nodes than `python-nodes`;
- a file that imports an SDK by a name a module of the project also has;
- a model argument bound in another module of the project;
- what a model argument can hold besides the text read, unless it is an object an SDK
  makes rather than text or a path one returns: a parameter, whatever its default; an
  attribute, an item or a call other than those above; text joined to something unread,
  or built from itself, which may grow when run again; a loop, `with`, `except` or
  pattern variable; a dict that is changed, handed on, spread from another or bound more
  than once; `**options` without a model; a starred positional argument; a path on a
  host, behind a routing prefix or not; a name of the module that the file also imports,
  or that an import with `*` may bind; and text that is no identifier, or a default a
  variable that cannot be named may override;
- a model that only an environment variable sets, once for each file that reads it so,
  as when its default names no model, such as `None`, `""` or `"default"`;
- options a weights library is given that the reader cannot read, such as
  `model_kwargs=options` or `**options`, which may let the model run its own code;
- a model argument given to a function or class the project defines, or to a method of
  one of its classes, which the reader does not follow;
- a bound the reader reached: a callee depth of 32, a following depth of 12, 16 values
  for one argument, 16 joined texts of up to 256 characters, 16 environment variables
  for one text, the directories it looks in for a module, a dotted name of 256
  characters, or the steps one file allows.

Unread arguments, and those given to the project's callees, are each counted in one gap
for the file, at the first of them; an argument bound in another module is a gap of its own.

`validate --project` reports the missing artifact of a reference it read again from
source as information, as it does for a cited model of an imported report. Without
`--project`, when another collector's component contradicts the reference, or when the
model may run its own code, it stays unknown.

## MCP servers declared in source

The collector treats a standard-library logger name such as
`logging.getLogger("mcp.server.demo")` as a logging label when it can establish
that `logging` is used only for attribute reads. Passing the module as a value,
including a default such as `def configure(mod=logging)`, produces a coverage gap
for that call. Other server and tool declarations in the file are still inventoried.

The `mcp` collector names a server it finds in Python, TypeScript or JavaScript
source by the name its constructor declares as a string literal, the name clients
see: the first argument or `name=` of `FastMCP("analytics-mcp")` or `MCPServer`,
and `name` in the object literal given to
`new McpServer({ name: "analytics-mcp", version: "1.0.0" })`. A name computed at
run time, such as an f-string, a template literal with a substitution, a variable
or a concatenation, keeps the variable the server is bound to as its name, as does
a literal of more than 128 characters, one with characters other than ASCII
letters, digits, `_`, `.`, `-` and single spaces between words, one without a
letter or digit, one that redaction would change, or one that holds a value the
scan read and does not publish. Those are the values of the MCP configuration
files and of Claude Code and Cursor settings, whose `env` reaches every server the
host starts: a credential in any field, such as an `env` value with no token shape,
a server's `apiKey` or Codex's `experimental_bearer_token`, URL user information,
and every `env`, header or query parameter value of at least 8 characters. While
one of those files cannot be read whole, every source server keeps its variable
([known limitations](known-limitations.md#mcp-servers-and-tools)). Every source
server records that variable in its `binding` property and the line of its
declaration in `declaration_line`. A TypeScript
server's reference (`mcp-source:<path>:<name>:<line>:<offset>`) carries the name
it is given. A Python server's reference stays `mcp-python:<path>:<variable>`,
because a file binds each variable once while two servers in it can declare the same
name. The [TypeScript inventory](typescript-inventory.md) page covers the
TypeScript forms in full.

For Python SDK imports, the collector considers both script-directory and module-launch search roots. A local framework import must resolve to a regular module in each applicable first search root before it can suppress a coverage gap. A checkout module that could supply an SDK import produces a gap. The SDK’s standard session and request types can appear directly in a Context annotation. SDK subscriptions receiving a server or agent class and unions combining SDK objects remain visible to registration analysis. Runtime changes to import paths are unverified.
Qualified SDK module imports remain unresolved when an installed or isolated launcher can skip a checkout package. An SDK-named helper inside a regular package can be ruled out when its bounded source contains only passive definitions and cannot supply the imported name or submodule. A same-stem alternate module, an adjacent excluded bytecode cache, or a directory link beneath the package leaves the import unresolved. Common standard-library imports before the helper definition are allowed only when the applicable search roots contain no candidate that could shadow the standard library.

## Coding-agent settings

A hook can select PowerShell through a variable or glob. When the program name
offers no PowerShell hint, `-enc` and longer prefixes of `-EncodedCommand` are
critical. The shorter `-e`, `-ec` and `-en` forms require a base64 operand that
has recognizable UTF-16LE text structure. Evidence includes a byte-order mark
with content, a quoted string, a command-like prefix, or sufficient ASCII text.
Ordinary search arguments such as
`$GREP -e Makefile` and a value computed by the shell stay medium.

Shell assignment prefixes end at the first command word. After a wrapper such
as `command` or `nohup`, an assignment-shaped word can name the program.
`env` consumes its own assignment operands.

For Claude Code, `ide_agents` records the permission mode (`bypassPermissions` is a high finding, `acceptEdits` medium), blanket grants in its allow list, how many allow, ask and deny rules and hook handlers it declares, and findings for hook commands (in settings, in `hooks/hooks.json` and the `./` hook files that `.claude-plugin/plugin.json` names in `hooks`, read inside the plugin root, and in the YAML front matter of `.claude/agents/*.md` subagents and `.claude/skills/*/SKILL.md` skills, each bound by a digest like a settings file), the `statusLine` and `fileSuggestion` commands, the credential helpers `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh` and `otelHeadersHelper` (each command rated as a hook command is), `env` variables that redirect the API endpoint or load code (by name only), MCP auto-approval, plugins and additional directories. It does not record the rules, commands or `env` values themselves. For Codex it records the approval and sandbox settings, for Cursor its hook commands, and for Cursor, Windsurf, Cline and Codex an `agent.permissionMode` key in their JSON settings. The MCP servers that Codex and Gemini CLI settings declare are inventoried by the `mcp` collector.

Every settings file `ide_agents` recognizes is bound by a digest of its redacted form, so a changed value is a high `diff` alert. A change only to a value the redaction removes, such as a token, an `env` value, a credential helper command or a URL path on the same host, changes the digest only with `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`; without it the record carries a low `completeness` finding, so `diff` raises a medium alert on every comparison that its values are unbound, without naming one, while a host glued to such a URL after a shell operator or another URL scheme still alerts. Without the key, a URL whose host URL parsers read differently, such as one with a backslash in its authority, is a collection failure. See [source binding](verification-source-binding.md#ide-agent-settings); [instructions and IDE settings](known-limitations.md#instructions-and-ide-settings) lists what this leaves out.
