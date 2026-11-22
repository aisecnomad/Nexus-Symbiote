# Collection limits

Every collector bounds what it reads from a project to limit the work and memory
used for very large or hostile input. Each bound fails closed.
When a collector reaches one, it records a scan failure and its status becomes
`failed`, so `scan`, `baseline`, `validate`, `risk` and the GitHub Action fail. The
failure names the limit, its value, the root-relative path where it was reached
and how to raise it, and quotes nothing from the file:

```text
vendor/legacy: entries limit of 100000 exceeded; raise it with --limit entries=N
models/llama/model.gguf: model-bytes limit of 64 GiB exceeded; raise it with --limit model-bytes=N
```

The failures are recorded under `metadata.completeness.scan_failures` in the
native inventory, and `validate` prints them. A walk, or the mcp collector's
source search, can fail once for every entry, so each collector lists such
failures only up to a [fixed bound](#fixed-bounds) and then adds one line for each
reason, naming the first path it did not list:

```text
vendor/links/l01000: symlink target is absolute (and 93999 more not listed)
```

Raising a limit moves the point where collection stops. It never turns a reported
stop into a silent one and never relaxes a gate, and lowering one can only add
failures.

Project-policy discovery has its own directory-listing budget, using the same
operator `entries` value. It must finish listing the project root before selecting
a policy or applying defaults. If that listing exceeds the bound, the command
refuses before writing an inventory; it does not silently assume there is no
policy. An operator who explicitly chooses `--no-project-policy` bypasses policy
discovery, while the collectors retain their own entry budgets.

- [Set a limit](#set-a-limit)
- [Limits](#limits)
- [Why these defaults](#why-these-defaults)
- [Fixed bounds](#fixed-bounds)

## Set a limit

Only the operator sets limits, in one of two ways:

- `--limit NAME=VALUE` before the command. Repeat it for several limits.
- The environment variable `NEXUS_SYMBIOTE_LIMITS`, as comma-separated
  `NAME=VALUE` pairs.

```bash
nexus-symbiote --limit entries=200000 --limit model-bytes=128GiB scan . -o agentbom.json
```

```bash
NEXUS_SYMBIOTE_LIMITS="entries=200000,source-scan-bytes=256MiB" nexus-symbiote scan . -o agentbom.json
```

`--limit` wins over the environment variable for the names it sets; the others
keep their environment value. Values are whole numbers. Byte limits also accept a
`KiB`, `MiB` or `GiB` suffix, which are powers of 1024. An unknown name, a
malformed or out-of-range value, or a name set twice in one place is a usage error
(exit status 2), whatever the command.

Limits apply to every command that collects from a project: `scan`, `baseline`,
`validate --project` and `risk --project`, which collect the project again, and
`verify-artifact`, which hashes under `model-bytes`. `advisories --offline-db`
matches under `advisory-matches`. `import-shadowscan` reads one
report under a [fixed bound](#fixed-bounds). Nothing in the scanned checkout can
change a limit, including the project policy file `.nexus-symbiote.yaml`. Use the
same limits for `scan` and for a later `validate --project` or `risk --project` of
its inventory, because those commands collect the project again.

In the GitHub Action, the `limits` input is passed to the scan as
`NEXUS_SYMBIOTE_LIMITS`, in the same comma-separated form:

```yaml
with:
  limits: 'entries=200000,model-total-bytes=512GiB'
```

The pre-commit hooks add their arguments after the command, so set
`NEXUS_SYMBIOTE_LIMITS` in the environment that runs them instead.

## Limits

| Limit | Default | Maximum | What it bounds | When it is reached |
|---|---|---|---|---|
| `file-bytes` | 4 MiB | 1 GiB | One file a collector reads into memory: configuration, manifests, lockfiles and instruction files. The mcp collector holds this much of each source file it searches. | The file is not read. A larger source file is still searched, as a stream; see [below](#source-files-the-mcp-collector-searches) for when it fails. |
| `total-bytes` | 32 MiB | 64 GiB | All bytes one collector reads, apart from model files, which have their own budget below. Each collector has its own budget. The mcp, a2a and rag collectors may read `source-scan-bytes` more, so their source search always reaches its own budget first; the files a ShadowScan report cites are bounded by `source-scan-bytes` alone. | That file is not read; later files are read only while they fit in what remains. |
| `entries` | 100000 | 10000000 | Entries listed by walks and exact-name verification share one collection budget. Directories named `.git`, `node_modules`, `__pycache__`, `.venv` or `venv`, and paths excluded by policy, count as one entry each and are not walked. Verifying an exact filename may also need its parent directory's entries. The same number independently bounds project-policy discovery and one collection's case-variant search, and twice it bounds the weight files the model collector, and `validate --project`, bind to models and the directory digests it records on them. | An incomplete directory listing is refused and later walks stop; an exact-name check needing that listing cannot succeed. Project-policy discovery instead refuses the command before an inventory is written. |
| `depth` | 64 | 256 | Directory nesting below the walk's starting directory. | That directory and everything beneath it are not walked. |
| `model-bytes` | 64 GiB | 1024 GiB | One model weight or tokenizer file that the model collector inspects and hashes; also the artifact `verify-artifact` hashes and each artifact `validate --project` hashes again. | The file is recorded without a hash. |
| `model-total-bytes` | 256 GiB | 16384 GiB | All bytes the model collector reads, weights and model configuration included; `validate --project` reads a model's bound weight files within the same amount. `validate` charges every artifact it reads to six times this limit, so a supplied inventory cannot multiply the work of the scan behind it. | That file is recorded without a hash; later files are hashed only while they fit in what remains. In `validate`, what does not fit is reported as not checked. |
| `source-scan-bytes` | 64 MiB | 64 GiB | Source text one collector reads while it looks for references, counted for each collector separately: the Python, TypeScript and JavaScript files the mcp collector searches for SDK and agent framework references, the Python files the a2a and rag collectors search for SDK and vector-store imports, and the files a ShadowScan report cites as holding a model identifier, which the shadowscan collector re-reads in a merged scan. How many files a project has does not matter. | One failure names the file being read when the budget ran out and says the rest were not read; nothing after it is searched. The mcp collector refuses a single file larger than the whole budget as a failure of its own, without spending the budget. |
| `syntax-bytes` | 256 KiB | 64 MiB | One file containing an MCP SDK or agent framework reference that the mcp collector parses. | That file is not parsed. |
| `ts-nodes` | 20000 | 10000000 | Syntax nodes in one TypeScript or JavaScript file the mcp collector parses for MCP servers and client transports. | That file is not collected. |
| `python-nodes` | 200000 | 10000000 | Syntax nodes in one Python file the mcp collector parses for MCP servers, clients and agent tools, counted as the Python that runs the scan parses the file. | That file is not collected. |
| `import-lookups` | 5000 | 1000000 | Memory files whose `@path` imports the prompt collector follows, and distinct import targets it looks up, together in one collection. A monorepo of 2,000 packages whose `CLAUDE.md` files each import three shared documents uses 2,003. | The imports of the file being followed, and of every file after it, are not inventoried. |
| `prompt-files` | 5000 | 1000000 | Text files under directories named `prompts`, and `*.prompt.md`, `*.prompt.yaml` and `*.prompt.yml` files, that the prompt collector reads as prompt templates at any depth in one collection, outside the trees it skips and those another walk inventories (see the [collector reference](collectors.md#what-each-collector-reads)). | That file, and every prompt file after it in path order, is not inventoried; instruction files found by name are still inventoried. |
| `advisory-matches` | 2000000 | 1000000000 | Work of one `advisories --offline-db` run that grows with the inventory and the bundle together: each advisory record that matches a package version, counted before alias pairs merge, plus one for every 32 `fixed` events of the matching range, and for a range of `n` versions `(n + 1)² / 32` when it is first evaluated. Advisories that do not match a version, and records that cannot be evaluated (whose errors the report caps), cost nothing here. The report stops at 20,000 advisories, so the default is reached only when more than 100 records merge into each one, or by a range with over 8,000 events. | Matching stops; the report holds one error naming the limit, is not complete, and the command exits 1. |

A bounded listing may fetch one additional entry to detect that it does not fit;
for a budget of `N` entries, an overflowing listing observes at most `N + 1`
entries. Partial exact-name indexes are never used. Complete indexes can be reused
without another listing; listing a changed directory spends the shared budget
again. Entries observed before an I/O error still spend that budget. These are
input and work bounds, not a process sandbox or a wall-clock
deadline. Keep an external job timeout for the complete operation.

### Source files the mcp collector searches

The mcp collector searches Python files and TypeScript and JavaScript files
(`.ts`, `.mts`, `.cts`, `.tsx`, `.js`, `.mjs`, `.cjs` and `.jsx`) at any depth
outside directories named `tests`, `test`, `dist`, `build`, `docs`, `benchmarks`
and `examples` (and `__tests__` for TypeScript and JavaScript servers), other than
declaration files (`.d.ts`, `.d.mts`, `.d.cts`) and scripts named with `.spec.` or
`.test.` before their suffix, root files first. A file that a configured server's
`command` or `args` names is searched wherever it is and whatever its name: a
path such as `examples/srv.py`, an extensionless path such as `examples/server`
(with each source suffix, or as a directory's `index` script or `__main__.py`), or a
`-m` module such as `examples.srv`, each also relative to the server's `cwd`. Shell
strings and `--flag=value` arguments are split into words for this. A source file named that way under one of those directories that
the walk did not reach is a gap. Each is read as a stream under
`source-scan-bytes`, in the text the language's own tools read, and only
candidates are parsed:

- A Python file is a candidate when it contains `mcp`, `MCPClient`, `MCPServer`,
  `FastMCP`, `StdioServerParameters`, `sse_client`, `stdio_client`,
  `streamablehttp_client`, `streamable_http_client`, `websocket_client` or the name of
  an agent framework whose tools are collected (`langchain`, `crewai`,
  `function_tool`, `smolagents`, `pydantic_ai`) as Python reads it: decoded as its
  encoding declaration says, with identifiers in the NFKC form Python compares them
  in, so fullwidth or other compatibility letters count.
- A TypeScript or JavaScript file is a server candidate when it contains
  `@modelcontextprotocol/` with `McpServer` or `ClientTransport`, or names a server
  or client module (it contains `@modelcontextprotocol/sdk/server`,
  `@modelcontextprotocol/sdk/client`, `@modelcontextprotocol/sdk/dist` or
  `@modelcontextprotocol/sdk@`, or `@modelcontextprotocol/server` or
  `@modelcontextprotocol/client` followed by a quote, `/` or `@`), and a client
  reference candidate when it contains `@modelcontextprotocol/sdk`. A
  TypeScript or JavaScript file that starts with a UTF-16 byte order mark is
  searched and parsed as UTF-16, as tsc and web browsers read it (bun reads only
  the little-endian form); any other is read as UTF-8, as tsc, Node.js and bun
  read it. That includes UTF-16 without a byte order mark, which a web server or
  page can declare but static reading cannot see.

These are failures rather than silent skips:

- A Python file whose encoding declaration names a codec that does not read ASCII
  as ASCII, such as `utf-7`, `unicode_escape`, UTF-16, ISO-2022 or an unknown
  codec, or a name longer than 64 characters, which no codec has. Such a file can
  spell a reference in a form that static reading cannot follow, and Python
  decodes it differently when it is run as a script and when it is imported.
  Single-byte code pages such as `latin-1` and `cp1252`, and the stateless
  multibyte codecs such as `shift_jis` and `gbk`, are followed.
- A Python file that `python -x` reads in another way. That option skips the
  first line through its line feed, so the line after it can declare a codec even
  when the first line is code. A declaration there that is not followed, or a
  different codec under which the rest of the file is valid and names the SDK,
  is the failure `unsupported source encoding declaration`.
- A Python file that is not valid in its encoding (`invalid UTF-8` when it
  declares none). Below the root, a file that declares no encoding and is not
  UTF-8 is not a failure, because Python can neither import nor run it, unless
  the rest of it after the first line feed, which `python -x` reads, names a
  reference.
- A root-level `.ts` or `.js` file without a UTF-16 byte order mark that is not
  valid UTF-8, as in earlier releases (`invalid UTF-8`), and a candidate that is
  not valid in its encoding (`invalid UTF-8` or `invalid UTF-16`). tsc would read
  such a file with replacement characters, but another runtime could decode it
  differently. Another script that is not a candidate, below the root or with
  another suffix, is not checked for valid UTF-8.
- A candidate larger than `syntax-bytes`, which is not parsed.
- A Python candidate with more syntax nodes than `python-nodes`, which is parsed
  but not analysed.
- A source file larger than `file-bytes` that is a candidate, or that is a Python
  file that is not plain ASCII, because its NFKC form cannot be searched without
  holding it.
- A plain ASCII Python file larger than `file-bytes` whose codec is unknown,
  because a line that can declare it starts as a comment and does not end in
  time: the first line, or the second after a blank or comment first line, within
  the first `file-bytes` of the file, or the line after the first line feed, which
  `python -x` reads, within `file-bytes` of that line feed. For example, a first
  line of `# ` and 5 MiB of text fails with the default limits.

Other plain ASCII sources of any size, such as generated protocol buffer modules
or bundles, are searched as a stream and pass.

An import of the Python MCP server SDK, or of an agent framework's tool decorator
or agent class, spelled only with compatibility characters is recorded as a gap,
because its servers and tools are not collected. So are a dynamic import whose
literal arguments name an MCP module, an MCP server that application code starts
or reaches, and the forms of the TypeScript SDK that the
[TypeScript inventory](typescript-inventory.md#gaps) lists as gaps. Only files
whose parse produced a component, a gap or a failure are listed under
`surfaces_scanned`, so adding an unrelated source file does not change the
inventory.

## Why these defaults

Most defaults are the values earlier releases used. Five changed because
ordinary projects exceeded them:

- `entries` was 20,000. Mid-size monorepos, and working trees with tool caches
  such as `.tox`, `.nox` or a vendored `site-packages`, have more files and
  directories than that.
- `model-bytes` was 5 GiB, and tokenizer files were held to `file-bytes`.
  Single-file quantized checkpoints, such as GGUF files of 7 to 40 GB, are
  common, as are `tokenizer.json` files above 4 MiB. Tokenizers are now hashed as
  streamed model files.
- `model-total-bytes` was 5 GiB plus 32 MiB. A sharded checkpoint of four
  5 GB shards exceeded it; a 70-billion-parameter model in 16-bit weights is about
  141 GB.
- The mcp collector used to count every Python file outside `tests`, `test`,
  `dist` and `build`, every TypeScript file, and every root-level `.ts` and `.js`
  file toward fixed limits of 50, 50, 10 and 10, before looking at their content,
  and the a2a collector failed above 20 Python files, so most medium-sized
  projects failed. A file count says nothing about cost: source collection is now
  bounded by the text read, 64 MiB for each collector under `source-scan-bytes`,
  and the mcp collector parses only candidates.
- `python-nodes` was a fixed bound of 20,000 syntax nodes that could be neither
  seen in this table nor raised, so an ordinary module that mentions `mcp` failed
  the gates; this repository's own `scanners/registry.py` is one such module.
  Real code has about 0.12 nodes per byte, and at most about 0.45. Of some 7,500
  modules (the Python 3.13 standard library, the packages of a development
  environment and this repository), the largest that fits within `syntax-bytes`
  has 55,456 nodes, and the largest of any size 95,753. Every analysis of a parsed
  file is linear in its nodes and runs only within the limit; `syntax-bytes` bounds
  the parse itself, which comes first. On one 2.1 GHz server core, a hostile
  256 KiB file took half a second and at most 240 MiB of memory to parse, and a
  file just within 200,000 nodes about a second to parse and analyse.

Hashing a 256 GiB model directory takes several minutes; keep a job timeout, as
the [GitHub Action guide](github-action.md#add-it-to-a-workflow) recommends.

## Fixed bounds

These bounds protect a format or the inventory rather than size a project, so
they are not operator settings. Reaching one is also a scan failure or a refusal
that names the file, except the listing bounds in the first two rows, which only
shorten lists whose content is recorded or bound anyway.

| Bound | Value |
|---|---|
| Failures one collector lists from its walks, and from the mcp collector's source search, before one line for each reason sums up the rest | 1,000 lines or 65,536 characters |
| Paths the prompt collector lists in the `imports` and `imported_by` properties of one collection; past it a list is replaced by `imports_count` and `imports_digest`, or by `imported_by_count`, which is not a failure because every imported file is still inventoried and the digest binds what each file imports | 262,144 characters |
| `@path` import references in one memory or imported file | 1,000 |
| Codec name in a Python encoding declaration | 64 characters |
| Dots separating key or table-name parts in TOML read by the registry, IDE and MCP collectors, including Codex settings and package-resolver configuration; quoted parts count, dots inside strings and comments do not | 16 (17 parts); checked before parsing |
| MCP tool registrations in one TypeScript or JavaScript file | 1,000 |
| Processor time of one TypeScript or JavaScript parse, the only bound on this page that counts time; see [the TypeScript parse time limit](#the-typescript-parse-time-limit) | 250 ms, in proportion to `syntax-bytes` above its default |
| Native inventories and ShadowScan reports read by any command | 16 MiB |
| Nesting levels of arrays and objects in a native inventory read through the shared reader, the root counted (`verify-discovery` and `verify-live` stop at the recursion limit instead; `attest` records a deeper subject, up to 256 levels, as native) | 128 |
| `agent.yaml` and `.nexus-symbiote.yaml` | 1 MiB each |
| Operator signature policy | 4 MiB |
| Model artifact named in an operator signature policy | 5 GiB |
| Sigstore bundle named in an operator signature policy | 4 MiB |
| Model file header read to identify and inspect its format | 1 MiB |
| Pickle sample inspected under another model suffix or in a file checked by content, and the opcodes read from it | 64 KiB; 4,096 |
| NumPy array header parsed in a model file, a file checked by content or a ZIP member; a longer one is rated `unknown` | 64 KiB |
| ZIP central directory read from the end of a model file or a file checked by content to find a pickle-family or object-array member; a longer one is rated `unknown` | 1 MiB |
| Shard indexes in one model directory | 16 |
| GGUF metadata the model collector inspects: keys, one string, one array, all metadata; a file beyond them is a gap | 65,536; 16 MiB; 2,097,152 items; 128 MiB |
| ONNX structure the model collector reads for external data: nesting, fields in one file, one location; a file beyond them that may name external data is a failure | 64; 4,000,000; 4,096 bytes |
| Structure units the ONNX and GGUF readers spend in one scan or one validation, shared with NumPy array headers at one unit a byte; a header past them is rated `unknown` | 16,000,000 |
| Python file the a2a and rag import heuristics parse; a larger file is skipped, and for a2a one that names `AgentCard` is a gap | 262,144 characters |
| Annotation strings the mcp collector parses as forward references in one Python file: characters of one string, strings nested in strings, and syntax nodes parsed from all of them; past any of them, in a file with a recognized server, a PydanticAI agent or an `mcp` or `fastmcp` import, is a gap | 4,096; 4; 10,000 |
| Root `requirements*.txt` files, together: text, and logical lines | 4 MiB; 100,000 |
| MCP servers in one MCP client file | 1,000 |
| Credential values of all MCP servers in one client file, those assigned inline through a launcher included, each scrubbed from every server's text; a file with more is a named failure and is not collected | 4,096 |
| MCP tools declared in one MCP client file, and by one server | 5,000 and 1,000 |
| Arguments, environment variables and headers of one MCP server | 1,024, 256 and 64 |
| Entries in one list field of an MCP server, such as `alwaysAllow` | 1,000 |
| Nodes and nesting levels of one MCP tool definition, and nodes of all tool definitions in one MCP client file | 20,000 and 64; 200,000 |
| Wrappers unwrapped around one MCP launch command (`env`, `sh -c`, `cmd /c`, ...); deeper nesting is a `launcher_identity` gap | 4 |
| Characters and words of an inline shell command line the launcher grammar reads; a longer one is a gap | 4,096 and 256 |
| Characters of one launched package reference; a longer one is a `launcher_identity` gap | 2,048 |
| Words in one MCP server's arguments, counting each word of an argument, that the launcher scan examines; more is a gap | 65,536 |

Some collectors apply further per-file bounds to the formats they parse, such as
JSON nesting, YAML token counts and A2A card entries; each is reported as a
failure or gap on the file that reached it. The registry collector's bounds on
manifests, lockfiles, Compose files and image references are in its
[limits table](registry-collector.md#limits), and
[model integrity](model-integrity.md) describes what happens to a model file beyond
the GGUF and ONNX bounds. A signature policy entry over either
signature bound is refused with "Policy artifact or bundle is unavailable beneath
the project root", which does not yet name the bound; a model artifact above
5 GiB can be hashed under `model-bytes` but cannot be verified by digest pin or
signature.

### The TypeScript parse time limit

Every other bound on this page counts something a scan reads, such as bytes,
entries or nodes, so whether a scan reaches it depends on the project and the
limits alone. The parse time limit counts time, and exists only for input that no
such count bounds: a file the grammar cannot parse, whose error recovery can take
far longer than the file's size or node count would suggest.

It is the same 250 ms as in releases up to 0.2.0, scaled the same way by `syntax-bytes`, but
it counts the processor time the parser itself uses, not time on the clock. So a
busy machine does not use it up, and neither does the one-time load of the parser
and its grammar before the first parse, which those releases counted and which
could turn a cold first scan of a small server into a failure. The parser can be
stopped only after an interval of wall-clock time; that interval equals the
budget, the deadline used before, so one attempt at a runaway parse stops where it
stopped before and uses no more time or memory. A parse the interval stops when
the parser has had less than half of the budget as processor time was held up by
the machine, and starts again from the beginning, for at most three attempts. That
lets a small server through on a loaded machine; a file that never gets its
processor time is then refused. A stopped parse that had at least half of the
budget is refused at once, so on an idle machine a file the grammar cannot end
costs one interval.

A file whose parse reaches the limit is the failure
`TypeScript parsing exceeded its time limit`, and fails the default gates. A file
that parses is bounded by `syntax-bytes` and `ts-nodes` instead; the analysis
after the parse is linear in the file's nodes, runs only within `ts-nodes` and has
no separate deadline. Ordinary source reaches the node limit first. A valid file
whose parse needs more than the budget is refused for time, as it was before: in
practice only an unusual file of a few hundred kilobytes of one token-dense
construct, such as a large array or object literal, parses slowly enough to reach
it.
