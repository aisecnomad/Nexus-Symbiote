<p align="center">
  <img src="https://raw.githubusercontent.com/Hunzee-VC/Nexus-Symbiote/main/docs/assets/nexus-symbiote-banner.jpg" alt="Nexus SymBiote: an Agent Bill of Materials for AI agent supply chains">
</p>

<h1 align="center">Nexus SymBiote</h1>

<p align="center">
  <strong>Know what your AI agents are built from. Gate them on evidence. Catch drift before it ships.</strong>
</p>

<p align="center">
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml"><img src="https://github.com/Hunzee-VC/Nexus-Symbiote/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&amp;logoColor=white" alt="Python 3.11 | 3.12 | 3.13 | 3.14"></a>
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Hunzee-VC/Nexus-Symbiote" alt="MIT license"></a>
  <a href="#project-status"><img src="https://img.shields.io/badge/status-alpha-orange" alt="Status: alpha"></a>
  <a href="#what-it-produces"><img src="https://img.shields.io/badge/exports-CycloneDX%201.7%20%7C%20SPDX%203.0.1%20%7C%20SARIF%20%7C%20VEX-0B7285" alt="Exports: CycloneDX 1.7, SPDX 3.0.1, SARIF, VEX"></a>
</p>

<p align="center">
  <a href="#why"><b>Why</b></a> ·
  <a href="#what"><b>What</b></a> ·
  <a href="#how"><b>How</b></a> ·
  <a href="https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/README.md"><b>Docs</b></a> ·
  <a href="#project-status"><b>Status</b></a>
</p>

Nexus SymBiote generates an **Agent Bill of Materials (AgentBOM)** — an evidence-backed inventory of the MCP servers, models, instructions, retrieval sources, A2A cards, IDE settings and container images an AI agent is assembled from. It reads a project **without running it**, flags supply-chain risk, fails CI on drift in what it records, and exports to CycloneDX 1.7, SPDX 3.0.1, SARIF and VEX.

```bash
nexus-symbiote scan ./my-agent --no-project-policy -o agentbom.json    # inventory, offline
nexus-symbiote risk agentbom.json --no-project-policy --threshold 50   # gate on risk
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert        # gate on drift
```

> **Alpha.** Interfaces, formats and policy semantics may change. Install the published release only after verifying its build attestation, or install a reviewed commit from source; both are shown under [How](#how). This release has [known detection gaps](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md#known-limitations-in-010): what the collectors do not record, no gate or `diff` can alert on.

## Why

**AI agents are assembled from parts you did not write, and most of those parts never appear in a software bill of materials.**

An agent's behavior depends on its configuration as much as its code — MCP servers, model weights, instruction files, retrieval sources, agent endpoints, IDE permissions — and each can change without a code review. Package SBOMs don't cover these. The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) lists agentic supply-chain vulnerabilities (ASI04) among the top risks.

| Risk | What it looks like | What Nexus SymBiote records |
| --- | --- | --- |
| Floating dependencies | MCP server at `@latest`; image without digest | Unpinned-version and missing-digest findings |
| Tool rug pulls | Tool description or schema changed post-review | RFC 8785 fingerprints of tools listed in a server's `tools` array in MCP configuration, or observed with `discover-mcp` or `verify-live` in live mode; a changed definition raises a critical drift alert. Tools declared in server source are recorded by name with a digest of the declaring source, so editing that source raises a drift alert, but their effective description and schema are not fingerprinted in a static scan |
| Endpoint repointing | MCP endpoint moved to another host; A2A card URL moved to HTTP or another host (for an A2A 1.0 card without `url`, its first `supportedInterfaces` entry); an A2A token, OpenID Connect or metadata URL, or an interface, moved to a host the card did not already use for such a URL, including the scheme-less `//host` form and `host:port` addresses whose host is a dotted name, `localhost` or a bracketed IP; an A2A card URL moved to another path on the same host | Critical/high drift alerts; medium `properties changed` for A2A credential endpoints and interfaces (other scheme-less addresses, such as `svc:50051`, are exported as `[redacted]` and bound only with `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`); for a same-host A2A path change, medium always with that key and without it only when the path depth changes or the path moves to or from `/` |
| Scope widening | An OAuth or OpenID Connect scope required by the `security` (A2A 0.3) or `securityRequirements` (A2A 1.0) list of a card or of one of its skills changed from `read:only` to `admin`, or from `https://www.googleapis.com/auth/drive.readonly` to `https://www.googleapis.com/auth/cloud-platform`, including for a scheme typed `OAuth2`; a requirement value of another or an undeclared scheme changed on a card or a skill | High drift alert on `capabilities`; medium `properties changed` for other schemes' requirement values |
| Executable model files | Pickle checkpoint; `.safetensors` that isn't one | Format classification without loading; SafeTensors header validation |
| Unsigned weights | Model file with no artifact-bound signature | `UNKNOWN` integrity verdict until signer policy verifies |
| Hidden instructions | Bidi or zero-width characters in `CLAUDE.md` | Findings for tag characters, bidi embedding, override and isolate controls, and five zero-width or invisible characters in the instruction files the `prompt` collector reads. Other invisible characters, such as U+FEFF, directional marks and variation selectors, are not detected yet |
| Over-broad permissions | Claude Code granted `Bash(*)` or a permissive default mode | Claude Code's permission mode, recorded but not scored, and whether its allow list contains a blanket `Bash`, `Edit`, `Write` or `*` grant, a medium finding; a drift alert when the mode changes or the first such grant appears. Further grants, scoped rules, hooks and other settings are not recorded yet ([known limitations](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md#known-limitations-in-010)) |
| Credential exposure | Tokens in MCP env blocks or connection strings | Env vars by name, never value; known secret patterns redacted |

The full trust model, design principles and offline-by-default enforcement are in the [security model](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md).

## What

**An AgentBOM: one evidence-backed inventory of an agent, with gates, drift checks and standard exports.**

### What it inventories

Eight built-in collectors read declared configuration and artifacts from the project directory. Select a subset with `--scanner`; collectors you leave out are recorded as unknown, not clean.

| Collector | Reads | Records |
| --- | --- | --- |
| `mcp` | MCP config files (`.mcp.json`, `mcp.json`, `.claude/mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`) and server source written in the supported SDK forms | Clients, servers, launchers, pinned versions, transports, endpoints, tool fingerprints |
| `model` | `.safetensors`, `.gguf`, `.ggml`, `.onnx`, Keras (`.h5`, `.hdf5`, `.keras`), `saved_model.pb` and pickle-family files (including `.ckpt` and `.pdparams`), with their config | SHA-256 hashes, serialization safety, SafeTensors structure, signature status |
| `prompt` | Instruction files at these paths from the project root: `CLAUDE.md`, `.claude/CLAUDE.md`, `AGENTS.md`, `.github/AGENTS.md`, `CODEX.md`, `codex.md`, `.codex/instructions.md`, `.github/copilot-instructions.md`, `.cursorrules`, `.clinerules`, `.windsurfrules`, `system_prompt.md`, `system_prompt.txt`; skill and command text files (`.md`, `.txt`, `.yaml`, `.yml`, `.json`) under `.claude/skills`, `.claude/commands` and `skills` | Instruction, skill and command digests; hidden-character findings for those instruction files |
| `rag` | `rag_config.*`, `retrieval_config.json`, `vector_store_config.json` | Declared retrieval sources and controls |
| `registry` | In the project root: `package.json` and `package-lock.json` (v2 or v3); `requirements*.txt`, read by pip 26.3's rules without following includes, constraints files, editable installs or URL, VCS and path requirements (an include, constraints file or editable install that reaches beyond the root `requirements*.txt` files or the project itself, a URL, VCS, archive or path requirement without a package name other than the project itself, an option pip 26.3 does not know on an option line, and a `${NAME}` variable in a requirement's name or in an option line's option place make the collector partial, and a declared encoding other than UTF-8 makes it failed; a `name @ URL` requirement is recorded under its name and URL origin, or as written when the URL has no `//`, without a gap unless pip could read its text as a path in the project, options after a requirement on the same line other than `-e` are not checked, and a variable inside an option's value is not resolved or reported); `pyproject.toml` (`[project]` dependencies and optional dependencies; Poetry's `dependencies`, `dev-dependencies` and `group.*.dependencies` tables, translated to PEP 508); `Dockerfile`, `Dockerfile.agent` and `docker-compose.yml` or `.yaml` | AI package identities, pins, npm lockfile integrity; container images named by each Dockerfile `FROM` instruction, read as BuildKit reads it (the instruction word in any case, `--flag` words skipped, continued lines joined and trimmed, comment lines and heredoc bodies skipped, earlier build stages left out), and by the first word after `FROM` or `image:` in compose files, when the image contains vllm, ollama, triton, tgi, llama or model, with whether it ends in a digest (in a Dockerfile, an ARG substitution, quotes or escapes in the image, a `FROM` or heredoc that cannot be parsed, or an escape directive other than a backslash make the collector partial) |
| `a2a` | `.well-known/agent.json`, `agent-card.json`, A2A client config | A2A 0.3 and 1.0 agent cards; origins of endpoints, `supportedInterfaces` (in order), `additionalInterfaces` and security scheme URLs, with network-path URLs (`//host/...`) and bare `host:port` addresses whose host is a dotted name, `localhost` or a bracketed IP as `//host:port` and other scheme-less URLs as `[redacted]` (paths and interface tenants bound only with `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`); OAuth and OpenID Connect scopes required by the `security` or `securityRequirements` lists of the card and of its skills, including scope URIs; security scheme types; declared authentication |
| `ide_agents` | Settings for Claude Code, Cursor, Codex, Windsurf, Cline, Copilot and others | Which agents are configured, from marker files. For Claude Code, the permission mode and whether its allow list has a blanket grant; for Cursor, Windsurf, Cline and Codex, only an `agent.permissionMode` key in their JSON settings. Not hooks, deny or ask rules, helpers, Codex `config.toml` or other settings |
| `shadowscan` | [Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) reports | Imported discovery claims, kept separate from local evidence. Reruns are compared by normalized content, and CI can require a signed report |

### What it checks

| Command | What it answers |
| --- | --- |
| `validate` | Did every collector finish without reporting a gap? Do hashes, signatures and source bindings still match? Surfaces the collectors do not support are not gaps ([known limitations](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md#known-limitations-in-010)) |
| `risk` | What are the findings, and does the score or worst severity cross your gate? |
| `diff` | What changed in the recorded inventory since the reviewed snapshot? Is any change security-relevant? Settings and files the collectors do not record are not compared |
| `verify-artifact`, `verify-discovery` | Do these bytes match a trusted digest, Sigstore identity or ShadowScan report? |
| `blast-radius` | Which agents and components are associated with a compromised component? |
| `runtime keygen/sign/verify` | Are signed snapshots, approvals and trust statements valid for a gateway? |
| `discover-mcp`, `verify-live`, `advisories` | What does a running server actually serve? Do exact versions have known advisories? *(live mode)* |

The [CLI reference](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/cli-reference.md) documents every command and option.

### What it produces

| Output | How to get it | Use it for |
| --- | --- | --- |
| Native AgentBOM JSON | `scan` (default) | Full-fidelity record; defined by the [AgentBOM schema](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/schemas/README.md) |
| CycloneDX 1.7 | `scan -f cyclonedx` | SBOM tooling; validated against the pinned official schema |
| SPDX 3.0.1 | `scan -f spdx` | SPDX tooling; validated against the pinned official schema |
| SARIF 2.1.0 | `scan -f sarif` | GitHub code scanning and other SARIF viewers |
| CycloneDX VEX | `vex` | Findings marked `in_triage`, with no exploitability claim |

Standard exports embed the native inventory in a digest-bound extension. Keep that extension to recover full semantics. Without it, a consumer never sees a conditional edge as an unconditional relationship, can read which native relationship each SPDX `other` relationship stands for, and sees coverage as `incomplete` or `unknown`, never `complete`. Exports written by earlier builds may need to be regenerated; see [fingerprint migration](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/fingerprint-migration.md).

### See it on the demo agent

The bundled [demo agent](https://github.com/Hunzee-VC/Nexus-Symbiote/tree/main/examples/demo-agent) is a small synthetic support assistant. Scanning it records 11 components across 9 types, including the following findings:

| Severity | Component | Finding |
| --- | --- | --- |
| high | `memory` MCP server | Unpinned package reference (`@latest`) |
| high | `models/intent-classifier.safetensors` | No verified, artifact-bound signature |
| high | `ollama/ollama:latest` container image | No immutable digest pin |
| medium | `notes` and `memory` MCP servers | stdio transport: each runs as a local process |
| medium | `product-notes` retrieval source | No declared content-filtering control |

The [examples walkthrough](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/examples/README.md) reproduces this, adds drift detection, validation, exports and a ShadowScan import — all offline.

### What a scan does not prove

A scan is an inventory, not a verdict. It does not show that a model is benign, that a tool's backend matches its description, or that every agent action was mediated. Read [what results do and do not establish](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md#what-results-do-and-do-not-establish) before using results in an approval process. Treat exported BOMs as sensitive.

## How

**Install a verified release or a reviewed commit, inventory the agent, then let CI hold the line.**

### Install a verified release

Requires Python 3.11+ on Linux, git, and the [GitHub CLI](https://cli.github.com/) signed in with `gh auth login`. Releases are built from `main` by the [release workflow](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/.github/workflows/release.yml) and published to PyPI through OIDC trusted publishing with build attestations. The block resolves the signed `v0.1.0` tag to its commit, downloads the exact wheel, verifies its attestation against that commit, and only then installs the hash-locked runtime from the same commit and the wheel without resolving anything else:

```bash
(
  set -euo pipefail
  python -m venv --clear .venv
  commit="$(git ls-remote https://github.com/Hunzee-VC/Nexus-Symbiote.git 'refs/tags/v0.1.0^{}' | cut -f1)"
  test -n "$commit" || { echo "tag v0.1.0 not found" >&2; exit 1; }
  .venv/bin/python -m pip download --no-deps --only-binary=:all: nexus-symbiote==0.1.0 -d dist
  gh attestation verify dist/nexus_symbiote-0.1.0-py3-none-any.whl --repo Hunzee-VC/Nexus-Symbiote \
    --signer-workflow Hunzee-VC/Nexus-Symbiote/.github/workflows/release.yml \
    --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
  curl -fsSL -o requirements-action.lock \
    "https://raw.githubusercontent.com/Hunzee-VC/Nexus-Symbiote/$commit/requirements-action.lock"
  .venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
  .venv/bin/python -m pip install --no-deps dist/nexus_symbiote-0.1.0-py3-none-any.whl
  .venv/bin/nexus-symbiote --version
)
```

The subshell first rebuilds `.venv` with `--clear`, then stops at the first failing command, including a missing or signed-out `gh` or a missing tag. The version check is the subshell's last step, so it runs only after every other step succeeded, and it runs the program inside `.venv`, so an earlier install elsewhere on your `PATH` cannot stand in for the verified wheel. Keep the block as it is: placing the subshell before `&&` or `||` makes bash ignore its `set -e`. Activate the environment with `. .venv/bin/activate` to use it. Nothing is installed unless the release workflow attested these exact wheel bytes for the commit the `v0.1.0` tag points at, and the lock file is fetched from that same commit. Release builds are reproducible, so this check cannot tell the published commit from another one that differs only in its lock file. Keeping the tag on the published commit is the job of the [release-tag ruleset](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/repository-controls.md#operator-prerequisites), which the release procedure applies before the first tag is created. Paste the block as one unit; running the lines one at a time loses these checks. [Releasing](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/releasing.md) describes what the attestation does and does not establish.

### Install from reviewed source

Requires Python 3.11+ on Linux. To run exactly the commit you reviewed, install it with the hash-locked runtime:

```bash
git clone https://github.com/Hunzee-VC/Nexus-Symbiote.git
cd Nexus-Symbiote
git checkout --detach REVIEWED_COMMIT_SHA
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-action.lock
python -m pip install --no-deps --no-build-isolation .
nexus-symbiote --version
```

Optional extras: `.[sigstore]` for Sigstore verification; `.[cyclonedx]` installs the CycloneDX Python library, which the test suite uses to cross-check exports (the tool itself does not import it); `.[all]` for both. For development: `make install-locked` (see [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md)).

### Try it in 60 seconds

From the checkout, inventory the bundled demo agent — nothing is executed and no network is used:

```bash
nexus-symbiote scan examples/demo-agent --report-only -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
nexus-symbiote risk demo.aibom.json --no-project-policy
nexus-symbiote validate demo.aibom.json --project examples/demo-agent --no-project-policy
```

The demo scan uses `--report-only` to retain an incomplete inventory for inspection. Its Claude settings are only partially inventoried, so the default scan gate and `validate` fail. The model's integrity also stays unknown because no signer policy was supplied. Report-only mode is not a production approval gate.

### Scan your own agent

```bash
nexus-symbiote scan /path/to/agent --no-project-policy -o agentbom.json
nexus-symbiote validate agentbom.json --project /path/to/agent --no-project-policy
nexus-symbiote risk agentbom.json --project /path/to/agent --no-project-policy --threshold 50
```

With `--project`, `risk` collects fresh evidence and refuses to score a BOM that disagrees with it. The [public-agent tutorial](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) walks through a real repository end to end.

### Gate drift in CI

Record a reviewed snapshot once, then compare every new collection:

```bash
nexus-symbiote baseline /path/to/agent -o reviewed.json
nexus-symbiote scan /path/to/agent --no-project-policy -o agentbom.json
nexus-symbiote diff reviewed.json agentbom.json --fail-on-alert
```

`--fail-on-alert` fails on any change to the recorded inventory rated medium or higher. It cannot alert on what the collectors do not record: Claude Code hooks, deny and ask rules, skill scripts and subagents are among the [known limitations](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md#known-limitations-in-010) of this release, so review changes to them separately. A baseline is unsigned — review it before treating it as an approval.

### GitHub Action

Pin the Action to a reviewed 40-character commit:

```yaml
name: Agent inventory
on: [push, pull_request]
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
      - uses: Hunzee-VC/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        with:
          scan-path: .
          output-file: agentbom.json
          validate: 'true'
          risk-check: 'true'
          risk-threshold: '50'
          sarif-upload: 'false'
```

With `validate: 'true'`, integrity passes only when at least one artifact hash or signature verifies and no component's evidence is unknown, so a repository in which nothing verifies, such as an empty checkout or one with only an MCP configuration, fails validation. A model counts only as a SafeTensors file whose artifact-bound signature verifies under a signer policy you own, so a repository that contains a model fails validation unless you pass such a policy and every model meets it. Write the policy outside the workspace from a trusted source, such as a repository or organization variable, never from the checked-out code:

```yaml
      - name: Write the signer policy
        env:
          SIGNER_POLICY: ${{ vars.NEXUS_SYMBIOTE_SIGNER_POLICY }}
        run: printf '%s' "$SIGNER_POLICY" > "$RUNNER_TEMP/signers.json"
      - uses: Hunzee-VC/Nexus-Symbiote@<reviewed-40-character-commit-sha>
        with:
          scan-path: .
          signature-policy: ${{ runner.temp }}/signers.json
```

The Action refuses a policy inside the workspace, a path that passes through a symlink (including a symlinked `RUNNER_TEMP`), or a hard link, passes one snapshot of it to collection and validation, and reports its SHA-256, as `sha256:<hex>`, in the `signature-policy-digest` output. It verifies signatures offline against the Sigstore trust root shipped in its hash-locked `sigstore` package, never a cache on the runner.

The Action installs its own hash-locked runtime, including Sigstore verification, ignores policy in the scanned checkout, and fails on collection errors. Keep a job timeout like the one above: hostile input can keep a scan running until the job times out. Run the Action once per workflow run, because its artifact name and SARIF category are fixed ([known limitations](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md#known-limitations-in-010)). Set `sarif-upload: 'true'` and add `security-events: write` for SARIF upload. Inputs and outputs are in [action.yml](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/action.yml). The repository also ships [pre-commit hooks](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/.pre-commit-hooks.yaml) (`nexus-symbiote-scan` and `nexus-symbiote-risk`).

Every command is offline by default. Only `discover-mcp`, `advisories` and `verify-live` reach the network, and only in live mode (`--live` or `NEXUS_SYMBIOTE_MODE=live`). Use `nexus-symbiote init` to generate a `.nexus-symbiote.yaml` policy file for a trusted project (it is read only from the project you scan or name with `--project`, never from a parent directory or from where an inventory file is saved), or pass `--no-project-policy` when the checkout is not yours. Details are in [offline and live modes](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/offline-and-live-modes.md).

### How it works

```text
             ┌──────────────────────────────────────────────┐
  agent      │ 8 static collectors: nothing is executed     │
  project ──>│ mcp · model · prompt · rag · registry        │
 (read-only) │ a2a · ide_agents · shadowscan                │
             └──────────────────────┬───────────────────────┘
                                    v
             ┌──────────────────────────────────────────────┐
             │ AgentBOM (native JSON)                       │
             │ components · relationships · findings        │
             │ coverage, gaps and assurance for every claim │
             └──────┬───────────────┬───────────────┬───────┘
                    v               v               v
             validate · risk       diff          exports
             gates, exit 0/1   drift alerts   CycloneDX · SPDX
                                               SARIF · VEX
```

1. **Collect.** Each collector reads its surfaces through confined, size-bounded file reads and returns components, findings and coverage status.
2. **Assemble.** Results merge into one AgentBOM. Every claim keeps its assurance level: declared, observed or verified.
3. **Gate.** `validate` checks completeness and integrity; `risk` scores findings against your policy. Detected unsupported instruction, skill, IDE and MCP surfaces are reported as coverage gaps. Other unsupported surfaces may remain undetected, so completeness is only a claim within the documented collection profile.
4. **Compare.** `diff` compares two snapshots semantically and rates each change.
5. **Export.** Standard formats are generated from the same collection, so every export describes the same evidence.

### Exit codes

| Exit | Meaning |
| --- | --- |
| `0` | The command completed and every requested gate passed |
| `1` | A gate or check failed (risk, integrity, drift, incomplete collection, or unreadable input) |
| `2` | Usage error, including a live command run in offline mode |

## Documentation

The [documentation hub](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/README.md) organizes every guide by Why, What and How. Start here:

| If you want to… | Read |
| --- | --- |
| Understand the trust model | [Security model](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/security-model.md) |
| Run the full offline demo | [Examples walkthrough](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/examples/README.md) |
| Scan a real project end to end | [Scanning a public agent](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/tutorials/scanning-a-public-agent.md) |
| Look up a command or option | [CLI reference](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/cli-reference.md) |
| Import Nexus-ShadowScan discovery | [ShadowScan integration](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/shadowscan-integration.md) |
| Mediate tool calls with signed contracts | [Runtime assurance](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/runtime-assurance.md) |
| Release or verify a release | [Releasing](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/releasing.md) · [Repository controls](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/repository-controls.md) |

## Project status

Nexus SymBiote is **alpha** with a single maintainer: APIs, formats and policy semantics may change, and there is no SLA. Known detection gaps in this release are listed in [SECURITY.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md#known-limitations-in-010). CI, including CodeQL, runs on every push and pull request. A release is published only by the environment-gated [release workflow](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/releasing.md), after its preflight has confirmed branch protection and a successful `Verified CI` run for the exact commit. Planned work is tracked in the [roadmap](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/ROADMAP.md) and changes are in the [changelog](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CHANGELOG.md).

[Nexus-ShadowScan](https://github.com/Hunzee-VC/Nexus-ShadowScan) is the companion discovery engine — it finds agents across many surfaces, and Nexus SymBiote turns its reports into AgentBOMs with local artifact and supply-chain verification.

## Security

Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SECURITY.md), never in a public issue.

## Contributing

Contributions are welcome — especially tested collector coverage, regression fixtures and documentation. See [CONTRIBUTING.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CONTRIBUTING.md) for setup and review contract, [GOVERNANCE.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/GOVERNANCE.md) for decisions, and [SUPPORT.md](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/SUPPORT.md) for troubleshooting. Please follow the [code of conduct](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CODE_OF_CONDUCT.md).

## Citation

If you use Nexus SymBiote in research or tooling, cite it with the metadata in [CITATION.cff](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/CITATION.cff), or use **Cite this repository** on GitHub.

## License

[MIT](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/LICENSE). Copyright (c) 2026 Emmanuel Dahunsi (AISecNomad). The vendored schemas under `src/nexus_symbiote/generators/schemas/vendor/` keep their upstream licenses: the CycloneDX schemas are Apache-2.0 ([license](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/LICENSE-APACHE-2.0.txt)), and the SPDX 3.0.1 schema and context come from the SPDX Specification, which is Community-Spec-1.0 with CC-BY-3.0 for pre-existing portions ([license](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/LICENSE-SPDX-3.0.1.txt)). The [notice](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/src/nexus_symbiote/generators/schemas/vendor/NOTICE.txt) gives their sources, so the distribution's license expression is `MIT AND Apache-2.0 AND Community-Spec-1.0`.
