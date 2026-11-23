# Agent manifest (`agent.yaml`)

`agent.yaml` is an optional file at the root of a scanned project. It declares the
agent the repository defines: a stable identity, the instruction files it reads and
the models it uses. `scan`, `baseline`, `validate --project` and `risk --project`
read it when they assemble the repository agent. Everything in it is a declaration
by whoever can write to the repository; it never raises trust or assurance.

## Example

```yaml
id: acme:support-triager
name: support-triager
version: "1.4"
purpose: Triage inbound support tickets
framework: langgraph
owner: platform-security
autonomy_level: L2-agent
instructions:
  - CLAUDE.md
  - docs/agents/triage-rules.md
models:
  classifier:
    path: models/classifier
  planner:
    provider: openai
    requested_ref: gpt-4o
```

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Agent name (non-empty) |
| `id` | no | Stable identity; the agent's reference is `agent:repository:` followed by the first 24 hexadecimal digits of the SHA-256 of `id` |
| `version`, `purpose`, `framework`, `owner` | no | Recorded as the agent's version, description, framework and supplier |
| `autonomy_level` | no | `L0-chatbot`, `L1-copilot`, `L2-agent`, `L3-autonomous` or `L4-fully-autonomous`; recorded as the property `declared_autonomy_level`, never as the agent's observed `autonomy_level` |
| `instructions` | no | Up to 1,024 paths of instruction files, relative to the project root |
| `models` | no | Up to 1,024 named models, each either `path` (a model file or the directory that holds it, relative to the project root) or both `provider` and `requested_ref` (a hosted model) |

Any other key is an error. The file must be a UTF-8 YAML mapping of at most 1 MiB
and 20,000 YAML tokens, without anchors, aliases or tags.
[`schemas/agent-manifest-1.0.schema.json`](../schemas/agent-manifest-1.0.schema.json)
describes the structure for editors and other tools; the path and file rules below
are checked only when a scan reads the manifest.

The exported `name`, `version`, `framework` and `owner` use the name rule of the
shared [redaction](security-model.md#known-false-positive-and-false-negative-classes),
which keeps an ordinary name such as `sk-research-assistant`, and `purpose` uses
free-text redaction. Recognized credentials are removed before these values enter
any inventory or export. Redaction does not recognize every possible secret, so keep credentials
out of these fields and review earlier exports before sharing them.

Redaction also keeps only the origin of a URL, so `owner: https://github.com/acme-platform`
is exported as `https://github.com`. The agent record binds the written value of each
field that redaction changed, and only of those: with
`NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, `static_value_binding` is an HMAC-SHA256
(profile `nexus-symbiote/agent-manifest-values/v1`) over them, so a change to one of
them changes it, while a change to a field exported as written shows in that field.
Without the key the record carries a low `completeness` finding that names the fields,
and `diff` raises its unbound-values alert on every comparison, as it does for the
other records with withheld values. A manifest whose fields are all exported as written
carries neither. A URL written with an upper-case host or a trailing slash counts as
changed, since the export normalizes it.

## What it changes

- **Identity.** Without `agent.yaml`, or without `id`, the repository agent's
  reference is `agent:repository:cdb4ee2aea69cc6a83331bbe` (derived as if `id` were
  `.`, "this repository"), the same in every checkout. It is named after the
  manifest's `name`, or `repository` for the inferred agent.
  `id` gives it a reference of your own. Changing `id` replaces the agent, so
  `diff` reports it removed and added.
- **Instructions.** A listed file that the `prompt` collector already reads, such
  as `CLAUDE.md`, maps to that collector's record; it is not inventoried twice. Its
  bytes must still match what the collector recorded. Any other listed file is
  inventoried as `prompt:manifest:<digest of its path>` with its SHA-256 and the same
  hidden-character checks the collector applies to instruction files. This is how
  instruction files the collector does not read, such as `docs/agents/rules.md` or a
  nested `CLAUDE.local.md`, enter the inventory. `surfaces_scanned` lists `agent.yaml`
  once it is read, and each file inventoried only because the manifest declares it.
- **Local models.** A `path` must match a model artifact the `model` collector
  recorded: the file itself, or a file directly in that directory. The manifest adds
  no model of its own; it confirms the declared artifact was collected.
- **Hosted models.** A `provider` and `requested_ref` add a model component with the
  requested alias, declared assurance and unknown trust. Its identity and integrity
  cannot be checked offline, so integrity validation reports them as unknown. The
  `provider` and `requested_ref` pass through the shared credential redactor first, so
  `gpt-4o?token=ghp_...` is recorded as `gpt-4o?token=***`; ordinary values such as
  `openai/gpt-4o-mini` are kept as written.
- **The risk gate.** A repository whose only local subject is the inferred agent
  fails with "no agent manifest or supported local inventory evidence was found".
  A manifest-declared agent, instruction or model is such evidence.

## Problems are recorded, not fatal

`scan` and `baseline` record each problem as a scan failure and still write the
inventory, so the default gate fails and the evidence stays available for review.

| Scan failure | Cause |
| --- | --- |
| `agent.yaml: does not conform to the agent manifest schema` | Not a YAML mapping, an unknown key, a missing `name`, a YAML anchor, alias or tag, or too many tokens. The inferred agent is recorded instead |
| `agent.yaml: read refused (...)`, `agent.yaml: symlink target ...`, `agent.yaml: file-bytes limit of 1 MiB exceeded; ...` or `agent.yaml: invalid UTF-8` | A non-regular file, a symbolic link other than a relative one to a regular file in the project, a file over 1 MiB, or bytes that are not UTF-8. The inferred agent is recorded instead |
| `agent.yaml#/instructions/N: must be a relative path beneath the repository` or `agent.yaml#/models/KEY: must be a relative path beneath the repository` | An absolute path, a `..` component, a backslash or a NUL character |
| `agent.yaml#/instructions/N: the declared instruction could not be collected safely` | Missing, a symbolic link other than a relative one to a regular file in the project, not a regular file, or larger than the `file-bytes` [collection limit](collection-limits.md) (4 MiB by default) |
| `agent.yaml#/instructions/N: names a path inside a directory that collection never reads` or `agent.yaml#/models/KEY: names a path inside a directory that collection never reads` | A path under `.git`, `node_modules`, `__pycache__`, `.venv` or `venv`, in any spelling a case-insensitive file system treats as the same name, such as `Node_Modules` |
| `agent.yaml#/instructions/N: instruction changed since scanner collection` | The file changed between collection and assembly. For a file the `prompt` collector recorded without `content_hash`, such as `AGENTS.md` linked to `config/app.json`, the keyed binding is compared instead; without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` nothing recorded its content, so it is not compared |
| `agent.yaml#/instructions/N: instruction content was bound under another key` or `agent.yaml#/instructions/N: instruction content binding has an unknown profile` | The collector bound a file recorded without `content_hash` under another key or profile, so assembly cannot compare it |
| `agent.yaml#/instructions/N: declared instruction is not UTF-8 text` | It cannot be checked for hidden characters |
| `agent.yaml#/models/KEY: the declared local model has no collected model artifact` | No collected model at that path |
| `agent.yaml#/models/KEY: the declared local model is unavailable` | The artifact can no longer be opened safely |
| `agent.yaml#/models/KEY: the key is too long for a component reference` | A hosted model key that, percent-encoded, makes the model's reference longer than 16,384 characters |
| `agent.yaml#/models: a model key is shaped like a credential` | A model key that the credential redactor would change, such as a pasted `ghp_...` token. The key becomes the component reference, which cannot be redacted, so the model is not recorded |
| `agent.yaml: declares a component reference that is already in use` | A declared instruction or hosted model would take the reference of a different component already in the inventory |

These failures name an entry by its position or its percent-encoded key, never by
its text: that text comes from the checkout and need not name a file.

`validate --project` and `risk --project` recollect the manifest and report any of
these as "Local agent manifest could not be reconciled."

The project policy's `scan.exclude_paths` (in `.nexus-symbiote.yaml`, which
`--no-project-policy` and the GitHub Action ignore) applies to `agent.yaml` and to
every path it names. An excluded path is never read or hashed; it is recorded as a
coverage gap (`PATH: excluded by collection policy`), so the default gate fails
rather than silently narrowing what was inventoried.

## Trust

`agent.yaml` is part of the checkout, so the change under review can edit it. It can
rename the agent, change its `id`, and add or drop declared instructions and models;
`diff` reports each of these against a reviewed baseline. It cannot make the scan
read outside the project root, follow a symlink out of the project, raise a trust
tier or an assurance level, or record a runtime observation: declared fields keep
declared assurance and the agent's runtime autonomy and deployment stay unknown.

A repository that already has an `agent.yaml` for another tool gets the
"does not conform" failure. Excluding the file in the project policy keeps it
unread, at the cost of a recorded coverage gap; under `--no-project-policy` the
file is read and the failure stays.
