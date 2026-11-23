# Approve agents for ShadowScan reconciliation

Nexus-ShadowScan calls a finding *shadow* when no entry of its approved inventory
(`--inventory`) binds the finding's resource. It does not read the native
AgentBOM as an approved inventory: it refuses it. `export-inventory` closes that
loop for the agent you approved in SymBiote review. It writes the inventory's
repository agent as ShadowScan's documented *simple list*, a JSON file that
ShadowScan's `--inventory` and `shadowscan inventory check` load. The format and
the binding rules below follow ShadowScan commit
[`999bef1`](https://github.com/Hunzee-VC/Nexus-ShadowScan/tree/999bef1a277cfbcdc44fdbca925e54c07efa278d)
(release 0.1.4); a later ShadowScan can change either.

The command is offline. It reads one native inventory and writes one file; it
does not run ShadowScan.

## Export the reviewed agent

Export from the inventory you reviewed, such as the baseline on your protected
branch, never from a scan of the change under review. With the fixture inventory
in this repository (a scan of a project whose `agent.yaml` declares
`id: acme:support-triager`):

```sh
nexus-symbiote export-inventory tests/fixtures/shadowscan-inventory/declared-agent.aibom.json \
  --format shadowscan-simple --resource-prefix github:acme/support-triager -o approved.json
```

The command prints on standard error:

```text
Wrote a ShadowScan 999bef1 simple-list inventory: approved.json
Agent id: agent:repository:651468131b187c7b2734b11c
Inventory file SHA-256: sha256:7bef469d45ccb52d4b6a952058890b157afc1d490a2734273cdb3f1beb069af1
Inventory content digest (nexus-symbiote/inventory-content/v1): sha256:0b70f2881535ed3334e4da35081126a3a86c89b5c189d4e9533eabeea5d76758
Review and sign the exported file, and keep it where the change ShadowScan scans cannot write: whoever can change it approves findings.
```

and writes `approved.json` (mode 0600):

```json
{
  "agents": [
    {
      "discriminators": [
        "project"
      ],
      "id": "agent:repository:651468131b187c7b2734b11c",
      "name": "support-triager",
      "owner": "platform-security",
      "resources": [
        "github:acme/support-triager"
      ],
      "surfaces": [
        "code"
      ]
    }
  ]
}
```

Pass the file to ShadowScan with `--inventory approved.json`, or check what it
loads with `shadowscan inventory check approved.json`. The two digests identify
the inventory the file came from: the SHA-256 of its bytes, and its content
digest under the profile `nexus-symbiote/inventory-content/v1`, which leaves out
only the serial number, the collection times and where an imported report was read
from, so two scans of the same content share it. Record both with the exported file.

## What the file approves

The export writes one entry, for the repository agent, with these fields:

| Field | Value |
| --- | --- |
| `id` | The agent's reference, `agent:repository:` followed by the first 24 hexadecimal digits of the SHA-256 of the `id` that `agent.yaml` declares. The inventory records this reference, not the declared text. An undeclared agent gets another id; see [below](#declared-and-unnamed-agents). |
| `name` | The `name` that `agent.yaml` declares. |
| `owner` | The `owner` that `agent.yaml` declares; left out when none is declared. ShadowScan gives it to an approved finding that names no owner. |
| `resources` | One pattern: `--resource-prefix`, escaped to match only that exact string. |
| `surfaces` | `code`. |
| `discriminators` | `project`. |

ShadowScan approves a finding only when exactly one entry's resource pattern
matches the finding's resource and that entry's scope constraints, such as its
surfaces and observation types (`identity_discriminator`), allow it; an entry
without a constraint allows every value. Its code connectors report a
repository's agent project with the resource `PREFIX` itself and the observation
type `project`. They report other things under the same or a longer resource: the
coding-agent configurations of the repository root (`coding-agent-config:...`) at
`PREFIX` too, and a credential, an MCP configuration or an agent card in a file at
`PREFIX/<path>`. The `project` and `code` constraints keep the entry to the
agent's project: without them, the same pattern would also approve each
coding-agent configuration at the repository root. ShadowScan marks an approved
finding as not shadow and lowers its risk score, so every extra approval hides
something.

The export binds nothing else the inventory records:

- **Components.** MCP configurations, A2A card files, models, prompts and
  coding-agent configurations stay findings that ShadowScan reconciles on their
  own. The inventory associates them with the agent by repository, without
  establishing which agent uses them, and a `.mcp.json` usually configures a
  coding agent such as Claude Code, not the agent the repository defines.
  ShadowScan's own AgentBOM reader likewise never lets component presence approve
  anything.
- **Remote MCP servers and A2A cards.** ShadowScan's endpoint connector reports an
  MCP tool as `SERVER/TOOL`, where `SERVER` is what the client's tool export calls
  the server (its name, or failing that its URL), and an A2A card by its full card
  URL. The inventory records remote MCP and A2A endpoints only by origin, and a
  tool is a component, not the agent, so the export binds neither.
- **Nested projects and source agents.** A project that ShadowScan finds below
  the root, at `PREFIX/<directory>`, is not approved, and neither is an agent that
  ShadowScan's `agent_granularity: source` mode reports in a source file
  (`PREFIX/<file>#agent:<name>`).

A pattern is a case-sensitive `fnmatch` glob. The export puts each `*`, `?` and
`[` of the prefix in a one-character class (`[*]`, `[?]`, `[[]`), exactly as
ShadowScan's own `literal_resource_pattern` does; a `]` outside a class is already
literal. The pattern therefore matches the prefix and nothing else: the prefix
`/srv/ci/[build]*?/repo]` is written as `/srv/ci/[[]build][*][?]/repo]`, which no
longer matches `/srv/ci/b/x/repo]`. ShadowScan keeps names and aliases as review
suggestions only, so the agent's name never approves a finding by itself.

## Choose the resource prefix

`--resource-prefix` must be the exact resource ShadowScan reports for the
repository's root project, which depends on how ShadowScan scans it:

| ShadowScan scan | Resource prefix |
| --- | --- |
| `shadowscan code --github-repo OWNER/REPO` | `github:OWNER/REPO` |
| `shadowscan code --gitlab-group GROUP` | `gitlab:` followed by the project's path with its namespace |
| A `code.filesystem` connector with `label` and a single `path` | The label |
| A `code.filesystem` connector with `label`, `paths` and `root_ids` | `LABEL/root-id-ID` |
| `shadowscan code PATH` (no label) | The absolute path of `PATH` (ShadowScan refuses a path through a symbolic link) |

When the inventory comes from a scan of a subdirectory that ShadowScan reports as
a nested project, the prefix is that project's resource, the label followed by
`/` and the directory's path. Prefer a label. A checkout path can differ between
runs, and the agent is then shadow again; for the same reason, give labelled
`paths` their `root_ids`, since without them ShadowScan names each root by a
digest of its resolved path. The inventory does not record any of these labels,
so the command never guesses one and cannot check yours. A prefix that names no
scanned repository approves nothing, and so does one that ShadowScan withholds
from its findings as credential-like text; a prefix that names another repository
approves that repository's project instead.

A prefix is refused when ShadowScan could not report it back exactly: empty,
longer than 4,096 characters, starting or ending with white space (ShadowScan
removes it), containing a control, format, line-separator or unencodable
character or another default-ignorable code point (such as a variation selector), or containing `[REDACTED]` (ShadowScan approves no resource that
does).

## Declared and unnamed agents

The repository agent counts as declared when the inventory is native format 1.1
or later, records `identity_source: agent.yaml`, and its reference is not the
inferred `agent:repository:cdb4ee2aea69cc6a83331bbe`: that is, `agent.yaml`
declares an `id` ([agent manifest](agent-manifest.md)). Otherwise the command
exits 1 with a hint to declare `id`. A format 1.0 inventory (release 0.1.0) never
counts as declared, because its reference for an agent without `id` came from the
checkout path; scan again with this release.

`--include-unnamed` exports an undeclared agent anyway, under the id
`agent:unnamed:` followed by the first 24 hexadecimal digits of the inventory's
content digest, and says so in the entry's `names`:

```json
"names": [
  "unnamed repository agent; id from inventory content digest sha256:59153bc238b0ab3dd8f507f16b2ea44a634a33129eda2a72ed66c2bf604d3f7e"
]
```

That id changes whenever the inventory's content changes. The entry carries the
`name` and `owner` that `agent.yaml` declares, if any; the placeholder name
`repository` of an agent without a manifest is not exported.

Other agent components, such as imported ShadowScan discovery, are never exported;
the command reports how many it left out. An inventory without a repository agent,
or with more than one, is refused: entries with the same binding would be
ambiguous, and ShadowScan approves nothing that two entries bind.

## Why the autonomy level is left out

ShadowScan's simple list accepts `autonomy_level`, an integer from 0 to 5. SymBiote
records `agent.yaml`'s `autonomy_level` on another scale, and the two do not align
one to one:

| SymBiote (`agent.yaml`) | ShadowScan |
| --- | --- |
| `L0-chatbot` | 0 chatbot |
| `L1-copilot` | 1 copilot |
| `L2-agent` | 2 supervised |
| `L3-autonomous` | 3 semi-autonomous |
| `L4-fully-autonomous` | 4 high autonomy |
| | 5 fully autonomous |

Copying the number would understate a fully autonomous agent as high autonomy,
and ShadowScan compares a declared level with the floor it observes. Mapping the
names would be a policy decision that neither tool's documentation makes. The
export therefore declares no level, and ShadowScan reports only the interval it
observes. The level stays in the native inventory as `declared_autonomy_level`.

## Keep the file out of the reviewed change's reach

The exported file is an approval list: whoever can change it approves findings.

- Export from the reviewed baseline, the way the
  [drift gate](drift-gate.md#the-trust-anchor-is-the-baseline) reads it from the
  protected base branch, never from a scan of the pull request.
- Keep the file outside the checkout that ShadowScan scans. ShadowScan warns when
  an inventory lies inside a scanned path, because scanned content could alter
  approvals; the warning does not fail the scan.
- Sign the file, for example with `nexus-symbiote attest`, which signs a file's
  exact bytes, and check the signature with `nexus-symbiote verify-attestation`
  before ShadowScan reads the file: ShadowScan checks no signature on an inventory
  file, and `export-inventory` signs nothing. A file that is not a native inventory
  is attested by its bytes only; see [inventory attestation](inventory-attestation.md).
- Replace the previous export instead of adding a new one beside it. Two files that
  bind the same resource approve nothing.

The file approves a location, not its content: a later change to the repository's
root project is still approved in ShadowScan. Compare content against the reviewed
baseline with `nexus-symbiote diff`; the export does not replace that gate.

## Refusals

The command exits 1, and writes nothing, when the inventory cannot be read as a
native inventory (a symbolic link, a FIFO, more than 16 MiB, not strict UTF-8
JSON, an unsupported format version, a schema mismatch, or no `components`
list), when it has no repository agent or more than one, when the
agent is not declared and `--include-unnamed` is absent, or when ShadowScan could
not read its name or owner back exactly (empty, longer than 4,096 characters,
padded with white space, or containing a control, format, line-separator or
unencodable character or another default-ignorable code point). Messages name the field, never its text. It exits 2 for a
usage error: a missing option, a prefix it refuses, an output that does not end
in `.json` (ShadowScan reads a file as strict JSON only by that suffix and skips
other names when it loads a directory), or an output that is the inventory
itself.

## What the export does not establish

- It does not authenticate the inventory, its producer or the file it writes.
- It does not check that the prefix names the repository the inventory describes;
  a prefix that names another repository approves that repository's project.
- It does not show that ShadowScan will find the agent, or that the agent is safe.
- It carries no autonomy level, framework, component or governance fact.
- Compatibility was checked against ShadowScan 999bef1 by loading the exported
  files with its own `Inventory.load` and matching findings with
  `Inventory.match`, outside the test suite. The tests pin the field names and
  the escaping that commit accepts, not a later release.
