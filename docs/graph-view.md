# Graph view

`nexus-symbiote graph` turns one native inventory into a view you can read and navigate:
every component, the relationships the inventory records between them, the
[risk classes](#risk-classes) its recorded evidence supports, its findings, and the
shortest recorded [exposure path](#exposure-paths) from each agent to each risky
component. It writes one self-contained HTML file, or the same view as a
[JSON document](#the-json-document). It runs offline and reads only the inventory.

- [What the view shows and does not show](#what-the-view-shows-and-does-not-show)
- [Risk classes](#risk-classes)
- [Exposure paths](#exposure-paths)
- [Focus and limits](#focus-and-limits)
- [The JSON document](#the-json-document)
- [How the page is made safe to open](#how-the-page-is-made-safe-to-open)
- [Example: the demo agent](#example-the-demo-agent)

## What the view shows and does not show

The view restates the inventory. It shows:

- one node per component, with its type, name, version, reference, assurance level,
  trust tier, source path, risk classes and their basis, the number of findings at each
  severity, the highest severity, and up to 20 findings, most severe first, with the
  number left out;
- selected security facts when the record has them: `version_pinned`, `transport`,
  `serialization_safety`, `signing_status`, `permission_mode`, `autonomy_level`,
  `authentication_required`, and a tool's `capability_evidence`;
- one edge per recorded dependency edge (its relationship, its assurance level and
  whether it carries conditions), and one edge per typed reference field, such as an
  MCP client's `server_refs`, that no dependency edge with the same source and target
  records; such an edge is labelled with the field name;
- the inventory's format version and collection time, and its coverage: `unknown` or
  `incomplete`, as [standard exports](standard-exports.md) state it, the verdict
  `risk` and `validate` reach (`complete`, `partial` or `unknown`), the number of scan
  failures and excluded surfaces, and up to 20 coverage gaps with the number left out.
  The gaps state each distinct collection failure once, ending in `(recorded N times)`
  when several collectors recorded it, and the collectors that are not complete as one
  gap per state, while the number of scan failures counts every record.

It does not show runtime reachability or effective authority. Every edge of a static
scan is a repository association: that an agent's repository configures a server does
not show that the agent calls it, or with what identity. Findings are the inventory's
own, except that a model also carries the findings `risk` derives from its recorded
fields when they are missing (see the [finding catalog](finding-catalog.md)).

Relationship conditions and component descriptions are not shown. A finding's
category and detail, a fact, and a coverage gap are cut at 2,000 characters.

## Risk classes

A risk class restates recorded evidence about what one component may do. The evidence
is mostly declared, or inferred from tool names and descriptions by the `mcp` collector,
whose tool records say so in `capability_evidence`
(`unverified-declaration-and-name-heuristic`). A class does not establish what a
component can do at run time, and the absence of a class does not establish that it
cannot. Classes are computed when the view is made and never written to the inventory.

| Component | Recorded value | Class | Basis |
| --- | --- | --- | --- |
| Any component with a capability declaration: agent, tool, skill package, A2A client and server, verified extension | capability `execute` | `code-exec` | `capabilities:execute` |
| | capability `write`, `destructive` or `payment` | `write-capable` | `capabilities:write`, `capabilities:destructive`, `capabilities:payment` |
| | side effect `state-modifying`, `destructive` or `financial-transaction` | `write-capable` | `side_effect_profile:state-modifying`, `side_effect_profile:destructive`, `side_effect_profile:financial-transaction` |
| | capability `network` | `network-egress` | `capabilities:network` |
| | a nonempty `egress_domains` | `network-egress` | `egress_domains:declared` |
| | capability `credentials` | `secret-access` | `capabilities:credentials` |
| | `network-egress` from the declaration, together with capability `read`, `filesystem` or `credentials` | `exfil-capable` | the network basis, and `capabilities:read`, `capabilities:filesystem` or `capabilities:credentials` |
| MCP server | `endpoint_url` with a plain authority (below) whose host is neither `localhost` nor a loopback address | `network-egress` | `endpoint_url:remote` |
| | any other `endpoint_url`: no host that can be read, such as `[redacted]` for an endpoint that depends on the environment, a scheme other than `http`, `https`, `ws` or `wss`, or an authority that is not plain, even one naming `localhost` | `network-egress` | `endpoint_url:unresolved` |
| | an `env` name the collector withheld as `[redacted-N]` | `secret-access` | `env:withheld-name` |
| Model | `serialization_safety` `unsafe-code-execution` | `code-exec` | `serialization_safety:unsafe-code-execution` |
| | `serialization_safety` `unsafe-template-injection` | `code-exec` | `serialization_safety:unsafe-template-injection` |
| | `trust_remote_code: true` | `code-exec` | `trust_remote_code:true` |
| IDE agent `claude-code` | `permission_mode` `bypassPermissions` | `code-exec`, `write-capable` | `permission_mode:bypassPermissions` |
| | `permission_mode` `acceptEdits` | `write-capable` | `permission_mode:acceptEdits` |
| IDE agent `codex` | property `approval_policy` `never` | `code-exec` | `approval_policy:never` |

A few rules need their reasons:

- An MCP server is not given its tools' classes; its tools are nodes of their own,
  joined to it by `provides-tool` edges.
- An endpoint on `localhost` or a loopback address (`127.0.0.0/8` or `::1`) is read but
  gives no class. Its host is read only from a plain authority: an `http`, `https`, `ws`
  or `wss` URL whose authority is a host name of ASCII letters, digits, `.`, `-` and
  `_`, an IPv4 address or a bracketed IPv6 address, and an optional port, with nothing
  else: no userinfo, backslash, percent-escape or whitespace.

  URL parsers can read any other authority as different hosts:
  `http://evil.example\@localhost/` is a request to `evil.example` for a WHATWG parser
  (used by Node-based MCP clients) and to `localhost` for Python's. Such an endpoint,
  like one whose host cannot be read, could be remote, so it counts as one. The `mcp`
  collector records an ambiguous authority as `[redacted]`.
- The `mcp` collector exports an environment variable's name, with its value masked,
  unless the name is token-shaped, not a plain field name, or holds a credential
  value; such a name is withheld as `[redacted-N]`. That marker is the only credential
  signal the record keeps, so a plainly named variable such as `GITHUB_TOKEN` gives no
  class: names are not guessed at. A withheld name that is merely unusual, not a
  credential, still gives `secret-access`.
- Both unsafe serialization values mean that loading the model, or rendering its chat
  template, can run code; the [finding catalog](finding-catalog.md) rates both as a
  critical `serialization_format` finding.
- For an IDE agent, only starting modes with unambiguous meaning are read. Claude Code's
  `bypassPermissions` skips every permission prompt, `acceptEdits` accepts file edits
  without one, and Codex's `approval_policy = "never"` runs commands without asking.

  Any other mode, Codex's `sandbox_mode`, the `agent.permissionMode` that Cursor,
  Windsurf, Cline and Codex settings may carry, and the unscoped allow rules that a
  `permission_scope` finding reports leave the agent unclassified. Classification does
  not parse finding text: a Claude Code agent whose `permissions.allow` is
  `["Bash", "Edit"]` is unclassified, while one with starting mode `acceptEdits` is
  `write-capable`. Effective approval also depends on deny and ask rules, user and
  managed settings and session flags, which no record holds.

A component is **unclassified** when its record holds no value these rules read. That
is unknown, not safe, and the view draws such a node with a dashed outline. A component
whose record holds such a value but gives no class (a tool declared `read` only, a
SafeTensors model recorded `safe`, an MCP endpoint on a loopback host) is shown as
having no derived class, which is also not a statement of safety. Declaration fields
the rules do not read, such as `oauth_scopes`, `filesystem_paths` or
`human_in_the_loop`, leave a component unclassified.

## Exposure paths

Sources are the agents and IDE agents in the view, at most 200; the number not searched
is reported. When there are more than 200, the sources searched are those whose own best
path ranks highest under the order below: the heaviest sink each reaches, then the
shortest distance to such a sink, then its reference. The 200 paths kept are therefore
the ones a search of every source would keep. A source that reaches no sink has no path
and is the first left out.
Sinks are components with a `code-exec`, `exfil-capable`, `write-capable` or
`secret-access` class or a high or critical finding; `network-egress` alone does not
make a sink. Nor do unscoped allow rules: they leave an IDE agent unclassified, with a
medium `permission_scope` finding, so an agent whose `permissions.allow` approves every
shell command is not a sink on that account, while one whose starting mode is
`acceptEdits` is (see [risk classes](#risk-classes)). The `unclassified` filter finds
such an agent. For each source the view finds the shortest forward path along the
edges above to each sink it reaches. A source that is itself a sink has a path of
length 0.

Paths are ranked by the sink's weight, then by length, then by the references of the
source and the sink. The weight compares, in this order, whether the sink has a
critical finding, a high finding, and the classes `code-exec`, `exfil-capable`,
`write-capable` and `secret-access`: each outranks everything after it. The first 200
paths are kept and the number left out is reported. Choosing the sources takes one
search back from the sinks, linear in the nodes and edges, and the paths take time linear
in the number of sources searched times the nodes and edges.

A path is potential reach through recorded associations. It does not show that an
agent can invoke a tool, that a credential reaches it, or that an exploit is possible.

## Focus and limits

```text
nexus-symbiote graph INVENTORY [-o OUTPUT] [--format html|json] [--focus REF] [--max-nodes N]
```

- `--focus REF` keeps the potential blast radius of one component, as
  [`blast-radius`](cli-reference.md#blast-radius) computes it: the component, everything
  that depends on it, and everything that the component and the components of type
  `agent` among those reach. What an IDE agent or a client among them reaches is not
  kept, although an IDE agent is a source of exposure paths, so a focused view can show
  fewer paths from it than the whole view. An unknown reference is an error that quotes
  only the reference you gave, shortened to 200 characters.
- `--max-nodes N` (default 2,000, at most 20,000) is the most components the view may
  hold, after `--focus`. A larger graph is an error with exit status 1, never a cut-down
  view; narrow it with `--focus` or raise the limit.
- An inventory whose graph is invalid (a dangling edge, a reference to a missing
  component or to the wrong type) is refused as `blast-radius` refuses it.
- HTML is written only to a file named with `-o`; JSON goes to standard output without
  one. The output may not be the inventory itself, under any name.

## The JSON document

`--format json` writes the view as a document whose `format` is
`nexus-symbiote/graph-view/v1`, with these keys:

| Key | Contents |
| --- | --- |
| `inventory` | `spec_version`, `timestamp` (`null` when the inventory records no collection time, as a scan without `SOURCE_DATE_EPOCH` does; the HTML page then says "not recorded"), and the inventory's `components` and `dependencies` counts |
| `focus` | The `--focus` reference, or `null` |
| `coverage` | `status` (`unknown` or `incomplete`), `collection` (`complete`, `partial` or `unknown`), `scan_failures`, `surfaces_excluded`, `gaps` and `gaps_omitted` |
| `limitations` | Fixed sentences on what the view does not establish |
| `nodes` | Per component: `index`, `ref`, `type`, `name`, `version`, `assurance`, `trust_tier`, `risk_classes`, `basis`, `assessed` (`false` when unclassified), `findings` (`total`, `highest`, `counts` per severity, `shown` with each `severity`, `category` and `detail`, and `omitted`), `facts`, `unpinned` and `source_path` |
| `edges` | `index`, `source` and `target` node indexes, `kind` (`dependency` or `reference`), `label` (the relationship or field name), `assurance` and `conditional` |
| `exposure` | `sources` (the agents and IDE agents in the view) and `sources_omitted` (those not searched), `sinks`, `paths` (each with `source` and `sink` node indexes, `length`, `nodes`, `edges` (edge indexes), `labels`, `sink_classes` and `sink_severity`) and `paths_omitted` |

Nodes are ordered by column, type, name and reference; edges by source, target, kind
and label. `unpinned` is true for a record with `version_pinned: false` or a
`version_pinning` or `mutable_image_tag` finding. The same inventory always gives the
same document, whatever the order of its components and edges.

## How the page is made safe to open

Everything in an inventory may be hostile, so the page treats every inventory string as
text:

- The graph, the legend, the header, the exposure paths and every component's details
  are rendered when the file is written. With scripts disabled, all of them are
  readable; the script adds tracing, filters and the details pane.
- Every inventory string is passed through one function: long text is cut (labels at
  28 characters, with the text up to 2,000 characters in the node's `<title>`; details
  at 2,000), so a long name costs no more than a short one; control, line-break,
  bidirectional and invisible characters, including every default-ignorable code point
  such as variation selectors and blank fillers, become U+FFFD and a `##name[` CI log
  command, such as `##vso[`, is broken; and the result is HTML-escaped, quotes included.
  Cutting only drops the end of the text and adds an ellipsis, so it cannot form what
  the next step removes. The text appears only as element text or as the value of an
  `aria-label` or `data-name` attribute, never in a script, a style, a URL, an id, a
  class or an attribute name. Ids, classes and the other `data-*` attributes are built
  from node indexes and fixed words.
- The first element of `<head>` is a `Content-Security-Policy` that allows nothing but
  the page's one style block and one script, each pinned by its SHA-256 hash, and
  `data:` images: `default-src 'none'`, `base-uri 'none'` and `form-action 'none'`. The
  page has no inline event handlers, `style` attributes, links or external resources,
  so it opens from `file://` and as a CI artifact without fetching anything.
- The script is fixed text with no data in it. It reads node and edge indexes and fixed
  words from `data-*` attributes, and the names it filters on from `data-name` only to
  compare them. It changes only classes, `aria-pressed`, the text of a status line and,
  on Escape, the name filter, and it scrolls the details it opens into view.

In the page, click a component or press Enter on it to highlight what it reaches and
what depends on it and to open its details; select an exposure path to highlight its
nodes and edges; use the chips to show only components with a risk class, a high or
critical finding, `unpinned` as the [JSON document](#the-json-document) defines it, or
no classification (a component must match every chip selected); type in the name
filter, which matches a name as the page shows it, whole up to 200 characters and
otherwise its first 199; and press Escape to clear the selection and the filters. The page follows the system's light or dark theme and prints with every
component's details.

## Example: the demo agent

Run from a repository checkout:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote graph demo.aibom.json -o demo-graph.html
```

```text
Graph view: 11 components, 13 edges, 3 exposure paths; coverage unknown
```

The view shows 11 components, 13 edges (10 recorded dependency edges and 3 reference
fields) and three exposure paths. Opening `demo-graph.html`, you will see:

- a banner that says coverage is unknown: every collector completed, but a static
  scan observes no runtime, network or live tools;
- the repository agent in the first column, with dashed `configured-with`,
  `uses-model`, `reads-instructions`, `retrieves-from` and `depends-on` edges to every
  other component, and dotted `server_refs` edges from the `claude-code` MCP client to
  the three MCP servers;
- three exposure paths, all from the repository agent and all to a high finding: the
  unpinned `memory` MCP server, the unsigned `models/intent-classifier.safetensors`
  model and the `ollama/ollama:latest` image without a digest;
- the remote `tickets` MCP server marked `NET` (`network-egress`, basis
  `endpoint_url:remote`), which is not a sink;
- the model shown with no derived class (`serialization_safety` is `safe`), and every
  other component unclassified, with a dashed outline: the demo declares no tool
  capabilities, and its `claude-code` settings set no starting mode. The IDE agent has
  no outgoing edges, so it starts no path.

The same view as JSON lists the paths by node and edge index:

```bash
nexus-symbiote graph demo.aibom.json --format json
```

```json
  "exposure": {
    "sources": 2,
    "sources_omitted": 0,
    "sinks": 3,
    "paths": [
      {
        "source": 0,
        "sink": 4,
        "length": 1,
        "nodes": [
          0,
          4
        ],
        "edges": [
          3
        ],
        "labels": [
          "configured-with"
        ],
        "sink_classes": [],
        "sink_severity": "high"
      },
```

A limit below the number of components fails rather than cutting the view:

```bash
nexus-symbiote graph demo.aibom.json -o demo-graph.html --max-nodes 10
```

```text
Error: The view would show 11 components, more than --max-nodes 10. Select part of the graph with --focus REF, or raise --max-nodes (at most 20000).
```

The exit status is 1 and nothing is written.
