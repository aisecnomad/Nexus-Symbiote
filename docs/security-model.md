# Security model

Nexus SymBiote connects an agent's inventory to evidence and policy. Keep the following states separate:

| State | Meaning |
| --- | --- |
| Declared composition | A repository, supplier, or configuration says a component is used. |
| Observed composition | A named collector measured a component in a stated scope and time. |
| Approved configuration | An authorized approver accepted a specific configuration and capabilities. |
| Mediated execution | An enforcement adapter checked an actual action against its trusted policy and approval. |

Nexus-ShadowScan is the primary discovery source; importing its report into Nexus SymBiote preserves the distinction between a supplied claim and a new local measurement. A2A Agent Cards, IDE configuration, and extension manifests are declarations until their relevant identity and evidence are separately verified.

An inventory entry never grants permission by itself. A schema hash pins an interface; it does not constrain a backend's hidden side effects. A signed malicious artifact remains malicious. Runtime metadata emitted by the agent itself has a different trust basis from an independent observation.

Collectors must preserve coverage limitations, denied reads, unsupported inputs, exclusions, and failures. Missing information means unknown, not verified absence. Secrets are references, not values. Avoid default capture of raw prompts, retrieved documents, tool arguments, or results. Tenant and deployment identifiers must remain part of approval and observation scope.

## Design principles

1. **Never runs what it inspects.** Collection is static. It does not execute project modules, model loaders, repository hooks or MCP launch commands.
2. **Offline by default, enforced at run time.** Every command refuses name resolution, network connections and process creation unless you opt into live mode for one of three commands.
3. **Unknown is not safe.** Missing evidence, failed reads and skipped collectors are recorded as gaps, and default gates fail on them instead of passing silently.
4. **Claims are not evidence.** Declared, observed, approved and mediated states stay separate. A supplier label or an adjacent signature file never upgrades trust by itself, and `--no-project-policy` stops an untrusted checkout from choosing its own gates.
5. **Standards first.** One native inventory exports to CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and VEX. Standard exports carry the full native inventory in a digest-bound extension, so a consumer that keeps it loses nothing.

When a supplier gives you an inventory and you have the corresponding checkout,
use both commands against the same project root.

```sh
nexus-symbiote validate inventory.json --project /reviewed/checkout --no-project-policy
nexus-symbiote risk inventory.json --project /reviewed/checkout --no-project-policy --json-output
```

Project reconciliation reruns the supported static collectors and compares
their security-relevant fields and findings with the supplied BOM. A mismatch
makes the project-backed risk command exit unsuccessfully with an unknown risk
level and a null score. Without a project, `risk` scores the supplied claims
and labels the result `supplied-bom`. For an operator-configured signature
check, supply the trusted signer policy when validating the project.

A mediated action needs a trusted approver, snapshot binding, authenticated workload and endpoint, action/resource constraints, validity, current revocation state, rollback protection, and any action-specific approval. One-use approval must bind to the action and arguments it authorizes. Adapter checks cannot govern tools invoked through an unmediated route; deployments need their own network, identity, and sandbox controls to make mediation complete.

For hosted models, an alias is a locator. Provider-reported revisions and behavioral canaries do not establish measured weight identity. Preserve identity assurance and unknowns explicitly. For retrieval and memory, record the source and index versions, effective reader/writer permissions, and derived records requiring invalidation after withdrawal.

## Known false-positive and false-negative classes

These are current behaviors, not guarantees. Review them before relying on a gate.

- **Model format by extension.** `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.joblib`, `.ckpt` and `.pdparams` are rated as potentially code-executing on file extension alone, before any content is read. A non-pickle `.bin` file (firmware, game data) is therefore a critical finding, which fails the default gate. Formats with no structural validator (`.onnx`, `.gguf`, `.ggml`, `.h5`, `.hdf5`, `.keras` and TensorFlow's `saved_model.pb`) are reported as unknown, not safe. Other `.pb` files are generic protobuf data and are not collected; formats outside these lists, such as NumPy `.npy` and `.npz` arrays, are not inventoried.
- **Risk score scale.** The aggregate score is the uncapped sum of finding weights (critical 10, high 7, medium 4, low 1). It grows with inventory size and is not a percentage, although the Action accepts thresholds from 0 to 100. Any critical finding fails the default gate regardless of the aggregate.
- **Free-text redaction.** Redaction removes known secret values and `name=value` or `name: value` pairs whose name contains `api_key`, `access_key`, `secret_key`, `private_key`, `token`, `password`, `passwd` or `secret`. Credentials in other shapes, such as quoted JSON keys or values containing spaces, are not recognized by pattern; structured collectors rely on scrubbing known environment values instead.
- **Hosted CI.** A configured workflow is not evidence that it ran; see `docs/repository-controls.md`.
## What results do and do not establish

A successful scan is an inventory result. It does not establish that a model is benign, that a tool backend obeys its description, or that every agent action was mediated. Inspect the exit status and the inventory's coverage, exclusions and failures: a command may write evidence and still return a failing gate, and exit code `0` for informational commands, report-only output and skipped gates does not establish approval.

Collection is static by default and does not execute project modules, model loaders, hooks or MCP launch commands. A completed search can find no matching files; unsupported declarations and failed reads remain coverage gaps, and collectors omitted from `--scanner` remain unknown. Configuration presence does not prove that a server is running or that its live tool definitions match the declaration. `verify-live` is a separate explicit execution operation requiring an independently pinned launcher policy and external isolation, and `discover-mcp` is an explicit HTTPS observation operation. Neither calls tools.

For trusted local projects, standalone `scan` loads project policy from the scanned directory, and `validate` and `risk` from the directory named with `--project`. Without `--project` they use the built-in policy and name any `.nexus-symbiote.yaml` they did not apply, because an inventory file can be written anywhere, including shared directories. A policy file in a parent directory, or beside an inventory file, is never consulted. Pass `--no-project-policy` when the scanned checkout must not choose your verification policy. Standalone ShadowScan imports require a new output path and retain partial coverage; `--report-only` is an explicit inspection mode. Imported discovery remains a source claim and does not establish deployment, effective access or authorization. When a project policy is honored, `validate` names its source and `risk` records it as `policy_source`, with every relaxation of the built-in gates listed under `policy_weakened` and warned about on stderr, so a switched-off gate is a visible choice rather than a silent one.

| Capability | Evidence and limitation |
| --- | --- |
| ShadowScan integration | Exact source-report digest, mapped components and supported declared edges, with unmapped indexes and projection limits; no automatic producer authentication or trust upgrade |
| MCP and tools | Scoped client/server references and supported source declarations; runtime descriptors and backend behavior need separate evidence |
| Model integrity | Whole-file hashes, bounded format inspection, SafeTensors metadata fingerprints and optional Sigstore checks; a format, header fingerprint or signature does not prove benignness |
| Instructions and skills | Source-bound artifacts and suspicious-content findings; detection is limited to supported files and patterns |
| Retrieval and registries | Declared configuration, package identities and lineage references; presence does not establish actual installation or retrieval ACL enforcement |
| A2A and IDE declarations | Agent Cards, host settings and extension declarations; supplier labels are not proof of endpoint identity, execution or signature validity |
| Runtime contracts | Ed25519-signed snapshots, approvals and trust status bound to authenticated context in a reference adapter; deployments must prevent bypass and protect state |
| Impact analysis | Potential graph reachability through recorded relationships, not proof that an exploit executed |
| GitHub Action | One collected inventory, caller-owned gates and optional SARIF upload; disabled or skipped gates are visible policy choices |

Project validation compares static MCP records and configured tool fingerprints with fresh local evidence. A structure binding detects added or removed arguments, environment variables and tools. With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, a keyed binding also detects same-version package swaps and changed argument, environment and endpoint values, without exporting anything a secret could be guessed from. MCP references include the relative configuration path and declared name. Legacy snapshots without the binding, or with name-only identities, need recollection; see [source reconciliation and migration](verification-source-binding.md). Python source declaration collection has bounded application-file coverage and reports unresolved or dynamic registrations as gaps.

CycloneDX 1.7 and SPDX 3.0.1 exports use supported standard structures and a digest-bound native extension. Consumers must retain that extension to recover full native semantics and inspect the selected-field loss report. A digest detects changes; it does not authenticate the producer. SPDX identities are scoped to each inventory revision. SARIF contains reviewable findings rather than an admission decision, and standalone ShadowScan imports do not support SARIF. VEX output marks findings `in_triage` and does not assert exploitability. Schema validity alone establishes neither semantic equivalence nor complete collection.

Inventories can expose infrastructure, permissions, source references and instruction fingerprints. Restrict evidence access and retention, and review artifacts before sharing them. Use independent expected digests and signer/issuer policies; a signature or registry label does not establish content safety. IDE permission records describe collected project declarations: Claude's `permissions.defaultMode` and broad tool allowances are retained, while user/managed policy, workspace trust, deny/ask precedence and session flags remain outside effective-authorization verification. Scanner failures emit application-owned diagnostic codes; raw exception text and invalid model configuration values are omitted from failure reports.

The security and inventory benchmark corpora are finite regression cases. They establish no representative field accuracy, complete collection or percentile ranking.
