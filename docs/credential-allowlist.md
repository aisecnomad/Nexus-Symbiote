# Credential allowlist

A vendor-shaped token is a `credential_exposure` finding even when its body looks like an example (`test`, `fake`, `example`, `dummy`, or a low-entropy run). That is the maintainer decision on [issue 200](https://github.com/aisecnomad/Nexus-Symbiote/issues/200#issuecomment-7217003342). Nothing is suppressed because it looks fake.

Strings that are not tokens stay quiet: `<YOUR_API_KEY>`, `sk-...`, `xxxx`, and any shape shorter than the vendor minimum in the existing shape table.

## The file

Suppression is a file at the scan root, not a key in `.nexus-symbiote.yaml` (that schema refuses unknown keys):

- `.nexus-symbiote-credential-allowlist.yaml`, or
- `.nexus-symbiote-credential-allowlist.yml`

A checkout can request credential suppressions. Pass `--accept-project-policy` to apply a reviewed allowlist to `scan`, `validate --project`, and `risk --project`. Each command records the accepted relaxation in `policy_weakened`. An operator policy withholds checkout credential suppressions. The MCP collector still redacts recognized literals from output, including reviewed samples.

A missing file suppresses nothing. Both names at once, a file over 64 KiB, undecodable bytes, or a document that is not the mapping below suppresses nothing and is a collection failure. `--no-project-policy` does not load the file.

```yaml
allow:
  - fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    reason: "Reviewed fixture token, rotated 2026-11-27."
  - path: "docs/examples/**"
    reason: "Checked-in documentation samples."
```

Each entry has a `reason` (one line, at most 200 characters, not blank) and exactly one of:

| Field | Matches |
| --- | --- |
| `fingerprint` | 64 lowercase hex digits. SHA-256 of the token after NFKC and after format characters, spaces and variation selectors are removed. The finding does not print this digest. |
| `path` | A relative glob. `*` is one path segment, `**` is any number of segments. No absolute path, backslash, or `..`, and not only wildcards: `**`, `*` and `**/*` are refused. |

A path entry suppresses every vendor-shaped token in each matching file. A fingerprint entry suppresses that spelling wherever the active file path is set. At most 256 entries.

The finding still does not contain the token. An allowlist entry does not either: it names a digest or a path.

## `.env` files

A `.env*` file is reported by path, line, key name and vendor type. Its value is not hashed: many of those values are low-entropy passwords, and a published unsalted SHA-256 can be attacked. A source finding does not publish an unkeyed digest either. With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set it records a keyed HMAC; otherwise it says the value is unbound.

`.env.example`, `.env.sample` and `.env.template` are templates. They use that same commitment, and still never include the token.

A path-glob allowlist entry suppresses a `.env` file. A fingerprint entry can match a value, but the finding does not record the digest.

If a path or key contains an assignment value from any scanned `.env` file,
the finding displays `an env file` or `a key name`. Allowlisted assignments
also protect these labels. Collection diagnostics and exclusions withhold
sensitive locations. When an input is incomplete or the comparison budget is
exhausted, the collector withholds all file and key names in its findings.
`validate --project` and `risk --project` repeat this collection when checking
an inventory against its checkout.

A symlink must point to the same kind of file. Store-to-store and
template-to-template links inside the checkout are supported. A link that
crosses those categories or leads to another file type is a collection failure.
