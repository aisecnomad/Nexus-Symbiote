# Credential allowlist

A vendor-shaped token is a `credential_exposure` finding even when its body looks like an example (`test`, `fake`, `example`, `dummy`, or a low-entropy run). That is the maintainer decision on [issue 200](https://github.com/aisecnomad/Nexus-Symbiote/issues/200#issuecomment-7217003342). Nothing is suppressed because it looks fake.

Strings that are not tokens stay quiet: `<YOUR_API_KEY>`, `sk-...`, `xxxx`, and any shape shorter than the vendor minimum in the existing shape table.

## The file

Suppression is a file at the scan root, not a key in `.nexus-symbiote.yaml` (that schema refuses unknown keys):

- `.nexus-symbiote-credential-allowlist.yaml`, or
- `.nexus-symbiote-credential-allowlist.yml`

A missing file suppresses nothing. Both names at once, a file over 64 KiB, undecodable bytes, or a document that is not the mapping below suppresses nothing and is a collection failure. `--no-project-policy` does not load the file.

```yaml
allow:
  - fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    reason: "Reviewed fixture token, rotated 2026-11-27."
  - path: "docs/examples/**"
    reason: "Checked-in documentation samples."
```

Each entry has a `reason` (one line, at most 200 characters) and exactly one of:

| Field | Matches |
| --- | --- |
| `fingerprint` | 64 lowercase hex digits. SHA-256 of the token after NFKC and after format characters, spaces and variation selectors are removed. The finding does not print this digest. |
| `path` | A relative glob. `*` is one path segment, `**` is any number of segments. No absolute path, backslash, or `..`. |

A path entry suppresses every vendor-shaped token in each matching file. A fingerprint entry suppresses that spelling wherever the active file path is set. At most 256 entries.

The finding still does not contain the token. An allowlist entry does not either: it names a digest or a path.
