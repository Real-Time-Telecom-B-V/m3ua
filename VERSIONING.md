# Versioning

`m3ua` follows [Semantic Versioning 2.0.0](https://semver.org/). The public
API — the `M3uaMessage` codec, the `CommonHeader` / `MessageClass` /
`MessageType` types, `Parameter` and the `tags` constants, `ProtocolData`, the
`Asp` / `AspState` / `AspAction` state machine, and `M3uaError` — is the
contract.

## The git tag is the source of truth

`Cargo.toml`'s `version` matches the release tag; the release workflow's
`verify-version` job refuses to publish if they disagree. Bump `version`, commit,
tag `vX.Y.Z`, push the tag.

## Post-1.0 rule

- **MAJOR** — remove / rename / re-signature a `pub` item, or change documented
  wire or state-machine semantics.
- **MINOR** — backward-compatible additions (new message builders, new
  `MessageType` / parameter `tags`, new accessors).
- **PATCH** — bug fixes, docs, behaviour-neutral dependency bumps.
