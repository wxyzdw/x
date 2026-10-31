# Summary

A one-line description of the change, in the imperative mood
("guards: add version-guard for ebuild drift").

## What and why

What does this change do, and which problem does it solve? Reference the
issue if one exists.

## Guard impact

Does this add or change anything the tree guards check? If yes, which
guard, and how was `cargo run -p xtask -- ci` updated?

## Checklist

- [ ] `cargo run -p xtask -- ci` passes locally (guards + build + tests +
      fmt + clippy + sbom)
- [ ] no new third-party dependency (or a written justification of the
      P0-exception kind)
- [ ] new `.rs` files carry the MPL-2.0 SPDX header
- [ ] versions: root manifest bumped if user-visible, ebuilds regenerated
- [ ] docs inside the affected crates updated
