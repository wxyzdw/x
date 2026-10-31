# namikaze-dupe

Leftover copy finder for sensitive data.

## Why

Privacy fails sideways. The vault copy of a document is encrypted, but
an unencrypted copy of the same bytes often sits in a cache, a tmp
directory or an export folder. `namikaze-dupe` finds content duplicates
across writable trees so the operator can shrink the plaintext surface
before it leaks through a backup, a sync folder or a forensic image.

## Detection

Two stages, cheap on big trees:

1. Key every regular file (symlinks skipped) by size plus SHA-256 of its
   first 4 KiB.
2. Only groups with more than one member get a full-content hash.

Scan roots default to `/tmp`, `/var/tmp` and `$HOME/.cache`; pass roots
as free arguments to scan anywhere. `--min-size N` ignores smaller
files.

## Reports

    namikaze-dupe scan [ROOT...] [--min-size N] [--out FILE]

Groups print biggest first; `--out` writes JSONL lines
`{"sha256":..,"size":N,"copies":[..]}` for machine consumption.

## Zeroing (opt-in, dry run by default)

    namikaze-dupe zero [--report FILE] [--apply]

Without `--apply` this is a dry run. With `--apply`, every copy except
the first (canonical) entry of each group is overwritten with zeros in
place: sizes are preserved and nothing is deleted, keeping directory
layouts plausible (principle P9: conceal, do not erase). The keeper of a
group is always the lexicographically first path.
