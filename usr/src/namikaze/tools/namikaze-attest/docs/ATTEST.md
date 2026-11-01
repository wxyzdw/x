# namikaze-attest

Supply-chain attestation for built NamikazeOS artifacts.

## Why

Deployment should not trust timestamps, file sizes or the word of an
installer. `namikaze-attest` fingerprints every file of a release
artifact directory with SHA-256 and seals the manifest with HMAC-SHA256.
A deployed machine can then answer "is my userland exactly the userland
the builder produced" with two commands and no network.

## Manifest

Compact JSON; objects are keyed maps, so the canonical form is
deterministic regardless of construction order:

    {"files":[{"path":..,"sha256":..,"size":N},...],
     "hmac":"<hex over the canonical manifest without the hmac field>",
     "ts":N,"version":"..."}

File entries are sorted by relative path; symlinks are never attested.

## Key handling

The signing key is 32 bytes given as hex via `--key` or the
`NK_ATTEST_KEY` environment variable. The key travels with the release
channel, never with the image: possession of the image grants nothing,
possession of the key proves authorship. MAC comparison is
constant-time.

## Commands

    namikaze-attest generate [--dir DIR] [--key HEX] [--out FILE]
    namikaze-attest verify   [--dir DIR] [--manifest FILE]
    namikaze-attest show     [--manifest FILE]

`generate` defaults to `dist` / `dist/manifest.json`; `verify`
re-fingerprints the directory and reports MISSING and CHANGED files,
exiting 1 when the attestation does not hold. A manifest whose HMAC does
not match is rejected before any file is inspected.
