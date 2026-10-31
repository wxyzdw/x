# NamikazeOS Security Policy

## Reporting

Report vulnerabilities to the project security contact on
`https://git.disroot.org/anbu141` (issue tracker, marked confidential) once the
forge is available. During the freeze, reports are collected offline and
triaged within 72 hours. Critical issues (CVSS >= 9.0) target a signed fix
advisory within 24 hours of a verified report.

## Guarantees

- Every crate except `namikaze-ffi` forbids `unsafe` at compile time.
- Key material is wrapped in `zeroize` types and wiped from RAM on teardown.
- No network egress except through Tor when `anonymity.level != standard`.
- Logs are minimized; persistent logs live inside LUKS2 only.
- Destructive tools (panic wipe, ram wipe) are opt-in and never touch disk data.

## Key hierarchy summary

```
slot 0: user passphrase (argon2id, 1 GiB memory cost)
slot 1: TPM2 PCR policy + PIN (machine-tamper bound) [when TPM2 present]
slot 2: one-time recovery code generated at install
```

Changing the passphrase re-keys a slot; it never re-encrypts data. Full volume
key rotation uses `namikaze-seal reencrypt` (LUKS2 online re-encryption).

## Build attestation

`cargo run -p xtask -- sbom` emits `dist/sbom.json` (workspace inventory declaring zero third-party dependencies) and `cargo run -p xtask -- verify` writes dist/SHA256SUMS (
inventory of workspace crates). Releases carry SLSA provenance from CI.
