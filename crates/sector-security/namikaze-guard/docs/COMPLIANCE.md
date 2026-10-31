# NamikazeOS Compliance Matrix

Engineering is "certification-ready": every control below has a concrete
implementation or artifact in this repository. Formal accreditation (CC, FIPS)
requires accredited laboratories and is tracked as a long-term objective.

| Standard | Scope | Implementation | Artifact |
|----------|-------|----------------|----------|
| ISO/IEC 15408 (CC) EAL4+ target | OS evaluation | TOE boundary docs, deterministic build, ALC evidence | docs (this repo) |
| FIPS 140-3 | Crypto module | namikaze-vault/seal primitives: argon2id, XChaCha20-Poly1305, documented KDF | vault crate + test vectors |
| CIS Benchmark (Gentoo mapping) | Hardening | `namikaze-config harden --profile cis-l1/l2` emits sysctl/config controls | config crate |
| DISA STIG (GP-OS mapping) | Config | STIG-aligned sysctl set in `sysroot/lib/sysctl.d/` | sysroot |
| NIST SP 800-53 Rev5 (moderate) | Controls | Control mapping documented | COMPLIANCE.md |
| IEC 62443-4-1 / 4-2 | Secure SDLC | forbid-unsafe policy, fuzz targets, dependency bans, review gates | CI workflows |
| SLSA v1.0 Build L3 | Supply chain | Signed tags, locked deps, SBOM, provenance workflow | xtask sbom, CI |
| OpenSSF Scorecard | Supply chain | Branch protection, signed commits, pinned deps | forge settings |
| EU CRA | Product security | SBOM per release, vulnerability intake, signed advisories | sec-advisories/ |

## Control-to-code samples

- `kernel.unprivileged_bpf_disabled=1` -> sysroot/lib/sysctl.d/90-namikaze-hardening.conf
- PAM failure lockout + tamper evidence -> crates/namikaze-sentinel
- Default-deny egress -> crates/namikaze-guard (nftables ruleset generator)
- Integrity baseline -> crates/namikaze-watch (blake3 manifest)
- Signed advisory trail -> sec-advisories/ (NAMK-YYYY-NNN, detached signature)
