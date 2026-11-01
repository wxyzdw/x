# Security Policy

NamikazeOS treats anonymity and data destruction as correctness properties.
This document explains what is in scope, how to report, and what to expect.

## Supported versions

Only the latest tagged release line receives security review:

| line  | status     |
| ----- | ---------- |
| 3.0.x | supported  |

## Reporting a vulnerability

Use GitHub's private security advisory feature on this repository
(Security tab, then "Report a vulnerability"). Do not open a public issue
for anything that can be exploited.

Please include: affected component (crate or overlay package), a minimal
reproduction, the threat model you assumed (live USB, persistent install,
multi-user host), and your assessment of severity.

## Response targets

- acknowledgement: within 7 days
- triage decision (accepted / wontfix with rationale): within 30 days
- coordinated fix and advisory: with the next release line

## Scope

In scope: every `namikaze-*` crate, the dist pipeline, the filesystem
service files, the kernel config fragments and the ::namikaze overlay.

Out of scope for this repository: the upstream kernel, upstream niri and
greetd code, and Gentoo's package manager itself.

## Hardening baseline

The following are enforced mechanically by the workspace guards and are
part of the security contract:

- zero third-party dependencies (dep-guard)
- no unsafe code outside the two documented P0 exceptions
  (namikaze-ffi and namikaze-sentinel PAM glue)
- no banned legacy toolchain tokens (gnu-guard)
- kernel config must keep the mandatory options on and the leak vectors
  off (xtask kernel-check)
- Niri session files must agree across the tree and the overlay (desk-guard)
