---
name: Bug report
about: Something in NamikazeOS misbehaves or contradicts its own guards
title: "component: short description"
labels: bug
---

## Environment

- NamikazeOS version / commit:
- boot tier (live USB / persistent install):
- architecture:

## What happened

Describe the observable failure, then the expected behavior.

## Reproduction

Minimal steps, including the exact command line.

## Logs

Relevant output from `namikaze-logd` / `namikaze-trace`, with anything
identifying redacted.

## Guard context

If a guard or `cargo run -p xtask -- ci` step failed, paste the failing
step output.
