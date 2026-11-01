# namikaze-doctor

Diagnostics for a running NamikazeOS: one command, every check,
actionable output.

## Why

Most support questions on a privacy-focused OS reduce to "which piece
of the posture is missing". `namikaze-doctor` answers with a fixed
check list - anonymity, storage, desktop, sentinel, config sanity -
and prints, per check, whether it passes and the exact remediation.

## Commands

    namikaze-doctor run     run every check, human-readable output
    namikaze-doctor report  emit the report as key=value lines

`run` is for humans and boot-time services; `report` is for scripts,
metrics collectors (`namikaze-metrics`) and issue templates, since
key=value lines diff and grep cleanly.

## Check sources

Checks are derived from the same sources the guards trust: the parsed
system configuration (`namikaze-config`), the live runtime state
(`namikaze-live-core`), and the config's own doctor hints
(`SystemConfig::doctor`). Adding a check means adding it there with its
remediation string - the doctor only formats.

## Exit codes

`run` exits zero only when every check passes, so it can gate service
startup or a login script without parsing output.
