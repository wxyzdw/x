# namikaze-sandbox

Per-application confinement profiles: compile once, apply at launch.

## Why

Application sandboxing usually lives in a daemon's compiled policy
format, which is opaque and hard to review. `namikaze-sandbox` keeps
profiles as plain TOML under `/etc/namikaze/sandbox`, compiles them to
launch recipes (namespaces, seccomp posture, private tmp, restricted
environment) and stores the compiled form under `/run` where session
launchers pick it up.

## Commands

    namikaze-sandbox compile <app> [--dir /etc/namikaze/sandbox]   print the launch recipe
    namikaze-sandbox apply <app>   [--dir /etc/namikaze/sandbox]   store it under /run
    namikaze-sandbox doctor        [--dir /etc/namikaze/sandbox]   validate every profile

## Profile file

See `sysroot/etc/namikaze/sandbox/example.toml` for the annotated
example. Keys cover filesystem visibility, device access, network
posture and environment scrubbing; unknown keys are rejected at compile
time, not ignored.

## Doctor

`doctor` validates every profile in the directory and reports the exact
key that is wrong, so CI and admins can run it unattended. The
`compile`/`apply` split means a profile can be reviewed as text and
applied as bytes, and nothing privileged happens until an applied
recipe is actually launched.
