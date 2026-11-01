# namikaze-anon

Tor status and onion service management for the anonymity stack.

## Why

`namikaze-guard` forces all egress through Tor. Operators then need two
small answers all the time: is the circuit actually up, and how do I
expose a local service without revealing the host. `namikaze-anon` does
exactly these two things and nothing else.

## Commands

    namikaze-anon status                    print Tor readiness
    namikaze-anon newnym                    request a fresh circuit
    namikaze-anon onion --target HOST:PORT [--port 80]

- `status` checks the control connection and reports readiness; use it
  in scripts before anything sensitive is allowed to start.
- `newnym` asks the control port for a fresh circuit; long-lived
  sessions should rotate instead of relying on upstream timeouts.
- `onion` provisions an onion service that forwards a public virtual
  port to a local `HOST:PORT` target.

## Design notes

All traffic to the Tor daemon goes over its local control interface;
the crate never talks to the network on its own account. Failure output
is written so that `namikaze-doctor` can classify it, and the tool is
safe to call repeatedly: every command is idempotent or explicitly
state-advancing (`newnym`).
