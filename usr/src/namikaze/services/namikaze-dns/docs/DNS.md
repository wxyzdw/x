# namikaze-dns

Policy-driven encrypted DNS: render resolver artifacts from a single
policy file, and refuse anything that would leak plaintext DNS.

## Why

The most common anonymity failure is not a broken tunnel, it is a
resolver fallback silently answering over UDP 53. `namikaze-dns` treats
the policy file as the only source of allowed upstreams (DNS over TLS,
DNS over HTTPS), pins their Server Name Indication and the tracker zones
that must never resolve, and derives every resolver-facing artifact from
it.

## Commands

    namikaze-dns plan     [--policy /etc/namikaze/dns.toml]   render, no writes
    namikaze-dns apply    [--policy ...]   write artifacts under /run/namikaze/dns
    namikaze-dns doctor   [--policy ...]   validate and report

## Artifacts

- `/run/namikaze/dns/resolv.conf` - loopback stub pointing at the local
  resolver (127.0.0.1)
- `/run/namikaze/dns/upstreams.conf` - the resolver drop-in, rendered
  from the policy (DoT/DoH endpoints, SNI pins, blocked zones)

## Guarantees

`apply` refuses to emit anything when the policy would leak plaintext
DNS: if an upstream is not DoT/DoH, if a zone bypasses the pin, or if
the policy is missing keys, the command fails loudly and leaves the
previous artifacts untouched. The sysctl pieces
(`namikaze-guard`, firewall rules) block outbound port 53 so the
refusal is defense in depth, not the only line.
