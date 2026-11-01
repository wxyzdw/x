# namikaze-cloak

Randomize the identity leaks a machine leaves on every network: MAC
addresses, hostname and machine-id.

## Why

Even with all egress forced through Tor, hosts announce stable
identifiers at layers Tor cannot see. A wireless association leaks the
NIC MAC, DHCP and mDNS leak the hostname, and any file written to
shared media can carry the `/etc/machine-id`. `namikaze-cloak` rotates
all three from one command, at boot via its OpenRC service
(`namikaze-cloak`) or on demand.

## Commands

    namikaze-cloak apply       randomize everything
    namikaze-cloak mac         randomize MAC addresses only
    namikaze-cloak hostname    randomize hostname only
    namikaze-cloak machine-id  refresh machine-id only

## Notes

- MAC randomization uses locally-administered unicast addresses only,
  so no vendor OUI is disclosed.
- `machine-id` writes a fresh random id and invalidates cached D-Bus
  machine ids; services that pin the old id are restarted by the boot
  service ordering, not by this tool.
- `macspin` (sector-network) is the per-interface specialist; `cloak`
  is the whole-host orchestrator and calls the same primitives.
