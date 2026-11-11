Fail over between WireGuard peers on OPNsense when the active peer dies.

## Assumptions

* Mullvad

* Policy-based routing in use

* A firewall rule exists to route 10.64.0.1 over Mullvad

* Wireguard Peers named as per Mullvad

* Unbound in use (optional, the script will just log an error)


## How it works

* Peers are the WireGuard peers in OPNsense, managed through its REST
  API. Exactly ONE peer is enabled at a time; switching = enable the
  next, disable the rest, reconfigure WireGuard, restart Unbound. The
  change is saved in the real config, so the GUI and a reboot agree
  with what the script did.

* Every PROBE_INTERVAL seconds a real DNS query for a random (so never
  cached) name is sent to the resolver inside the tunnel. An answer
  proves traffic flows both ways AND that the peer can reach the
  internet; a bare ping does not.  The probe follows the same path as
  Unbound's own queries (your PBR rule).

* If probes fail for FAIL_AFTER seconds, we check that the same probe
  works OUTSIDE the tunnel (otherwise the WAN is down and switching
  peers is pointless), then switch to a random other peer with the
  same name prefix ("uk-001" -> "uk-*"), or restart WireGuard if it is
  the only one in its group.

* Repeated failovers back off exponentially so a country-wide outage
  doesn't turn into a restart storm.

## Config

Create /usr/local/etc/wg-failover.json with 'key', 'secret', 'instance'
(OPNsense instance name), 'interface' (e.g. wg1) and optionally 'url'.

The API key needs access to VPN: WireGuard and Services: Unbound
DNS. N.B. if you forget to add the permissions after creating the API
key, you need to need recreate the key.

Run with --dry-run first: API changes are only logged.
