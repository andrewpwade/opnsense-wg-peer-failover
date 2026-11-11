#!/usr/local/bin/python3
"""Fail over between WireGuard peers on OPNsense when the active peer dies.

Assumptions
----------

* Mullvad

* Policy-based routing in use

* A firewall rule exists to route 10.64.0.1 over Mullvad

* Wireguard Peers named as per Mullvad

* Unbound in use (optional, the script will just log an error)


How it works
------------

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

Config
------

Create /usr/local/etc/wg-failover.json with 'key', 'secret', 'instance'
(OPNsense instance name), 'interface' (e.g. wg1) and optionally 'url'.

The API key needs access to VPN: WireGuard and Services: Unbound
DNS. N.B. if you forget to add the permissions after creating the API
key, you need to need recreate the key.

Run with --dry-run first: API changes are only logged.

"""

import argparse
import json
import logging
import random
import re
import secrets
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass

import requests
import urllib3

log = logging.getLogger("wg-failover")
HTTP_TRACE = 5  # custom level, enabled by -vv

# What we probe.
TUNNEL_DNS = "10.64.0.1"  # resolver reachable through every peer
DIRECT_DNS = ("1.1.1.1", "9.9.9.9")  # via WAN: tells "peer down" from "WAN down"
PROBE_DOMAIN = "example.com"  # we query <random>.example.com (expect NXDOMAIN/NOERROR)

# Timing, in seconds.
PROBE_INTERVAL = 10  # time between probes
PROBE_TIMEOUT = 2  # a probe with no answer by now counts as failed
FAIL_AFTER = 15  # no successful probe for this long => peer is dead
MIN_FAILURES = 3  # ...and at least this many failed probes in a row
STABLE_AFTER = 120  # healthy this long => forget previous failovers (reset backoff)
MAX_HOLD = 600  # longest pause between failovers when everything is failing
RECENT_FAILURE = 600  # avoid peers that failed within this window if others exist
SYNC_EVERY = 30  # how often to re-check that exactly one peer is enabled
API_TIMEOUT = 30  # reconfigure / unbound restart can take a few seconds


@dataclass(frozen=True)
class Peer:
    uuid: str
    name: str
    enabled: bool

    @property
    def group(self):
        """Country prefix: 'uk-002' -> 'uk'."""
        return self.name.split("-", 1)[0]


class Api:
    """Minimal OPNsense API client. Calls that change things honour dry-run."""

    def __init__(self, url, key, secret, dry_run):
        self.url = url.rstrip("/")
        self.dry_run = dry_run
        self.http = requests.Session()
        self.http.auth = (key, secret)
        self.http.verify = False  # loopback to the GUI's self-signed certificate
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, path):
        return self._send("GET", path)

    def read_post(self, path, data):
        """A POST that only reads (search endpoints take paging parameters)."""
        return self._send("POST", path, data)

    def change(self, path):
        """A POST that changes state. Returns None in dry-run mode."""
        if self.dry_run:
            log.info("[dry-run] would POST %s", path)
            return None
        return self._send("POST", path)

    def _send(self, method, path, data=None):
        log.debug("%s %s data=%s", method, path, data)
        response = self.http.request(
            method, self.url + path, data=data, timeout=API_TIMEOUT
        )
        # At -vv this shows what OPNsense really said, e.g. the reason for a 500.
        log.log(HTTP_TRACE, "HTTP %s: %s", response.status_code, response.text[:2000])
        if not response.ok:
            body = response.text.strip()[:300] or "empty body"
            raise RuntimeError(f"{method} {path} -> {response.status_code}: {body}")
        return response.json()


def dns_probe(server):
    """Resolve a random, uncached name via `server`.

    True if it answers NOERROR or NXDOMAIN with the matching transaction id.
    Timeouts, SERVFAIL and REFUSED all count as failure.
    """
    txid = secrets.randbits(16)
    name = f"{secrets.token_hex(6)}.{PROBE_DOMAIN}"
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    # Header: id, flags (recursion desired), 1 question; then name, type A, class IN.
    query = struct.pack(">6H", txid, 0x0100, 1, 0, 0, 0)
    query += qname + b"\0" + struct.pack(">2H", 1, 1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(PROBE_TIMEOUT)
            sock.connect((server, 53))  # also drops packets from other sources
            sock.send(query)
            reply = sock.recv(512)
    except OSError:  # timeout, unreachable, refused...
        return False

    if len(reply) < 12:
        return False
    reply_id, flags = struct.unpack(">2H", reply[:4])
    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    return reply_id == txid and is_response and rcode in (0, 3)  # NOERROR, NXDOMAIN


def route_interface(ip):
    """Interface the router would use to reach `ip`, or None."""
    out = subprocess.run(
        ["route", "-n", "get", ip], capture_output=True, text=True
    ).stdout
    match = re.search(r"^\s*interface:\s*(\S+)", out, re.MULTILINE)
    return match.group(1) if match else None


def load_config(path):
    """Read the JSON config and make sure the required keys are present."""
    with open(path) as f:
        config = json.load(f)
    required = ("key", "secret", "instance", "interface")
    missing = [k for k in required if not config.get(k)]
    if missing:
        raise ValueError(f"missing in {path}: {', '.join(missing)}")
    config.setdefault("url", "https://127.0.0.1")
    return config


class Failover:
    def __init__(self, api, instance, iface, dry_run):
        self.api = api
        self.instance = instance  # OPNsense instance name; scopes the peers
        self.iface = iface
        self.dry_run = dry_run
        self.active = None  # Peer currently carrying traffic
        self.failures = 0  # consecutive failed probes
        self.last_ok = time.monotonic()  # last successful probe
        self.healthy_since = None  # start of the current run of good probes
        self.hold_until = 0.0  # no failover before this (backoff / WAN down)
        self.switches = 0  # failovers since the last stable period
        self.failed_at = {}  # uuid -> monotonic time we failed away from it
        self.last_sync = 0.0

    # ---- OPNsense state ---------------------------------------------------

    def instance_uuid(self):
        rows = self.api.get("/api/wireguard/client/list_servers")["rows"]
        for row in rows:
            if row["name"] == self.instance:
                return row["uuid"]
        raise RuntimeError(f"no WireGuard instance named {self.instance!r}")

    def list_peers(self):
        """Peers attached to our instance only."""
        uuid = self.instance_uuid()
        server = self.api.get(f"/api/wireguard/server/get_server/{uuid}")["server"]
        ours = {u for u, opt in server["peers"].items() if opt["selected"]}
        reply = self.api.read_post(
            "/api/wireguard/client/search_client", {"current": 1, "rowCount": -1}
        )
        if len(reply["rows"]) != reply["total"]:
            raise RuntimeError(f"got {len(reply['rows'])} of {reply['total']} peers")
        rows = [r for r in reply["rows"] if r["uuid"] in ours]
        peers = [Peer(r["uuid"], r["name"], str(r["enabled"]) == "1") for r in rows]
        if not peers:
            raise RuntimeError("no WireGuard peers configured")
        return peers

    def handshake_ages(self):
        """Seconds since last handshake per peer name (None = never)."""
        rows = self.api.get("/api/wireguard/service/show").get("rows", [])
        return {r.get("name"): r.get("latest-handshake-age") for r in rows}

    def set_active(self, new, peers):
        """Enable `new`, disable every other peer, apply."""
        # Enable first so there is never a moment with no peer at all.
        for peer in sorted(peers, key=lambda p: p.uuid != new.uuid):
            if peer.enabled != (peer.uuid == new.uuid):
                self.api.change(f"/api/wireguard/client/toggle_client/{peer.uuid}")
        result = self.api.change("/api/wireguard/service/reconfigure")
        if result is not None and result.get("result") != "ok":
            raise RuntimeError(f"WireGuard reconfigure failed: {result}")
        if not self.dry_run:
            enabled = {p.uuid for p in self.list_peers() if p.enabled}
            if enabled != {new.uuid}:
                raise RuntimeError(f"expected only {new.name} enabled, got {enabled}")

    def sync(self):
        """Find the active peer; if none or several are enabled, fix that."""
        self.last_sync = time.monotonic()
        peers = self.list_peers()
        enabled = [p for p in peers if p.enabled]
        if len(enabled) != 1:
            ages = self.handshake_ages()
            # Several enabled: keep the freshest. None enabled: pick any.
            keep = min(
                enabled or peers,
                key=lambda p: ages.get(p.name) if ages.get(p.name) is not None else 1e9,
            )
            log.warning("%d peers enabled, keeping %s", len(enabled), keep.name)
            self.set_active(keep, peers)
            enabled = [keep]
        if enabled[0] != self.active:
            log.info("active peer is %s", enabled[0].name)
        self.active = enabled[0]

    # ---- probing ----------------------------------------------------------

    def preflight(self):
        """Direct probes are only meaningful if the router's own traffic uses WAN."""
        if route_interface(DIRECT_DNS[0]) == self.iface:
            sys.exit(
                f"{DIRECT_DNS[0]} is routed via {self.iface}: the router's own default "
                "route must be WAN, otherwise WAN and peer failures look identical"
            )

    # ---- the decision -----------------------------------------------------

    def step(self):
        now = time.monotonic()
        if self.active is None or now - self.last_sync >= SYNC_EVERY:
            self.sync()

        if dns_probe(TUNNEL_DNS):
            if self.failures:
                log.info("probe recovered after %d failures", self.failures)
            self.failures = 0
            self.last_ok = now
            if self.healthy_since is None:
                self.healthy_since = now
            elif now - self.healthy_since >= STABLE_AFTER:
                self.switches = 0
            log.debug("probe ok (%s)", self.active.name)
            return

        self.failures += 1
        self.healthy_since = None
        silent_for = now - self.last_ok
        log.warning(
            "probe via %s failed (%d in a row, %.0fs since last success)",
            self.active.name,
            self.failures,
            silent_for,
        )
        too_early = self.failures < MIN_FAILURES or silent_for < FAIL_AFTER
        if too_early or now < self.hold_until:
            return

        if not any(dns_probe(server) for server in DIRECT_DNS):
            log.warning("probe fails outside the tunnel too: WAN down, not switching")
            self.failures = 0
            self.last_ok = now  # give the peer a fresh window once WAN returns
            self.hold_until = now + PROBE_INTERVAL * 3
            return

        self.fail_over(now)

    def pick_next(self, peers, now):
        """Random other peer with the same prefix, avoiding recent failures."""
        candidates = [
            p
            for p in peers
            if p.group == self.active.group and p.uuid != self.active.uuid
        ]
        fresh = [
            p
            for p in candidates
            if now - self.failed_at.get(p.uuid, float("-inf")) > RECENT_FAILURE
        ]
        return random.choice(fresh or candidates) if candidates else None

    def fail_over(self, now):
        old = self.active
        self.failed_at[old.uuid] = now
        try:  # context for the log: what did WireGuard itself think?
            age = self.handshake_ages().get(old.name)
            when = f"{age}s ago" if age else "never"
            log.info("%s: last handshake %s", old.name, when)
        except (requests.RequestException, KeyError, ValueError) as err:
            log.debug("could not read handshake age: %s", err)

        peers = self.list_peers()
        new = self.pick_next(peers, now)
        if new is None:
            # Nothing to switch to, but bouncing the tunnel sometimes fixes it.
            log.warning("no other '%s-' peer: restarting WireGuard", old.group)
            self.api.change("/api/wireguard/service/restart")
        else:
            log.warning("FAILING OVER %s -> %s", old.name, new.name)
            self.set_active(new, peers)
        try:  # the switch itself already happened
            self.api.change("/api/unbound/service/restart")
        except (RuntimeError, requests.RequestException) as err:
            log.error("unbound restart failed: %s", err)

        now = time.monotonic()
        self.switches += 1
        self.failures = 0
        self.last_ok = now  # the new peer gets a full window to prove itself
        # 15s, 30s, 60s ... between failovers while nothing is healthy for long.
        self.hold_until = now + min(FAIL_AFTER * 2 ** (self.switches - 1), MAX_HOLD)
        self.sync()

    def run_forever(self):
        self.preflight()
        log.info(
            "watching %s via %s%s",
            self.iface,
            TUNNEL_DNS,
            " (dry-run)" if self.dry_run else "",
        )
        while True:
            started = time.monotonic()
            try:
                self.step()
            except (RuntimeError, requests.RequestException) as err:
                log.warning("%s", err)  # expected trouble: GUI busy, wg restarting
            except Exception:  # a bug must not kill the watchdog
                log.exception("unexpected error")
            time.sleep(max(0.0, PROBE_INTERVAL - (time.monotonic() - started)))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "-c",
        "--config",
        default="/usr/local/etc/wg-failover.json",
        help="default: %(default)s",
    )
    parser.add_argument("-n", "--dry-run", action="store_true", help="only log")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v: log every probe and API call; -vv: also HTTP details",
    )
    args = parser.parse_args()

    logging.addLevelName(HTTP_TRACE, "HTTP")
    logging.basicConfig(
        level=[logging.INFO, logging.DEBUG, HTTP_TRACE][min(args.verbose, 2)],
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if args.verbose >= 2:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
    try:
        config = load_config(args.config) 
    except (OSError, ValueError) as err:
        sys.exit(f"cannot use {args.config}: {err}")

    api = Api(config["url"], config["key"], config["secret"], args.dry_run)
    failover = Failover(api, config["instance"], config["interface"], args.dry_run)
    try:
        failover.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

