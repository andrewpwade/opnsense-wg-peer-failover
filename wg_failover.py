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

from __future__ import annotations

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
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

import requests
import urllib3

log = logging.getLogger("wg-failover")

# Custom log level, enabled by -vv.
HTTP_TRACE = 5

# What we probe.
# Resolver reachable through every peer.
TUNNEL_DNS = "10.64.0.1"
# Via WAN: tells "peer down" from "WAN down".
DIRECT_DNS = ("1.1.1.1", "9.9.9.9")
# We query <random>.example.com (expect NXDOMAIN/NOERROR).
PROBE_DOMAIN = "example.com"
DNS_NOERROR = 0
DNS_NXDOMAIN = 3

# Timing, in seconds.
# Time between probes.
PROBE_INTERVAL = 10
# A probe with no answer by now counts as failed.
PROBE_TIMEOUT = 2
# No successful probe for this long => peer is dead.
FAIL_AFTER = 15
# ...and at least this many failed probes in a row.
MIN_FAILURES = 3
# Healthy this long => forget previous failovers (reset backoff).
STABLE_AFTER = 120
# Longest pause between failovers when everything is failing.
MAX_HOLD = 600
# Avoid peers that failed within this window if others exist.
RECENT_FAILURE = 600
# How often to re-check that exactly one peer is enabled.
SYNC_EVERY = 30
# Reconfigure / unbound restart can take a few seconds.
API_TIMEOUT = 30

# Sort key for peers that have never completed a handshake.
NEVER = 1e9


@dataclass(frozen=True)
class Peer:
    uuid: str
    name: str
    enabled: bool

    @property
    def group(self) -> str:
        """Country prefix: 'uk-002' -> 'uk'."""
        return self.name.split("-", 1)[0]


@dataclass(frozen=True)
class Config:
    key: str
    secret: str
    instance: str
    interface: str
    url: str = "https://127.0.0.1"


class Api:
    """Minimal OPNsense API client. Calls that change things honour dry-run."""

    def __init__(self, url: str, key: str, secret: str, dry_run: bool) -> None:
        self.url = url.rstrip("/")
        self.dry_run = dry_run

        self.http = requests.Session()
        self.http.auth = (key, secret)
        # Loopback to the GUI's self-signed certificate.
        self.http.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, path: str) -> Any:
        return self._send("GET", path)

    def read_post(self, path: str, data: dict[str, Any]) -> Any:
        """A POST that only reads (search endpoints take paging parameters)."""
        return self._send("POST", path, data)

    def change(self, path: str) -> Any:
        """A POST that changes state. Returns None in dry-run mode."""
        if self.dry_run:
            log.info("[dry-run] would POST %s", path)
            return None

        return self._send("POST", path)

    def _send(self, method: str, path: str, data: dict[str, Any] | None = None) -> Any:
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


class DnsClient:
    """Minimal UDP DNS client, just enough to tell if a resolver is working."""

    def __init__(
        self, domain: str = PROBE_DOMAIN, timeout: float = PROBE_TIMEOUT
    ) -> None:
        self.domain = domain
        self.timeout = timeout

    def probe(self, server: str) -> bool:
        """Resolve a random, uncached name via `server`.

        True if it answers NOERROR or NXDOMAIN with the matching transaction
        id. Timeouts, SERVFAIL and REFUSED all count as failure.
        """
        txid = secrets.randbits(16)
        query = self._build_query(txid, f"{secrets.token_hex(6)}.{self.domain}")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                # Connecting also drops packets from other sources.
                sock.connect((server, 53))
                sock.send(query)
                reply = sock.recv(512)
        except OSError:
            # Timeout, unreachable, refused...
            return False

        return self._is_valid_reply(reply, txid)

    def _build_query(self, txid: int, name: str) -> bytes:
        """Wire-format A query for `name`, recursion desired."""
        labels = name.split(".")
        qname = b"".join(bytes([len(label)]) + label.encode() for label in labels)

        # Header: id, flags (recursion desired), 1 question; then name, type A,
        # class IN.
        header = struct.pack(">6H", txid, 0x0100, 1, 0, 0, 0)

        return header + qname + b"\0" + struct.pack(">2H", 1, 1)

    def _is_valid_reply(self, reply: bytes, txid: int) -> bool:
        """True for a response to `txid` with rcode NOERROR or NXDOMAIN."""
        if len(reply) < 12:
            return False

        reply_id, flags = struct.unpack(">2H", reply[:4])
        is_response = bool(flags & 0x8000)
        rcode = flags & 0x000F

        return reply_id == txid and is_response and rcode in (DNS_NOERROR, DNS_NXDOMAIN)


def route_interface(ip: str) -> str | None:
    """Interface the router would use to reach `ip`, or None."""
    out = subprocess.run(
        ["route", "-n", "get", ip], capture_output=True, text=True
    ).stdout

    match = re.search(r"^\s*interface:\s*(\S+)", out, re.MULTILINE)

    return match.group(1) if match else None


def load_config(path: str) -> Config:
    """Read the JSON config and make sure the required keys are present."""
    with open(path) as f:
        raw = json.load(f)

    required = ("key", "secret", "instance", "interface")
    missing = [k for k in required if not raw.get(k)]
    if missing:
        raise ValueError(f"missing in {path}: {', '.join(missing)}")

    known = {k: raw[k] for k in (*required, "url") if k in raw}

    return Config(**known)


class Failover:
    def __init__(
        self, api: Api, dns: DnsClient, instance: str, iface: str, dry_run: bool
    ) -> None:
        self.api = api
        self.dns = dns

        # OPNsense instance name; scopes the peers.
        self.instance = instance
        self.iface = iface
        self.dry_run = dry_run

        # Peer currently carrying traffic.
        self.active: Peer | None = None

        # Consecutive failed probes.
        self.failures: int = 0

        # Last successful probe.
        self.last_ok = time.monotonic()

        # Start of the current run of good probes.
        self.healthy_since: float | None = None

        # No failover before this (backoff / WAN down).
        self.hold_until = 0.0

        # Failovers since the last stable period.
        self.switches = 0

        # uuid -> monotonic time we failed away from it.
        self.failed_at: dict[str, float] = {}

        self.last_sync = 0.0

    # ---- OPNsense state ---------------------------------------------------

    def instance_uuid(self) -> str:
        rows = self.api.get("/api/wireguard/client/list_servers")["rows"]
        for row in rows:
            if row["name"] == self.instance:
                return row["uuid"]
        raise RuntimeError(f"no WireGuard instance named {self.instance!r}")

    def list_peers(self) -> list[Peer]:
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

    def handshake_ages(self) -> dict[str, float | None]:
        """Seconds since last handshake per peer name (None = never)."""
        rows = self.api.get("/api/wireguard/service/show").get("rows", [])
        return {r.get("name"): r.get("latest-handshake-age") for r in rows}

    def set_active(self, new: Peer, peers: Sequence[Peer]) -> None:
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

    def freshest(self, candidates: Sequence[Peer]) -> Peer:
        """Candidate with the most recent handshake."""
        ages = self.handshake_ages()

        def age(peer: Peer) -> float:
            value = ages.get(peer.name)
            return NEVER if value is None else value

        return min(candidates, key=age)

    def sync(self) -> Peer:
        """Find the active peer; if none or several are enabled, fix that."""
        self.last_sync = time.monotonic()

        peers = self.list_peers()
        enabled = [p for p in peers if p.enabled]

        if len(enabled) != 1:
            # Several enabled: keep the freshest. None enabled: pick any.
            keep = self.freshest(enabled or peers)
            log.warning("%d peers enabled, keeping %s", len(enabled), keep.name)
            self.set_active(keep, peers)
            enabled = [keep]

        if enabled[0] != self.active:
            log.info("active peer is %s", enabled[0].name)
        self.active = enabled[0]
        return self.active

    # ---- probing ----------------------------------------------------------

    def preflight(self) -> None:
        """Direct probes are only meaningful if the router's own traffic uses WAN."""
        if route_interface(DIRECT_DNS[0]) == self.iface:
            sys.exit(
                f"{DIRECT_DNS[0]} is routed via {self.iface}: the router's own default "
                "route must be WAN, otherwise WAN and peer failures look identical"
            )

    # ---- the decision -----------------------------------------------------

    def step(self) -> None:
        now = time.monotonic()
        active = self.active
        if active is None or now - self.last_sync >= SYNC_EVERY:
            active = self.sync()

        if self.dns.probe(TUNNEL_DNS):
            self.record_success(now, active)
        elif self.record_failure(now, active):
            self.handle_dead_peer(now, active)

    def record_success(self, now: float, active: Peer) -> None:
        if self.failures:
            log.info("probe recovered after %d failures", self.failures)

        self.failures = 0
        self.last_ok = now

        if self.healthy_since is None:
            self.healthy_since = now
        elif now - self.healthy_since >= STABLE_AFTER:
            self.switches = 0

        log.debug("probe ok (%s)", active.name)

    def record_failure(self, now: float, active: Peer) -> bool:
        """Count a failed probe. True if it is time to act on it."""
        self.failures += 1
        self.healthy_since = None

        silent_for = now - self.last_ok
        log.warning(
            "probe via %s failed (%d in a row, %.0fs since last success)",
            active.name,
            self.failures,
            silent_for,
        )

        too_early = self.failures < MIN_FAILURES or silent_for < FAIL_AFTER

        return not too_early and now >= self.hold_until

    def handle_dead_peer(self, now: float, active: Peer) -> None:
        if any(self.dns.probe(server) for server in DIRECT_DNS):
            self.fail_over(now, active)
            return

        log.warning("probe fails outside the tunnel too: WAN down, not switching")
        self.failures = 0
        # Give the peer a fresh window once WAN returns.
        self.last_ok = now
        self.hold_until = now + PROBE_INTERVAL * 3

    def pick_next(
        self, active: Peer, peers: Iterable[Peer], now: float
    ) -> Peer | None:
        """Random other peer with the same prefix, avoiding recent failures."""
        candidates = [
            p for p in peers if p.group == active.group and p.uuid != active.uuid
        ]

        fresh = [
            p
            for p in candidates
            if now - self.failed_at.get(p.uuid, float("-inf")) > RECENT_FAILURE
        ]

        return random.choice(fresh or candidates) if candidates else None

    def log_handshake(self, peer: Peer) -> None:
        """Context for the log: what did WireGuard itself think?"""
        try:
            age = self.handshake_ages().get(peer.name)
        except (requests.RequestException, KeyError, ValueError) as err:
            log.debug("could not read handshake age: %s", err)
            return

        when = f"{age}s ago" if age else "never"
        log.info("%s: last handshake %s", peer.name, when)

    def restart_unbound(self) -> None:
        # The switch itself already happened, so a failure here is only logged.
        try:
            self.api.change("/api/unbound/service/restart")
        except (RuntimeError, requests.RequestException) as err:
            log.error("unbound restart failed: %s", err)

    def fail_over(self, now: float, old: Peer) -> None:
        self.failed_at[old.uuid] = now

        self.log_handshake(old)

        peers = self.list_peers()
        new = self.pick_next(old, peers, now)
        if new is None:
            # Nothing to switch to, but bouncing the tunnel sometimes fixes it.
            log.warning("no other '%s-' peer: restarting WireGuard", old.group)
            self.api.change("/api/wireguard/service/restart")
        else:
            log.warning("FAILING OVER %s -> %s", old.name, new.name)
            self.set_active(new, peers)

        self.restart_unbound()

        now = time.monotonic()
        self.switches += 1
        self.failures = 0

        # The new peer gets a full window to prove itself.
        self.last_ok = now

        # 15s, 30s, 60s ... between failovers while nothing is healthy for long.
        self.hold_until = now + min(FAIL_AFTER * 2 ** (self.switches - 1), MAX_HOLD)
        self.sync()

    def run_forever(self) -> NoReturn:
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
                # Expected trouble: GUI busy, wg restarting.
                log.warning("%s", err)
            except Exception:
                # A bug must not kill the watchdog.
                log.exception("unexpected error")

            time.sleep(max(0.0, PROBE_INTERVAL - (time.monotonic() - started)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])

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

    return parser.parse_args()


def setup_logging(verbosity: int) -> None:
    logging.addLevelName(HTTP_TRACE, "HTTP")

    logging.basicConfig(
        level=[logging.INFO, logging.DEBUG, HTTP_TRACE][min(verbosity, 2)],
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if verbosity >= 2:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)

    try:
        config = load_config(args.config)
    except (OSError, ValueError) as err:
        sys.exit(f"cannot use {args.config}: {err}")

    api = Api(config.url, config.key, config.secret, args.dry_run)
    failover = Failover(
        api, DnsClient(), config.instance, config.interface, args.dry_run
    )

    try:
        failover.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
