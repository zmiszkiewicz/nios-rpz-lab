#!/usr/bin/env python3
"""
Make the Grid Master a working resolver before the participant ever sees it.

Run once from track_scripts/setup-shell, after wait_for_nios.py. When this
finishes, the desktop can resolve any public name through the Grid Master, and
the only thing left for the participant to build is the RPZ policy itself.

This is groundwork, not lab content. Starting a DNS service and ticking
"allow recursive queries" teaches nobody anything about DNS Firewall, and both
are unforgiving to get wrong — a stopped service looks identical to a working
block from the client side.

No other lab in this organisation does this. In the rest of the estate the Grid
Master is only ever a configuration target: zones and records are created on it,
but resolution happens through NIOS-X or a BIND host, so nothing there ever
needed the GM to answer a query.

Steps:
  1. Start the DNS service on every grid member
  2. Enable recursion and allow it from the lab subnet
  3. Point forwarders at the VPC resolver (see --no-forwarders)
  4. Restart DNS
  5. Poll from the desktop until a real lookup succeeds

Environment: GM_IP, NIOS_ADMIN_PASSWORD, DESKTOP_IP,
TF_VAR_windows_admin_password, LAB_SUBNET_CIDR, LAB_VPC_CIDR.
"""

import argparse
import ipaddress
import os
import sys
import time

import domains as D
from configure_rpz import enable_dns_service, enable_recursion
from desktop_dns import DesktopUnreachable, explain_failure, probe_desktop
from nios_wapi import NiosWapi, WapiError, WapiUnreachable, get_logger

log = get_logger("bootstrap_nios")

LAB_SUBNET_CIDR = os.getenv("LAB_SUBNET_CIDR", "10.100.0.0/24")
LAB_VPC_CIDR = os.getenv("LAB_VPC_CIDR", "10.100.0.0/16")


def default_forwarder(vpc_cidr=LAB_VPC_CIDR):
    """
    The AWS VPC resolver, which always sits at the VPC base address plus two.

    Forwarding there rather than recursing to the root servers makes the lab
    deterministic: it removes any dependency on outbound UDP 53 to the internet
    reaching thirteen specific hosts, and it is what most enterprises actually
    configure. RPZ is applied to the response either way, so nothing about the
    lab's subject matter changes.
    """
    try:
        return str(ipaddress.ip_network(vpc_cidr, strict=False).network_address + 2)
    except ValueError:
        return None


def set_forwarders(wapi, forwarder):
    """Point the grid at an upstream resolver, leaving root recursion as fallback."""
    grid_dns = wapi.grid_dns(fields=["forwarders", "forwarders_only"])
    current = grid_dns.get("forwarders") or []

    if forwarder in current:
        log.info("Forwarder %s already configured", forwarder)
        return False

    # forwarders_only stays false so the grid can still recurse if the VPC
    # resolver ever stops answering.
    wapi.put(grid_dns["_ref"], {"forwarders": [forwarder], "forwarders_only": False})
    log.info("Forwarding to %s (root recursion retained as fallback)", forwarder)
    return True


def wait_for_resolution(domain=None, timeout=300, interval=15):
    """
    Poll the desktop until the Grid Master answers a real query.

    This is the only check that proves the groundwork actually worked. WAPI can
    happily report enable_dns=true while named is still starting.
    """
    domain = domain or D.CONTROL_DOMAIN
    deadline = time.time() + timeout
    attempt = 0
    last = None

    while time.time() < deadline:
        attempt += 1
        try:
            probe = probe_desktop([domain])
            result = probe["results"].get(domain, {})
            if result.get("resolved"):
                log.info("Resolution working: %s -> %s",
                         domain, ", ".join(result["addresses"]))
                return True
            last = explain_failure(probe) or f"{domain}: {result.get('status')}"
        except DesktopUnreachable as exc:
            last = str(exc)

        log.info("Not resolving yet (attempt %d): %s", attempt, last)
        time.sleep(interval)

    log.error("Grid Master still not resolving after %ds. Last state: %s", timeout, last)
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Prepare the Grid Master as a working recursive resolver.")
    parser.add_argument("--gm", default=os.getenv("GM_IP"))
    parser.add_argument("--password", default=None)
    parser.add_argument("--subnet", default=LAB_SUBNET_CIDR,
                        help=f"Subnet allowed to recurse (default: {LAB_SUBNET_CIDR})")
    parser.add_argument("--forwarder", default=os.getenv("NIOS_FORWARDER"),
                        help="Upstream resolver (default: the VPC resolver)")
    parser.add_argument("--no-forwarders", action="store_true",
                        help="Recurse to the root servers instead of forwarding")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Seconds to wait for resolution to start working")
    parser.add_argument("--skip-verify", action="store_true",
                        help="Configure only; do not wait for the desktop")
    args = parser.parse_args()

    try:
        wapi = NiosWapi(host=args.gm, password=args.password)
        wapi.connect(retries=3, delay=15)
    except WapiUnreachable as exc:
        log.error("Cannot reach the Grid Master: %s", exc)
        return 1

    changed = False

    log.info("--- 1/5 DNS service ---")
    changed |= enable_dns_service(wapi)

    log.info("--- 2/5 recursion ---")
    changed |= enable_recursion(wapi, args.subnet)

    log.info("--- 3/5 forwarders ---")
    if args.no_forwarders:
        log.info("Skipped, recursing to the root servers")
    else:
        forwarder = args.forwarder or default_forwarder()
        if not forwarder:
            log.warning("Could not derive a forwarder from %s, skipping", LAB_VPC_CIDR)
        else:
            try:
                changed |= set_forwarders(wapi, forwarder)
            except WapiError as exc:
                # Not fatal: recursion to root still works without it.
                log.warning("Could not set forwarders (%s), continuing", exc)

    log.info("--- 4/5 restart DNS ---")
    if changed:
        wapi.restart_dns()
    else:
        log.info("Nothing changed, no restart needed")

    log.info("--- 5/5 verify ---")
    if args.skip_verify:
        log.info("Skipped by request")
        return 0

    if not wait_for_resolution(timeout=args.timeout):
        log.error("Groundwork incomplete — the participant will not be able to see "
                  "a difference when the RPZ is applied. Run "
                  "'python3 configure_rpz.py status' to inspect.")
        return 1

    log.info("Grid Master is ready: DNS running, recursion scoped to %s, "
             "public names resolving.", args.subnet)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except WapiError as exc:
        log.error("WAPI call failed: %s", exc)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — top-level guard
        log.error("%s", exc)
        sys.exit(1)
