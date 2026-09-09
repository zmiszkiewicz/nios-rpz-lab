#!/usr/bin/env python3
"""
Turn the registered NIOS-X host into a working DNS Forwarding Proxy.

Terraform launches the host with a join token, which is enough to make it
appear in the CSP under Infrastructure > Hosts. It is not enough to make it
answer DNS: the DFP *service* has to be created on the host's pool, and that
can only happen once the host has actually registered. Terraform has no way to
wait for that, so it happens here.

    python3 setup_dfp.py              wait for the host, enable DFP, report
    python3 setup_dfp.py --status     report only, change nothing
    python3 setup_dfp.py --wait-only  wait for registration, do not enable

Run after `terraform apply`, before generating any traffic.

Why the participant does not do this: enabling a service and waiting for it to
come up teaches nothing about Shadow AI governance, and a half-started DFP
looks exactly like a working block from the client side. The lab starts from a
proxy that works and is about the policy on top of it.

Environment: INFOBLOX_EMAIL, INFOBLOX_PASSWORD (or TF_VAR_ddi_api_key),
DFP_PRIVATE_IP (defaults to the Terraform value, 10.100.0.200).
"""

import argparse
import os
import sys
import time
from datetime import datetime, timezone

from csp_api import (CspAuthError, CspError, CspSession, get_logger, read_state,
                     write_state)

log = get_logger("setup_dfp")

DFP_PRIVATE_IP = os.getenv("DFP_PRIVATE_IP", "10.100.0.200")

# The service name the participant will see in the portal. Deliberately
# recognisable rather than a UUID, because they are asked to find it.
DFP_SERVICE_NAME = os.getenv("DFP_SERVICE_NAME", "instruqt-shadow-ai-dfp")

# What the infra plane calls a DNS Forwarding Proxy. "dfp" is what the
# capability is named on a Universal Service, so it is tried first, but the
# infra plane has used the longer form too.
DFP_SERVICE_TYPES = ["dfp", "dns_forwarding_proxy", "dnsfwdproxy"]

HOSTS_PATH = "/api/infra/v1/detail_hosts"
SERVICES_PATH = "/api/infra/v1/services"
DETAIL_SERVICES_PATH = "/api/infra/v1/detail_services"
POLICIES_PATH = "/api/atcfw/v1/security_policies"


# --------------------------------------------------------------------------- #
# Host registration
# --------------------------------------------------------------------------- #

def find_host(csp, ip=None):
    """
    The NIOS-X host record, matched on private IP.

    Falls back to the only host in the tenant when the IP is not visible in
    the record, which happens on some CSP releases before the host finishes
    reporting its interfaces. A sandbox has exactly one host, so that fallback
    is safe here and would not be in a real deployment.
    """
    ip = ip or DFP_PRIVATE_IP
    hosts = csp.results(HOSTS_PATH)
    if not hosts:
        return None

    for host in hosts:
        if ip and ip in _host_addresses(host):
            return host

    if len(hosts) == 1:
        log.debug("Host %s not matched by IP, using the only host in the tenant",
                  ip)
        return hosts[0]

    log.warning("%d hosts in the tenant and none has address %s", len(hosts), ip)
    return None


def _host_addresses(host):
    """Every IP string anywhere in a host record."""
    found = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("address", "ip_address", "ipv4_address") and isinstance(value, str):
                    found.add(value.split("/")[0])
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(host)
    return found


def host_is_connected(host):
    """True when the CSP considers the host online."""
    for key in ("connection_status", "status", "composite_status", "state"):
        value = str(host.get(key, "")).lower()
        if value in ("connected", "active", "online", "ready"):
            return True
        if value in ("degraded", "error", "disconnected", "pending"):
            return False
    # No recognisable status field: treat presence with a pool as good enough,
    # because the service call is the real test and it fails clearly.
    return bool(_pool_id(host))


def _pool_id(host):
    """Raw pool id for a host, or None."""
    pool = host.get("pool") or {}
    return pool.get("pool_id") or pool.get("id")


def wait_for_host(csp, timeout=900, interval=20, ip=None):
    """
    Block until the NIOS-X host registers with the tenant.

    A NIOS-X host takes roughly four to eight minutes from instance launch to
    showing up connected, so the default budget is fifteen minutes. Polling the
    real signal beats a fixed sleep: it returns as soon as the host is there
    and it fails loudly if it never arrives.
    """
    deadline = time.time() + timeout
    attempt = 0

    while time.time() < deadline:
        attempt += 1
        try:
            host = find_host(csp, ip)
        except CspError as exc:
            log.debug("detail_hosts not readable yet: %s", exc)
            host = None

        if host and host_is_connected(host):
            name = host.get("display_name") or host.get("host_name") or host.get("id")
            log.info("Host registered and connected: %s", name)
            return host

        remaining = int(deadline - time.time())
        state = "not registered" if not host else "registered, not connected yet"
        log.info("Waiting for the NIOS-X host (%s, attempt %d, %ds left)...",
                 state, attempt, max(remaining, 0))
        time.sleep(interval)

    raise TimeoutError(
        f"The NIOS-X host did not register within {timeout}s. Check that the "
        f"join token was valid and that the instance has outbound 443 to "
        f"csp.infoblox.com."
    )


# --------------------------------------------------------------------------- #
# DFP service
# --------------------------------------------------------------------------- #

def find_dfp_service(csp, pool_id=None):
    """An existing DFP service in this tenant, or None."""
    for path in (DETAIL_SERVICES_PATH, SERVICES_PATH):
        try:
            services = csp.results(path)
        except CspError:
            continue
        for service in services:
            stype = str(service.get("service_type", "")).lower()
            if stype in DFP_SERVICE_TYPES:
                if pool_id and _bare(service.get("pool_id", "")) != _bare(pool_id):
                    continue
                return service
    return None


def enable_dfp_service(csp, pool_id, name=DFP_SERVICE_NAME):
    """
    Create the DFP service on the host's pool.

    Mirrors the DNS-service call in
    app-migration-niosx/terraform/scripts/enable_service_dns.py, including the
    resource-URI form of pool_id, which the API requires and which is not
    what detail_hosts hands back.
    """
    existing = find_dfp_service(csp, pool_id)
    if existing:
        log.info("DFP service already present: %s",
                 existing.get("name", existing.get("id", "?")))
        return existing, False

    now = datetime.now(timezone.utc).isoformat()
    last = None

    for service_type in DFP_SERVICE_TYPES:
        payload = {
            "name": name,
            "service_type": service_type,
            "pool_id": f"infra/pool/{_bare(pool_id)}",
            "desired_state": "start",
            "created_at": now,
            "updated_at": now,
            "tags": {},
        }
        try:
            body = csp.post(SERVICES_PATH, payload)
        except CspError as exc:
            # A rejected service_type is a 400 or 422; keep trying the others.
            # Anything else is a real failure and should surface now.
            if exc.status in (400, 422):
                log.debug("service_type %r rejected: %s", service_type, exc.body[:200])
                last = exc
                continue
            raise

        service = body.get("result") or body
        log.info("Enabled DFP service %r (service_type=%r)", name, service_type)
        return service, True

    raise CspError("POST", SERVICES_PATH, 400,
                   f"no accepted service_type for a DFP. Tried "
                   f"{', '.join(DFP_SERVICE_TYPES)}. Last error: {last}")


def wait_for_service(csp, timeout=600, interval=20):
    """Block until a DFP service reports itself started."""
    deadline = time.time() + timeout
    attempt = 0

    while time.time() < deadline:
        attempt += 1
        service = find_dfp_service(csp)
        if service:
            state = str(service.get("current_state")
                        or service.get("desired_state") or "").lower()
            if state in ("start", "started", "running", "active"):
                log.info("DFP service is running")
                return service
            log.info("DFP service state is %r (attempt %d)...", state or "unknown",
                     attempt)
        else:
            log.info("DFP service not visible yet (attempt %d)...", attempt)
        time.sleep(interval)

    log.warning("DFP service did not report running within %ds. It may still "
                "come up; the traffic check will show whether it resolves.",
                timeout)
    return None


# --------------------------------------------------------------------------- #
# Policy scope
# --------------------------------------------------------------------------- #

def default_policy(csp):
    """The tenant's default (catch-all) security policy, or None."""
    try:
        policies = csp.results(POLICIES_PATH)
    except CspError as exc:
        log.warning("Could not read security policies: %s", exc)
        return None
    return next((p for p in policies if p.get("is_default")), None)


def report_policy_scope(csp):
    """
    Say which policy will act on the DFP's queries.

    The default policy is a catch-all: it applies to every DFP that is not
    explicitly bound to another policy, so nothing normally needs binding
    here. This reports rather than changes, because silently rebinding a
    policy would hide the very thing the participant is about to edit.
    """
    policy = default_policy(csp)
    if not policy:
        log.warning("No default security policy found. The participant will "
                    "have nothing to edit in the enforcement challenge.")
        return None

    rules = policy.get("rules") or []
    bound = policy.get("dfp_services") or []
    log.info("Default policy %r: %d rule(s), %d explicitly bound DFP service(s)",
             policy.get("name", "?"), len(rules), len(bound))
    if not bound:
        log.info("No explicit DFP binding, which is correct: the default policy "
                 "is a catch-all and already covers this proxy.")
    write_state("policy_id.txt", policy.get("id", ""))
    return policy


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #

def show_status(csp):
    """Print everything this script manages."""
    print()
    print("=" * 68)
    print(f"  Threat Defense lab status - {read_state('sandbox_name.txt', 'unknown')}")
    print("=" * 68)

    host = find_host(csp)
    if not host:
        print("  NIOS-X host        NOT REGISTERED")
    else:
        name = host.get("display_name") or host.get("host_name") or host.get("id")
        state = "connected" if host_is_connected(host) else "not connected"
        print(f"  NIOS-X host        {name} ({state})")
        addresses = sorted(_host_addresses(host))
        if addresses:
            print(f"  Addresses          {', '.join(addresses)}")
        print(f"  Pool               {_pool_id(host) or 'unknown'}")

    service = find_dfp_service(csp)
    if not service:
        print("  DFP service        NOT ENABLED - the desktop cannot resolve")
    else:
        state = (service.get("current_state") or service.get("desired_state")
                 or "unknown")
        print(f"  DFP service        {service.get('name', '?')} "
              f"(type={service.get('service_type')}, state={state})")

    policy = default_policy(csp)
    if not policy:
        print("  Security policy    NONE FOUND")
    else:
        rules = policy.get("rules") or []
        app_rules = [r for r in rules
                     if "app" in str(r.get("type", "")).lower()
                     or r.get("application_filter_id") is not None]
        print(f"  Security policy    {policy.get('name')} "
              f"({len(rules)} rules, {len(app_rules)} application rules)")

    print("=" * 68)
    print()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Register the NIOS-X host and enable its DFP service.")
    parser.add_argument("--status", action="store_true", help="Report only")
    parser.add_argument("--wait-only", action="store_true",
                        help="Wait for host registration, do not enable the service")
    parser.add_argument("--ip", default=DFP_PRIVATE_IP,
                        help=f"Private IP of the NIOS-X host (default {DFP_PRIVATE_IP})")
    parser.add_argument("--timeout", type=int, default=900,
                        help="Seconds to wait for host registration")
    args = parser.parse_args()

    csp = CspSession()
    # The infra plane needs a JWT; an API key alone is not enough for
    # detail_hosts on some releases, so always establish a session when we can.
    try:
        if csp.email and csp.password:
            csp.connect(read_state("sandbox_id.txt"))
        elif not csp.api_key:
            log.error("Need INFOBLOX_EMAIL and INFOBLOX_PASSWORD, or an API key.")
            return 1
    except CspAuthError as exc:
        log.error("%s", exc)
        return 1

    if args.status:
        show_status(csp)
        return 0

    log.info("--- 1/4 waiting for the NIOS-X host ---")
    host = wait_for_host(csp, timeout=args.timeout, ip=args.ip)

    if args.wait_only:
        log.info("Registered. Stopping here as requested.")
        return 0

    pool_id = _pool_id(host)
    if not pool_id:
        log.error("Host registered but exposes no pool id, so the DFP service "
                  "cannot be created. Host record keys: %s",
                  ", ".join(sorted(host)))
        return 1

    log.info("--- 2/4 enabling the DFP service ---")
    enable_dfp_service(csp, pool_id)

    log.info("--- 3/4 waiting for the service to start ---")
    wait_for_service(csp)

    log.info("--- 4/4 policy scope ---")
    report_policy_scope(csp)

    show_status(csp)
    log.info("DFP ready at %s. Point clients there and Threat Defense will see "
             "their queries.", args.ip)
    return 0


def _bare(value):
    """Trailing segment of a resource URI, e.g. infra/pool/X -> X."""
    return str(value or "").split("/")[-1]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TimeoutError as exc:
        log.error("%s", exc)
        sys.exit(1)
    except (CspError, CspAuthError) as exc:
        log.error("%s", exc)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — top-level guard
        log.error("%s", exc)
        sys.exit(1)
