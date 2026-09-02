#!/usr/bin/env python3
"""
Run DNS lookups on the unmanaged host, over SSH.

The counterpart to desktop_dns.py. Where that box resolves through the Grid
Master, this one deliberately does not, so comparing the two is what makes the
bypass visible.

    bypass_host.py                    show the resolver and test the usual names
    bypass_host.py claude.ai          test specific names
    bypass_host.py --resolver         print the host's configured resolver only
    bypass_host.py --use-corporate    switch it onto the Grid Master
    bypass_host.py --use-public       switch it back to the public resolver
    bypass_host.py --json             machine-readable

Uses the ssh binary rather than paramiko: the key Terraform generates is already
on disk in the container, and the estate's other labs shell out to ssh the same
way.

Environment: BYPASS_IP, LAB_SSH_KEY (defaults to the key beside the Terraform
root), GM_LAN1_PRIVATE_IP, BYPASS_PUBLIC_RESOLVER.
"""

import json
import os
import re
import shlex
import subprocess
import sys
import time

from desktop_dns import DOMAIN_RE, classify
from nios_wapi import get_logger

log = get_logger("bypass_host")

DEFAULT_KEY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "terraform", "instruqt-lab-key.pem",
)

DEFAULT_TARGETS = ["claude.ai", "chatgpt.com", "www.infoblox.com"]

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=15",
]


class BypassHostUnreachable(RuntimeError):
    """The unmanaged host did not answer over SSH."""


def _key_path():
    key = os.getenv("LAB_SSH_KEY", DEFAULT_KEY)
    if not os.path.exists(key):
        raise BypassHostUnreachable(
            f"SSH key not found at {key}. Set LAB_SSH_KEY, or check that "
            f"terraform apply wrote it."
        )
    return key


def run_remote(command, host=None, timeout=90):
    """Run a shell command on the unmanaged host. Returns (rc, stdout, stderr)."""
    host = host or os.getenv("BYPASS_IP")
    if not host:
        raise BypassHostUnreachable("BYPASS_IP is not set.")

    argv = ["ssh", "-i", _key_path()] + SSH_OPTS + [f"ubuntu@{host}", command]

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise BypassHostUnreachable(
            f"SSH to {host} timed out after {timeout}s"
        ) from exc
    except FileNotFoundError as exc:
        raise BypassHostUnreachable("The ssh client is not installed.") from exc

    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def wait_for_host(host=None, timeout=300, interval=15):
    """Block until the host accepts SSH and its bootstrap has finished."""
    deadline = time.time() + timeout
    attempt = 0
    last = None

    while time.time() < deadline:
        attempt += 1
        try:
            rc, out, err = run_remote("test -x ./show-dns.sh && echo ready",
                                      host=host, timeout=30)
            if rc == 0 and "ready" in out:
                log.info("Unmanaged host is ready")
                return True
            last = err or out or f"exit {rc}"
        except BypassHostUnreachable as exc:
            last = str(exc)

        log.info("Unmanaged host not ready yet (attempt %d): %s", attempt, last)
        time.sleep(interval)

    raise BypassHostUnreachable(
        f"Unmanaged host did not become ready within {timeout}s. Last: {last}"
    )


def current_resolver(host=None):
    """The nameservers in the host's /etc/resolv.conf, in order."""
    rc, out, err = run_remote(
        "grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}'", host=host)
    if rc != 0:
        raise BypassHostUnreachable(f"Could not read /etc/resolv.conf: {err}")
    return [line.strip() for line in out.splitlines() if line.strip()]


def resolve(domains=None, server=None, host=None):
    """
    Resolve names from the unmanaged host.

    With server=None the host's own resolver is used, which is the whole point.
    Returns {domain: {"resolved", "addresses", "error", "status"}}.
    """
    domains = domains or DEFAULT_TARGETS
    for domain in domains:
        if not DOMAIN_RE.match(domain):
            raise ValueError(f"Implausible domain name: {domain!r}")

    at = f"@{server} " if server else ""
    results = {}

    for domain in domains:
        # +tries=1 keeps a blocked lookup from stalling the whole check.
        cmd = f"dig {at}+timeout=3 +tries=1 {shlex.quote(domain)} A"
        rc, out, err = run_remote(cmd, host=host, timeout=45)

        addresses = [
            line.split()[-1] for line in out.splitlines()
            if re.match(r"^\S+\s+\d+\s+IN\s+A\s+", line)
        ]
        header = re.search(r"status:\s*([A-Z]+)", out)
        rcode = header.group(1) if header else ""

        entry = {
            "resolved": bool(addresses),
            "addresses": addresses,
            "error": "" if addresses else (rcode or "no response"),
        }
        # dig reports the DNS rcode directly, so trust it over text matching.
        if addresses:
            entry["status"] = "RESOLVED"
        elif rcode == "NXDOMAIN":
            entry["status"] = "NXDOMAIN"
        elif rcode == "REFUSED":
            entry["status"] = "REFUSED"
        elif rcode == "SERVFAIL":
            entry["status"] = "SERVFAIL"
        elif not rcode:
            entry["status"] = "TIMEOUT"
        else:
            entry["status"] = classify(entry)

        results[domain] = entry

    return results


def switch_resolver(to_corporate, host=None):
    """Point the host at the Grid Master, or back at the public resolver."""
    script = "./use-corporate-dns.sh" if to_corporate else "./use-public-dns.sh"
    rc, out, err = run_remote(script, host=host)
    if rc != 0:
        raise BypassHostUnreachable(f"{script} failed: {err or out}")
    return out


_LABEL = {"RESOLVED": "RESOLVED", "NXDOMAIN": "BLOCKED", "REFUSED": "REFUSED",
          "TIMEOUT": "TIMEOUT", "SERVFAIL": "SERVFAIL", "NO_ANSWER": "NO ANSWER"}


def main():
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if "--use-corporate" in flags:
        print(switch_resolver(True))
        return 0
    if "--use-public" in flags:
        print(switch_resolver(False))
        return 0

    resolvers = current_resolver()

    if "--resolver" in flags:
        print("\n".join(resolvers))
        return 0

    results = resolve(args or DEFAULT_TARGETS)

    if "--json" in flags:
        print(json.dumps({"resolver": resolvers, "results": results}, indent=2))
        return 0

    gm = os.getenv("GM_LAN1_PRIVATE_IP", "10.100.0.11")
    governed = gm in resolvers

    print(f"  Host resolver : {', '.join(resolvers) or 'none'}"
          f"  ({'corporate Grid Master' if governed else 'PUBLIC — outside policy'})")
    print()
    for domain, result in results.items():
        label = _LABEL.get(result["status"], result["status"])
        detail = ", ".join(result["addresses"]) if result["resolved"] else result["error"]
        print(f"  {label:10s} {domain:26s} {detail[:60]}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BypassHostUnreachable, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)
