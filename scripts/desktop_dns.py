#!/usr/bin/env python3
"""
Run DNS lookups on the Windows desktop, over WinRM.

The challenge checks have to prove the block from where the participant
actually experiences it. Querying the Grid Master from the Instruqt shell
container would not: the lab's security groups deliberately keep port 53 inside
the VPC so the Grid Master is never an open resolver on the internet.

Used as a library by verify_rpz.py, and standalone for troubleshooting:

    desktop_dns.py claude.ai www.infoblox.com
    desktop_dns.py --json claude.ai

Environment: DESKTOP_IP, TF_VAR_windows_admin_password, GM_LAN1_PRIVATE_IP.
"""

import json
import os
import re
import sys

from nios_wapi import get_logger

log = get_logger("desktop_dns")

DOMAIN_RE = re.compile(r"^[A-Za-z0-9_*][A-Za-z0-9._*-]{0,252}[A-Za-z0-9]$")

# PowerShell run on the desktop. Resolve-DnsName writes an error and returns
# nothing on NXDOMAIN, so an empty address list is what "blocked" looks like.
PS_TEMPLATE = """
$ErrorActionPreference = "SilentlyContinue"
Clear-DnsClientCache
$server = "__SERVER__"
$results = @()
foreach ($d in @(__DOMAINS__)) {
    $addresses = @()
    $answer = Resolve-DnsName -Name $d -Type A -Server $server -DnsOnly -ErrorAction SilentlyContinue
    if ($answer) {
        $addresses = @($answer | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    }
    $results += [pscustomobject]@{
        domain    = $d
        resolved  = ($addresses.Count -gt 0)
        addresses = $addresses
    }
}
ConvertTo-Json -InputObject @($results) -Compress -Depth 4
"""


class DesktopUnreachable(RuntimeError):
    """The desktop did not answer over WinRM."""


def _validate(domains):
    for domain in domains:
        if not DOMAIN_RE.match(domain):
            raise ValueError(f"Refusing to inject an implausible domain name: {domain!r}")
    return domains


def _build_script(domains, server):
    quoted = ",".join(f'"{domain}"' for domain in _validate(domains))
    if not DOMAIN_RE.match(server) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server):
        raise ValueError(f"Implausible DNS server address: {server!r}")
    return PS_TEMPLATE.replace("__DOMAINS__", quoted).replace("__SERVER__", server)


def resolve_on_desktop(domains, server=None, host=None, password=None, timeout=90):
    """
    Resolve each domain from the desktop against the Grid Master.

    Returns {domain: {"resolved": bool, "addresses": [str, ...]}}.
    """
    try:
        import winrm  # imported lazily so --help works without pywinrm
    except ImportError as exc:
        raise DesktopUnreachable(
            "pywinrm is not installed. Run: pip3 install pywinrm"
        ) from exc

    host = host or os.getenv("DESKTOP_IP")
    password = password or os.getenv("TF_VAR_windows_admin_password")
    server = server or os.getenv("GM_LAN1_PRIVATE_IP", "10.100.0.11")

    if not host:
        raise DesktopUnreachable("DESKTOP_IP is not set — cannot reach the desktop.")
    if not password:
        raise DesktopUnreachable("TF_VAR_windows_admin_password is not set.")

    session = winrm.Session(
        f"http://{host}:5985/wsman",
        auth=("Administrator", password),
        transport="basic",
        read_timeout_sec=timeout,
        operation_timeout_sec=timeout - 10,
    )

    script = _build_script(domains, server)

    try:
        result = session.run_ps(script)
    except Exception as exc:  # pywinrm raises a wide range of transport errors
        raise DesktopUnreachable(
            f"WinRM call to {host}:5985 failed: {exc}"
        ) from exc

    stdout = (result.std_out or b"").decode("utf-8", errors="replace").strip()
    stderr = (result.std_err or b"").decode("utf-8", errors="replace").strip()

    if result.status_code != 0 and not stdout:
        raise DesktopUnreachable(
            f"Lookup script failed on the desktop (exit {result.status_code}): "
            f"{stderr[:300]}"
        )

    if not stdout:
        raise DesktopUnreachable("The desktop returned no output from the lookup script.")

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise DesktopUnreachable(
            f"Could not parse the desktop's lookup output: {stdout[:300]}"
        ) from exc

    if isinstance(payload, dict):  # single result comes back unwrapped
        payload = [payload]

    return {
        entry["domain"]: {
            "resolved": bool(entry.get("resolved")),
            "addresses": list(entry.get("addresses") or []),
        }
        for entry in payload
    }


def wait_for_desktop(host=None, password=None, timeout=600, interval=20):
    """Block until the desktop answers WinRM. Windows takes a while to boot."""
    import time

    deadline = time.time() + timeout
    attempt = 0
    last_error = None

    while time.time() < deadline:
        attempt += 1
        try:
            resolve_on_desktop(["localhost"], server="127.0.0.1",
                               host=host, password=password, timeout=30)
            log.info("Desktop is answering WinRM")
            return True
        except DesktopUnreachable as exc:
            last_error = exc
            log.info("Desktop not ready yet (attempt %d)...", attempt)
            time.sleep(interval)

    raise DesktopUnreachable(
        f"Desktop did not answer WinRM within {timeout}s. Last error: {last_error}"
    )


def main():
    args = [a for a in sys.argv[1:] if a != "--json"]
    as_json = "--json" in sys.argv[1:]

    if not args:
        print(__doc__)
        return 2

    results = resolve_on_desktop(args)

    if as_json:
        print(json.dumps(results, indent=2))
        return 0

    for domain, result in results.items():
        if result["resolved"]:
            print(f"  RESOLVED  {domain:32s} {', '.join(result['addresses'])}")
        else:
            print(f"  BLOCKED   {domain:32s} (no answer / NXDOMAIN)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DesktopUnreachable, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)
