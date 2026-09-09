#!/usr/bin/env python3
"""
Run DNS lookups on the Windows desktop, over WinRM.

The challenge checks have to prove the block from where the participant
actually experiences it. Querying the DFP from the Instruqt shell container
would not: the lab's security groups deliberately keep port 53 inside the VPC,
so the proxy is never an open resolver on the internet. It is also the wrong
vantage point — Threat Defense policy is scoped to the clients behind the DFP,
and the desktop is the client the lab is about.

Used as a library by verify_lab.py, and standalone for troubleshooting:

    desktop_dns.py claude.ai www.infoblox.com
    desktop_dns.py --json claude.ai

Environment: DESKTOP_IP, TF_VAR_windows_admin_password, DFP_PRIVATE_IP.
"""

import json
import os
import re
import sys

from csp_api import get_logger

log = get_logger("desktop_dns")

DOMAIN_RE = re.compile(r"^[A-Za-z0-9_*][A-Za-z0-9._*-]{0,252}[A-Za-z0-9]$")

# PowerShell run on the desktop.
#
# "No addresses returned" is not one condition, it is four, and telling them
# apart is the whole point of this script:
#
#   NXDOMAIN  Threat Defense matched a Block rule — the lab working
#   REFUSED   the proxy answered but will not serve this client
#   TIMEOUT   nothing is listening, or the packets are not arriving
#   SERVFAIL  the proxy tried and failed, usually upstream
#
# An earlier version of this lab reported all four as "BLOCKED", which made a
# dead resolver look like a successful policy — the single most misleading
# failure a DNS lab can have. The TCP probe on 53 runs first so we can say
# "nothing is listening" without inferring it from a lookup failure.
PS_TEMPLATE = """
$ErrorActionPreference = "SilentlyContinue"
Clear-DnsClientCache
$server = "__SERVER__"

$listening = $false
try {
    $listening = (Test-NetConnection -ComputerName $server -Port 53 `
                    -InformationLevel Quiet -WarningAction SilentlyContinue)
} catch {
    $listening = $false
}

$configured = @()
try {
    $configured = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
                    Where-Object { $_.ServerAddresses } |
                    ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
} catch {
    $configured = @()
}

$results = @()
foreach ($d in @(__DOMAINS__)) {
    $err = $null
    $addresses = @()
    $answer = Resolve-DnsName -Name $d -Type A -Server $server -DnsOnly `
                -ErrorAction SilentlyContinue -ErrorVariable err
    if ($answer) {
        $addresses = @($answer | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    }
    $msg = ""
    if ($err -and $err.Count -gt 0) {
        $msg = $err[0].Exception.Message
        if (-not $msg) { $msg = $err[0].ToString() }
    }
    $results += [pscustomobject]@{
        domain    = $d
        resolved  = ($addresses.Count -gt 0)
        addresses = $addresses
        error     = $msg
    }
}

ConvertTo-Json -Compress -Depth 5 -InputObject ([pscustomobject]@{
    server            = $server
    port53_listening  = $listening
    configured_dns    = @($configured)
    results           = @($results)
})
"""

# Windows phrases these differently across builds, so match on substrings.
_STATUS_PATTERNS = (
    ("NXDOMAIN", ("does not exist", "name does not exist", "nxdomain")),
    ("TIMEOUT", ("timed out", "timeout", "no response from server")),
    ("REFUSED", ("refused",)),
    ("SERVFAIL", ("server failure", "servfail", "unreachable")),
)


def classify(entry):
    """Turn a raw lookup result into one of the statuses above."""
    if entry.get("resolved"):
        return "RESOLVED"
    error = (entry.get("error") or "").lower()
    for status, needles in _STATUS_PATTERNS:
        if any(needle in error for needle in needles):
            return status
    return "NO_ANSWER"


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


def probe_desktop(domains, server=None, host=None, password=None, timeout=90):
    """
    Resolve each domain from the desktop against the DNS Forwarding Proxy.

    Returns:
        {
          "server":           the resolver that was queried,
          "port53_listening": bool — TCP 53 reachable from the desktop,
          "configured_dns":   [str, ...] — the desktop's own resolver list,
          "results": {domain: {"resolved", "addresses", "error", "status"}},
        }
    """
    try:
        import winrm  # imported lazily so --help works without pywinrm
    except ImportError as exc:
        raise DesktopUnreachable(
            "pywinrm is not installed. Run: pip3 install pywinrm"
        ) from exc

    host = host or os.getenv("DESKTOP_IP")
    password = password or os.getenv("TF_VAR_windows_admin_password")
    server = server or os.getenv("DFP_PRIVATE_IP", "10.100.0.200")

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

    entries = payload.get("results") or []
    if isinstance(entries, dict):  # a single result comes back unwrapped
        entries = [entries]

    results = {}
    for entry in entries:
        results[entry["domain"]] = {
            "resolved": bool(entry.get("resolved")),
            "addresses": list(entry.get("addresses") or []),
            "error": entry.get("error") or "",
            "status": classify(entry),
        }

    configured = payload.get("configured_dns") or []
    if isinstance(configured, str):
        configured = [configured]

    return {
        "server": payload.get("server") or server,
        "port53_listening": bool(payload.get("port53_listening")),
        "configured_dns": list(configured),
        "results": results,
    }


def resolve_on_desktop(domains, server=None, host=None, password=None, timeout=90):
    """
    Per-domain results only, for callers that do not need the resolver metadata.

    Returns {domain: {"resolved", "addresses", "error", "status"}}.
    """
    return probe_desktop(domains, server=server, host=host,
                         password=password, timeout=timeout)["results"]


def explain_failure(probe):
    """
    One sentence naming the most likely cause when nothing resolves.

    Returns None if resolution is working, so callers can use it as a guard.
    """
    results = probe.get("results") or {}
    if any(r["resolved"] for r in results.values()):
        return None

    statuses = {r["status"] for r in results.values()}
    server = probe.get("server")

    if not probe.get("port53_listening"):
        return (f"Nothing is listening on {server}:53. The DFP service is not "
                f"running on the NIOS-X host. Check it with: "
                f"python3 setup_dfp.py --status")
    if statuses == {"TIMEOUT"}:
        return (f"{server} accepted a TCP connection on 53 but answered no query. "
                f"The DFP service is still starting, or the host registered "
                f"without the service being enabled.")
    if "REFUSED" in statuses:
        return (f"{server} refused the queries. The DFP is running but is not "
                f"serving this client, which usually means the host is not fully "
                f"registered with the CSP yet.")
    if "SERVFAIL" in statuses:
        return (f"{server} returned SERVFAIL. The DFP cannot reach Infoblox "
                f"Threat Defense upstream — check that the NIOS-X host has "
                f"outbound 443 to csp.infoblox.com.")
    return None


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


_STATUS_LABEL = {
    "RESOLVED": "RESOLVED",
    "NXDOMAIN": "BLOCKED",    # Threat Defense matched a Block rule
    "REFUSED":  "REFUSED",
    "TIMEOUT":  "TIMEOUT",
    "SERVFAIL": "SERVFAIL",
    "NO_ANSWER": "NO ANSWER",
}


def main():
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in flags

    # --probe answers "is the resolver alive and is it mine?" without caring
    # about any particular domain. Used by challenge 1, before recursion exists.
    if "--probe" in flags and not args:
        args = ["www.infoblox.com"]

    if not args:
        print(__doc__)
        return 2

    probe = probe_desktop(args)

    if as_json:
        print(json.dumps(probe, indent=2))
        return 0

    server = probe["server"]
    configured = probe["configured_dns"]

    print(f"  Desktop resolver : {', '.join(configured) or 'none configured'}")
    print(f"  Querying         : {server}")
    print(f"  TCP {server}:53   : {'listening' if probe['port53_listening'] else 'NOT LISTENING'}")
    print()

    for domain, result in probe["results"].items():
        label = _STATUS_LABEL.get(result["status"], result["status"])
        detail = ", ".join(result["addresses"]) if result["resolved"] else result["error"]
        print(f"  {label:10s} {domain:32s} {detail[:70]}")

    reason = explain_failure(probe)
    if reason:
        print()
        print(f"  ! {reason}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DesktopUnreachable, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)
