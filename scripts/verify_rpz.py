#!/usr/bin/env python3
"""
Verify the participant's work, one challenge at a time.

Every challenge check script calls this with a --stage. On failure the reason is
written to /tmp/rpz_check_reason.txt so the check script can hand it straight to
Instruqt's fail-message, and the participant is told what is actually wrong
rather than just seeing a red cross.

    verify_rpz.py --stage dns-service    challenge 1
    verify_rpz.py --stage recursion      challenge 2
    verify_rpz.py --stage rpz            challenge 3
    verify_rpz.py --stage block          challenge 4
    verify_rpz.py --stage logging        challenge 5
    verify_rpz.py --stage passthru       challenge 6
    verify_rpz.py --stage all            everything, for a maintainer smoke test

Environment: GM_IP, DESKTOP_IP, TF_VAR_windows_admin_password,
GM_LAN1_PRIVATE_IP, optionally LAB_SUBNET_CIDR.
"""

import argparse
import gzip
import os
import sys

import domains as D
from configure_rpz import recursion_fields
from desktop_dns import DesktopUnreachable, explain_failure, probe_desktop
from nios_wapi import (NiosWapi, WapiError, WapiUnreachable, clear_reason, fail,
                       get_logger)

log = get_logger("verify_rpz")

LAB_SUBNET_CIDR = os.getenv("LAB_SUBNET_CIDR", "10.100.0.0/24")

# Kept small so the WinRM round trip stays quick. These three are the ones the
# assignments tell the participant to try in the browser.
SAMPLE_BLOCKED = ["claude.ai", "chatgpt.com", "openai.com"]

# Minimum rule count for the zone to count as configured: an apex rule and a
# wildcard for every generative-AI domain. DoH rules are optional extra credit.
MIN_EXPECTED_RULES = len(D.GENAI_DOMAINS) * 2


# --------------------------------------------------------------------------- #
# Stage 1 — DNS service
# --------------------------------------------------------------------------- #

def check_baseline(wapi):
    """
    Challenge 1: the groundwork is in place and the participant has looked at it.

    Not a test of the participant's configuration — bootstrap_nios.py does that
    work at setup. It is a readiness gate: if the Grid Master is not resolving,
    every later challenge produces a misleading result, so it is worth catching
    here with a message that says so.
    """
    check_dns_service(wapi)
    check_recursion(wapi, LAB_SUBNET_CIDR)

    try:
        probe = probe_desktop([D.CONTROL_DOMAIN, "claude.ai"])
    except DesktopUnreachable as exc:
        fail(f"Could not reach the Windows desktop to test resolution: {exc}")

    reason = explain_failure(probe)
    if reason:
        fail(reason)

    control = probe["results"].get(D.CONTROL_DOMAIN, {})
    if not control.get("resolved"):
        fail(f"The Grid Master is running but {D.CONTROL_DOMAIN} does not resolve "
             f"from the desktop ({control.get('status')}). Resolution has to work "
             f"before an RPZ can demonstrate anything. Run "
             f"'python3 bootstrap_nios.py' from the Terminal tab to repair it.")

    log.info("PASS  %s resolves from the desktop (%s)",
             D.CONTROL_DOMAIN, ", ".join(control.get("addresses", [])))

    configured = probe.get("configured_dns") or []
    log.info("PASS  Desktop resolver is %s", ", ".join(configured) or "unset")

    # Informational only. If the participant has already built the RPZ and come
    # back to re-run this check, claude.ai being blocked is correct, not a fault.
    ai = probe["results"].get("claude.ai", {})
    if ai.get("resolved"):
        log.info("NOTE  claude.ai currently resolves (%s) — the 'before' state",
                 ", ".join(ai.get("addresses", [])))
    else:
        log.info("NOTE  claude.ai is already blocked (%s) — policy is in place",
                 ai.get("status"))
    return True


def check_dns_service(wapi):
    members = wapi.members_dns()
    if not members:
        fail("The Grid Master returned no DNS members. The grid may still be "
             "initialising — wait a minute and check again.")

    running = [m for m in members if m.get("enable_dns")]
    if not running:
        names = ", ".join(m.get("host_name", "?") for m in members)
        fail(f"The DNS service is not running on the Grid Master ({names}). In Grid "
             f"Manager go to Data Management > DNS > Members, select the Grid Master "
             f"and click Start.")

    for member in running:
        log.info("PASS  DNS service running on %s", member.get("host_name", "?"))
    return True


# --------------------------------------------------------------------------- #
# Stage 2 — recursion
# --------------------------------------------------------------------------- #

def check_recursion(wapi, subnet=LAB_SUBNET_CIDR):
    # Field names come from the appliance's schema — see configure_rpz for why.
    enable_field, acl_field = recursion_fields(wapi)
    grid_dns = wapi.grid_dns(fields=[enable_field, acl_field])

    if not grid_dns.get(enable_field):
        fail("Recursion is disabled on the grid. Without it NIOS never resolves the "
             "desktop's queries, so an RPZ can never match. Run "
             "'python3 bootstrap_nios.py' to repair the groundwork.")

    log.info("PASS  Recursion is enabled (%s)", enable_field)

    acl = grid_dns.get(acl_field) or []
    if not acl:
        log.info("PASS  allow_recursion is unrestricted (all clients may recurse)")
        return True

    permitted = [e for e in acl if e.get("permission") == "ALLOW"]
    if not any(_acl_covers(entry.get("address"), subnet) for entry in permitted):
        listed = ", ".join(f"{e.get('address')}:{e.get('permission')}" for e in acl) or "none"
        fail(f"Recursion is on, but the lab subnet {subnet} is not in {acl_field} "
             f"(currently: {listed}). The desktop's queries will be refused. Run "
             f"'python3 bootstrap_nios.py' to repair the groundwork.")

    log.info("PASS  %s permits %s", acl_field, subnet)
    return True


def _acl_covers(address, subnet):
    """
    True if an ACL entry plausibly covers the lab subnet.

    Deliberately loose: participants legitimately enter the exact subnet, a
    wider supernet, "any", or a single host. Only an exact-prefix comparison
    would be strict enough to be wrong more often than right.
    """
    if not address:
        return False
    if address.lower() in ("any", "0.0.0.0/0"):
        return True
    if address == subnet:
        return True

    try:
        import ipaddress
        candidate = ipaddress.ip_network(address, strict=False)
        target = ipaddress.ip_network(subnet, strict=False)
        return candidate.supernet_of(target) or candidate.overlaps(target)
    except (ValueError, AttributeError):
        return False


# --------------------------------------------------------------------------- #
# Stage 3 — the zone and its rules
# --------------------------------------------------------------------------- #

def check_rpz(wapi):
    zone = wapi.get_one("zone_rp", fqdn=D.RPZ_ZONE_FQDN,
                        **{"_return_fields+": "fqdn,rpz_policy,rpz_severity"})
    if not zone:
        existing = wapi.get("zone_rp", **{"_return_fields+": "fqdn"})
        names = ", ".join(z.get("fqdn", "?") for z in existing) or "none"
        fail(f"No Response Policy Zone called {D.RPZ_ZONE_FQDN} exists "
             f"(found: {names}). Create it under Data Management > DNS > Response "
             f"Policy Zones > Add > Local Response Policy Zone.")

    log.info("PASS  RPZ %s exists (policy %s, severity %s)",
             zone["fqdn"], zone.get("rpz_policy"), zone.get("rpz_severity"))

    records = wapi.get("record:rpz:cname", zone=D.RPZ_ZONE_FQDN,
                       **{"_return_fields+": "name,canonical"})
    if not records:
        fail(f"The Response Policy Zone {D.RPZ_ZONE_FQDN} exists but has no rules in "
             f"it. Add a Block (No Such Domain) rule for each generative AI domain.")

    by_name = {r["name"]: r.get("canonical", "") for r in records}
    blocked_apexes = {
        name.replace(f".{D.RPZ_ZONE_FQDN}", "")
        for name, canonical in by_name.items()
        if canonical == D.BLOCK_NXDOMAIN_CANONICAL and not name.startswith("*.")
    }

    missing = [d for d in D.genai_domains() if d not in blocked_apexes]
    if missing:
        fail(f"{len(missing)} generative AI domain(s) have no Block rule: "
             f"{', '.join(missing[:5])}"
             f"{' and others' if len(missing) > 5 else ''}. Add a Block (No Such "
             f"Domain) rule for each.")

    log.info("PASS  %d rules present, all %d generative AI domains blocked",
             len(records), len(D.genai_domains()))

    doh_blocked = [d for d in D.doh_domains() if d in blocked_apexes]
    if doh_blocked:
        log.info("PASS  %d/%d DoH bootstrap domains also blocked",
                 len(doh_blocked), len(D.doh_domains()))
    else:
        log.info("NOTE  No DoH bootstrap rules — optional, but a browser that "
                 "re-enables DoH could bypass this policy")

    wildcards = [n for n in by_name if n.startswith("*.")]
    if not wildcards:
        log.info("NOTE  No wildcard rules — subdomains such as chat.openai.com "
                 "will still resolve")

    return True


# --------------------------------------------------------------------------- #
# Stage 4 — the block, proved from the desktop
# --------------------------------------------------------------------------- #

def check_block(sample=None):
    sample = sample or SAMPLE_BLOCKED
    targets = sample + [D.CONTROL_DOMAIN]

    try:
        probe = probe_desktop(targets)
    except DesktopUnreachable as exc:
        fail(f"Could not run the lookup on the Windows desktop: {exc}")

    results = probe["results"]

    # A dead resolver fails every lookup, which looks exactly like a perfect
    # block until you ask why. Name the real cause before judging the policy.
    reason = explain_failure(probe)
    if reason:
        fail(reason)

    control = results.get(D.CONTROL_DOMAIN, {})
    if not control.get("resolved"):
        fail(f"The control domain {D.CONTROL_DOMAIN} does not resolve from the "
             f"desktop either ({control.get('status', 'no answer')}), so this is not "
             f"a policy block — resolution itself is broken. Check that recursion is "
             f"enabled and that the DNS service is running.")

    log.info("PASS  Control domain %s still resolves (%s)",
             D.CONTROL_DOMAIN, ", ".join(control.get("addresses", [])))

    still_resolving = [d for d in sample if results.get(d, {}).get("resolved")]
    if still_resolving:
        addresses = results[still_resolving[0]]["addresses"]
        fail(f"{', '.join(still_resolving)} still resolve(s) from the desktop "
             f"(got {', '.join(addresses)}). The RPZ rule is not taking effect — "
             f"check the rule action is Block (No Such Domain) and that DNS has been "
             f"restarted.")

    # Blocked must mean NXDOMAIN. A timeout or a REFUSED is a broken resolver
    # wearing the costume of a working policy, and must not pass.
    wrong_status = {d: results[d]["status"] for d in sample
                    if results.get(d, {}).get("status") not in ("NXDOMAIN", "NO_ANSWER")}
    if wrong_status:
        detail = ", ".join(f"{d} -> {s}" for d, s in wrong_status.items())
        fail(f"Those domains are not resolving, but not because of the RPZ: {detail}. "
             f"A Block (No Such Domain) rule produces NXDOMAIN; a timeout or refusal "
             f"means the Grid Master is not answering properly.")

    for domain in sample:
        log.info("PASS  %s is blocked from the desktop (%s)",
                 domain, results[domain]["status"])
    return True


# --------------------------------------------------------------------------- #
# Stage 5 — logging
# --------------------------------------------------------------------------- #

def check_logging(wapi):
    grid_dns = wapi.grid_dns(fields=["logging_categories"])
    categories = grid_dns.get("logging_categories") or {}
    rpz_keys = [key for key in categories if "rpz" in key.lower()]

    if not rpz_keys:
        log.info("NOTE  This NIOS build exposes no RPZ logging category over WAPI; "
                 "skipping the toggle check")
    elif not all(categories.get(key) for key in rpz_keys):
        off = [key for key in rpz_keys if not categories.get(key)]
        fail(f"RPZ query logging is still off ({', '.join(off)}). Enable it under "
             f"Data Management > DNS > Grid DNS Properties > Logging so blocked "
             f"lookups are recorded.")
    else:
        log.info("PASS  RPZ logging enabled (%s)", ", ".join(rpz_keys))

    # The block must still be live, otherwise there is nothing to log.
    check_block()

    hits = _try_fetch_rpz_hits(wapi)
    if hits:
        log.info("PASS  Found %d RPZ hit line(s) in the Grid Master syslog", len(hits))
        for line in hits[:5]:
            log.info("      %s", line[:160])
    else:
        log.info("NOTE  Could not read RPZ hits from syslog over WAPI — this is not "
                 "fatal. View them in Grid Manager under Administration > Logs > "
                 "Syslog, filtered on 'rpz'.")

    return True


def _try_fetch_rpz_hits(wapi, limit=200):
    """
    Best-effort syslog scrape for RPZ hit lines.

    Deliberately soft: the fileop download dance varies across NIOS releases and
    a quirk there must never fail a challenge the participant completed
    correctly. Returns a list of matching lines, or [] if anything goes wrong.
    """
    try:
        members = wapi.members_dns(fields=("host_name",))
        if not members:
            return []
        host_name = members[0].get("host_name")

        response = wapi.call("fileop", "get_log_files", {
            "log_type": "SYSLOG",
            "member": host_name,
            "node_type": "ACTIVE",
        })
        url = response.get("url")
        token = response.get("token")
        if not url:
            return []

        # download_file rewrites the internal host NIOS puts in the URL and
        # releases the download afterwards.
        content = wapi.download_file(url, token=token)

        if content[:2] == b"\x1f\x8b":
            content = gzip.decompress(content)

        text = content.decode("utf-8", errors="replace")
        needles = ("rpz", "RPZ")
        return [
            line for line in text.splitlines()[-5000:]
            if any(needle in line for needle in needles)
        ][-limit:]

    except Exception as exc:  # noqa: BLE001 — best effort by design
        log.debug("Syslog fetch failed: %s", exc)
        return []


# --------------------------------------------------------------------------- #
# Stage 6 — passthru
# --------------------------------------------------------------------------- #

def check_passthru(wapi, domain=None):
    domain = domain or D.PASSTHRU_DEFAULT_DOMAIN
    apex_rule = f"{domain}.{D.RPZ_ZONE_FQDN}"

    records = wapi.get("record:rpz:cname", zone=D.RPZ_ZONE_FQDN,
                       **{"_return_fields+": "name,canonical"})
    by_name = {r["name"]: r.get("canonical", "") for r in records}

    if apex_rule not in by_name:
        fail(f"There is no rule for {domain} in {D.RPZ_ZONE_FQDN} at all. Add a "
             f"Passthru rule for it.")

    canonical = by_name[apex_rule]
    if canonical == D.BLOCK_NXDOMAIN_CANONICAL:
        fail(f"The rule for {domain} is still set to Block (No Such Domain). Change "
             f"its action to Passthru so the approved service is allowed through "
             f"while everything else stays blocked.")

    log.info("PASS  %s is a Passthru rule (canonical %r)", apex_rule, canonical)

    # A passthru that leaves every other AI domain reachable is not a policy.
    others = [d for d in SAMPLE_BLOCKED if d != domain][:2]
    try:
        probe = probe_desktop([domain] + others + [D.CONTROL_DOMAIN])
    except DesktopUnreachable as exc:
        fail(f"Could not run the lookup on the Windows desktop: {exc}")

    reason = explain_failure(probe)
    if reason:
        fail(reason)

    results = probe["results"]

    if not results.get(domain, {}).get("resolved"):
        fail(f"{domain} is configured as Passthru but still does not resolve from the "
             f"desktop. Restart DNS services, then flush the client cache with "
             f"'ipconfig /flushdns' — the NXDOMAIN may still be cached.")

    log.info("PASS  %s now resolves from the desktop (%s)",
             domain, ", ".join(results[domain]["addresses"]))

    leaked = [d for d in others if results.get(d, {}).get("resolved")]
    if leaked:
        fail(f"Allow-listing {domain} also unblocked {', '.join(leaked)}. The Passthru "
             f"rule should apply to one domain only — check you edited the rule for "
             f"{domain} rather than the zone-wide policy.")

    for other in others:
        log.info("PASS  %s is still blocked", other)
    return True


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

STAGES = ("baseline", "dns-service", "recursion", "rpz", "block", "logging",
          "passthru", "all")


def main():
    parser = argparse.ArgumentParser(
        description="Verify one stage of the NIOS RPZ generative-AI block.")
    parser.add_argument("--stage", required=True, choices=STAGES)
    parser.add_argument("--gm", default=os.getenv("GM_IP"))
    parser.add_argument("--password", default=None)
    parser.add_argument("--subnet", default=LAB_SUBNET_CIDR)
    parser.add_argument("--domain", default=D.PASSTHRU_DEFAULT_DOMAIN,
                        help="Domain to check for the passthru stage")
    args = parser.parse_args()

    clear_reason()

    # The block stage is proved entirely from the desktop and needs no WAPI session.
    wapi = None
    if args.stage != "block":
        try:
            wapi = NiosWapi(host=args.gm, password=args.password)
            wapi.connect(retries=3, delay=10)
        except WapiUnreachable as exc:
            fail(f"Could not reach the Grid Master: {exc}")

    stage = args.stage
    log.info("--- verifying stage: %s ---", stage)

    if stage == "baseline":
        check_baseline(wapi)
    if stage in ("dns-service", "all"):
        check_dns_service(wapi)
    if stage in ("recursion", "all"):
        check_recursion(wapi, args.subnet)
    if stage in ("rpz", "all"):
        check_rpz(wapi)
    if stage in ("block", "all"):
        check_block()
    if stage in ("logging", "all"):
        check_logging(wapi)
    if stage in ("passthru", "all"):
        check_passthru(wapi, args.domain)

    log.info("--- stage %s passed ---", stage)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except WapiError as exc:
        fail(f"A WAPI call failed while checking your work: {exc}")
    except Exception as exc:  # noqa: BLE001 — top-level guard
        fail(f"Unexpected error while checking your work: {exc}")
