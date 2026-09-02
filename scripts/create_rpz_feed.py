#!/usr/bin/env python3
"""
Build the whole generative-AI blocklist on NIOS in one command.

    python3 create_rpz_feed.py              create the RPZ and every block rule
    python3 create_rpz_feed.py --no-doh     skip the DNS-over-HTTPS rules
    python3 create_rpz_feed.py --dry-run    show what would be created

Creates a local Response Policy Zone and populates it with a Block (No Such
Domain) rule for every generative AI service on the company's list, plus a
wildcard for each so subdomains are covered. Then restarts DNS so the policy
takes effect.

This is the "feed" the lab hands the participant. NIOS has no managed feed that
carries generative AI domains — the published catalogue is Base, Base IP,
High/Medium/Low Risk and Informational plus special-purpose feeds such as
cryptocurrency and public DoH, and feed content cannot be edited in NIOS at all.
Curating the list yourself in a local RPZ is the supported way to do it, and
this script is what makes that practical: thirty rules is not a clicking
exercise.

Idempotent — safe to re-run, and safe to run after making rules by hand in Grid
Manager. Anything already correct is left alone.

Environment: GM_IP, NIOS_ADMIN_PASSWORD (or TF_VAR_nios_admin_password /
TF_VAR_windows_admin_password).
"""

import argparse
import os
import sys

import domains as D
from configure_rpz import add_block_rules, create_zone, find_zone, list_rules
from nios_wapi import NiosWapi, WapiError, WapiUnreachable, get_logger

log = get_logger("create_rpz_feed")


def preview(include_doh=True):
    """Print what would be created, without touching the grid."""
    print(f"\n  Response Policy Zone: {D.RPZ_ZONE_FQDN}")
    print(f"  Policy: GIVEN (per-rule actions)   Severity: MAJOR\n")

    groups = [("Generative AI services", D.GENAI_DOMAINS)]
    if include_doh:
        groups.append(("DNS-over-HTTPS resolvers", D.DOH_BOOTSTRAP_DOMAINS))

    total = 0
    for title, entries in groups:
        print(f"  {title} ({len(entries)} domains, {len(entries) * 2} rules)")
        for entry in entries:
            names = D.rule_names(entry["domain"])
            print(f"    Block(NXDOMAIN)  {names[0]}")
            print(f"    Block(NXDOMAIN)  {names[1]}")
            total += 2
        print()

    print(f"  {total} rules total\n")


def main():
    parser = argparse.ArgumentParser(
        description="Create the generative-AI RPZ and all of its block rules.")
    parser.add_argument("--gm", default=os.getenv("GM_IP"))
    parser.add_argument("--password", default=None)
    parser.add_argument("--no-doh", action="store_true",
                        help="Skip the DNS-over-HTTPS bootstrap rules")
    parser.add_argument("--dry-run", action="store_true",
                        help="List what would be created and exit")
    parser.add_argument("--no-restart", action="store_true",
                        help="Do not restart DNS afterwards")
    args = parser.parse_args()

    include_doh = not args.no_doh

    if args.dry_run:
        preview(include_doh)
        return 0

    try:
        wapi = NiosWapi(host=args.gm, password=args.password)
        wapi.connect(retries=3, delay=15)
    except WapiUnreachable as exc:
        log.error("Cannot reach the Grid Master: %s", exc)
        return 1

    print()
    log.info("--- 1/3 Response Policy Zone ---")
    if create_zone(wapi):
        log.info("Created %s", D.RPZ_ZONE_FQDN)
    else:
        log.info("%s was already there", D.RPZ_ZONE_FQDN)

    log.info("--- 2/3 block rules ---")
    changed = add_block_rules(wapi, include_doh=include_doh)

    log.info("--- 3/3 activate ---")
    if changed and not args.no_restart:
        wapi.restart_dns()
    elif not changed:
        log.info("Nothing changed, no restart needed")

    # Report what is actually on the grid, not what we intended to put there.
    zone = find_zone(wapi)
    rules = list_rules(wapi)
    blocked = {name.replace(f".{D.RPZ_ZONE_FQDN}", "")
               for name, r in rules.items()
               if r.get("canonical", "") == "" and not name.startswith("*.")}

    genai_covered = [d for d in D.genai_domains() if d in blocked]
    doh_covered = [d for d in D.doh_domains() if d in blocked]

    print()
    print("=" * 66)
    print(f"  {zone['fqdn'] if zone else D.RPZ_ZONE_FQDN}")
    print("=" * 66)
    print(f"  Rules on the grid        {len(rules)}")
    print(f"  Generative AI blocked    {len(genai_covered)}/{len(D.genai_domains())}")
    print(f"  DoH resolvers blocked    {len(doh_covered)}/{len(D.doh_domains())}")
    passthru = sorted(n for n, r in rules.items() if r.get("canonical", ""))
    if passthru:
        print(f"  Passthru exceptions      {len(passthru)}")
        for name in passthru:
            print(f"    {name}")
    print("=" * 66)
    print()

    missing = [d for d in D.genai_domains() if d not in blocked]
    if missing:
        log.error("Not every generative AI domain got a rule. Missing: %s",
                  ", ".join(missing))
        return 1

    log.info("Done. Open Data Management > DNS > Response Policy Zones in Grid "
             "Manager to see the rules.")
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
