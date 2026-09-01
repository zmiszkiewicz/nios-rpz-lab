#!/usr/bin/env python3
"""
Configure the generative-AI block on NIOS over WAPI.

Every subcommand is idempotent: re-running it converges the Grid Master on the
target state instead of failing on objects that already exist.

    configure_rpz.py status                 show what is currently configured
    configure_rpz.py dns-service            start DNS on the Grid Master member
    configure_rpz.py recursion              enable recursion + allow_recursion ACL
    configure_rpz.py zone                   create the local Response Policy Zone
    configure_rpz.py rules                  add the Block (NXDOMAIN) rules
    configure_rpz.py logging                enable the RPZ logging category
    configure_rpz.py passthru claude.ai     flip one domain to Passthru
    configure_rpz.py block claude.ai        flip it back to Block
    configure_rpz.py all                    everything above except passthru

The lab is designed to be driven through Grid Manager by hand — this script is
the automation equivalent, offered in the assignments as an accelerator and used
by the maintainer to smoke-test a freshly deployed grid.

Environment: GM_IP, NIOS_ADMIN_PASSWORD (or TF_VAR_nios_admin_password /
TF_VAR_windows_admin_password), optionally LAB_SUBNET_CIDR.
"""

import argparse
import os
import sys

import domains as D
from nios_wapi import NiosWapi, WapiError, already_exists, get_logger

log = get_logger("configure_rpz")

LAB_SUBNET_CIDR = os.getenv("LAB_SUBNET_CIDR", "10.100.0.0/24")

# NIOS does not name these after their BIND equivalents. The GUI's "Allow
# recursive queries" is `allow_recursive_query`, and "Allow recursive queries
# from" is `recursive_query_list`. Both are resolved against the live WAPI
# schema rather than assumed, because the names have moved between releases —
# an earlier version of this script guessed `recursion` and failed with
# "Unknown argument/field" on WAPI v2.13.1.
RECURSION_ENABLE_FIELDS = ("allow_recursive_query", "recursion", "enable_recursion")
RECURSION_ACL_FIELDS = ("recursive_query_list", "allow_recursion", "allow_recursive_query_list")
FORWARDER_FIELDS = ("forwarders",)
FORWARDER_ONLY_FIELDS = ("forwarders_only",)


def recursion_fields(wapi):
    """(enable field, ACL field) as this appliance actually names them."""
    return (
        wapi.resolve_field("grid:dns", RECURSION_ENABLE_FIELDS, "recursion"),
        wapi.resolve_field("grid:dns", RECURSION_ACL_FIELDS, "recursion ACL"),
    )


# --------------------------------------------------------------------------- #
# DNS service
# --------------------------------------------------------------------------- #

def enable_dns_service(wapi):
    """Start the DNS service on every grid member that is not already running it."""
    members = wapi.members_dns()
    if not members:
        log.error("No member:dns objects returned — is the grid initialised?")
        return False

    changed = False
    for member in members:
        host = member.get("host_name", "?")
        if member.get("enable_dns"):
            log.info("DNS already running on %s", host)
            continue
        wapi.put(member["_ref"], {"enable_dns": True})
        log.info("Started DNS on %s", host)
        changed = True

    return changed


# --------------------------------------------------------------------------- #
# Recursion
# --------------------------------------------------------------------------- #

def enable_recursion(wapi, subnet=LAB_SUBNET_CIDR):
    """
    Turn on recursion and allow it from the lab subnet.

    RPZ only rewrites answers for queries NIOS actually resolves. With recursion
    off the desktop gets REFUSED and the policy never applies, which is why this
    is groundwork rather than lab content.
    """
    enable_field, acl_field = recursion_fields(wapi)
    grid_dns = wapi.grid_dns(fields=[enable_field, acl_field])

    acl = grid_dns.get(acl_field) or []
    has_subnet = any(entry.get("address") == subnet and entry.get("permission") == "ALLOW"
                     for entry in acl)

    if grid_dns.get(enable_field) and has_subnet:
        log.info("Recursion already enabled and %s already permitted", subnet)
        return False

    if not has_subnet:
        acl = acl + [{"_struct": "addressac", "address": subnet, "permission": "ALLOW"}]

    wapi.put(grid_dns["_ref"], {enable_field: True, acl_field: acl})
    log.info("Recursion enabled (%s), %s now permits %s", enable_field, acl_field, subnet)

    _warn_on_member_override(wapi, enable_field, acl_field)
    return True


def _warn_on_member_override(wapi, enable_field, acl_field):
    """
    Flag members that override the grid setting.

    A member with use_allow_recursive_query=true ignores what we just set on the
    grid, and the only visible symptom is a REFUSED that looks like the grid
    change silently failed.
    """
    use_flags = [f"use_{enable_field}", f"use_{acl_field}"]
    available = [f for f in use_flags if f in wapi.schema("member:dns")]
    if not available:
        return

    try:
        members = wapi.get("member:dns",
                           **{"_return_fields+": ",".join(["host_name"] + available)})
    except WapiError:
        return

    for member in members:
        overriding = [f for f in available if member.get(f)]
        if overriding:
            log.warning("Member %s overrides the grid setting (%s). The grid-level "
                        "change will not apply there.",
                        member.get("host_name", "?"), ", ".join(overriding))


# --------------------------------------------------------------------------- #
# Response Policy Zone
# --------------------------------------------------------------------------- #

def find_zone(wapi, fqdn=D.RPZ_ZONE_FQDN):
    """The zone_rp object for the lab's RPZ, or None."""
    return wapi.get_one("zone_rp", fqdn=fqdn,
                        **{"_return_fields+": "fqdn,rpz_policy,rpz_severity,comment"})


def create_zone(wapi, fqdn=D.RPZ_ZONE_FQDN):
    """Create the local Response Policy Zone if it is not already there."""
    if find_zone(wapi, fqdn):
        log.info("Response Policy Zone %s already exists", fqdn)
        return False

    payload = {
        "fqdn": fqdn,
        # GIVEN means "use whatever action each rule specifies" rather than
        # overriding every rule with a single zone-wide action.
        "rpz_policy": "GIVEN",
        "rpz_severity": "MAJOR",
        "rpz_type": "LOCAL",
        "comment": D.RPZ_ZONE_COMMENT,
        "view": D.DNS_VIEW,
    }

    try:
        wapi.post("zone_rp", payload)
    except WapiError as exc:
        if already_exists(exc):
            log.info("Response Policy Zone %s already exists", fqdn)
            return False
        if _is_licensing_error(exc):
            log.error(
                "NIOS refused to create the Response Policy Zone. This almost "
                "always means the grid has no DNS Firewall (RPZ) licence. Check "
                "the temp_license line in the nios-gm module — see README "
                "Troubleshooting."
            )
        raise

    log.info("Created Response Policy Zone %s (policy GIVEN, severity MAJOR)", fqdn)
    return True


def _is_licensing_error(exc):
    body = (exc.body or "").lower()
    return any(token in body for token in ("licen", "not permitted", "unsupported"))


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

def list_rules(wapi, zone=D.RPZ_ZONE_FQDN):
    """Every record:rpz:cname in the lab's RPZ, keyed by rule name."""
    records = wapi.get("record:rpz:cname", zone=zone,
                       **{"_return_fields+": "name,canonical,zone"})
    return {record["name"]: record for record in records}


def _upsert_rule(wapi, name, canonical, existing, zone=D.RPZ_ZONE_FQDN):
    """
    Create the rule, or update it if it exists with a different action.

    Returns "created", "updated" or "unchanged".
    """
    current = existing.get(name)

    if current is not None:
        if current.get("canonical", "") == canonical:
            return "unchanged"
        wapi.put(current["_ref"], {"canonical": canonical})
        return "updated"

    payload = {"name": name, "canonical": canonical, "rp_zone": zone, "view": D.DNS_VIEW}
    try:
        wapi.post("record:rpz:cname", payload)
    except WapiError as exc:
        if already_exists(exc):
            return "unchanged"
        if exc.status == 400 and "view" in (exc.body or "").lower():
            # Some WAPI versions reject an explicit view on RPZ records because
            # the parent zone already pins it. Retry without it.
            payload.pop("view")
            wapi.post("record:rpz:cname", payload)
            return "created"
        raise
    return "created"


def add_block_rules(wapi, include_doh=True, zone=D.RPZ_ZONE_FQDN):
    """
    Add a Block (No Such Domain) rule for every AI domain, plus a wildcard so
    subdomains are covered too.
    """
    existing = list_rules(wapi, zone)
    tally = {"created": 0, "updated": 0, "unchanged": 0}

    for domain in D.all_blocked_domains(include_doh=include_doh):
        for name in D.rule_names(domain, zone):
            outcome = _upsert_rule(wapi, name, D.BLOCK_NXDOMAIN_CANONICAL, existing, zone)
            tally[outcome] += 1
            if outcome != "unchanged":
                log.info("%-9s Block(NXDOMAIN)  %s", outcome, name)

    log.info("Block rules: %d created, %d updated, %d already correct",
             tally["created"], tally["updated"], tally["unchanged"])
    return tally["created"] + tally["updated"] > 0


def set_passthru(wapi, domain, zone=D.RPZ_ZONE_FQDN):
    """
    Flip a domain from Block to Passthru.

    An RPZ Passthru rule is a CNAME to the queried name itself, which tells the
    resolver to ignore the policy and answer normally. The wildcard is flipped
    as well, otherwise the apex resolves but every subdomain stays dead.
    """
    existing = list_rules(wapi, zone)
    changed = False

    for name in D.rule_names(domain, zone):
        # canonical == the name being rewritten is the RPZ passthru form.
        target = name.replace(f".{zone}", "")
        outcome = _upsert_rule(wapi, name, target, existing, zone)
        if outcome != "unchanged":
            log.info("%-9s Passthru         %s -> %s", outcome, name, target)
            changed = True

    if not changed:
        log.info("%s is already set to Passthru", domain)
    return changed


def set_block(wapi, domain, zone=D.RPZ_ZONE_FQDN):
    """Flip a domain back to Block (No Such Domain)."""
    existing = list_rules(wapi, zone)
    changed = False

    for name in D.rule_names(domain, zone):
        outcome = _upsert_rule(wapi, name, D.BLOCK_NXDOMAIN_CANONICAL, existing, zone)
        if outcome != "unchanged":
            log.info("%-9s Block(NXDOMAIN)  %s", outcome, name)
            changed = True

    if not changed:
        log.info("%s is already blocked", domain)
    return changed


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def enable_rpz_logging(wapi):
    """
    Switch on the RPZ syslog category so blocked lookups are recorded.

    The exact field name inside logging_categories has moved between NIOS
    releases, so this discovers the RPZ-related keys rather than assuming one.
    """
    grid_dns = wapi.grid_dns(fields=["logging_categories"])
    categories = dict(grid_dns.get("logging_categories") or {})

    rpz_keys = [key for key in categories if "rpz" in key.lower()]
    if not rpz_keys:
        log.warning("This NIOS build exposes no RPZ logging category via WAPI; "
                    "enable 'RPZ' under Grid DNS Properties > Logging by hand.")
        return False

    if all(categories.get(key) for key in rpz_keys):
        log.info("RPZ logging already enabled (%s)", ", ".join(rpz_keys))
        return False

    for key in rpz_keys:
        categories[key] = True

    wapi.put(grid_dns["_ref"], {"logging_categories": categories})
    log.info("Enabled RPZ logging categories: %s", ", ".join(rpz_keys))
    return True


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #

def show_status(wapi):
    """Print the current state of everything this lab touches."""
    print()
    print("=" * 68)
    print(f"  NIOS RPZ status — {wapi.host} (WAPI {wapi.version})")
    print("=" * 68)

    for member in wapi.members_dns():
        state = "running" if member.get("enable_dns") else "STOPPED"
        print(f"  DNS service        {member.get('host_name', '?')}: {state}")

    enable_field, acl_field = recursion_fields(wapi)
    fields = [enable_field, acl_field, "logging_categories"]
    for optional in ("forwarders", "forwarders_only"):
        if optional in wapi.schema("grid:dns"):
            fields.append(optional)

    grid_dns = wapi.grid_dns(fields=fields)
    print(f"  Recursion          "
          f"{'enabled' if grid_dns.get(enable_field) else 'DISABLED'}  ({enable_field})")
    acl = grid_dns.get(acl_field) or []
    if not acl:
        print(f"    {acl_field:16s} <empty — all clients may recurse>")
    for entry in acl:
        print(f"    {acl_field:16s} {entry.get('address')} {entry.get('permission')}")

    forwarders = grid_dns.get("forwarders") or []
    if forwarders:
        print(f"  Forwarders         {', '.join(forwarders)}"
              f"{' (only)' if grid_dns.get('forwarders_only') else ''}")

    categories = grid_dns.get("logging_categories") or {}
    rpz_keys = [key for key in categories if "rpz" in key.lower()]
    if rpz_keys:
        state = "on" if all(categories.get(key) for key in rpz_keys) else "off"
        print(f"  RPZ logging        {state} ({', '.join(rpz_keys)})")

    zone = find_zone(wapi)
    if not zone:
        print(f"  RPZ zone           {D.RPZ_ZONE_FQDN}: NOT CREATED")
        print("=" * 68)
        print()
        return

    print(f"  RPZ zone           {zone['fqdn']} (policy {zone.get('rpz_policy')}, "
          f"severity {zone.get('rpz_severity')})")

    rules = list_rules(wapi)
    blocked = sorted(name for name, r in rules.items() if r.get("canonical", "") == "")
    passthru = sorted(name for name, r in rules.items() if r.get("canonical", "") != "")

    print(f"  Rules              {len(rules)} total — {len(blocked)} block, "
          f"{len(passthru)} passthru")
    for name in passthru:
        print(f"    passthru         {name}")
    print("=" * 68)
    print()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def build_parser():
    parser = argparse.ArgumentParser(
        description="Configure the generative-AI RPZ block on a NIOS Grid Master.")
    parser.add_argument("--gm", default=os.getenv("GM_IP"),
                        help="Grid Master address (default: $GM_IP)")
    parser.add_argument("--password", default=None,
                        help="NIOS admin password (default: from the environment)")
    parser.add_argument("--subnet", default=LAB_SUBNET_CIDR,
                        help=f"Lab subnet permitted to recurse (default: {LAB_SUBNET_CIDR})")
    parser.add_argument("--no-doh-rules", action="store_true",
                        help="Skip the DNS-over-HTTPS bootstrap rules")
    parser.add_argument("--no-restart", action="store_true",
                        help="Do not restart DNS afterwards")

    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "dns-service", "recursion", "zone", "rules", "logging", "all"):
        sub.add_parser(name)

    passthru = sub.add_parser("passthru")
    passthru.add_argument("domain", nargs="?", default=D.PASSTHRU_DEFAULT_DOMAIN)

    block = sub.add_parser("block")
    block.add_argument("domain", nargs="?", default=D.PASSTHRU_DEFAULT_DOMAIN)

    return parser


def main():
    args = build_parser().parse_args()

    wapi = NiosWapi(host=args.gm, password=args.password)
    wapi.connect(retries=3, delay=15)

    changed = False
    needs_restart = False

    if args.command == "status":
        show_status(wapi)
        return 0

    if args.command in ("dns-service", "all"):
        if enable_dns_service(wapi):
            changed = needs_restart = True

    if args.command in ("recursion", "all"):
        if enable_recursion(wapi, args.subnet):
            changed = needs_restart = True

    if args.command in ("zone", "all"):
        if create_zone(wapi):
            changed = needs_restart = True

    if args.command in ("rules", "all"):
        if add_block_rules(wapi, include_doh=not args.no_doh_rules):
            changed = True

    if args.command in ("logging", "all"):
        if enable_rpz_logging(wapi):
            changed = needs_restart = True

    if args.command == "passthru":
        changed = set_passthru(wapi, args.domain)

    if args.command == "block":
        changed = set_block(wapi, args.domain)

    if needs_restart and not args.no_restart:
        wapi.restart_dns()

    log.info("Done — %s", "configuration changed" if changed else "nothing to change")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except WapiError as exc:
        log.error("WAPI call failed: %s", exc)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — top-level guard, message matters more than type
        log.error("%s", exc)
        sys.exit(1)
