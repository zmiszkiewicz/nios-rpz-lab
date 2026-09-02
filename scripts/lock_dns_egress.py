#!/usr/bin/env python3
"""
Close the DNS bypass by rewriting the unmanaged host's egress rules.

    lock_dns_egress.py --status     show the current egress rules
    lock_dns_egress.py --lock       DNS may only leave towards the Grid Master
    lock_dns_egress.py --unlock     restore unrestricted egress

An RPZ governs the clients that ask you. A host pointed at 8.8.8.8 never does,
so no amount of policy on the appliance reaches it. The fix is not on the
appliance at all: stop the host from talking DNS to anything except the
corporate resolver. That is a firewall rule, and here it is a security group.

Locked egress permits:
    UDP/TCP 53  -> the Grid Master only
    TCP 80, 443 -> anywhere    (the host stays usable)
    ICMP        -> anywhere
Notably absent: port 53 to the internet, and 853 in any direction, so
DNS-over-TLS is not an escape hatch either.

Modelled on the boto3 security-group rewriting in
secure-ai-infoblox/scripts/SG_Change.py.

Environment: BYPASS_SG_NAME (or BYPASS_SG_ID), GM_LAN1_PRIVATE_IP, AWS_REGION.
"""

import argparse
import os
import sys

import boto3
from botocore.exceptions import ClientError

from nios_wapi import get_logger

log = get_logger("lock_dns_egress")

OPEN_EGRESS = [{
    "IpProtocol": "-1",
    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Unrestricted"}],
}]


def locked_egress(gm_ip):
    """Egress rules that force DNS through the Grid Master."""
    gm_cidr = f"{gm_ip}/32"
    return [
        {"IpProtocol": "udp", "FromPort": 53, "ToPort": 53,
         "IpRanges": [{"CidrIp": gm_cidr, "Description": "DNS to the Grid Master only"}]},
        {"IpProtocol": "tcp", "FromPort": 53, "ToPort": 53,
         "IpRanges": [{"CidrIp": gm_cidr, "Description": "DNS to the Grid Master only"}]},
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
         "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS"}]},
        {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1,
         "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "ICMP"}]},
    ]


def find_group(ec2, sg_id=None, sg_name=None):
    """Look the security group up by id if we have one, otherwise by name."""
    if sg_id:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
    elif sg_name:
        response = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [sg_name]}])
    else:
        raise SystemExit("Set BYPASS_SG_ID or BYPASS_SG_NAME, or pass --sg-id/--sg-name.")

    groups = response.get("SecurityGroups") or []
    if not groups:
        raise SystemExit(f"No security group matched {sg_id or sg_name!r}.")
    if len(groups) > 1:
        raise SystemExit(f"{len(groups)} groups matched {sg_name!r}; pass --sg-id instead.")
    return groups[0]


def describe(group):
    """Print the group's egress rules in a readable form."""
    print()
    print(f"  {group['GroupName']}  ({group['GroupId']})")
    print("  egress:")
    rules = group.get("IpPermissionsEgress") or []
    if not rules:
        print("    (none — the host cannot originate any traffic)")
    for rule in rules:
        proto = rule.get("IpProtocol")
        proto = "all" if proto == "-1" else proto
        lo, hi = rule.get("FromPort"), rule.get("ToPort")
        ports = "all" if lo is None else (str(lo) if lo == hi else f"{lo}-{hi}")
        targets = ", ".join(r["CidrIp"] for r in rule.get("IpRanges", [])) or "-"
        print(f"    {proto:5s} {ports:11s} -> {targets}")
    print()


def is_locked(group, gm_ip):
    """True if DNS egress is already restricted to the Grid Master."""
    for rule in group.get("IpPermissionsEgress") or []:
        proto = rule.get("IpProtocol")
        if proto == "-1":
            return False
        if proto in ("udp", "tcp") and rule.get("FromPort") == 53:
            for entry in rule.get("IpRanges", []):
                if entry["CidrIp"] not in (f"{gm_ip}/32",):
                    return False
    return any(
        rule.get("FromPort") == 53 and rule.get("IpProtocol") in ("udp", "tcp")
        for rule in group.get("IpPermissionsEgress") or []
    )


def replace_egress(ec2, group, new_rules):
    """Swap the group's egress rules for new_rules."""
    sg_id = group["GroupId"]
    existing = group.get("IpPermissionsEgress") or []

    if existing:
        try:
            ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=existing)
            log.info("Revoked %d existing egress rule(s)", len(existing))
        except ClientError as exc:
            log.error("Could not revoke existing egress: %s", exc)
            return False

    try:
        ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=new_rules)
        log.info("Authorised %d new egress rule(s)", len(new_rules))
    except ClientError as exc:
        # Leaving the host with no egress at all would be worse than the bypass,
        # so put the open rules back rather than fail half-applied.
        log.error("Could not authorise new egress: %s", exc)
        log.error("Restoring unrestricted egress to avoid stranding the host.")
        try:
            ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=OPEN_EGRESS)
        except ClientError:
            pass
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Lock or unlock DNS egress on the unmanaged host.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--lock", action="store_true",
                        help="Permit DNS only towards the Grid Master")
    action.add_argument("--unlock", action="store_true",
                        help="Restore unrestricted egress")
    action.add_argument("--status", action="store_true",
                        help="Show the current egress rules")
    parser.add_argument("--sg-id", default=os.getenv("BYPASS_SG_ID"))
    parser.add_argument("--sg-name", default=os.getenv("BYPASS_SG_NAME"))
    parser.add_argument("--gm-ip", default=os.getenv("GM_LAN1_PRIVATE_IP", "10.100.0.11"))
    parser.add_argument("--region", default=os.getenv("AWS_REGION",
                                                      os.getenv("AWS_DEFAULT_REGION", "eu-central-1")))
    args = parser.parse_args()

    ec2 = boto3.client("ec2", region_name=args.region)
    group = find_group(ec2, args.sg_id, args.sg_name)

    if args.status:
        describe(group)
        print(f"  DNS egress is {'LOCKED to ' + args.gm_ip if is_locked(group, args.gm_ip) else 'OPEN to the internet'}\n")
        return 0

    if args.lock:
        if is_locked(group, args.gm_ip):
            log.info("Egress is already locked to %s", args.gm_ip)
            describe(group)
            return 0
        log.info("Restricting DNS egress to %s...", args.gm_ip)
        if not replace_egress(ec2, group, locked_egress(args.gm_ip)):
            return 1
        log.info("Done. The host can no longer reach a public resolver, so its "
                 "queries must go to the Grid Master — where the RPZ applies.")
    else:
        log.info("Restoring unrestricted egress...")
        if not replace_egress(ec2, group, OPEN_EGRESS):
            return 1
        log.info("Done. The host can bypass the Grid Master again.")

    describe(find_group(ec2, group["GroupId"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ClientError as exc:
        log.error("AWS call failed: %s", exc)
        sys.exit(1)
