#!/usr/bin/env python3
"""
Publish per-participant public DNS names for the Grid Master and the desktop.

Copy-adapted from tech-summit-security-niosx/terraform/scripts/setup_dns.py,
trimmed from six records to two.

Two names are created in the shared demo Route 53 zone:

    <participant-id>-infoblox.<zone>   -> Grid Master Elastic IP
    <participant-id>-desktop.<zone>    -> desktop Elastic IP

The first is what the `infoblox-gm` virtual browser tab in config.yml opens; the
second is what setup-rdpclient points Guacamole at. Both are written to
created_fqdn.txt so cleanup_dns_records.py can remove exactly what was added.

Note the two-account split this inherits from the other labs: lab infrastructure
lives in the Instruqt AWS sandbox, but the public DNS zone belongs to a separate
long-lived demo account, reached with the DEMO_* credentials.

Environment: DEMO_AWS_ACCESS_KEY_ID, DEMO_AWS_SECRET_ACCESS_KEY,
DEMO_HOSTED_ZONE_ID, INSTRUQT_PARTICIPANT_ID, GM_IP, DESKTOP_IP,
optionally LAB_DNS_ZONE and DEMO_AWS_REGION.
"""

import os
import sys
from datetime import datetime, timezone

import boto3

LOG_FILE = "dns_record_log.txt"
FQDN_FILE = "created_fqdn.txt"

# Override with LAB_DNS_ZONE if this lab is ever pointed at a different zone.
DEFAULT_ZONE = "iracictechguru.com"

log_lines = [f"\n--- DNS Record Creation Log [{datetime.now(timezone.utc).isoformat()}] ---\n"]


def log(message):
    print(message)
    log_lines.append(message + "\n")


def flush_log():
    with open(LOG_FILE, "a") as handle:
        handle.writelines(log_lines)


def upsert(route53, hosted_zone_id, fqdn, ip):
    log(f"Creating A record: {fqdn} -> {ip}")
    response = route53.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Comment": f"Upsert A record for {fqdn}",
            "Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": fqdn,
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": ip}],
                },
            }],
        },
    )
    log(f"  created, change status {response['ChangeInfo']['Status']}")


def main():
    access_key = os.getenv("DEMO_AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("DEMO_AWS_SECRET_ACCESS_KEY")
    hosted_zone_id = os.getenv("DEMO_HOSTED_ZONE_ID")
    region = os.getenv("DEMO_AWS_REGION", "us-east-1")
    zone = os.getenv("LAB_DNS_ZONE", DEFAULT_ZONE)

    participant_id = os.getenv("INSTRUQT_PARTICIPANT_ID")
    gm_ip = os.getenv("GM_IP")
    desktop_ip = os.getenv("DESKTOP_IP")

    missing = [name for name, value in (
        ("DEMO_AWS_ACCESS_KEY_ID", access_key),
        ("DEMO_AWS_SECRET_ACCESS_KEY", secret_key),
        ("DEMO_HOSTED_ZONE_ID", hosted_zone_id),
        ("INSTRUQT_PARTICIPANT_ID", participant_id),
        ("GM_IP", gm_ip),
        ("DESKTOP_IP", desktop_ip),
    ) if not value]

    if missing:
        log(f"ERROR: missing required environment variables: {', '.join(missing)}")
        flush_log()
        return 1

    records = [
        (f"{participant_id}-infoblox.{zone}.", gm_ip),
        (f"{participant_id}-desktop.{zone}.", desktop_ip),
    ]

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    route53 = session.client("route53")

    created = []
    for fqdn, ip in records:
        try:
            upsert(route53, hosted_zone_id, fqdn, ip)
            created.append((fqdn, ip))
        except Exception as exc:  # noqa: BLE001 — report and keep going
            log(f"ERROR: failed to create {fqdn}: {exc}")

    # Written even on partial failure so cleanup removes whatever did land.
    with open(FQDN_FILE, "w") as handle:
        for fqdn, ip in created:
            handle.write(f"{fqdn} {ip}\n")
    log(f"Wrote {len(created)} record(s) to {FQDN_FILE}")

    flush_log()
    return 0 if len(created) == len(records) else 1


if __name__ == "__main__":
    sys.exit(main())
