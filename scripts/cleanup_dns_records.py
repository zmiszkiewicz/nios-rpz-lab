#!/usr/bin/env python3
"""
Delete the Route 53 records setup_dns.py created for this participant.

Copy-adapted from tech-summit-security-niosx/terraform/scripts/cleanup_dns_records.py.
Reads created_fqdn.txt so it only ever removes records this run added, and never
fails the teardown: a missing record is reported and skipped, because
track_scripts/cleanup-shell still has a `terraform destroy` to get to.

Environment: DEMO_AWS_ACCESS_KEY_ID, DEMO_AWS_SECRET_ACCESS_KEY,
DEMO_HOSTED_ZONE_ID, optionally DEMO_AWS_REGION.
"""

import os
import sys
from datetime import datetime, timezone

import boto3

LOG_FILE = "dns_record_cleanup_log.txt"
FQDN_FILE = "created_fqdn.txt"

log_lines = [f"\n--- DNS Record Deletion Log [{datetime.now(timezone.utc).isoformat()}] ---\n"]


def log(message):
    print(message)
    log_lines.append(message + "\n")


def flush_log():
    with open(LOG_FILE, "a") as handle:
        handle.writelines(log_lines)


def main():
    try:
        with open(FQDN_FILE) as handle:
            records = [line.split() for line in handle if line.strip()]
    except FileNotFoundError:
        log(f"{FQDN_FILE} not found — nothing to clean up")
        flush_log()
        return 0

    if not records:
        log("No DNS records recorded, nothing to clean up")
        flush_log()
        return 0

    access_key = os.getenv("DEMO_AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("DEMO_AWS_SECRET_ACCESS_KEY")
    hosted_zone_id = os.getenv("DEMO_HOSTED_ZONE_ID")
    region = os.getenv("DEMO_AWS_REGION", "us-east-1")

    if not all((access_key, secret_key, hosted_zone_id)):
        log("ERROR: DEMO_AWS_ACCESS_KEY_ID, DEMO_AWS_SECRET_ACCESS_KEY and "
            "DEMO_HOSTED_ZONE_ID must all be set")
        flush_log()
        return 1

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    route53 = session.client("route53")

    for fqdn, ip in records:
        log(f"Deleting A record: {fqdn} -> {ip}")
        try:
            response = route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    "Comment": f"Delete A record for {fqdn}",
                    "Changes": [{
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": fqdn,
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": ip}],
                        },
                    }],
                },
            )
            log(f"  deleted, change status {response['ChangeInfo']['Status']}")
        except route53.exceptions.InvalidChangeBatch:
            log(f"  {fqdn} does not exist or was already removed")
        except Exception as exc:  # noqa: BLE001 — teardown must continue
            log(f"  ERROR deleting {fqdn}: {exc}")

    flush_log()
    return 0


if __name__ == "__main__":
    sys.exit(main())
