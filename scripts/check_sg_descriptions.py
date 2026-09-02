#!/usr/bin/env python3
"""
Fail if any security-group description uses a character AWS rejects.

    python3 check_sg_descriptions.py           # scan ../terraform
    python3 check_sg_descriptions.py <dir>

AWS validates security-group descriptions against

    ^[0-9A-Za-z_ .:/()#,@\\[\\]+=&;{}!$*-]*$

which excludes em dashes and apostrophes among others. `terraform validate`
does not catch it, so the failure surfaces at `terraform apply` — in this lab's
case eight minutes into a track start, after the participant is already waiting.

This checks the two places that reach the AWS API:
  * `description` inside an aws_security_group block (rules and the group itself)
  * `Description` values in the boto3 IpPermissions in lock_dns_egress.py

Terraform variable and output descriptions are deliberately not checked — they
never leave the local state and prose reads better with real punctuation.

Run it before pushing a Terraform change:
    python3 scripts/check_sg_descriptions.py && echo ok
"""

import os
import re
import sys

ALLOWED = re.compile(r'^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$')


def offending_chars(value):
    return sorted({c for c in value if not ALLOWED.match(c)})


def scan_terraform(path):
    """Descriptions inside aws_security_group blocks."""
    problems = []

    for root, _, files in os.walk(path):
        for name in sorted(files):
            if not name.endswith(".tf"):
                continue
            full = os.path.join(root, name)
            lines = open(full).read().splitlines()

            depth = 0
            inside = False
            for number, line in enumerate(lines, 1):
                if re.match(r'\s*resource\s+"aws_security_group"', line):
                    inside, depth = True, 0

                if inside:
                    match = re.search(r'\bdescription\s*=\s*"([^"]*)"', line)
                    if match:
                        bad = offending_chars(match.group(1))
                        if bad:
                            problems.append((full, number, match.group(1), bad))

                    depth += line.count("{") - line.count("}")
                    if depth <= 0 and "{" in line or (inside and depth <= 0):
                        if depth <= 0 and number > 1:
                            inside = False

    return problems


def scan_boto3(path):
    """Description values handed to authorize_security_group_* calls."""
    problems = []
    target = os.path.join(path, "lock_dns_egress.py")
    if not os.path.exists(target):
        return problems

    for number, line in enumerate(open(target), 1):
        for match in re.finditer(r'"Description":\s*"([^"]*)"', line):
            bad = offending_chars(match.group(1))
            if bad:
                problems.append((target, number, match.group(1), bad))
    return problems


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    tf_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "terraform")

    problems = scan_terraform(tf_dir) + scan_boto3(here)

    if not problems:
        print("  All security-group descriptions are AWS-safe.")
        return 0

    print(f"  {len(problems)} security-group description(s) AWS will reject:\n")
    for path, number, value, bad in problems:
        print(f"    {os.path.relpath(path)}:{number}")
        print(f"      {value!r}")
        print(f"      offending characters: {bad}")
    print("\n  Replace them with plain ASCII. AWS allows only:")
    print(r"    ^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$")
    return 1


if __name__ == "__main__":
    sys.exit(main())
