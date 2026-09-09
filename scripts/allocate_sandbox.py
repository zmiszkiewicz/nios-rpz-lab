#!/usr/bin/env python3
"""
Claim a pre-created CSP sandbox for this participant from the Sandbox Broker.

Called from track_scripts/setup-shell before `terraform apply`. The Broker owns a
warm pool of CSP subtenant accounts; allocating from it takes a second, whereas
creating a subtenant inline takes minutes and occasionally fails, which would
strand the student on a blank first challenge. Allocation is idempotent per
participant: calling it twice returns HTTP 200 with the same sandbox instead of
burning a second one from the pool.

This talks to the Broker, not the Infoblox CSP, so it deliberately does not use
the lab's csp_api.py helper and depends on nothing but `requests`.

Usage in Instruqt (setup-shell):
    export BROKER_API_TOKEN="<token>"
    python3 allocate_sandbox.py

Environment variables (Instruqt provides all but the token automatically):
    BROKER_API_URL          Broker endpoint. Defaults to the production Broker.
    BROKER_API_TOKEN        Required. API token for the Broker.
    INSTRUQT_PARTICIPANT_ID Required. Unique per student, supplied by Instruqt.
    INSTRUQT_TRACK_SLUG     Lab identifier, supplied by Instruqt.
    SANDBOX_NAME_PREFIX     Only consider sandboxes whose name starts with this
                            (default "lab"), so one Broker can serve several labs.

Output files, all written next to this script:
    subtenant_id.txt      CSP ID, e.g. 2026838
    external_id.txt       Account UUID, e.g. 588424ea-ac7c-4fb3-...
    sandbox_id.txt        The external_id, NOT the Broker sandbox_id. See below.
    sandbox_name.txt      Human name, e.g. lab-adventure-0086
    sfdc_account_id.txt   Salesforce ID, e.g. 001SAND15956299f9d
    sandbox_env.sh        Source-able exports for the bash-based challenge tabs

The files land beside the script rather than in the working directory because
setup-shell, the challenge tabs and cleanup-shell all run from different cwds;
a bare relative path would write six files that deallocate_sandbox.py and the
challenge checks could not find.
"""

import os
import random
import sys
import time

import requests

BROKER_API_URL = os.environ.get(
    "BROKER_API_URL",
    "https://api-sandbox-broker.highvelocitynetworking.com/v1"
)
BROKER_API_TOKEN = os.environ.get("BROKER_API_TOKEN")
INSTRUQT_SANDBOX_ID = os.environ.get("INSTRUQT_PARTICIPANT_ID")
INSTRUQT_TRACK_ID = os.environ.get("INSTRUQT_TRACK_SLUG", "unknown-lab")
SANDBOX_NAME_PREFIX = os.environ.get("SANDBOX_NAME_PREFIX", "lab")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

MAX_RETRIES = 5
RETRY_STATUSES = {500, 502, 503, 504}


def log(message):
    # flush because Instruqt tails the setup log live; buffered output makes the
    # track look hung while allocation retries.
    print(message, flush=True)


def backoff(attempt):
    """Exponential backoff with jitter, capped at 30s.

    The jitter matters: every participant in a class starts their track at the
    same moment, so identical sleeps would keep them in lockstep and hammer the
    Broker in synchronised waves.
    """
    time.sleep(min(2 ** attempt + random.uniform(0, 1), 30))


def build_headers():
    headers = {
        "Authorization": f"Bearer {BROKER_API_TOKEN}",
        "Content-Type": "application/json",
        "X-Instruqt-Sandbox-ID": INSTRUQT_SANDBOX_ID,
        "X-Instruqt-Track-ID": INSTRUQT_TRACK_ID,
    }
    if SANDBOX_NAME_PREFIX:
        headers["X-Sandbox-Name-Prefix"] = SANDBOX_NAME_PREFIX
    return headers


def allocate():
    """POST /allocate until it succeeds. Returns the response body, or None."""
    headers = build_headers()

    for attempt in range(MAX_RETRIES):
        try:
            log(f"Allocation attempt {attempt + 1}/{MAX_RETRIES}...")
            resp = requests.post(
                f"{BROKER_API_URL}/allocate",
                headers=headers,
                timeout=(5, 30),
            )

            if resp.status_code in (200, 201):
                # 201 = a sandbox was taken from the pool, 200 = this participant
                # already had one and the Broker returned it again.
                log(f"Allocated sandbox (HTTP {resp.status_code})")
                return resp.json()

            if resp.status_code == 409:
                # Pool exhausted is not transient — retrying cannot conjure a
                # sandbox, so fail fast and let the instructor top up the pool.
                log("ERROR: Pool exhausted, no sandboxes available")
                sys.exit(1)

            if resp.status_code == 403:
                log("Rate limited, waiting...")
                time.sleep(10)
            elif resp.status_code in RETRY_STATUSES:
                log(f"Server error {resp.status_code}, retrying...")
                backoff(attempt)
            else:
                log(f"ERROR: HTTP {resp.status_code}: {resp.text}")
                sys.exit(1)

        except requests.exceptions.Timeout:
            log("Timeout, retrying...")
            backoff(attempt)
        except Exception as exc:  # noqa: BLE001 — any hiccup is worth one retry
            log(f"Error: {exc}")
            backoff(attempt)

    return None


def write_files(sandbox_id, external_id, sandbox_name, sfdc_account_id):
    files = {
        "subtenant_id.txt": sandbox_id,
        "external_id.txt": external_id,
        # Not a typo: sandbox_id.txt holds the external_id (the CSP account
        # UUID), because the challenge checks and the older lab scripts that
        # read this file expect the UUID under that name. The Broker's own
        # sandbox_id lives in subtenant_id.txt. Renaming either file would
        # break every downstream consumer, so the mismatch stays.
        "sandbox_id.txt": external_id,
        "sandbox_name.txt": sandbox_name,
        "sfdc_account_id.txt": sfdc_account_id,
    }

    for filename, value in files.items():
        with open(os.path.join(SCRIPT_DIR, filename), "w") as handle:
            handle.write(value)
        log(f"Wrote {filename}: {value}")

    env_path = os.path.join(SCRIPT_DIR, "sandbox_env.sh")
    with open(env_path, "w") as handle:
        handle.write("#!/bin/bash\n")
        handle.write("# Auto-generated by allocate_sandbox.py\n")
        handle.write(f"export STUDENT_TENANT={sandbox_name}\n")
        handle.write(f"export CSP_ACCOUNT_ID={external_id}\n")
        handle.write(f"export BROKER_SANDBOX_ID={sandbox_id}\n")
        handle.write(f"export SFDC_ACCOUNT_ID={sfdc_account_id}\n")
    log("Wrote sandbox_env.sh")


def main():
    # Startup jitter: a whole class hits setup-shell simultaneously, so spread
    # the first request out before anything else happens.
    time.sleep(random.uniform(1, 5))

    if not BROKER_API_TOKEN:
        log("ERROR: BROKER_API_TOKEN environment variable not set")
        return 1

    if not INSTRUQT_SANDBOX_ID:
        log("ERROR: INSTRUQT_PARTICIPANT_ID not found (are you running in Instruqt?)")
        return 1

    log(f"Student: {INSTRUQT_SANDBOX_ID}")
    log(f"Lab: {INSTRUQT_TRACK_ID}")
    if SANDBOX_NAME_PREFIX:
        log(f"Filter: '{SANDBOX_NAME_PREFIX}*'")

    allocation = allocate()
    if allocation is None:
        log("ERROR: Allocation failed after all retries")
        return 1

    sandbox_id = allocation.get("sandbox_id", "")
    external_id = allocation.get("external_id", "")
    sandbox_name = allocation.get("name", "")
    expires_at = allocation.get("expires_at", 0)
    sfdc_account_id = allocation.get("sfdc_account_id", "")

    if not sandbox_id or not external_id:
        log(f"ERROR: Invalid response: {allocation}")
        return 1

    # Some Broker versions return the external_id as a resource path
    # ("identity/accounts/<uuid>"); downstream callers want the bare UUID.
    if "/" in external_id:
        external_id = external_id.split("/")[-1]

    write_files(sandbox_id, external_id, sandbox_name, sfdc_account_id)

    log("")
    log(f"Instruqt: set-var STUDENT_TENANT {sandbox_name}")
    log(f"          set-var CSP_ACCOUNT_ID {external_id}")
    log(f"          set-var BROKER_SANDBOX_ID {sandbox_id}")
    log(f"          set-var SFDC_ACCOUNT_ID {sfdc_account_id}")

    log("")
    log("=" * 60)
    log(f"Allocated sandbox {sandbox_name}")
    log(f"   CSP ID:     {sandbox_id}")
    log(f"   Account ID: {external_id}")
    log(f"   SFDC ID:    {sfdc_account_id}")
    log(f"   Expires:    {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(expires_at))}")
    log("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
