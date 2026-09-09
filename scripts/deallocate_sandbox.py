#!/usr/bin/env python3
"""
Hand this participant's CSP sandbox back to the Sandbox Broker.

Called from track_scripts/cleanup-shell. This only marks the sandbox for
deletion; the Broker's background worker then runs the NIOSXaaS cleanup, deletes
the CSP subtenant account and drops the DynamoDB record, usually within about
five minutes. That means the call returns immediately and the track can tear
down without waiting on CSP.

This talks to the Broker, not the Infoblox CSP, so it deliberately does not use
the lab's csp_api.py helper and depends on nothing but `requests`.

Usage in Instruqt (cleanup-shell, after the lab's own cleanup scripts):
    export BROKER_API_TOKEN="$BROKER_API_TOKEN"
    export INSTRUQT_PARTICIPANT_ID="$INSTRUQT_PARTICIPANT_ID"
    python3 deallocate_sandbox.py

Environment variables:
    BROKER_API_URL          Broker endpoint. Defaults to the production Broker.
    BROKER_API_TOKEN        Required. API token for the Broker.
    INSTRUQT_PARTICIPANT_ID Required. The same value used during allocation.

Input file, read from next to this script (not from the working directory,
because cleanup-shell runs from a different cwd than setup-shell did):
    subtenant_id.txt        Broker sandbox ID, written by allocate_sandbox.py

Exit codes: this script exits 0 for anything short of missing credentials --
a missing or empty subtenant_id.txt, a 404, a 5xx, a network failure. It runs
inside cleanup-shell, where a non-zero exit aborts the remaining teardown
steps, and the steps after this one destroy the Terraform-managed EC2
instances. Failing loudly here would leak billable resources, so unexpected
Broker responses are reported as warnings and the teardown continues. Anything
genuinely left behind is reaped by the Broker's own expiry sweep.
"""

import os
import sys

import requests

BROKER_API_URL = os.environ.get(
    "BROKER_API_URL",
    "https://api-sandbox-broker.highvelocitynetworking.com/v1"
)
BROKER_API_TOKEN = os.environ.get("BROKER_API_TOKEN")
INSTRUQT_SANDBOX_ID = os.environ.get("INSTRUQT_PARTICIPANT_ID")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SUBTENANT_ID_FILE = os.path.join(SCRIPT_DIR, "subtenant_id.txt")


def log(message):
    # flush because Instruqt tails the cleanup log live.
    print(message, flush=True)


def read_subtenant_id():
    """Return the allocated Broker sandbox ID, or None if there is nothing to do."""
    try:
        with open(SUBTENANT_ID_FILE) as handle:
            subtenant_id = handle.read().strip()
    except FileNotFoundError:
        log("subtenant_id.txt not found, nothing to deallocate")
        return None

    if not subtenant_id:
        log("subtenant_id.txt is empty, nothing to deallocate")
        return None

    return subtenant_id


def mark_for_deletion(subtenant_id):
    """POST the mark-for-deletion request.

    Returns True if the Broker accepted the request (or the sandbox was already
    gone), False if it did not. Either way the caller exits 0 -- see the module
    docstring -- so the return value only controls what gets logged.
    """
    headers = {
        "Authorization": f"Bearer {BROKER_API_TOKEN}",
        "X-Instruqt-Sandbox-ID": INSTRUQT_SANDBOX_ID,
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            f"{BROKER_API_URL}/sandboxes/{subtenant_id}/mark-for-deletion",
            headers=headers,
            timeout=(5, 15),
        )
    except requests.exceptions.RequestException as exc:
        log(f"WARNING: Network error talking to the Broker: {exc}")
        return False

    # Any 2xx, not just 200. A mark-for-deletion that answers 202 Accepted is
    # entirely plausible for an operation a background worker completes, and
    # checking for one specific code cost this lab a live start elsewhere:
    # csp_api.switch_account() accepted only 200 against an endpoint that
    # returns 201 and reported 23 successes as a timeout.
    if 200 <= resp.status_code < 300:
        try:
            status = resp.json().get("status", "unknown")
        except ValueError:
            status = "unknown"
        log(f"Marked sandbox for deletion (HTTP {resp.status_code})")
        log(f"   Status: {status}")
        log("   Cleanup will run within ~5 minutes")
        return True

    if resp.status_code == 404:
        log(f"Sandbox {subtenant_id} not found (already cleaned up?)")
        return True

    if resp.status_code == 403:
        try:
            error = resp.json()
            msg = error.get("detail", {}).get("message", "Unknown")
            code = error.get("detail", {}).get("code", "")
            log(f"WARNING: Authorization error: {msg} ({code})")
        except Exception:  # noqa: BLE001 — a 403 body is not always JSON
            log(f"WARNING: Authorization error (HTTP 403): {resp.text}")
        return False

    log(f"WARNING: Failed to mark sandbox for deletion: HTTP {resp.status_code}")
    log(f"   Response: {resp.text}")
    return False


def main():
    if not BROKER_API_TOKEN:
        log("ERROR: BROKER_API_TOKEN not set, cannot deallocate the sandbox")
        return 1

    if not INSTRUQT_SANDBOX_ID:
        log("ERROR: INSTRUQT_PARTICIPANT_ID not set, cannot deallocate the sandbox")
        return 1

    subtenant_id = read_subtenant_id()
    if subtenant_id is None:
        return 0

    log("Marking sandbox for deletion...")
    log(f"   Broker Sandbox ID: {subtenant_id}")
    log(f"   Student: {INSTRUQT_SANDBOX_ID}")

    accepted = mark_for_deletion(subtenant_id)

    log("")
    log("=" * 60)
    if accepted:
        log("Sandbox deallocation requested")
    else:
        # Still exit 0: the rest of cleanup-shell has a `terraform destroy` to
        # get to, and the Broker's expiry sweep reclaims anything stranded here.
        log("Sandbox deallocation could not be requested, continuing teardown")
    log("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
