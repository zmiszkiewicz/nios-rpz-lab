#!/usr/bin/env python3
"""
Prepare the freshly allocated CSP sandbox for the lab.

Three things have to exist before Terraform can run, and all three need a JWT
scoped to the sandbox account, so they are done together in one session rather
than in three scripts that each log in again:

    1. A portal user      the participant signs in to portal.infoblox.com with
                          this. Everything the lab asks them to do is in the
                          portal UI, so without it there is no lab.
    2. An API key         account-scoped token for the Threat Defense planes.
                          The challenge checks and the policy helper use it.
    3. A join token       registers the NIOS-X host with this tenant on first
                          boot. Terraform needs it as an input, so it must be
                          minted before `terraform apply`.

Run after allocate_sandbox.py, before `terraform apply`:

    python3 provision_tenant.py

    python3 provision_tenant.py --delete    remove the user (cleanup only)

Environment: INFOBLOX_EMAIL, INFOBLOX_PASSWORD, INSTRUQT_PARTICIPANT_ID.
Reads: sandbox_id.txt, sandbox_name.txt, sfdc_account_id.txt
Writes: user_email.txt, user_password.txt, user_id.txt, api_key.txt,
        join_token.txt, tenant_env.sh
"""

import argparse
import os
import random
import string
import sys
import time

from csp_api import (CspAuthError, CspError, CspSession, get_logger, read_state,
                     write_state)

log = get_logger("provision_tenant")

USER_DOMAIN = os.getenv("USER_DOMAIN", "infoblox.lab")

# The lab runs well inside this, but a key that expires mid-track produces a
# baffling failure, so it is set far out rather than cleverly.
API_KEY_EXPIRY = os.getenv("API_KEY_EXPIRY", "2027-12-31T23:59:59.000Z")


# --------------------------------------------------------------------------- #
# Portal user
# --------------------------------------------------------------------------- #

def generate_password(length=16):
    """
    A password the CSP will accept.

    CSP policy wants upper, lower, digits and at least two specials. Building
    it from guaranteed pieces and shuffling beats generating randomly and
    hoping, which fails a small fraction of the time and only in production.
    """
    chars = (random.choices(string.ascii_uppercase, k=3)
             + random.choices(string.ascii_lowercase, k=5)
             + random.choices(string.digits, k=4)
             + random.choices("!@#$%&", k=4))
    random.shuffle(chars)
    return "".join(chars)[:length]


def group_ids(csp):
    """(user group id, account admin group id) for this account."""
    groups = csp.results("/v2/groups")
    user_gid = next((g["id"] for g in groups if g.get("name") == "user"), None)
    admin_gid = next((g["id"] for g in groups if g.get("name") == "act_admin"), None)
    if not user_gid or not admin_gid:
        names = ", ".join(sorted(g.get("name", "?") for g in groups)) or "none"
        raise CspError("GET", "/v2/groups", 200,
                       f"expected groups 'user' and 'act_admin', found: {names}")
    return user_gid, admin_gid


def find_user(csp, email):
    """Existing user id for an email, or None."""
    results = csp.results("/v2/users", _filter=f'email=="{email}"')
    if not results:
        return None
    return _bare_id(results[0].get("id", ""))


def create_user(csp, name, email, password):
    """
    Create the participant's portal user and set its password.

    Idempotent: an existing user is adopted and its password reset, so a
    re-run of setup does not fail on the second attempt.
    """
    user_gid, admin_gid = group_ids(csp)

    user_id = find_user(csp, email)
    if user_id:
        log.info("Portal user %s already exists, reusing it", email)
    else:
        body = csp.post("/v2/users", {
            "name": name,
            "email": email,
            "type": "interactive",
            "group_ids": [user_gid, admin_gid],
        })
        user_id = _bare_id((body.get("result") or {}).get("id", ""))
        if not user_id:
            raise CspError("POST", "/v2/users", 201, "response contained no user id")
        log.info("Created portal user %s", email)

    csp.post(f"/v2/users/{user_id}/password", {"new_password": password})
    log.info("Password set on %s", email)
    return user_id


def delete_user(csp):
    """Remove the participant's user. Best effort: never raises."""
    user_id = read_state("user_id.txt")
    if not user_id:
        log.info("No user_id.txt, nothing to delete")
        return True
    try:
        csp.delete(f"/v2/users/{user_id}")
        log.info("Deleted portal user %s", user_id)
        return True
    except CspError as exc:
        log.warning("Could not delete user %s: %s", user_id, exc)
        return False


# --------------------------------------------------------------------------- #
# Join token
# --------------------------------------------------------------------------- #

# Host activation has lived at more than one path across CSP releases, so the
# tenant is asked rather than assumed. POST-only endpoints cannot be probed
# with a GET, so these are tried in order on the real call.
JOIN_TOKEN_PATHS = [
    "/atlas-host-activation/v1/jointoken",
    "/api/host-activation/v1/jointoken",
    "/atlas-host-activation/v1/join_token",
]


def create_join_token(csp, name=None):
    """
    Mint a join token that registers the NIOS-X host with this tenant.

    The token goes into the host's cloud-config as `host_setup: jointoken:`.
    On first boot the host calls home, registers itself, and appears in
    Infrastructure > Hosts. Nothing else is needed to enrol it.
    """
    name = name or f"instruqt-{read_state('sandbox_name.txt', 'lab')}"
    last = None

    for path in JOIN_TOKEN_PATHS:
        try:
            body = csp.request("POST", path, payload={"name": name}, prefer_jwt=True)
        except CspError as exc:
            # A 404 means wrong path, so move on. Anything else is a real
            # failure on the right path and should surface immediately.
            if exc.status == 404:
                last = exc
                continue
            raise

        token = (body.get("join_token")
                 or (body.get("result") or {}).get("join_token")
                 or body.get("token"))
        if token:
            log.info("Created join token %r via %s", name, path)
            return token
        last = CspError("POST", path, 200, f"no join_token in response: {body}")

    raise CspError("POST", JOIN_TOKEN_PATHS[0], 404,
                   f"host activation endpoint not found. Tried "
                   f"{', '.join(JOIN_TOKEN_PATHS)}. Last error: {last}")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Provision the portal user, API key and join token on the sandbox.")
    parser.add_argument("--delete", action="store_true",
                        help="Delete the portal user and exit (cleanup path)")
    parser.add_argument("--skip-user", action="store_true",
                        help="Do not create a portal user")
    args = parser.parse_args()

    sandbox_id = read_state("sandbox_id.txt")
    if not sandbox_id:
        log.error("sandbox_id.txt is missing. Run allocate_sandbox.py first.")
        return 1

    csp = CspSession()
    try:
        csp.connect(sandbox_id)
    except CspAuthError as exc:
        log.error("%s", exc)
        return 1

    if args.delete:
        delete_user(csp)
        return 0

    sandbox_name = read_state("sandbox_name.txt", "unknown")
    participant = os.getenv("INSTRUQT_PARTICIPANT_ID")
    if not participant:
        log.error("INSTRUQT_PARTICIPANT_ID is not set.")
        return 1

    log.info("Sandbox %s (%s)", sandbox_name, sandbox_id)

    # --- 1. portal user -----------------------------------------------------
    user_email = user_password = ""
    if args.skip_user:
        log.info("--- 1/3 portal user (skipped) ---")
    else:
        log.info("--- 1/3 portal user ---")
        user_email = f"{participant}@{USER_DOMAIN}"
        user_password = generate_password()
        user_id = create_user(csp, participant, user_email, user_password)
        write_state("user_email.txt", user_email)
        write_state("user_password.txt", user_password)
        write_state("user_id.txt", user_id)

    # --- 2. API key ---------------------------------------------------------
    log.info("--- 2/3 API key ---")
    api_key = csp.create_api_key(name="Instruqt", expires_at=API_KEY_EXPIRY)
    write_state("api_key.txt", api_key)

    # --- 3. join token ------------------------------------------------------
    log.info("--- 3/3 join token ---")
    join_token = create_join_token(csp)
    write_state("join_token.txt", join_token)

    # --- exports ------------------------------------------------------------
    # setup-shell sources this rather than parsing the log, and Terraform reads
    # TF_VAR_infoblox_join_token from it.
    env_path = write_state("tenant_env.sh", "\n".join([
        "#!/bin/bash",
        "# Auto-generated by provision_tenant.py",
        f"export STUDENT_TENANT='{sandbox_name}'",
        f"export CSP_ACCOUNT_ID='{sandbox_id}'",
        f"export CSP_USER_EMAIL='{user_email}'",
        f"export CSP_USER_PASSWORD='{user_password}'",
        f"export TF_VAR_ddi_api_key='{api_key}'",
        f"export BLOXONE_API_KEY='{api_key}'",
        f"export TF_VAR_infoblox_join_token='{join_token}'",
        f"export INFOBLOX_JOIN_TOKEN='{join_token}'",
    ]))

    print()
    print("=" * 66)
    print("  Tenant ready")
    print("=" * 66)
    print(f"  Sandbox        {sandbox_name}")
    print(f"  Account        {sandbox_id}")
    if user_email:
        print(f"  Portal user    {user_email}")
        print(f"  Portal pass    {user_password}")
    print(f"  API key        {api_key[:8]}... ({len(api_key)} chars)")
    print(f"  Join token     {join_token[:8]}... ({len(join_token)} chars)")
    print(f"  Exports        {env_path}")
    print("=" * 66)
    print()
    return 0


def _bare_id(value):
    """Trailing segment of a CSP resource URI, e.g. identity/users/X -> X."""
    return value.split("/")[-1] if "/" in value else value


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CspError, CspAuthError) as exc:
        log.error("%s", exc)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — top-level guard, message beats type
        log.error("%s", exc)
        sys.exit(1)
