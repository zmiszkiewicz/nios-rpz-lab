#!/usr/bin/env python3
"""
Challenge checks for the Shadow AI lab.

    python3 verify_lab.py --stage baseline     challenge 1
    python3 verify_lab.py --stage discovery    challenge 2
    python3 verify_lab.py --stage classify     challenge 3
    python3 verify_lab.py --stage enforce      challenge 4
    python3 verify_lab.py --stage all          everything, for smoke tests

Exit 0 passes. Exit non-zero writes one actionable sentence to
/tmp/lab_check_reason.txt, which check-shell hands to Instruqt's fail-message.

## Two rules these checks follow

**Prove it from the client, not the API.** A policy that exists in the CSP but
does not change what the desktop resolves has not been applied. The enforcement
check therefore asserts on DNS answers from the Windows desktop, and only then
looks at the policy for a better error message. This also makes the most
important check independent of the Application Discovery API, whose paths are
unconfirmed - see app_discovery.py.

**Never let a broken resolver look like a working block.** Every stage that
expects something to be blocked first confirms something else still resolves.
Without that, a dead DFP passes the enforcement check perfectly: everything
fails to resolve, including the things that should. explain_failure() is called
before any block is interpreted as success.

## Strictness

When the Application Discovery API cannot be located, the classify stage warns
loudly and passes rather than bricking the lab for a participant who did the
work correctly in the portal. Set LAB_STRICT_CHECKS=1 to make that fatal
instead, which is what you want while fixing the endpoint lists.

Environment: DESKTOP_IP, TF_VAR_windows_admin_password, DFP_PRIVATE_IP,
TF_VAR_ddi_api_key (or INFOBLOX_EMAIL + INFOBLOX_PASSWORD).
"""

import argparse
import os
import sys
import time

import app_discovery as AD
import domains as D
import security_policy as SP
from csp_api import (CspAuthError, CspError, CspSession, EndpointNotFound,
                     clear_reason, fail, get_logger, read_state)
from desktop_dns import DesktopUnreachable, explain_failure, probe_desktop

log = get_logger("verify_lab")

STRICT = os.getenv("LAB_STRICT_CHECKS", "").strip() in ("1", "true", "yes")

# How many of the five AI applications must show up before challenge 2 passes.
# Not all five: Application Discovery is a classifier, and one tool being slow
# to categorise should not block a participant who has clearly generated
# traffic and can see the report working.
MIN_DISCOVERED = int(os.getenv("MIN_DISCOVERED_APPS", "3"))

# Policy changes take a little while to reach the DFP.
ENFORCE_TIMEOUT = int(os.getenv("ENFORCE_TIMEOUT", "180"))
ENFORCE_INTERVAL = 20


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

def connect_csp():
    """A CSP session, or None if no credential is available."""
    try:
        csp = CspSession()
        if not csp.api_key:
            csp.connect(read_state("sandbox_id.txt"))
        return csp
    except (CspAuthError, CspError) as exc:
        log.warning("Cannot reach the CSP: %s", exc)
        return None


def probe(domains):
    """probe_desktop with the failure translated into a check failure."""
    try:
        return probe_desktop(domains)
    except DesktopUnreachable as exc:
        fail(f"Could not reach the Windows desktop over WinRM: {exc} "
             f"The desktop may still be booting - wait a minute and check again.")


def require_resolution_works(result):
    """
    Abort the check if nothing resolves at all.

    Called before interpreting any absence of an answer as a block.
    """
    reason = explain_failure(result)
    if reason:
        fail(reason)


# --------------------------------------------------------------------------- #
# Stage 1 - baseline
# --------------------------------------------------------------------------- #

def check_baseline():
    """
    The environment works: the DFP resolves for the desktop.

    Not a test of anything the participant did. It is a readiness gate, because
    every later challenge produces a misleading result if this is broken, and
    it is far kinder to say so here.
    """
    result = probe([D.CONTROL_DOMAIN] + D.primary_domains()[:2])
    server = result["server"]

    if not result["port53_listening"]:
        fail(f"Nothing is listening on {server}:53, so the DNS Forwarding Proxy "
             f"is not serving yet. Check it with: python3 setup_dfp.py --status")

    configured = result["configured_dns"]
    if configured and server not in configured:
        fail(f"The desktop is using {', '.join(configured)} for DNS, not the DFP "
             f"at {server}. Its queries bypass Threat Defense entirely, so "
             f"nothing will appear in Application Discovery.")

    require_resolution_works(result)

    control = result["results"].get(D.CONTROL_DOMAIN, {})
    if not control.get("resolved"):
        fail(f"{D.CONTROL_DOMAIN} does not resolve through the DFP at {server}. "
             f"Ordinary browsing is broken, so the lab cannot demonstrate a "
             f"policy. Status was {control.get('status')}.")

    log.info("DFP at %s is resolving for the desktop", server)
    log.info("Desktop resolver: %s", ", ".join(configured) or "unknown")
    return True


# --------------------------------------------------------------------------- #
# Stage 2 - discovery
# --------------------------------------------------------------------------- #

def check_discovery():
    """
    Application Discovery has seen the AI tools.

    The participant's action here is to browse the tools and read a report,
    which is not directly verifiable. What is verifiable is that the data
    exists, so that is what this asserts.
    """
    csp = connect_csp()
    if not csp:
        fail("Could not authenticate to the Infoblox CSP, so Application "
             "Discovery cannot be checked. Confirm the lab finished setting up.")

    try:
        states = AD.ai_application_status(csp)
    except EndpointNotFound as exc:
        # The report is a UI surface; if the API is unreachable, fall back to
        # proving the precondition instead of failing a correct participant.
        log.warning("%s", exc)
        if STRICT:
            fail("The Application Discovery API could not be located. Run "
                 "python3 discover_td_api.py and update app_discovery.py.")
        return _discovery_fallback()

    seen = [name for name, app in states.items() if app]
    if len(seen) < MIN_DISCOVERED:
        missing = [n for n in D.app_names() if n not in seen]
        fail(f"Application Discovery has only seen {len(seen)} of the "
             f"{len(D.app_names())} AI applications ({', '.join(seen) or 'none'}). "
             f"Still missing: {', '.join(missing)}. Browse them from the desktop, "
             f"or run: python3 generate_ai_traffic.py --rounds 3")

    log.info("Application Discovery has seen %d application(s): %s",
             len(seen), ", ".join(seen))
    return True


def _discovery_fallback():
    """
    Prove the traffic that feeds the report actually happened.

    Weaker than reading the report, and it says so in the log rather than
    quietly pretending the check was equivalent.
    """
    log.warning("Falling back to verifying that AI traffic resolves from the "
                "desktop. This does not prove the report is populated.")
    result = probe(D.primary_domains() + [D.CONTROL_DOMAIN])
    require_resolution_works(result)

    resolved = [d for d, r in result["results"].items()
                if r["resolved"] and D.entry_for_domain(d)]
    if len(resolved) < MIN_DISCOVERED:
        fail(f"Only {len(resolved)} AI domain(s) resolve from the desktop, so "
             f"Application Discovery has little to work with. Run: "
             f"python3 generate_ai_traffic.py --rounds 3")

    log.info("%d AI domain(s) resolve from the desktop", len(resolved))
    return True


# --------------------------------------------------------------------------- #
# Stage 3 - classify
# --------------------------------------------------------------------------- #

def check_classify(approved_app=D.DEFAULT_APPROVED_APP):
    """
    The AI applications have been split into Approved and Unapproved.

    Requires exactly one approved application and at least two unapproved.
    Insisting on all four unapproved would fail someone who reasonably decided
    two tools were acceptable, and the lesson survives either way.
    """
    csp = connect_csp()
    if not csp:
        fail("Could not authenticate to the Infoblox CSP, so the classification "
             "cannot be checked.")

    try:
        states = AD.ai_application_status(csp)
    except EndpointNotFound as exc:
        log.warning("%s", exc)
        if STRICT:
            fail("The Application Discovery API could not be located. Run "
                 "python3 discover_td_api.py and update app_discovery.py.")
        log.warning("Cannot verify classification. Passing on the assumption "
                    "the portal work was done - fix the endpoint list to make "
                    "this a real check.")
        return True

    approved = [n for n, a in states.items() if a and a["status"] == AD.APPROVED]
    unapproved = [n for n, a in states.items() if a and a["status"] == AD.UNAPPROVED]
    unreviewed = [n for n, a in states.items()
                  if a and a["status"] in (AD.NEEDS_REVIEW, "unknown")]
    unseen = [n for n, a in states.items() if not a]

    if unseen:
        fail(f"{', '.join(unseen)} has not been discovered yet, so it cannot be "
             f"classified. Generate more traffic and wait a moment: "
             f"python3 generate_ai_traffic.py --rounds 3")

    if not approved:
        fail(f"No AI application is marked Approved. The policy needs one "
             f"sanctioned tool, or the Allow rule has nothing to match. Mark "
             f"one (the lab suggests {approved_app}) as Approved under Security "
             f"> Threat Defense > Application Discovery.")

    if len(approved) > 1:
        fail(f"{len(approved)} applications are marked Approved "
             f"({', '.join(approved)}). The scenario sanctions exactly one, so "
             f"mark the others Unapproved.")

    if len(unapproved) < 2:
        fail(f"Only {len(unapproved)} application(s) are marked Unapproved "
             f"({', '.join(unapproved) or 'none'}). Mark the remaining tools "
             f"Unapproved: {', '.join(unreviewed)}.")

    log.info("Approved: %s", ", ".join(approved))
    log.info("Unapproved: %s", ", ".join(unapproved))
    return True


# --------------------------------------------------------------------------- #
# Stage 4 - enforce
# --------------------------------------------------------------------------- #

def check_enforce():
    """
    The policy is enforcing: unapproved tools fail, the approved one works.

    This is the check that matters, and it is deliberately grounded in DNS
    answers from the desktop rather than in the policy object. A policy with
    perfect rules that has not reached the DFP has not done anything.
    """
    csp = connect_csp()
    approved_name = None
    unapproved_names = []

    # Use the participant's actual classification where we can read it, so the
    # check follows their decision rather than assuming they picked the
    # suggested tool.
    if csp:
        try:
            states = AD.ai_application_status(csp)
            approved_name = next((n for n, a in states.items()
                                  if a and a["status"] == AD.APPROVED), None)
            unapproved_names = [n for n, a in states.items()
                                if a and a["status"] == AD.UNAPPROVED]
        except EndpointNotFound:
            pass

    if not approved_name:
        approved_name, unapproved_names = D.expected_split()
        log.info("Could not read the classification, assuming the suggested "
                 "split (approved: %s)", approved_name)

    approved_domains = D.domains_for_app(approved_name, include_extra=False)
    unapproved_domains = [d for n in unapproved_names
                          for d in D.domains_for_app(n, include_extra=False)]

    if not unapproved_domains:
        fail("No application is marked Unapproved, so there is nothing for the "
             "Block rule to act on. Classify the unsanctioned tools first.")

    targets = approved_domains + unapproved_domains + [D.CONTROL_DOMAIN]

    deadline = time.time() + ENFORCE_TIMEOUT
    attempt = 0
    still_resolving = []

    while True:
        attempt += 1
        result = probe(targets)

        # Before reading any failure as a block, prove the resolver is alive.
        # The control domain and the approved tool are the evidence.
        require_resolution_works(result)

        control = result["results"].get(D.CONTROL_DOMAIN, {})
        if not control.get("resolved"):
            fail(f"{D.CONTROL_DOMAIN} stopped resolving. The policy is blocking "
                 f"ordinary browsing, not just AI tools - check that the Block "
                 f"rule targets the unapproved application filter and nothing "
                 f"broader.")

        still_resolving = [d for d in unapproved_domains
                           if result["results"].get(d, {}).get("resolved")]

        if not still_resolving:
            break

        if time.time() >= deadline:
            break

        log.info("%d unapproved domain(s) still resolving, waiting for the "
                 "policy to reach the DFP (attempt %d)...",
                 len(still_resolving), attempt)
        time.sleep(ENFORCE_INTERVAL)

    # --- the approved tool must still work ---------------------------------
    approved_ok = any(result["results"].get(d, {}).get("resolved")
                      for d in approved_domains) if approved_domains else True

    if still_resolving:
        detail = ", ".join(still_resolving[:3])
        problems = _policy_problems(csp)
        hint = f" {problems[0]}" if problems else (
            " Confirm the Block rule for the unapproved filter is above the "
            "Allow rule and that the policy was saved.")
        fail(f"{detail} still resolves from the desktop after "
             f"{ENFORCE_TIMEOUT}s, so unapproved AI tools are not blocked.{hint}")

    if not approved_ok:
        fail(f"Every AI tool is blocked, including {approved_name}, which you "
             f"marked Approved. The Allow rule is missing or sits below the "
             f"Block rule - Threat Defense stops at the first match, so "
             f"Blocked must come before Allowed.")

    log.info("Blocked: %s", ", ".join(unapproved_domains))
    log.info("Allowed: %s", ", ".join(approved_domains) or "(none configured)")
    log.info("Control domain %s still resolves", D.CONTROL_DOMAIN)

    # Policy shape is a secondary assertion: the DNS behaviour above already
    # proves enforcement, but a wrong rule order that happens to work today
    # is worth reporting.
    for problem in _policy_problems(csp):
        log.warning("Policy note: %s", problem)

    return True


def _policy_problems(csp):
    """Policy problems as sentences, for enriching an error. Never raises."""
    if not csp:
        return []
    try:
        ok, problems = SP.verify(csp)
        return [] if ok else problems
    except (CspError, EndpointNotFound, CspAuthError):
        return []


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

STAGES = {
    "baseline": check_baseline,
    "discovery": check_discovery,
    "classify": check_classify,
    "enforce": check_enforce,
}


def main():
    parser = argparse.ArgumentParser(
        description="Verify a stage of the Shadow AI lab.")
    parser.add_argument("--stage", required=True,
                        choices=list(STAGES) + ["all"])
    args = parser.parse_args()

    clear_reason()

    stages = list(STAGES) if args.stage == "all" else [args.stage]
    for name in stages:
        log.info("=== %s ===", name)
        STAGES[name]()
        log.info("%s: PASS", name)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — top-level guard
        fail(f"The check hit an unexpected error: {exc}")
