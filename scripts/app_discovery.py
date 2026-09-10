#!/usr/bin/env python3
"""
Read and set application approval state in Infoblox Threat Defense.

    python3 app_discovery.py list                    what the tenant has discovered
    python3 app_discovery.py status                  the AI apps and their approval
    python3 app_discovery.py approve ChatGPT         mark one Approved
    python3 app_discovery.py unapprove Claude        mark one Unapproved
    python3 app_discovery.py apply-policy            approve the default, unapprove the rest
    python3 app_discovery.py filters                 the built-in application filters

The lab asks the participant to do the classification in the portal, which is
the point: Application Discovery is a visibility-and-judgement exercise, not an
API exercise. This module exists so the challenge checks can *verify* what they
did, and so a stuck participant can be unblocked without a support ticket.

## A warning about the endpoints in this file

Application Discovery is not covered by any published Infoblox API document.
The Threat Defense API guide lists Atcfw, Atcep, Atcdfp, Tdlad, TIDEDossier and
TIDEData, and none of them documents application approval.
/api/atcfw/v1/openapi.json returns 401 without credentials, and no other lab in
this organisation touches this plane, so there was nothing to copy.

Every path below is therefore a *candidate list*, resolved against the live
tenant at runtime by CspSession.discover(). If none match, the error says which
paths were tried and what each returned, and points at discover_td_api.py to
search more widely. That is deliberate: a wrong hardcoded URL fails silently
and confusingly six months from now, whereas this fails once, loudly, with the
next step written on it.

When you learn the real paths, put them first in these lists.

Environment: TF_VAR_ddi_api_key (or INFOBLOX_EMAIL + INFOBLOX_PASSWORD).
"""

import argparse
import sys

import domains as D
from csp_api import (CspAuthError, CspError, CspSession, EndpointNotFound,
                     get_logger, read_state)

log = get_logger("app_discovery")

# Collections of discovered applications, newest-looking guesses first.
APP_LIST_CANDIDATES = [
    "/api/atcfw/v1/app_discovery/applications",
    "/api/atcfw/v1/applications",
    "/api/atcfw/v1/discovered_applications",
    "/api/atcfw/v1/app_approvals",
    "/api/atcfw/v1/application_approvals",
    "/api/appdiscovery/v1/applications",
    "/api/atcfw/v1/application_discovery/applications",
]

# Application filters, including the built-in approved/unapproved pair.
FILTER_CANDIDATES = [
    "/api/atcfw/v1/application_filters",
    "/api/atcfw/v1/app_filters",
    "/api/atcfw/v1/filters/applications",
]

# The names Infoblox ships the dynamic filters under. Matched loosely because
# the exact wording differs between the docs and the UI.
APPROVED_FILTER_HINTS = ["all approved", "approved application"]
UNAPPROVED_FILTER_HINTS = ["all unapproved", "unapproved application"]

APPROVED = "approved"
UNAPPROVED = "unapproved"
NEEDS_REVIEW = "needs review"


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #

def list_applications(csp):
    """
    Every application the tenant knows about, normalised.

    Returns a list of dicts with at least: name, status, raw. `status` is
    lowercased to one of approved / unapproved / needs review / unknown, since
    the field name and casing vary.
    """
    path = csp.discover("application list", APP_LIST_CANDIDATES)
    records = csp.results(path)
    return [_normalise_app(record) for record in records]


def _normalise_app(record):
    """One discovered-application record in a shape the rest of the file uses."""
    name = (record.get("name") or record.get("app_name")
            or record.get("application_name") or record.get("display_name") or "")

    status = ""
    for key in ("status", "approval_status", "approval", "state", "review_status"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            status = value
            break
    # Some shapes carry a boolean instead of a string.
    if not status:
        for key in ("approved", "is_approved"):
            if key in record:
                status = APPROVED if record[key] else UNAPPROVED
                break

    return {
        "name": name,
        "status": _normalise_status(status),
        "category": (record.get("category") or record.get("app_category") or ""),
        "id": record.get("id") or record.get("app_id") or "",
        "raw": record,
    }


def _normalise_status(value):
    text = str(value or "").strip().lower().replace("_", " ")
    if not text:
        return "unknown"
    if "unapprov" in text or "not approv" in text or text == "deny":
        return UNAPPROVED
    if "approv" in text or text in ("allow", "allowed", "sanctioned"):
        return APPROVED
    if "review" in text or "pending" in text or text == "new":
        return NEEDS_REVIEW
    return text


def ai_application_status(csp):
    """
    Approval state of each AI application the lab cares about.

    Keyed by the canonical name from domains.py, so a tenant that calls it
    "Bard" and a lab that calls it "Google Gemini" still line up.
    """
    discovered = list_applications(csp)
    found = {}

    for app in discovered:
        entry = D.entry_for_app(app["name"])
        if not entry:
            continue
        # Keep the most decided status if an app appears more than once.
        current = found.get(entry["app"])
        if current is None or current["status"] in ("unknown", NEEDS_REVIEW):
            found[entry["app"]] = app

    return {name: found.get(name) for name in D.app_names()}


def list_filters(csp):
    """Application filters defined in the tenant."""
    path = csp.discover("application filters", FILTER_CANDIDATES)
    return csp.results(path)


def builtin_filters(csp):
    """
    (approved filter, unapproved filter) as the tenant names them.

    These are the dynamic filters the policy rules reference. Their whole value
    is that they track the classification automatically, so a policy written
    against them never needs editing when a new tool shows up.
    """
    approved = unapproved = None
    for record in list_filters(csp):
        name = str(record.get("name", "")).lower()
        if any(hint in name for hint in APPROVED_FILTER_HINTS):
            approved = record
        elif any(hint in name for hint in UNAPPROVED_FILTER_HINTS):
            unapproved = record
    return approved, unapproved


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #

def set_status(csp, app_name, status):
    """
    Mark one application Approved or Unapproved.

    Tries the shapes this API plausibly takes, in order: a PATCH on the
    application resource, a PUT on the same, then a bulk POST. Stops at the
    first that the tenant accepts.
    """
    entry = D.entry_for_app(app_name)
    canonical = entry["app"] if entry else app_name

    target = next((app for app in list_applications(csp)
                   if D.entry_for_app(app["name"])
                   and D.entry_for_app(app["name"])["app"] == canonical), None)
    if not target:
        raise CspError("GET", "application list", 404,
                       f"{canonical} has not been discovered yet. Generate "
                       f"traffic first: python3 generate_ai_traffic.py")

    if target["status"] == status:
        log.info("%s is already %s", canonical, status)
        return False

    path = csp.discover("application list", APP_LIST_CANDIDATES)
    app_id = _bare(target["id"])
    wire = status.capitalize()
    attempts = []

    shapes = [
        ("PATCH", f"{path}/{app_id}", {"status": wire}),
        ("PATCH", f"{path}/{app_id}", {"approval_status": wire}),
        ("PUT", f"{path}/{app_id}", {"status": wire}),
        ("POST", path, {"applications": [{"id": target["id"], "status": wire}]}),
        ("POST", f"{path}/status", {"ids": [target["id"]], "status": wire}),
    ]

    for method, url, payload in shapes:
        if not app_id and "{}" not in url and url.endswith("/"):
            continue
        try:
            csp.request(method, url, payload=payload)
        except CspError as exc:
            if exc.status in (400, 404, 405, 422):
                attempts.append(f"{method} {url}: HTTP {exc.status}")
                continue
            raise
        log.info("Marked %s as %s (%s %s)", canonical, status, method, url)
        return True

    detail = "\n  ".join(attempts)
    raise CspError("PATCH", path, 400,
                   f"could not set {canonical} to {status}. Tried:\n  {detail}\n"
                   f"Classify it in the portal instead: Security > Threat "
                   f"Defense > Application Discovery.")


def apply_lab_policy(csp, approved_apps=D.DEFAULT_APPROVED_APPS):
    """Approve the sanctioned tools, unapprove the rest. Returns a change count."""
    approved, unapproved = D.expected_split(approved_apps)
    changed = 0

    for name in approved:
        try:
            if set_status(csp, name, APPROVED):
                changed += 1
        except CspError as exc:
            log.warning("%s", exc)

    for name in unapproved:
        try:
            if set_status(csp, name, UNAPPROVED):
                changed += 1
        except CspError as exc:
            log.warning("%s", exc)

    return changed


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def show_status(csp, approved_apps=D.DEFAULT_APPROVED_APPS):
    """
    Print what the API can say about the AI applications.

    Careful about what this does and does not mean. The portal has two
    different surfaces for applications:

      * Application Discovery, under Monitor > Reports > Security. An
        analytics report of what has been observed on the network. This is
        where an application sits while it is Needs Review, and it is the
        authoritative answer to "is this being used here".
      * The application catalogue, which is what this API returns. An
        application appears here with a status once it has one.

    An application can therefore be plainly visible in the report and absent
    from this output. That is normal and is not a problem to fix. An earlier
    version of this printed "NOT SEEN" against such applications and told the
    participant to generate more traffic, which sent people chasing a
    non-problem while the report in front of them already showed the data.

    So this reports approval state, which the API does know, and defers to the
    portal for discovery, which it does not.
    """
    want_approved, _ = D.expected_split(approved_apps)
    states = ai_application_status(csp)

    print()
    print("=" * 74)
    print(f"  AI application approval - {read_state('sandbox_name.txt', 'tenant')}")
    print("=" * 74)
    print(f"  {'APPLICATION':<22} {'STATUS':<20} TARGET")
    print("  " + "-" * 70)

    for name in D.app_names():
        app = states.get(name)
        want = APPROVED if name in want_approved else UNAPPROVED
        if not app:
            status = "not classified yet"
        else:
            status = app["status"]
        flag = "" if (app and app["status"] == want) else "  <-- to do"
        print(f"  {name:<22} {status:<20} {want}{flag}")

    print("=" * 74)

    unclassified = [n for n, a in states.items() if not a]
    if unclassified:
        print(f"  {len(unclassified)} application(s) have no approval status yet.")
        print()
        print("  This does NOT mean they have not been discovered. Applications")
        print("  awaiting review live in the Application Discovery report and")
        print("  only appear here once you classify them. Check the report:")
        print("    Monitor > Reports > Security > Application Discovery")
        print()
        print("  If the report genuinely has no AI applications in it, then")
        print("  there is no traffic to classify, and that is worth fixing:")
        print("    python3 generate_ai_traffic.py --rounds 3")
    else:
        print("  Every AI application has an approval status.")
    print()
    return states


def show_filters(csp):
    """Print the application filters, highlighting the built-in dynamic pair."""
    approved, unapproved = builtin_filters(csp)

    print()
    print("=" * 72)
    print("  Application filters")
    print("=" * 72)
    for record in list_filters(csp):
        name = record.get("name", "?")
        marker = ""
        if approved and record.get("id") == approved.get("id"):
            marker = "  (built-in: approved)"
        elif unapproved and record.get("id") == unapproved.get("id"):
            marker = "  (built-in: unapproved)"
        print(f"  {name}{marker}")
    print("=" * 72)

    if not approved or not unapproved:
        print("  WARNING: could not find both built-in filters. The policy "
              "challenge expects 'All Approved Applications' and 'All "
              "Unapproved Applications' to exist.")
    print()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def connect():
    """A CSP session with whatever credential is available."""
    csp = CspSession()
    if not csp.api_key:
        csp.connect(read_state("sandbox_id.txt"))
    return csp


def main():
    parser = argparse.ArgumentParser(
        description="Inspect and set Threat Defense application approval.")
    parser.add_argument("--approved-app", action="append", dest="approved_apps",
                        help="A sanctioned tool. Repeatable. Default: "
                             f"{', '.join(D.DEFAULT_APPROVED_APPS)}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("list", "status", "filters", "apply-policy"):
        sub.add_parser(name)
    for name in ("approve", "unapprove"):
        p = sub.add_parser(name)
        p.add_argument("app")
    args = parser.parse_args()

    csp = connect()
    approved_apps = args.approved_apps or D.DEFAULT_APPROVED_APPS

    if args.command == "list":
        apps = list_applications(csp)
        print(f"\n{len(apps)} application(s) in the catalogue\n")
        for app in sorted(apps, key=lambda a: a["name"].lower()):
            ours = " *" if D.entry_for_app(app["name"]) else ""
            print(f"  {app['name']:<34} {app['status']:<14}{app['category']}{ours}")
        print("\n  * an application this lab governs")
        print("\n  This is the application catalogue, not the Application")
        print("  Discovery report. Applications awaiting review may not be")
        print("  listed here yet. The report is the authoritative view:")
        print("    Monitor > Reports > Security > Application Discovery\n")
        return 0

    if args.command == "status":
        show_status(csp, approved_apps)
        return 0

    if args.command == "filters":
        show_filters(csp)
        return 0

    if args.command == "apply-policy":
        changed = apply_lab_policy(csp, approved_apps)
        log.info("Done - %d application(s) reclassified", changed)
        return 0

    status = APPROVED if args.command == "approve" else UNAPPROVED
    set_status(csp, args.app, status)
    return 0


def _bare(value):
    return str(value or "").split("/")[-1]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except EndpointNotFound as exc:
        log.error("%s", exc)
        sys.exit(1)
    except (CspError, CspAuthError) as exc:
        log.error("%s", exc)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — top-level guard
        log.error("%s", exc)
        sys.exit(1)
