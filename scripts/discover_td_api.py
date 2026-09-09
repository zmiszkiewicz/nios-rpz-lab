#!/usr/bin/env python3
"""
Find the real Application Discovery endpoints on a live tenant.

Application Discovery is absent from the published Infoblox API documentation,
and /api/atcfw/v1/openapi.json needs credentials, so app_discovery.py ships
with candidate lists rather than confirmed paths. This script closes that gap:
run it once against a real sandbox and it reports exactly which paths exist.

    python3 discover_td_api.py                  probe everything
    python3 discover_td_api.py --spec           pull the OpenAPI spec and grep it
    python3 discover_td_api.py --probe          probe candidate paths only
    python3 discover_td_api.py --grep policy    filter spec paths by keyword

The spec pass is the one that matters. With a valid API key the CSP will serve
its own OpenAPI document, which lists every path it implements. That turns the
guesswork in app_discovery.py into fact in a single run. The probe pass is the
fallback for when a plane does not publish a spec.

Output is written to discovered_endpoints.txt so the result survives the
container, and printed as a paste-ready block for the candidate lists.

Environment: TF_VAR_ddi_api_key (preferred) or INFOBLOX_EMAIL + INFOBLOX_PASSWORD.
"""

import argparse
import json
import sys

from csp_api import CspAuthError, CspError, CspSession, get_logger, read_state, write_state

log = get_logger("discover_td_api")

# Planes worth asking for a spec. atcfw is where Threat Defense policy lives
# and therefore the most likely home for application approval.
SPEC_PATHS = [
    "/api/atcfw/v1/openapi.json",
    "/api/atcfw/v1/swagger.json",
    "/apidoc/docs/Atcfw",
    "/api/atcep/v1/openapi.json",
    "/api/atcdfp/v1/openapi.json",
    "/api/infra/v1/openapi.json",
]

# Candidate collections. Deliberately wider than app_discovery.py's list: this
# is the net, that is the hypothesis.
PROBE_PATHS = [
    # applications
    "/api/atcfw/v1/applications",
    "/api/atcfw/v1/app_discovery/applications",
    "/api/atcfw/v1/app_discovery",
    "/api/atcfw/v1/discovered_applications",
    "/api/atcfw/v1/app_approvals",
    "/api/atcfw/v1/application_approvals",
    "/api/atcfw/v1/application_discovery/applications",
    "/api/appdiscovery/v1/applications",
    "/api/atcfw/v1/apps",
    # filters
    "/api/atcfw/v1/application_filters",
    "/api/atcfw/v1/app_filters",
    "/api/atcfw/v1/category_filters",
    "/api/atcfw/v1/filters/applications",
    # policy, known-good control
    "/api/atcfw/v1/security_policies",
    "/api/atcfw/v1/security_policy_rules",
    "/api/atcfw/v1/named_lists",
    # infra, known-good control
    "/api/infra/v1/detail_hosts",
    "/api/infra/v1/services",
    "/api/infra/v1/detail_services",
]

# Keywords that make a spec path interesting for this lab.
INTERESTING = ["app", "application", "approv", "discover", "filter", "policy", "rule"]


# --------------------------------------------------------------------------- #
# Spec pass
# --------------------------------------------------------------------------- #

def fetch_spec(csp, path):
    """An OpenAPI document from the tenant, or None."""
    try:
        body = csp.get(path)
    except CspError as exc:
        log.debug("%s -> HTTP %s", path, exc.status)
        return None
    if isinstance(body, dict) and ("paths" in body or "swagger" in body
                                   or "openapi" in body):
        return body
    return None


def spec_pass(csp, grep=None):
    """
    Pull every available spec and list the paths that look relevant.

    Returns {spec_path: [(http_path, [methods])]}.
    """
    findings = {}

    for spec_path in SPEC_PATHS:
        spec = fetch_spec(csp, spec_path)
        if not spec:
            continue

        title = (spec.get("info") or {}).get("title", spec_path)
        paths = spec.get("paths") or {}
        log.info("Spec found at %s (%s): %d paths", spec_path, title, len(paths))

        keywords = [grep.lower()] if grep else INTERESTING
        hits = []
        for http_path, operations in sorted(paths.items()):
            if not any(word in http_path.lower() for word in keywords):
                continue
            methods = sorted(m.upper() for m in operations
                             if m.lower() in ("get", "post", "put", "patch", "delete"))
            hits.append((http_path, methods))

        findings[spec_path] = hits

    return findings


# --------------------------------------------------------------------------- #
# Probe pass
# --------------------------------------------------------------------------- #

def probe_pass(csp, paths=None):
    """
    GET every candidate and classify the outcome.

    Returns a list of (path, status, note). A 401 or 403 is reported as
    "exists, not permitted", which is a completely different problem from a
    404 and needs a completely different fix: check the subscription tier or
    the API key's role, not the URL.
    """
    results = []

    for path in (paths or PROBE_PATHS):
        try:
            body = csp.get(path)
        except CspError as exc:
            if exc.status in (401, 403):
                note = "exists, not permitted (check subscription tier or key role)"
            elif exc.status == 404:
                note = "not found"
            else:
                note = f"error: {exc.body[:80]}"
            results.append((path, exc.status, note))
            continue

        count = len(_records(body))
        results.append((path, 200, f"OK, {count} record(s)"))

    return results


def _records(body):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("results", "result", "items", "data"):
            value = body.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return [value]
    return []


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def report(spec_findings, probe_results):
    """Print both passes and return the text written to disk."""
    lines = []

    def out(text=""):
        print(text)
        lines.append(text)

    out()
    out("=" * 74)
    out("  OpenAPI spec pass")
    out("=" * 74)
    if not spec_findings:
        out("  No spec was readable. Either the credential lacks permission or")
        out("  this CSP release does not publish one. Rely on the probe below.")
    for spec_path, hits in spec_findings.items():
        out(f"\n  {spec_path}")
        if not hits:
            out("    (no matching paths)")
        for http_path, methods in hits:
            out(f"    {','.join(methods):<26} {http_path}")

    out()
    out("=" * 74)
    out("  Probe pass")
    out("=" * 74)
    working = []
    for path, status, note in probe_results:
        marker = "OK  " if status == 200 else f"{status:<4}"
        out(f"  {marker} {path:<52} {note}")
        if status == 200:
            working.append(path)

    out()
    out("=" * 74)
    out("  Paste-ready")
    out("=" * 74)
    if working:
        out("  Paths that answered 200. Put the relevant ones FIRST in the")
        out("  candidate lists in app_discovery.py:")
        out()
        for path in working:
            out(f'    "{path}",')
    else:
        out("  Nothing answered 200. Check the credential first:")
        out("    python3 csp_api.py whoami")
    out()

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Discover the real Threat Defense API paths on this tenant.")
    parser.add_argument("--spec", action="store_true", help="Spec pass only")
    parser.add_argument("--probe", action="store_true", help="Probe pass only")
    parser.add_argument("--grep", help="Filter spec paths by keyword")
    parser.add_argument("--path", action="append",
                        help="Probe an extra path (repeatable)")
    parser.add_argument("--dump", metavar="PATH",
                        help="GET one path and print the raw body")
    args = parser.parse_args()

    csp = CspSession()
    if not csp.api_key:
        log.info("No API key in the environment, falling back to interactive login")
        csp.connect(read_state("sandbox_id.txt"))
    else:
        log.info("Using the API key from the environment")

    if args.dump:
        print(json.dumps(csp.get(args.dump), indent=2)[:20000])
        return 0

    do_spec = args.spec or not args.probe
    do_probe = args.probe or not args.spec

    spec_findings = spec_pass(csp, args.grep) if do_spec else {}
    probe_results = probe_pass(
        csp, (PROBE_PATHS + args.path) if args.path else None) if do_probe else []

    text = report(spec_findings, probe_results)
    path = write_state("discovered_endpoints.txt", text)
    log.info("Written to %s", path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CspError, CspAuthError) as exc:
        log.error("%s", exc)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 — top-level guard
        log.error("%s", exc)
        sys.exit(1)
