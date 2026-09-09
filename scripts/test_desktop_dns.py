#!/usr/bin/env python3
"""
Offline regression tests for desktop_dns.

    python3 test_desktop_dns.py

No network, no desktop, no WinRM. Run by preflight.sh on every push.

The PowerShell in this module cannot be executed on the machine that writes it,
so these tests check the things that would otherwise only be discovered on a
live Windows host: that the script renders with no placeholders left, that its
braces balance, that the two guards which stop it hanging are present, and
that a hostile domain name cannot be injected into it.

Why the guards matter. A ten-domain run against a DFP that was not yet serving
took longer than the WinRM operation timeout, because every Resolve-DnsName
waited out its own retry schedule. From the outside that looked like a hang
during "desktop querying" rather than the DNS Forwarding Proxy being down. Two
changes fixed it and both are asserted below:

    -QuickTimeout            bounds each lookup to about a second
    if (-not $listening)     skips the lookups entirely when TCP 53 is dead
"""

import sys

import desktop_dns as DD

PASS = "  ok   "
FAIL = "  FAIL "

failures = []


def check(condition, description):
    print((PASS if condition else FAIL) + description)
    if not condition:
        failures.append(description)


# --------------------------------------------------------------------------- #
# Script rendering
# --------------------------------------------------------------------------- #

def test_script_renders_without_placeholders():
    script = DD._build_script(["claude.ai", "www.infoblox.com"], "10.100.0.200")
    check("__DOMAINS__" not in script, "no __DOMAINS__ placeholder remains")
    check("__SERVER__" not in script, "no __SERVER__ placeholder remains")
    check('"claude.ai"' in script, "domains are quoted into the script")
    check('"www.infoblox.com"' in script, "every domain is present")
    check('$server = "10.100.0.200"' in script, "server address is substituted")


def test_script_braces_balance():
    """A truncated or malformed script fails on the host, not here."""
    script = DD._build_script(["a.example"], "10.0.0.1")
    for open_ch, close_ch, label in (("{", "}", "braces"),
                                     ("(", ")", "parentheses"),
                                     ("[", "]", "brackets")):
        check(script.count(open_ch) == script.count(close_ch),
              f"{label} balance ({script.count(open_ch)} vs {script.count(close_ch)})")

    check(script.count('"') % 2 == 0, "double quotes are balanced")


def test_the_two_anti_hang_guards_are_present():
    """The regression. Losing either of these reintroduces the hang."""
    script = DD._build_script(["a.example"], "10.0.0.1")
    check("-QuickTimeout" in script,
          "-QuickTimeout bounds each lookup")
    check("if (-not $listening)" in script,
          "lookups are skipped when nothing is listening on 53")
    check("$skipped" in script and "lookups_skipped" in script,
          "the skip is reported back to the caller")
    check("BeginConnect" in script and "WaitOne(3000" in script,
          "the TCP probe has an explicit 3s timeout")


def test_script_emits_the_expected_json_keys():
    script = DD._build_script(["a.example"], "10.0.0.1")
    for key in ("server", "port53_listening", "lookups_skipped",
                "configured_dns", "results"):
        check(key in script, f"output JSON includes {key}")


# --------------------------------------------------------------------------- #
# Injection safety
# --------------------------------------------------------------------------- #

def test_hostile_domains_are_rejected():
    """
    Domains are interpolated into a script, so they are validated first.

    These are all rejected before any string building happens.
    """
    hostile = [
        'a.com"; Remove-Item C:\\ -Recurse; "',
        "a.com`nWrite-Host pwned",
        'a.com" }; $x = "',
        "a.com; whoami",
        "a.com$(whoami)",
        "'; DROP TABLE hosts; --",
        "a b.com",
        "",
        "-" * 300,
    ]
    for value in hostile:
        try:
            DD._build_script([value], "10.0.0.1")
            rejected = False
        except ValueError:
            rejected = True
        check(rejected, f"rejects domain {value[:34]!r}")


def test_hostile_servers_are_rejected():
    for value in ['1.2.3.4"; whoami; "', "not a server", "1.2.3.4; ls", ""]:
        try:
            DD._build_script(["a.example"], value)
            rejected = False
        except ValueError:
            rejected = True
        check(rejected, f"rejects server {value[:34]!r}")


def test_legitimate_names_are_accepted():
    for value in ["claude.ai", "www.infoblox.com", "gemini.google.com",
                  "chat.openai.com", "a-b.example.co.uk", "*.claude.ai"]:
        try:
            DD._build_script([value], "10.100.0.200")
            ok = True
        except ValueError:
            ok = False
        check(ok, f"accepts domain {value!r}")

    for value in ["10.100.0.200", "127.0.0.1", "dfp.example.com"]:
        try:
            DD._build_script(["a.example"], value)
            ok = True
        except ValueError:
            ok = False
        check(ok, f"accepts server {value!r}")


# --------------------------------------------------------------------------- #
# Timeout scaling
# --------------------------------------------------------------------------- #

def test_winrm_timeout_scales_with_workload():
    """
    A fixed 90s was fine for two domains and not for ten.

    The seed run walks ten domains, and the timeout has to cover all of them
    plus the cache flush and the probe.
    """
    one = DD.winrm_timeout_for(["a"])
    ten = DD.winrm_timeout_for(["a"] * 10)
    twenty = DD.winrm_timeout_for(["a"] * 20)

    check(one >= 60, f"a single domain still gets a floor ({one}s)")
    check(ten > one, f"ten domains get longer than one ({ten}s > {one}s)")
    check(twenty > ten, f"twenty longer than ten ({twenty}s > {ten}s)")
    check(ten >= 100, f"ten domains get at least 100s ({ten}s)")


# --------------------------------------------------------------------------- #
# Status classification
# --------------------------------------------------------------------------- #

def test_classify_distinguishes_the_four_failure_modes():
    """
    NXDOMAIN is a working policy. The other three are broken plumbing.

    Reporting all of them as "blocked" made a dead resolver look like a
    successful block, which is the most misleading failure a DNS lab can have.
    """
    cases = [
        ({"resolved": True, "addresses": ["1.2.3.4"], "error": ""},
         "RESOLVED", "a successful answer"),
        ({"resolved": False, "error": "DNS name does not exist"},
         "NXDOMAIN", "NXDOMAIN wording"),
        ({"resolved": False, "error": "DNS request timed out"},
         "TIMEOUT", "timeout wording"),
        ({"resolved": False, "error": "DNS query refused by server"},
         "REFUSED", "refused wording"),
        ({"resolved": False, "error": "DNS server failure"},
         "SERVFAIL", "servfail wording"),
        ({"resolved": False, "error": "something unfamiliar"},
         "NO_ANSWER", "an unrecognised error"),
        ({"resolved": False, "error": ""},
         "NO_ANSWER", "no error text at all"),
    ]
    for entry, expected, label in cases:
        got = DD.classify(entry)
        check(got == expected, f"classify: {label} -> {expected} (got {got})")


def test_nxdomain_is_labelled_blocked_but_kept_distinct():
    check(DD._STATUS_LABEL["NXDOMAIN"] == "BLOCKED",
          "NXDOMAIN is displayed as BLOCKED")
    for status in ("TIMEOUT", "REFUSED", "SERVFAIL", "NO_ANSWER"):
        check(DD._STATUS_LABEL[status] != "BLOCKED",
              f"{status} is NOT displayed as BLOCKED")


# --------------------------------------------------------------------------- #
# Failure explanation
# --------------------------------------------------------------------------- #

def test_explain_failure_names_the_cause():
    dead_port = {"server": "10.100.0.200", "port53_listening": False,
                 "lookups_skipped": True, "results": {}}
    reason = DD.explain_failure(dead_port)
    check(reason is not None, "a dead port 53 produces an explanation")
    check(reason is not None and "not running" in reason,
          "it says the DFP service is not running")
    check(reason is not None and "setup_dfp.py" in reason,
          "it names the command to run")

    working = {"server": "10.100.0.200", "port53_listening": True,
               "results": {"a.com": {"resolved": True, "addresses": ["1.2.3.4"],
                                     "status": "RESOLVED", "error": ""}}}
    check(DD.explain_failure(working) is None,
          "no explanation when something resolves")

    refused = {"server": "10.100.0.200", "port53_listening": True,
               "results": {"a.com": {"resolved": False, "addresses": [],
                                     "status": "REFUSED", "error": "refused"}}}
    reason = DD.explain_failure(refused)
    check(reason is not None and "refused" in reason.lower(),
          "REFUSED is explained distinctly")

    # A block is NOT a failure: NXDOMAIN everywhere must not be explained away
    # as broken plumbing, or the enforcement check could never pass.
    blocked = {"server": "10.100.0.200", "port53_listening": True,
               "results": {"claude.ai": {"resolved": False, "addresses": [],
                                         "status": "NXDOMAIN", "error": "does not exist"}}}
    check(DD.explain_failure(blocked) is None,
          "an all-NXDOMAIN result is not reported as a plumbing failure")


def main():
    print("\ndesktop_dns regression tests\n")
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"{name}:")
            fn()
    print()
    if failures:
        print(f"{len(failures)} FAILED:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
