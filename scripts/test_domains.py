#!/usr/bin/env python3
"""
Offline regression tests for domains.py and its consumers' approval logic.

    python3 test_domains.py

No network, no credentials. Run by preflight.sh on every push.

These pin down the move from a single approved application to a set of two.
ChatGPT and OpenAI are both Approved, because ChatGPT depends on openai.com to
authenticate and to reach parts of its own API. A version of this lab that
only approved ChatGPT would enforce a policy that breaks the sanctioned tool:
the participant would see ChatGPT allowed, click into it, and hit a wall the
DNS check would call a pass.

expected_split() moved from returning a single approved name to a list, and
every caller had to change with it. The tests below catch a caller silently
going back to only reading the first name, since that produces no error, just
a webpage that stops working for a client tab or an OpenAI SDK call.
"""

import sys

import domains as D

PASS = "  ok   "
FAIL = "  FAIL "

failures = []


def check(condition, description):
    print((PASS if condition else FAIL) + description)
    if not condition:
        failures.append(description)


# --------------------------------------------------------------------------- #
# The roster
# --------------------------------------------------------------------------- #

def test_five_applications_no_copilot():
    names = D.app_names()
    check(len(names) == 5, f"five applications are defined ({len(names)})")
    check("Microsoft Copilot" not in names, "Copilot is not in the roster")
    check(D.entry_for_app("Copilot") is None, "Copilot cannot be found by alias")
    check(D.entry_for_domain("copilot.microsoft.com") is None,
          "copilot.microsoft.com resolves to nothing")


def test_chatgpt_and_openai_are_distinct():
    chatgpt = D.entry_for_app("ChatGPT")
    openai = D.entry_for_app("OpenAI")
    check(chatgpt is not None and openai is not None,
          "both ChatGPT and OpenAI exist as entries")
    check(chatgpt["app"] != openai["app"], "they are not the same entry")
    check(chatgpt["domain"] == "chatgpt.com", "ChatGPT owns chatgpt.com")
    check(openai["domain"] == "openai.com", "OpenAI owns openai.com")
    check(D.entry_for_domain("chatgpt.com")["app"] == "ChatGPT",
          "chatgpt.com resolves to ChatGPT")
    check(D.entry_for_domain("openai.com")["app"] == "OpenAI",
          "openai.com resolves to OpenAI, not ChatGPT")
    check(D.entry_for_domain("chat.openai.com")["app"] == "ChatGPT",
          "chat.openai.com still belongs to ChatGPT, not OpenAI")


# --------------------------------------------------------------------------- #
# expected_split
# --------------------------------------------------------------------------- #

def test_default_approves_both_chatgpt_and_openai():
    """
    The regression. Approving only ChatGPT breaks ChatGPT.

    ChatGPT calls back to openai.com for authentication and API traffic, so a
    policy that allows chatgpt.com and blocks openai.com leaves the sanctioned
    tool broken even though its own domain resolves.
    """
    approved, unapproved = D.expected_split()
    check(set(approved) == {"ChatGPT", "OpenAI"},
          f"default approves exactly ChatGPT and OpenAI (got {approved})")
    check("OpenAI" not in unapproved, "OpenAI is not also in the unapproved list")
    check(set(unapproved) == {"Claude", "Google Gemini", "Perplexity"},
          f"the other three are unapproved (got {unapproved})")


def test_expected_split_accepts_a_single_string():
    """Backward compatibility: callers that only ever cared about one app."""
    approved, unapproved = D.expected_split("Claude")
    check(approved == ["Claude"], "a bare string is wrapped into a list")
    check("Claude" not in unapproved, "the approved app is excluded from unapproved")
    check(len(unapproved) == 4, "the other four are unapproved")


def test_expected_split_accepts_an_explicit_list():
    approved, unapproved = D.expected_split(["ChatGPT", "OpenAI", "Claude"])
    check(set(approved) == {"ChatGPT", "OpenAI", "Claude"},
          "three explicit approvals are honoured")
    check(set(unapproved) == {"Google Gemini", "Perplexity"},
          "the remaining two are unapproved")


def test_expected_split_deduplicates():
    approved, _ = D.expected_split(["ChatGPT", "ChatGPT", "Chat GPT"])
    check(approved == ["ChatGPT"],
          f"repeats and aliases of the same app collapse to one entry (got {approved})")


def test_domains_for_approved_apps_combine():
    approved, _ = D.expected_split()
    domains = [d for name in approved
              for d in D.domains_for_app(name, include_extra=False)]
    check(set(domains) == {"chatgpt.com", "openai.com"},
          f"approved domains cover both chatgpt.com and openai.com (got {domains})")


def main():
    print("\ndomains.py regression tests\n")
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
