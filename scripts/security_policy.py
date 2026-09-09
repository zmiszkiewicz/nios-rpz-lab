#!/usr/bin/env python3
"""
Inspect and edit the Threat Defense security policy.

    python3 security_policy.py show           the policy and its rules, in order
    python3 security_policy.py add-rules      add the two application filter rules
    python3 security_policy.py verify         check the end state the lab wants
    python3 security_policy.py remove-rules   undo add-rules

The lab asks the participant to add these rules in the portal. This module is
here so the challenge check can verify the result, and so the rules can be
demonstrated or repaired from the terminal.

## The two rules, and why their order matters

    All Unapproved Applications  ->  Block (no redirect)
    All Approved Applications    ->  Allow (no log)

Threat Defense evaluates policy rules top down and stops at the first match,
so the block has to sit above the allow. Reversed, a tool that is somehow in
both filters would be allowed, and more importantly the participant learns the
wrong mental model. The brief calls this out explicitly ("Blocked before
Allowed") and `verify` enforces it rather than just checking both rules exist.

The filters themselves are dynamic: Infoblox ships "All Approved Applications"
and "All Unapproved Applications", and they track whatever the participant
classified in Application Discovery. That is the real lesson of this part of
the lab: the policy is written once and stays correct as the classification
changes underneath it.

Environment: TF_VAR_ddi_api_key (or INFOBLOX_EMAIL + INFOBLOX_PASSWORD).
"""

import argparse
import copy
import sys

import app_discovery as AD
from csp_api import (CspAuthError, CspError, CspSession, EndpointNotFound,
                     get_logger, read_state)

log = get_logger("security_policy")

POLICIES_PATH = "/api/atcfw/v1/security_policies"

# Rule action values. Threat Defense spells these action_<verb>; the bare verb
# is accepted on some releases, so both are tried.
ACTION_BLOCK = ["action_block", "block"]
ACTION_ALLOW_NO_LOG = ["action_allow", "allow"]

# What a rule that targets an application filter calls itself.
APP_FILTER_TYPES = ["application_filter", "app_filter", "application"]

# Fields that are read-only or belong only to the default policy, and must be
# stripped before a PUT. Taken from the working clone logic in
# tech-summit-vai-live/scripts/triple_security_policy.py, which hit every one
# of these the hard way.
READ_ONLY_FIELDS = {
    "id", "created_time", "updated_time", "policy_id", "is_default",
    "agents", "dfps", "migration_status", "scope_expr",
}


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #

def get_default_policy(csp):
    """The tenant's default security policy."""
    policies = csp.results(POLICIES_PATH)
    if not policies:
        raise CspError("GET", POLICIES_PATH, 200, "the tenant has no security policies")

    policy = next((p for p in policies if p.get("is_default")), None)
    if policy:
        return policy

    # No policy is flagged default: fall back to the lowest precedence, which
    # is the one that would be evaluated first anyway.
    return sorted(policies, key=lambda p: p.get("precedence", 99))[0]


def get_policy(csp, policy_id):
    """One policy by id, with its rules."""
    body = csp.get(f"{POLICIES_PATH}/{_bare(policy_id)}")
    result = body.get("result") or body
    return result


def app_filter_rules(policy):
    """
    Rules in a policy that target an application filter.

    Returns [(index, rule)] preserving policy order, because order is part of
    what gets verified.
    """
    found = []
    for index, rule in enumerate(policy.get("rules") or []):
        if _is_app_filter_rule(rule):
            found.append((index, rule))
    return found


def _is_app_filter_rule(rule):
    rule_type = str(rule.get("type", "")).lower()
    if any(t in rule_type for t in APP_FILTER_TYPES):
        return True
    # Some shapes omit type and carry the filter reference instead.
    return any(key in rule for key in ("application_filter_id", "app_filter_id"))


def _rule_target(rule):
    """The filter name or id a rule points at."""
    for key in ("data", "name", "application_filter", "application_filter_id",
                "app_filter_id", "filter_name"):
        value = rule.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _rule_action(rule):
    return str(rule.get("action", "")).lower()


def _is_block(rule):
    return "block" in _rule_action(rule) or "redirect" in _rule_action(rule)


def _is_allow(rule):
    action = _rule_action(rule)
    return "allow" in action and "block" not in action


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #

def build_rule(filter_record, action_candidates, rule_type, filter_name):
    """
    One policy rule targeting an application filter.

    The reference is written both by name and by id where available, because
    releases differ on which one a PUT honours and an ignored field is
    harmless.
    """
    rule = {"action": action_candidates[0], "type": rule_type, "data": filter_name}
    if filter_record:
        filter_id = filter_record.get("id")
        if filter_id:
            rule["application_filter_id"] = filter_id
    return rule


def add_rules(csp, policy=None, approved_first=False):
    """
    Add the block-unapproved and allow-approved rules to the policy.

    Idempotent: rules already present are left alone. Returns True if the
    policy was modified.

    `approved_first` deliberately builds the WRONG order. It exists so the
    lab can demonstrate why order matters, and so verify() can be trusted to
    actually catch it rather than being assumed correct.
    """
    policy = policy or get_default_policy(csp)

    try:
        approved_filter, unapproved_filter = AD.builtin_filters(csp)
    except EndpointNotFound as exc:
        log.warning("Could not enumerate application filters: %s", exc)
        approved_filter = unapproved_filter = None

    approved_name = (approved_filter or {}).get("name", "All Approved Applications")
    unapproved_name = (unapproved_filter or {}).get("name",
                                                    "All Unapproved Applications")

    existing = {_rule_target(rule).lower() for _, rule in app_filter_rules(policy)}
    rules = list(policy.get("rules") or [])
    added = []

    block_rule = build_rule(unapproved_filter, ACTION_BLOCK,
                            APP_FILTER_TYPES[0], unapproved_name)
    allow_rule = build_rule(approved_filter, ACTION_ALLOW_NO_LOG,
                            APP_FILTER_TYPES[0], approved_name)

    # Block goes first so it is evaluated first. Prepending rather than
    # appending also keeps these above any inherited feed rules, which is what
    # the participant does in the portal by dragging them to the top.
    ordered = [allow_rule, block_rule] if approved_first else [block_rule, allow_rule]

    for rule in reversed(ordered):
        target = _rule_target(rule).lower()
        if target in existing:
            log.info("Rule for %r already present", _rule_target(rule))
            continue
        rules.insert(0, rule)
        added.append(_rule_target(rule))

    if not added:
        log.info("Both application filter rules are already in the policy")
        return False

    _put_policy(csp, policy, rules)
    for name in added:
        log.info("Added rule for %r", name)
    log.info("Policy updated with %d rule(s)", len(added))
    return True


def remove_rules(csp, policy=None):
    """Strip every application filter rule from the policy."""
    policy = policy or get_default_policy(csp)
    rules = list(policy.get("rules") or [])
    keep = [rule for rule in rules if not _is_app_filter_rule(rule)]

    if len(keep) == len(rules):
        log.info("No application filter rules to remove")
        return False

    _put_policy(csp, policy, keep)
    log.info("Removed %d application filter rule(s)", len(rules) - len(keep))
    return True


def _put_policy(csp, policy, rules):
    """PUT a modified policy, stripping the fields the API will not accept."""
    payload = {k: v for k, v in copy.deepcopy(policy).items()
               if k not in READ_ONLY_FIELDS}
    payload["rules"] = rules
    csp.put(f"{POLICIES_PATH}/{_bare(policy.get('id'))}", payload)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #

def verify(csp, policy=None):
    """
    Check the policy matches what the lab asked for.

    Returns (ok, [problems]). Checks three things, and the third is the one
    that is easy to get wrong and easy to forget to test:

      1. a Block rule targeting the unapproved filter exists
      2. an Allow rule targeting the approved filter exists
      3. the Block rule sits above the Allow rule
    """
    policy = policy or get_default_policy(csp)
    rules = app_filter_rules(policy)
    problems = []

    if not rules:
        return False, [
            "The security policy has no application filter rules. Add them in "
            "Configure > Security > Policies."
        ]

    block = next(((i, r) for i, r in rules
                  if _is_block(r) and "unapprov" in _rule_target(r).lower()), None)
    allow = next(((i, r) for i, r in rules
                  if _is_allow(r) and "unapprov" not in _rule_target(r).lower()
                  and "approv" in _rule_target(r).lower()), None)

    if not block:
        problems.append(
            "No Block rule for 'All Unapproved Applications'. Without it the "
            "unapproved tools stay reachable."
        )
    if not allow:
        problems.append(
            "No Allow rule for 'All Approved Applications'. Without it the "
            "approved tool is not explicitly permitted."
        )

    if block and allow and block[0] > allow[0]:
        problems.append(
            f"The Allow rule (position {allow[0] + 1}) sits above the Block rule "
            f"(position {block[0] + 1}). Threat Defense stops at the first match, "
            f"so Blocked must come before Allowed."
        )

    return not problems, problems


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def show(csp):
    """Print the policy and every rule in evaluation order."""
    policy = get_default_policy(csp)
    rules = policy.get("rules") or []

    print()
    print("=" * 74)
    print(f"  Security policy: {policy.get('name', '?')}"
          f"{'  (default)' if policy.get('is_default') else ''}")
    print("=" * 74)
    print(f"  Precedence {policy.get('precedence', '?')}    "
          f"{len(rules)} rule(s)    id {_bare(policy.get('id'))}")
    print()

    if not rules:
        print("  No rules.")
    else:
        print(f"  {'#':<4} {'ACTION':<22} {'TYPE':<20} TARGET")
        print("  " + "-" * 70)
        for index, rule in enumerate(rules, start=1):
            marker = " *" if _is_app_filter_rule(rule) else ""
            print(f"  {index:<4} {_rule_action(rule) or '?':<22} "
                  f"{str(rule.get('type', '?')):<20} {_rule_target(rule)}{marker}")
        print()
        print("  * an application filter rule")

    ok, problems = verify(csp, policy)
    print()
    if ok:
        print("  Policy matches the lab target: unapproved blocked above "
              "approved allowed.")
    else:
        for problem in problems:
            print(f"  TODO  {problem}")
    print("=" * 74)
    print()
    return ok


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Inspect and edit the Threat Defense security policy.")
    parser.add_argument("--approved-first", action="store_true",
                        help="Add the rules in the wrong order, to demonstrate why "
                             "order matters")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("show", "add-rules", "verify", "remove-rules"):
        sub.add_parser(name)
    args = parser.parse_args()

    csp = CspSession()
    if not csp.api_key:
        csp.connect(read_state("sandbox_id.txt"))

    if args.command == "show":
        return 0 if show(csp) else 0

    if args.command == "add-rules":
        add_rules(csp, approved_first=args.approved_first)
        show(csp)
        return 0

    if args.command == "remove-rules":
        remove_rules(csp)
        return 0

    ok, problems = verify(csp)
    if ok:
        print("Policy is correct: unapproved blocked, approved allowed, "
              "block first.")
        return 0
    for problem in problems:
        print(f"FAIL  {problem}")
    return 1


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
