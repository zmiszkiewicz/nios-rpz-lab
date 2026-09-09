#!/usr/bin/env python3
"""
Offline regression tests for setup_dfp host readiness.

    python3 test_setup_dfp.py

No network, no credentials, no tenant. Run by preflight.sh on every push.

These exist because of one specific failure. host_is_connected() required the
host's status field to equal "connected", "active", "online" or "ready", and
treated anything else as not-ready. On a real tenant a host registered
perfectly well, reported a status that was not in that list, and the wait loop
blocked for the full fifteen minutes before failing with a message that sent
people looking at join tokens and firewall rules.

/api/infra/v1/detail_hosts is not a documented API. Its status vocabulary was
never confirmed, so any check against a fixed set of strings was a guess. The
replacement asks only what it can answer honestly: is the host in a state it
can never recover from, and does it have a pool a service can attach to.

The tests below encode that: unknown status values must NOT block.
"""

import sys

import setup_dfp

PASS = "  ok   "
FAIL = "  FAIL "

failures = []


def check(condition, description):
    print((PASS if condition else FAIL) + description)
    if not condition:
        failures.append(description)


# --------------------------------------------------------------------------- #
# Pool extraction
# --------------------------------------------------------------------------- #

def test_pool_id_from_every_plausible_shape():
    cases = [
        ({"pool": {"pool_id": "p-1"}}, "p-1", "pool.pool_id (reference shape)"),
        ({"pool": {"id": "p-2"}}, "p-2", "pool.id"),
        ({"pool": "p-3"}, "p-3", "pool as a bare string"),
        ({"pool_id": "p-4"}, "p-4", "top-level pool_id"),
        ({"poolId": "p-5"}, "p-5", "camelCase poolId"),
        ({"a": {"b": {"pool_id": "p-6"}}}, "p-6", "pool_id nested arbitrarily"),
        ({"legacy": [{"pool_id": "p-7"}]}, "p-7", "pool_id inside a list"),
        ({}, None, "no pool at all"),
        ({"pool": {}}, None, "empty pool object"),
    ]
    for host, expected, label in cases:
        got = setup_dfp._pool_id(host)
        check(got == expected, f"_pool_id reads {label} ({got!r} == {expected!r})")


# --------------------------------------------------------------------------- #
# Readiness
# --------------------------------------------------------------------------- #

def test_unknown_status_does_not_block():
    """
    The regression. A host with a pool and an unrecognised status is ready.

    These are the values the old check would have rejected.
    """
    for value in ("Active", "ACTIVE", "running", "in_sync", "provisioned",
                  "Ready", "connected", "healthy", "OK", "pending",
                  "degraded", "something-nobody-has-seen", ""):
        host = {"pool": {"pool_id": "p-1"}, "status": value}
        check(setup_dfp.host_is_ready(host),
              f"status={value!r} does not block readiness")


def test_terminal_states_do_block():
    for value in ("error", "Error", "FAILED", "disconnected", "terminated",
                  "deleted", "unavailable"):
        host = {"pool": {"pool_id": "p-1"}, "connection_status": value}
        check(not setup_dfp.host_is_ready(host),
              f"status={value!r} correctly blocks readiness")


def test_no_pool_is_not_ready():
    check(not setup_dfp.host_is_ready({"status": "active"}),
          "a host with no pool is not ready")
    check(not setup_dfp.host_is_ready({}), "an empty host record is not ready")


def test_pending_with_pool_is_allowed():
    """
    'pending' was in the old blocking list and should not be.

    A host can report a transient pending state while already having a pool,
    and the service-creation call is the real gate.
    """
    host = {"pool": {"pool_id": "p-1"}, "composite_status": "pending"}
    check(setup_dfp.host_is_ready(host), "pending with a pool is ready")


# --------------------------------------------------------------------------- #
# Diagnostics
# --------------------------------------------------------------------------- #

def test_host_status_collects_what_exists():
    host = {
        "status": "active",
        "connection_status": "connected",
        "state": None,
        "composite_status": "",
        "irrelevant": "x",
    }
    status = setup_dfp.host_status(host)
    check("status" in status and "connection_status" in status,
          "host_status collects populated status fields")
    check("state" not in status and "composite_status" not in status,
          "host_status drops empty and None values")
    check("irrelevant" not in status,
          "host_status ignores non-status fields")


def test_describe_host_is_useful_on_failure():
    """The timeout message has to say what was actually seen."""
    host = {"display_name": "niosx-1", "status": "weird",
            "pool": {"pool_id": "p-9"}}
    text = setup_dfp.describe_host(host)
    for fragment in ("niosx-1", "weird", "p-9"):
        check(fragment in text, f"describe_host mentions {fragment!r}")

    bare = setup_dfp.describe_host({"id": "h-1"})
    check("no status fields" in bare,
          "describe_host says so when there are no status fields")


def test_find_host_strategy_order():
    """
    Token name beats IP beats sole-host.

    A host enrolled with a join token registers as ZTP_<token name>_<suffix>,
    which is ours by construction. Matching on the IP alone was not enough:
    the interfaces are absent from the record for the first minutes after
    registration, which is exactly when this gets polled.
    """
    import os
    import tempfile

    state = tempfile.mkdtemp()
    os.environ["LAB_STATE_DIR"] = state
    with open(os.path.join(state, "join_token_name.txt"), "w") as fh:
        fh.write("instruqt-lab-0144\n")

    class Csp:
        def __init__(self, hosts): self.hosts = hosts
        def results(self, path): return self.hosts

    mine = {"display_name": "ZTP_instruqt-lab-0144_xyz",
            "pool": {"pool_id": "p-mine"}}
    other = {"display_name": "someone-else", "ip_address": "10.100.0.200",
             "pool": {"pool_id": "p-other"}}

    got = setup_dfp.find_host(Csp([other, mine]))
    check(setup_dfp._pool_id(got) == "p-mine",
          "token name wins even when another host matches the IP")

    # No token name on disk: fall back to IP.
    os.remove(os.path.join(state, "join_token_name.txt"))
    got = setup_dfp.find_host(Csp([{"display_name": "x", "pool": {"pool_id": "p-x"}},
                                   other]))
    check(setup_dfp._pool_id(got) == "p-other", "falls back to matching the IP")

    # Neither: a single host is accepted.
    got = setup_dfp.find_host(Csp([mine]))
    check(setup_dfp._pool_id(got) == "p-mine", "falls back to the only host")

    # Neither, and several hosts: refuse to guess.
    got = setup_dfp.find_host(Csp([{"display_name": "a", "pool": {"pool_id": "1"}},
                                   {"display_name": "b", "pool": {"pool_id": "2"}}]))
    check(got is None, "refuses to guess between several unmatched hosts")

    check(setup_dfp.find_host(Csp([])) is None, "no hosts yields None")
    os.environ.pop("LAB_STATE_DIR", None)


def test_host_addresses_finds_nested_ips():
    host = {"interfaces": [{"addresses": [{"address": "10.100.0.200/24"}]}],
            "ip_address": "1.2.3.4"}
    found = setup_dfp._host_addresses(host)
    check("10.100.0.200" in found, "_host_addresses strips the CIDR suffix")
    check("1.2.3.4" in found, "_host_addresses finds top-level ip_address")


def test_placeholder_addresses_are_ignored():
    """
    A NIOS-X host reports 0.0.0.0 for an interface it has not bound yet.

    Keeping it made the status output claim the host's address was 0.0.0.0,
    and matching on it would make every host look like every other host.
    """
    for junk in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "::"):
        found = setup_dfp._host_addresses({"ip_address": junk})
        check(found == set(), f"{junk} is not treated as a host address")

    mixed = setup_dfp._host_addresses(
        {"interfaces": [{"address": "0.0.0.0"}, {"address": "10.100.0.200"}]})
    check(mixed == {"10.100.0.200"},
          "a real address survives alongside a placeholder")


# --------------------------------------------------------------------------- #
# Service state
# --------------------------------------------------------------------------- #

def test_desired_state_is_never_proof_of_running():
    """
    The regression. desired_state is what we asked for, not what is.

    wait_for_service() fell back to desired_state when current_state was
    absent, which it always is in the first seconds after creation. So the
    wait returned in the same second the service was created, and port 53 was
    still dead eleven seconds later.
    """
    fresh = {"name": "dfp", "service_type": "dfp", "desired_state": "start"}
    check(setup_dfp.service_current_state(fresh) is None,
          "a service with only desired_state has no current state")

    check(setup_dfp.service_current_state({}) is None,
          "an empty service record has no current state")

    check(setup_dfp.service_current_state(
        {"desired_state": "start", "current_state": ""}) is None,
        "an empty current_state is not a state")


def test_current_state_is_read_from_any_plausible_field():
    for key in ("current_state", "status", "state", "composite_state",
                "service_status", "operational_state"):
        got = setup_dfp.service_current_state({key: "running",
                                               "desired_state": "start"})
        check(got == "running", f"current state read from {key}")

    got = setup_dfp.service_current_state({"current_state": "  RUNNING  "})
    check(got == "running", "current state is normalised")


def test_running_states_cover_the_plausible_vocabulary():
    for value in ("start", "started", "running", "active", "online", "ready"):
        check(value in setup_dfp.RUNNING_STATES,
              f"{value!r} counts as running")
    for value in ("stopped", "starting", "pending", "error"):
        check(value not in setup_dfp.RUNNING_STATES,
              f"{value!r} does not count as running")


def main():
    print("\nsetup_dfp regression tests\n")
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
