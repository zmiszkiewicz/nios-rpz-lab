#!/usr/bin/env python3
"""
Offline regression tests for csp_api.

    python3 test_csp_api.py

No network, no credentials, no tenant. Run by preflight.sh on every push.

These exist because of one specific failure. csp_api.switch_account() checked
for HTTP 200, but /v2/session/account_switch answers **201**. Every switch
succeeded and every one was rejected, and because provision_tenant.py wraps the
call in a propagation-retry loop, the symptom was a four-minute
"subtenant was still not usable" timeout in a live lab start rather than
anything pointing at a status code.

The lesson generalises: the CSP is not consistent about which 2xx it returns
for a given operation, so any check for one specific success code is wrong
eventually. These tests pin that down for the calls that hand-roll their status
handling instead of going through request().
"""

import json
import sys

import csp_api

PASS = "  ok   "
FAIL = "  FAIL "

failures = []


def check(condition, description):
    print((PASS if condition else FAIL) + description)
    if not condition:
        failures.append(description)


class FakeResponse:
    def __init__(self, status_code, body=None, text=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = text if text is not None else json.dumps(self._body)

    def json(self):
        if self.text and not self._body:
            raise ValueError("not json")
        return self._body


class FakeSession:
    """Answers sign_in with 200 and everything else with a fixed code."""

    def __init__(self, code, body=None):
        self.code = code
        self.body = body if body is not None else {"jwt": "sandbox-jwt"}
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        if "sign_in" in url:
            return FakeResponse(200, {"jwt": "parent-jwt"})
        return FakeResponse(self.code, self.body)

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return FakeResponse(self.code, self.body)

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return FakeResponse(self.code, self.body)


def session_for(code, body=None):
    csp = csp_api.CspSession(email="lab@example.com", password="x")
    csp.session = FakeSession(code, body)
    csp.jwt = "parent-jwt"
    return csp


# --------------------------------------------------------------------------- #

def test_switch_account_accepts_every_2xx():
    """The regression. account_switch answers 201, not 200."""
    for code in (200, 201, 202, 204):
        csp = session_for(code)
        try:
            csp.switch_account("f721995d-d2f1-4732-8a0b-f985d91413d0")
            ok = True
        except csp_api.CspAuthError:
            ok = False
        check(ok, f"switch_account accepts HTTP {code}")


def test_switch_account_still_rejects_failures():
    for code in (400, 401, 403, 404, 500):
        csp = session_for(code)
        try:
            csp.switch_account("x")
            ok = False
        except csp_api.CspAuthError:
            ok = True
        check(ok, f"switch_account rejects HTTP {code}")


def test_login_accepts_every_2xx():
    for code in (200, 201):
        csp = csp_api.CspSession(email="lab@example.com", password="x")
        # sign_in must return the code under test, so answer it directly.
        csp.session = type("S", (), {
            "post": lambda self, url, **kw: FakeResponse(code, {"jwt": "j"})
        })()
        try:
            csp.login()
            ok = True
        except csp_api.CspAuthError:
            ok = False
        check(ok, f"login accepts HTTP {code}")


def test_create_api_key_accepts_every_2xx():
    for code in (200, 201):
        csp = session_for(code, {"result": {"key": "abc123"}})
        try:
            key = csp.create_api_key()
            ok = key == "abc123"
        except csp_api.CspError:
            ok = False
        check(ok, f"create_api_key accepts HTTP {code}")


def test_api_key_expiry_is_relative_and_within_the_cap():
    """
    A hardcoded expiry is wrong in both directions.

    2027-12-31 was rejected with "expiration date cannot be later than
    2027-10-09" - a rolling ~13 month cap, so no literal stays valid.
    """
    from datetime import datetime, timedelta, timezone

    stamp = csp_api._iso_days_from_now(30)
    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.000Z").replace(
        tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    check(parsed > now, "computed expiry is in the future")
    check(parsed < now + timedelta(days=31), "computed expiry is ~30 days out")
    check(parsed < now + timedelta(days=390),
          "computed expiry is inside the CSP 13-month cap")
    check(stamp.endswith("Z") and ".000Z" in stamp,
          "expiry format matches what the CSP accepts")


def test_expiry_ceiling_parsed_from_the_real_error():
    """The verbatim rejection from the failing lab start."""
    body = ('{"error":[{"message":"HTTP interceptor error: expiration date '
            'cannot be later than 2027-10-09"}]}')
    ceiling = csp_api._expiry_ceiling(body)
    check(ceiling is not None, "ceiling extracted from the CSP error")
    check(ceiling is not None and ceiling.startswith("2027-10-08"),
          f"ceiling backs off a day from the stated cap (got {ceiling})")

    check(csp_api._expiry_ceiling('{"error":"something else"}') is None,
          "unrelated errors yield no ceiling")
    check(csp_api._expiry_ceiling("") is None, "empty body yields no ceiling")
    check(csp_api._expiry_ceiling("later than not-a-date") is None,
          "unparseable date yields no ceiling")


def test_create_api_key_retries_against_the_cap():
    """A capped expiry must self-heal rather than fail the lab."""
    class CappingSession:
        def __init__(self):
            self.attempts = []

        def post(self, url, **kwargs):
            expires = kwargs["json"]["expires_at"]
            self.attempts.append(expires)
            if len(self.attempts) == 1:
                return FakeResponse(400, text=(
                    '{"error":[{"message":"expiration date cannot be later '
                    'than 2027-10-09"}]}'))
            return FakeResponse(201, {"result": {"key": "healed"}})

    csp = csp_api.CspSession(email="lab@example.com", password="x")
    csp.session = CappingSession()
    csp.jwt = "jwt"

    try:
        key = csp.create_api_key(lifetime_days=5000)
    except csp_api.CspError:
        key = None

    check(key == "healed", "create_api_key retries with the capped expiry")
    check(len(csp.session.attempts) == 2, "exactly one retry was made")
    check(len(csp.session.attempts) == 2
          and csp.session.attempts[1].startswith("2027-10-08"),
          "the retry used the ceiling from the error")


def test_unwrap_handles_every_envelope():
    """The CSP uses results, result, a bare list, and sometimes items."""
    cases = [
        ({"results": [{"a": 1}, {"a": 2}]}, 2, "results list"),
        ({"result": {"a": 1}}, 1, "result object"),
        ({"result": [{"a": 1}]}, 1, "result list"),
        ([{"a": 1}, {"a": 2}, {"a": 3}], 3, "bare list"),
        ({"items": [{"a": 1}]}, 1, "items list"),
        ({}, 0, "empty object"),
    ]
    for body, expected, label in cases:
        got = len(csp_api._unwrap(body))
        check(got == expected, f"_unwrap handles {label} ({got} == {expected})")


def test_auth_header_selection():
    """API key preferred when present; JWT used when prefer_jwt is set."""
    csp = csp_api.CspSession(api_key="KEY", email="a@b.c", password="x")
    csp.jwt = "JWT"

    h = csp._headers()
    check(h["Authorization"] == "Token KEY", "api key gives 'Token <key>'")

    h = csp._headers(prefer_jwt=True)
    check(h["Authorization"] == "Bearer JWT", "prefer_jwt gives 'Bearer <jwt>'")

    # No credential at all must raise rather than send an unauthenticated call.
    bare = csp_api.CspSession.__new__(csp_api.CspSession)
    bare.api_key = None
    bare.jwt = None
    try:
        bare._headers()
        ok = False
    except csp_api.CspAuthError:
        ok = True
    check(ok, "no credential raises CspAuthError")


def main():
    print("\ncsp_api regression tests\n")
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
