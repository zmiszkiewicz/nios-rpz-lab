#!/usr/bin/env python3
"""
Minimal Infoblox Cloud Services Portal client shared by every script here.

Copy-adapted from the login / account-switch / API-key helpers used across this
organisation's labs (tech-summit-vai-live/scripts/deploy_api_key.py,
app-migration-niosx/.../enable_service_dns.py,
secure-ai-infoblox/scripts/user_provision.py), consolidated into one class so
the eight scripts in this lab stop reimplementing the same three requests
slightly differently.

Two authentication modes, because the CSP needs both and they are not
interchangeable:

    JWT       email + password, then an account switch into the sandbox.
              Required for the identity and infrastructure planes:
              /v2/*, /atlas-host-activation/*, /api/infra/*.

    API key   a token minted inside the sandbox account.
              Required for the Threat Defense planes: /api/atcfw/*.
              Carries its own account scope, so no switch is needed.

A single call site rarely cares which it is holding, so `request()` picks
whichever credential is present and prefers the API key when both are.

Configuration comes from the environment, matching the convention in the other
labs:

    INFOBLOX_EMAIL        CSP admin email, for JWT auth
    INFOBLOX_PASSWORD     CSP admin password
    TF_VAR_ddi_api_key    sandbox-scoped API key (also read as
                          BLOXONE_API_KEY / CSP_API_KEY)
    CSP_URL               override the base host (default csp.infoblox.com)
"""

import json
import logging
import os
import sys
import time

import requests

DEFAULT_TIMEOUT = 45

# Statuses worth trying again. 429 and the 5xx family are transient; the CSP
# rate-limits bursts during lab starts when many participants begin at once.
RETRY_STATUSES = {429, 500, 502, 503, 504}


def _ok(response):
    """
    True for any 2xx.

    The CSP is not consistent about which success code it returns for a given
    operation: /v2/session/account_switch answers 201, /v2/session/users/sign_in
    answers 200, and /v2/current_api_keys has been seen to do either. Checking
    for a specific code is therefore always wrong eventually.

    This cost a live lab start. An earlier version of switch_account() accepted
    only 200, so it rejected 23 consecutive *successful* 201 responses - each
    one carrying a perfectly good JWT in its body - and the retry loop around
    it reported the result as a four-minute propagation timeout. The reference
    implementations in this organisation all use requests' raise_for_status(),
    which accepts any 2xx and never had the problem.
    """
    return 200 <= response.status_code < 300


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def get_logger(name):
    """Console logger with a consistent shape across every script in the lab."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s",
                                               datefmt="%H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    return logger


log = get_logger("csp_api")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class CspError(RuntimeError):
    """A CSP call returned a non-success status."""

    def __init__(self, method, url, status, body):
        self.method = method
        self.url = url
        self.status = status
        self.body = body or ""
        super().__init__(f"{method} {url} -> HTTP {status}: {self.body[:400]}")


class CspAuthError(RuntimeError):
    """No usable credential, or the CSP rejected the one supplied."""


class EndpointNotFound(RuntimeError):
    """None of the candidate paths for an operation exist on this tenant."""


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class CspSession:
    """Thin, synchronous CSP wrapper. One instance per tenant."""

    def __init__(self, base_url=None, email=None, password=None, api_key=None,
                 timeout=DEFAULT_TIMEOUT):
        host = base_url or os.getenv("CSP_URL", "csp.infoblox.com")
        host = host.replace("https://", "").replace("http://", "").rstrip("/")
        self.base_url = f"https://{host}"

        self.email = email or os.getenv("INFOBLOX_EMAIL")
        self.password = password or os.getenv("INFOBLOX_PASSWORD")
        self.api_key = api_key or _api_key_from_env()

        self.timeout = timeout
        self.jwt = None
        self.account_id = None
        self.session = requests.Session()

        self._endpoint_cache = {}

    # -- authentication ------------------------------------------------------ #

    def login(self):
        """Exchange email and password for a JWT. Returns the JWT."""
        if not self.email or not self.password:
            raise CspAuthError(
                "INFOBLOX_EMAIL and INFOBLOX_PASSWORD are required for JWT auth."
            )

        r = self.session.post(
            f"{self.base_url}/v2/session/users/sign_in",
            json={"email": self.email, "password": self.password},
            timeout=self.timeout,
        )
        if not _ok(r):
            raise CspAuthError(
                f"CSP rejected the credentials for {self.email} (HTTP {r.status_code})."
            )

        self.jwt = r.json().get("jwt")
        if not self.jwt:
            raise CspAuthError("CSP sign-in succeeded but returned no JWT.")
        log.info("Authenticated with the CSP as %s", self.email)
        return self.jwt

    def switch_account(self, account_id=None):
        """
        Re-scope the JWT to a sandbox account. Returns the new JWT.

        Without this the JWT is scoped to the parent account and every
        infrastructure call silently operates on the wrong tenant, which is far
        worse than an error.
        """
        account_id = account_id or read_state("sandbox_id.txt")
        if not account_id:
            raise CspAuthError(
                "No account to switch to. Pass account_id or create "
                "sandbox_id.txt with allocate_sandbox.py first."
            )
        if not self.jwt:
            self.login()

        r = self.session.post(
            f"{self.base_url}/v2/session/account_switch",
            headers={"Authorization": f"Bearer {self.jwt}",
                     "Content-Type": "application/json"},
            json={"id": f"identity/accounts/{account_id}"},
            timeout=self.timeout,
        )
        # account_switch answers 201, not 200. Accept any 2xx.
        if not _ok(r):
            raise CspAuthError(
                f"Could not switch into account {account_id} (HTTP {r.status_code}): "
                f"{r.text[:200]}"
            )

        self.jwt = r.json().get("jwt")
        self.account_id = account_id
        log.info("Switched into sandbox account %s", account_id)
        return self.jwt

    def connect(self, account_id=None):
        """login() + switch_account(), the pair almost every script needs."""
        self.login()
        self.switch_account(account_id)
        return self

    def create_api_key(self, name="Instruqt", expires_at="2027-12-31T23:59:59.000Z"):
        """
        Mint an API key inside the currently scoped account.

        Stores it on the session so subsequent calls prefer it, and returns the
        raw key. The caller is responsible for persisting it.
        """
        if not self.jwt:
            raise CspAuthError("create_api_key needs a JWT; call connect() first.")

        r = self.session.post(
            f"{self.base_url}/v2/current_api_keys",
            headers={"Authorization": f"Bearer {self.jwt}",
                     "Content-Type": "application/json"},
            json={"name": name, "expires_at": expires_at},
            timeout=self.timeout,
        )
        if not _ok(r):
            raise CspError("POST", "/v2/current_api_keys", r.status_code, r.text)

        key = (r.json().get("result") or {}).get("key")
        if not key:
            raise CspError("POST", "/v2/current_api_keys", r.status_code,
                           "response contained no key")

        self.api_key = key
        log.info("Created API key %r in account %s", name, self.account_id or "current")
        return key

    # -- verbs --------------------------------------------------------------- #

    def _headers(self, prefer_jwt=False):
        """
        Auth header for a request.

        The API key is preferred when present because it is account-scoped and
        cannot drift, but the identity and infrastructure planes only accept a
        JWT, so those call sites pass prefer_jwt.
        """
        if prefer_jwt or not self.api_key:
            if not self.jwt:
                if self.api_key:
                    return {"Authorization": f"Token {self.api_key}",
                            "Content-Type": "application/json"}
                raise CspAuthError(
                    "No credential available. Set TF_VAR_ddi_api_key, or "
                    "INFOBLOX_EMAIL and INFOBLOX_PASSWORD."
                )
            return {"Authorization": f"Bearer {self.jwt}",
                    "Content-Type": "application/json"}
        return {"Authorization": f"Token {self.api_key}",
                "Content-Type": "application/json"}

    def request(self, method, path, payload=None, params=None, prefer_jwt=False,
                retries=3, expect=None):
        """
        One CSP call, with retries on transient statuses.

        Returns the decoded JSON body, or {} for an empty 204. Raises CspError
        on a status outside `expect` (default: any 2xx).
        """
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        last = None

        for attempt in range(1, retries + 1):
            try:
                r = self.session.request(
                    method, url,
                    headers=self._headers(prefer_jwt=prefer_jwt),
                    json=payload,
                    params=params,
                    timeout=self.timeout,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                last = str(exc)
                if attempt < retries:
                    delay = min(2 ** attempt, 20)
                    log.debug("%s %s failed (%s), retrying in %ds",
                              method, url, exc, delay)
                    time.sleep(delay)
                    continue
                raise CspError(method, url, 0, f"transport error: {last}")

            ok = (r.status_code in expect) if expect else (200 <= r.status_code < 300)
            if ok:
                if not r.text.strip():
                    return {}
                try:
                    return r.json()
                except ValueError:
                    return {"_raw": r.text}

            if r.status_code in RETRY_STATUSES and attempt < retries:
                delay = min(2 ** attempt, 20)
                log.debug("%s %s -> HTTP %d, retrying in %ds",
                          method, url, r.status_code, delay)
                time.sleep(delay)
                continue

            raise CspError(method, url, r.status_code, r.text)

        raise CspError(method, url, 0, f"exhausted retries: {last}")

    def get(self, path, **params):
        return self.request("GET", path, params=params or None)

    def post(self, path, payload=None):
        return self.request("POST", path, payload=payload or {})

    def put(self, path, payload=None):
        return self.request("PUT", path, payload=payload or {})

    def patch(self, path, payload=None):
        return self.request("PATCH", path, payload=payload or {})

    def delete(self, path):
        return self.request("DELETE", path)

    def results(self, path, **params):
        """
        GET a collection and return its list of records.

        The CSP is inconsistent about the envelope: most planes use `results`,
        a few use `result`, and a couple return a bare list. Callers should not
        have to care.
        """
        body = self.get(path, **params)
        return _unwrap(body)

    # -- defensive endpoint discovery ---------------------------------------- #

    def discover(self, purpose, candidates, prefer_jwt=False, params=None):
        """
        First candidate path that this tenant actually answers.

        Application Discovery is not in any published Infoblox API document and
        /api/atcfw/v1/openapi.json needs credentials to read, so the exact paths
        could not be confirmed while this lab was written. Rather than hardcode
        a guess that fails opaquely six months from now, each operation carries
        a candidate list and the tenant decides.

        A 401 or 403 counts as "exists but not permitted" and is reported as
        such, because that means the path is right and the licence or role is
        the problem — a completely different fix from a wrong URL.

        Results are cached per purpose for the life of the session.
        """
        if purpose in self._endpoint_cache:
            return self._endpoint_cache[purpose]

        attempts = []
        for path in candidates:
            url = f"{self.base_url}/{path.lstrip('/')}"
            try:
                r = self.session.get(
                    url,
                    headers=self._headers(prefer_jwt=prefer_jwt),
                    params=params,
                    timeout=self.timeout,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                attempts.append(f"{path}: transport error ({exc})")
                continue

            if 200 <= r.status_code < 300:
                log.info("Discovered %s endpoint: %s", purpose, path)
                self._endpoint_cache[purpose] = path
                return path

            if r.status_code in (401, 403):
                attempts.append(f"{path}: HTTP {r.status_code} (exists, not permitted)")
                continue

            attempts.append(f"{path}: HTTP {r.status_code}")

        detail = "\n  ".join(attempts)
        raise EndpointNotFound(
            f"No working endpoint for {purpose} on {self.base_url}.\n"
            f"  {detail}\n"
            f"Run 'python3 discover_td_api.py --purpose {purpose}' to search "
            f"more widely, then add the winning path to the candidate list."
        )

    def try_discover(self, purpose, candidates, **kwargs):
        """discover() that returns None instead of raising."""
        try:
            return self.discover(purpose, candidates, **kwargs)
        except EndpointNotFound as exc:
            log.warning("%s", exc)
            return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _api_key_from_env():
    for name in ("TF_VAR_ddi_api_key", "BLOXONE_API_KEY", "CSP_API_KEY",
                 "INFOBLOX_API_KEY"):
        value = os.getenv(name)
        if value:
            return value
    return None


def _unwrap(body):
    """Records out of whichever envelope the CSP used."""
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for key in ("results", "result", "items", "data"):
        value = body.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
    return []


def state_dir():
    """
    Directory holding the small text files the lifecycle scripts exchange.

    Defaults to the scripts directory so a script works when run from anywhere,
    which matters because the challenge tabs open in different working
    directories than setup-shell uses.
    """
    return os.getenv("LAB_STATE_DIR") or os.path.dirname(os.path.abspath(__file__))


def read_state(filename, default=None):
    """Contents of a state file, or default if it is missing or empty."""
    path = filename if os.path.isabs(filename) else os.path.join(state_dir(), filename)
    try:
        with open(path) as handle:
            value = handle.read().strip()
            return value or default
    except OSError:
        return default


def write_state(filename, value):
    """Write a state file, returning the path written."""
    path = filename if os.path.isabs(filename) else os.path.join(state_dir(), filename)
    with open(path, "w") as handle:
        handle.write(str(value).strip() + "\n")
    return path


def fail(reason, reason_file="/tmp/lab_check_reason.txt"):
    """
    Record a single-sentence failure reason and exit non-zero.

    Challenge check scripts read the file and hand it to Instruqt's
    fail-message, so the participant sees why rather than a bare red cross.
    """
    log.error(reason)
    try:
        with open(reason_file, "w") as handle:
            handle.write(reason.strip() + "\n")
    except OSError:
        pass
    sys.exit(1)


def clear_reason(reason_file="/tmp/lab_check_reason.txt"):
    """Remove a stale reason from an earlier failed attempt."""
    try:
        os.remove(reason_file)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# CLI — inspect a tenant without writing a throwaway script
# --------------------------------------------------------------------------- #

def _main():
    """
        python3 csp_api.py whoami
        python3 csp_api.py get /api/atcfw/v1/security_policies
        python3 csp_api.py get /api/infra/v1/detail_hosts
    """
    import argparse

    parser = argparse.ArgumentParser(description="Poke the Infoblox CSP.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("whoami")
    getter = sub.add_parser("get")
    getter.add_argument("path")
    args = parser.parse_args()

    csp = CspSession()

    # An API key alone is enough for the Threat Defense planes; only fall back
    # to interactive login when there is no key to use.
    if not csp.api_key:
        csp.connect()

    if args.command == "whoami":
        print(json.dumps({
            "base_url": csp.base_url,
            "auth": "api-key" if csp.api_key else "jwt",
            "account_id": csp.account_id or read_state("sandbox_id.txt", "unknown"),
            "sandbox_name": read_state("sandbox_name.txt", "unknown"),
        }, indent=2))
        return 0

    print(json.dumps(csp.get(args.path), indent=2)[:8000])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (CspError, CspAuthError, EndpointNotFound) as exc:
        log.error("%s", exc)
        sys.exit(1)
