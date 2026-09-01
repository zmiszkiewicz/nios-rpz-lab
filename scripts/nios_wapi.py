#!/usr/bin/env python3
"""
Minimal NIOS WAPI client shared by every script in this lab.

Copy-adapted from the version-probe / auth / POST helpers in
tech-summit-security-niosx/terraform/scripts/deploy_dns_zones.py, extended with
PUT, DELETE, WAPI function calls, retries and structured logging.

Configuration comes from the environment, matching the convention in the other
Infoblox labs:

    GM_IP                 Grid Master address (Elastic IP or FQDN)
    NIOS_ADMIN_USER       defaults to "admin"
    NIOS_ADMIN_PASSWORD   falls back to TF_VAR_nios_admin_password,
                          then TF_VAR_windows_admin_password
"""

import logging
import os
import sys
import time
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Newest first. The GM is asked for each in turn until one answers 200.
WAPI_VERSIONS = ["v2.13.1", "v2.13", "v2.12.3", "v2.12", "v2.11.2", "v2.11", "v2.10"]

DEFAULT_TIMEOUT = 30


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


log = get_logger("nios_wapi")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class WapiError(RuntimeError):
    """A WAPI call returned a non-success status."""

    def __init__(self, method, url, status, body):
        self.method = method
        self.url = url
        self.status = status
        self.body = body
        super().__init__(f"{method} {url} -> HTTP {status}: {body[:400]}")


class WapiUnreachable(RuntimeError):
    """No supported WAPI version answered, or the GM never came up."""


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class NiosWapi:
    """Thin, synchronous WAPI wrapper. One instance per Grid Master."""

    def __init__(self, host=None, username=None, password=None,
                 timeout=DEFAULT_TIMEOUT, verify=False):
        self.host = host or os.getenv("GM_IP")
        self.username = username or os.getenv("NIOS_ADMIN_USER", "admin")
        self.password = password or _password_from_env()
        self.timeout = timeout
        self.verify = verify
        self.version = None

        if not self.host:
            raise WapiUnreachable("GM_IP is not set — cannot reach a Grid Master.")
        if not self.password:
            raise WapiUnreachable(
                "No NIOS admin password. Set NIOS_ADMIN_PASSWORD, "
                "TF_VAR_nios_admin_password or TF_VAR_windows_admin_password."
            )

        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = verify

    # -- connection ---------------------------------------------------------- #

    def connect(self, retries=1, delay=10):
        """Probe for a usable WAPI version. Returns the version string."""
        for attempt in range(1, retries + 1):
            for version in WAPI_VERSIONS:
                url = f"https://{self.host}/wapi/{version}/grid"
                try:
                    r = self.session.get(url, timeout=self.timeout)
                except (requests.ConnectionError, requests.Timeout):
                    # Wrong version would answer 400, not refuse the connection,
                    # so a transport error means the GM is not up yet. Stop
                    # walking versions and let the retry loop wait.
                    break
                if r.status_code == 200:
                    self.version = version
                    log.info("Connected to %s using WAPI %s", self.host, version)
                    return version
                if r.status_code in (401, 403):
                    raise WapiUnreachable(
                        f"Grid Master rejected the credentials for user "
                        f"'{self.username}' (HTTP {r.status_code})."
                    )

            if attempt < retries:
                log.info("Grid Master not ready (attempt %d/%d), waiting %ds...",
                         attempt, retries, delay)
                time.sleep(delay)

        raise WapiUnreachable(
            f"No supported WAPI version answered on https://{self.host}. "
            f"Tried: {', '.join(WAPI_VERSIONS)}."
        )

    def _url(self, path):
        if not self.version:
            self.connect()
        return f"https://{self.host}/wapi/{self.version}/{path.lstrip('/')}"

    # -- verbs --------------------------------------------------------------- #

    def get(self, path, **params):
        """GET an object type or a _ref. Returns the decoded JSON body."""
        url = self._url(path)
        r = self.session.get(url, params=params or None, timeout=self.timeout)
        if r.status_code != 200:
            raise WapiError("GET", url, r.status_code, r.text)
        return r.json()

    def get_one(self, path, **params):
        """GET expecting at most one match. Returns the object or None."""
        result = self.get(path, **params)
        if isinstance(result, dict):
            return result
        return result[0] if result else None

    def post(self, path, payload):
        """Create an object. Returns its _ref."""
        url = self._url(path)
        r = self.session.post(url, json=payload, timeout=self.timeout)
        if r.status_code != 201:
            raise WapiError("POST", url, r.status_code, r.text)
        return r.json()

    def put(self, ref, payload):
        """Update an existing object by _ref. Returns the (possibly new) _ref."""
        url = self._url(ref)
        r = self.session.put(url, json=payload, timeout=self.timeout)
        if r.status_code != 200:
            raise WapiError("PUT", url, r.status_code, r.text)
        return r.json()

    def delete(self, ref):
        """Delete an object by _ref."""
        url = self._url(ref)
        r = self.session.delete(url, timeout=self.timeout)
        if r.status_code != 200:
            raise WapiError("DELETE", url, r.status_code, r.text)
        return r.json()

    def call(self, ref, function, payload=None):
        """Invoke a WAPI function such as restartservices on an object."""
        url = f"{self._url(ref)}?_function={function}"
        r = self.session.post(url, json=payload or {}, timeout=self.timeout)
        if r.status_code not in (200, 201):
            raise WapiError("POST", url, r.status_code, r.text)
        return r.json() if r.text else {}

    def download_file(self, url, token=None):
        """
        Fetch a file offered by a fileop function, then release the download.

        The URL NIOS returns in a fileop response is built from the appliance's
        *internal* address, which is unreachable from the Instruqt shell
        container — the download hangs until it times out. Rewriting the host
        while keeping the path is the fix; credit to
        app-migration-niosx/terraform/scripts/create_gmc_cloudinit.py, which hit
        the same thing downloading the Grid Master certificate.

        Returns the raw bytes. Always calls downloadcomplete, because NIOS holds
        the file open until something does.
        """
        path = urlparse(url).path
        fixed = f"https://{self.host}{path}"
        if fixed != url:
            log.debug("Rewrote fileop URL %s -> %s", url, fixed)

        try:
            r = self.session.get(fixed, timeout=self.timeout)
            if r.status_code != 200:
                raise WapiError("GET", fixed, r.status_code, r.text)
            return r.content
        finally:
            if token:
                try:
                    self.call("fileop", "downloadcomplete", {"token": token})
                except WapiError as exc:
                    log.debug("downloadcomplete failed: %s", exc)

    # -- convenience --------------------------------------------------------- #

    def grid_ref(self):
        """_ref of the Grid object."""
        grid = self.get("grid")
        if not grid:
            raise WapiUnreachable("The Grid Master returned no grid object.")
        return grid[0]["_ref"]

    def grid_dns(self, fields=None):
        """The grid:dns object, optionally restricted to specific fields."""
        params = {}
        if fields:
            params["_return_fields+"] = ",".join(fields)
        result = self.get("grid:dns", **params)
        if isinstance(result, list):
            if not result:
                raise WapiUnreachable("No grid:dns object found.")
            return result[0]
        return result

    def members_dns(self, fields=("host_name", "enable_dns")):
        """All member:dns objects with the requested fields."""
        return self.get("member:dns", **{"_return_fields+": ",".join(fields)})

    def restart_dns(self, wait=True):
        """Restart DNS across the grid so pending changes take effect."""
        log.info("Restarting DNS services across the grid...")
        self.call(self.grid_ref(), "restartservices", {
            "member_order": "SIMULTANEOUSLY",
            "service_option": "DNS",
            "restart_option": "RESTART_IF_NEEDED",
        })
        if wait:
            # NIOS returns immediately; named needs a moment to come back.
            time.sleep(15)
        log.info("DNS restart requested.")

    def wait_until_ready(self, timeout=900, interval=20):
        """
        Block until the Grid Master answers WAPI, or raise.

        A freshly launched vNIOS takes six to ten minutes to boot, apply its
        temporary licence and start the web UI, so the default budget is
        fifteen minutes.
        """
        deadline = time.time() + timeout
        attempt = 0
        while time.time() < deadline:
            attempt += 1
            try:
                return self.connect()
            except WapiUnreachable as exc:
                if "rejected the credentials" in str(exc):
                    raise
                remaining = int(deadline - time.time())
                log.info("Grid Master not ready yet (attempt %d, %ds left)...",
                         attempt, max(remaining, 0))
                time.sleep(interval)
        raise WapiUnreachable(
            f"Grid Master at {self.host} did not answer WAPI within {timeout}s."
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _password_from_env():
    for name in ("NIOS_ADMIN_PASSWORD",
                 "TF_VAR_nios_admin_password",
                 "TF_VAR_windows_admin_password"):
        value = os.getenv(name)
        if value:
            return value
    return None


def already_exists(exc):
    """True if a WapiError is NIOS complaining the object is already there."""
    if not isinstance(exc, WapiError):
        return False
    body = (exc.body or "").lower()
    return exc.status == 400 and ("already exists" in body or "duplicate" in body)


def fail(reason, reason_file="/tmp/rpz_check_reason.txt"):
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


def clear_reason(reason_file="/tmp/rpz_check_reason.txt"):
    """Remove a stale reason from an earlier failed attempt."""
    try:
        os.remove(reason_file)
    except OSError:
        pass
