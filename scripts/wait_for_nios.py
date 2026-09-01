#!/usr/bin/env python3
"""
Block until the Grid Master and the Windows desktop are both usable.

Called from track_scripts/setup-shell after `terraform apply`. A fresh vNIOS
needs six to ten minutes to boot, apply its temporary licence and start the web
UI; Windows takes about four. Waiting on the real readiness signal beats the
fixed `sleep 480` the older labs in this org use, because it finishes as soon as
the grid is actually up and it fails loudly if it never does.

Usage:
    wait_for_nios.py                  wait for both
    wait_for_nios.py --nios-only      skip the desktop
    wait_for_nios.py --timeout 1200   override the per-component budget

Environment: GM_IP, DESKTOP_IP, TF_VAR_windows_admin_password.
"""

import argparse
import sys
import time

from desktop_dns import DesktopUnreachable, wait_for_desktop
from nios_wapi import NiosWapi, WapiUnreachable, get_logger

log = get_logger("wait_for_nios")


def main():
    parser = argparse.ArgumentParser(description="Wait for the lab to become ready.")
    parser.add_argument("--timeout", type=int, default=900,
                        help="Per-component budget in seconds (default: 900)")
    parser.add_argument("--nios-only", action="store_true")
    parser.add_argument("--desktop-only", action="store_true")
    args = parser.parse_args()

    started = time.time()
    failures = []

    if not args.desktop_only:
        log.info("Waiting for the NIOS Grid Master...")
        try:
            wapi = NiosWapi()
            wapi.wait_until_ready(timeout=args.timeout)
            log.info("Grid Master ready after %ds", int(time.time() - started))
        except WapiUnreachable as exc:
            failures.append(f"Grid Master: {exc}")

    if not args.nios_only:
        log.info("Waiting for the Windows desktop...")
        mark = time.time()
        try:
            wait_for_desktop(timeout=args.timeout)
            log.info("Desktop ready after %ds", int(time.time() - mark))
        except DesktopUnreachable as exc:
            failures.append(f"Desktop: {exc}")

    if failures:
        for failure in failures:
            log.error("%s", failure)
        return 1

    log.info("Lab ready in %ds", int(time.time() - started))
    return 0


if __name__ == "__main__":
    sys.exit(main())
