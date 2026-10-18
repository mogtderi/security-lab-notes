#!/usr/bin/env python3
"""
check_dnn_installer.py
Lab tool for CVE-2015-2794 (DotNetNuke <= 7.4.0 unauthenticated install wizard).

Checks ONE target you specify whether the DNN install wizard is reachable
without authentication. This is a detection check only: it requests the
page and looks at the response, it does NOT submit the install form and
does NOT create any account.

Use only against systems you own or are explicitly authorized to test.

Usage:
    python3 check_dnn_installer.py https://your-lab-vm.local
    python3 check_dnn_installer.py your-lab-vm.local --timeout 5

Exit codes:
    0 = check completed (see printed verdict)
    2 = target unreachable / request failed
"""

import argparse
import sys
from urllib.parse import urlparse

import requests

INSTALL_PATH = "/Install/InstallWizard.aspx"
# This query string only loads the wizard page to inspect it; it never
# submits the install form, so it cannot create an account by itself.
QUERY = "?__VIEWSTATE=&culture=en-US"

# A patched DNN either blocks the path (403/404) or bounces to login.
# An unpatched, still-installed instance serves the wizard UI directly.
VULNERABLE_MARKERS = ("Installation Wizard", "Administrative Information", "dnnInstall")


def normalize_target(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"Could not parse target: {raw!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


def check(target: str, timeout: float) -> int:
    base = normalize_target(target)
    url = base + INSTALL_PATH + QUERY

    print(f"[*] Target base URL : {base}")
    print(f"[*] Requesting      : {url}")

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        print(f"[!] Request failed: {exc}")
        return 2

    print(f"[*] HTTP status     : {resp.status_code}")
    if resp.history:
        redirected_to = resp.url
        print(f"[*] Redirected to   : {redirected_to}")

    body = resp.text or ""
    hit = resp.status_code == 200 and any(marker in body for marker in VULNERABLE_MARKERS)

    print()
    if hit:
        print("[!!] LIKELY VULNERABLE: the install wizard responded directly, without authentication.")
        print("     This matches CVE-2015-2794 (DotNetNuke <= 7.4.0).")
        print("     Fix: upgrade to DNN 7.4.1+, or block /Install/ at the web server / firewall.")
    elif resp.status_code in (301, 302, 303, 307, 308) or resp.status_code in (401, 403, 404):
        print("[OK] Not vulnerable to this check: the install path is blocked or redirected")
        print("     (patched version, or the installer folder was removed/locked down).")
    else:
        print("[?] Inconclusive: got a response, but it didn't match a known vulnerable or")
        print("    patched pattern. Review the response manually before drawing conclusions.")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check a single DNN target for the unauthenticated install wizard (CVE-2015-2794). "
        "Lab / authorized-testing use only."
    )
    parser.add_argument("target", help="Target host or URL, e.g. your-lab-vm.local or https://your-lab-vm.local")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    try:
        sys.exit(check(args.target, args.timeout))
    except ValueError as exc:
        print(f"[!] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
