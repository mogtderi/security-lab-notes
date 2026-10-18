#!/usr/bin/env python3
"""
check_dnn_installer.py
Lab tool for CVE-2015-2794 (DotNetNuke <= 7.4.0 unauthenticated install wizard).

Checks ONE target you specify whether the DNN install wizard is reachable
without authentication. This is a detection check only: it requests the
page and looks at the response, it does NOT submit the install form and
does NOT create any account.

Use only against systems you own or are explicitly authorized to test.

Usage (command line):
    python3 check_dnn_installer.py https://your-lab-vm.local
    python3 check_dnn_installer.py your-lab-vm.local --timeout 5

Usage (double-click):
    Just run the file. It will ask you for the target and press Enter to
    confirm, and the window stays open at the end so you can read the result.

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

# ---------------------------------------------------------------- colors ---
# Plain ANSI codes (no extra dependency). Windows 10+ terminals support
# these natively; colorama (if installed) is used only to enable them on
# older consoles, and everything still works fine without it.
try:
    import colorama
    colorama.init()
except ImportError:
    pass

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def banner() -> None:
    print(c("=" * 60, CYAN))
    print(c("  DNN Install Wizard Checker — CVE-2015-2794", BOLD + CYAN))
    print(c("  Lab / authorized-testing use only", DIM))
    print(c("=" * 60, CYAN))
    print()


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"Could not parse target: {raw!r}")
    return f"{parsed.scheme}://{parsed.netloc}"


def check(target: str, timeout: float) -> int:
    base = normalize_target(target)
    url = base + INSTALL_PATH + QUERY

    print(c("[*]", CYAN), "Target base URL :", c(base, BOLD))
    print(c("[*]", CYAN), "Requesting      :", url)

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        print(c("[!]", RED), f"Request failed: {exc}")
        return 2

    status_color = GREEN if resp.status_code < 400 else YELLOW
    print(c("[*]", CYAN), "HTTP status     :", c(str(resp.status_code), status_color))
    if resp.history:
        print(c("[*]", CYAN), "Redirected to   :", resp.url)

    body = resp.text or ""
    hit = resp.status_code == 200 and any(marker in body for marker in VULNERABLE_MARKERS)

    print()
    if hit:
        print(c("[!!] LIKELY VULNERABLE", BOLD + RED))
        print(c("     The install wizard responded directly, without authentication.", RED))
        print(c("     This matches CVE-2015-2794 (DotNetNuke <= 7.4.0).", RED))
        print(c("     Fix: upgrade to DNN 7.4.1+, or block /Install/ at the web server / firewall.", YELLOW))
    elif resp.status_code in (301, 302, 303, 307, 308, 401, 403, 404):
        print(c("[OK] Not vulnerable to this check", BOLD + GREEN))
        print(c("     The install path is blocked or redirected", GREEN))
        print(c("     (patched version, or the installer folder was removed/locked down).", GREEN))
    else:
        print(c("[?] Inconclusive", BOLD + YELLOW))
        print(c("    Got a response, but it didn't match a known vulnerable or patched pattern.", YELLOW))
        print(c("    Review the response manually before drawing conclusions.", YELLOW))

    return 0


def run_interactive() -> int:
    """No command-line arguments were given (e.g. the file was double-clicked):
    ask the user for the target instead of exiting immediately."""
    banner()
    print(c("No target was given on the command line, so let's ask for one.", DIM))
    print(c("Only point this at a system you own or are authorized to test", YELLOW) +
          c(" (e.g. your lab VM's address, like 192.168.56.10 or localhost).", YELLOW))
    print()
    try:
        target = input(c("Target host or URL: ", MAGENTA)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return 2

    if not target:
        print(c("[!] No target entered.", RED))
        input(c("\nPress Enter to close...", DIM))
        return 2

    print()
    rc = check(target, timeout=10.0)
    input(c("\nPress Enter to close...", DIM))
    return rc


def main() -> None:
    if len(sys.argv) == 1:
        # Double-clicked, or run with no arguments at all: go interactive
        # instead of printing a usage error and closing immediately.
        sys.exit(run_interactive())

    parser = argparse.ArgumentParser(
        description="Check a single DNN target for the unauthenticated install wizard (CVE-2015-2794). "
        "Lab / authorized-testing use only."
    )
    parser.add_argument("target", help="Target host or URL, e.g. your-lab-vm.local or https://your-lab-vm.local")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    banner()
    try:
        sys.exit(check(args.target, args.timeout))
    except ValueError as exc:
        print(c(f"[!] {exc}", RED))
        sys.exit(2)


if __name__ == "__main__":
    main()
