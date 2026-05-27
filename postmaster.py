#!/usr/bin/env python3
"""
POSTMaster
==========
Modular framework for assessing SMTP services (port 25 by default).

Tool created by jrhackerman.
Version: 1.0

LEGAL NOTICE
------------
Use ONLY against systems for which you have explicit, written authorization.
Unauthorized scanning or relay-abuse testing is illegal in most jurisdictions.

Usage:
    python postmaster.py -t mail.example.com -p 25 --all
    python postmaster.py -t 10.0.0.5 --relay --internal-relay
    python postmaster.py -t mail.example.com --enum --users wordlists/users.txt
"""
import argparse
import json
import sys
import os
from datetime import datetime

# Ensure modules are importable regardless of CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.session import SMTPSession
from core.reporter import Reporter
from modules import banner, enumeration, auth_probe, relay, internal_relay, starttls


BANNER = r"""
  ____   ___  ____ _____ __  __           _
 |  _ \ / _ \/ ___|_   _|  \/  | __ _ ___| |_ ___ _ __
 | |_) | | | \___ \ | | | |\/| |/ _` / __| __/ _ \ '__|
 |  __/| |_| |___) || | | |  | | (_| \__ \ ||  __/ |
 |_|    \___/|____/ |_| |_|  |_|\__,_|___/\__\___|_|

      SMTP Penetration Testing Framework  v1.0
      ─────────────────────────────────────────
              Tool created by  jrhackerman
"""

TOOL_NAME = "POSTMaster"
AUTHOR = "jrhackerman"
VERSION = "1.0"


def parse_args():
    p = argparse.ArgumentParser(
        prog="postmaster",
        description="POSTMaster — SMTP penetration testing framework  ·  by jrhackerman",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {VERSION} (by {AUTHOR})")
    p.add_argument("-t", "--target", required=True, help="Target host or IP")
    p.add_argument("-p", "--port", type=int, default=25, help="SMTP port (default: 25)")
    p.add_argument("--timeout", type=int, default=10, help="Socket timeout in seconds")
    p.add_argument("--helo", default="mail.localdomain",
                   help="HELO/EHLO domain to advertise (default: mail.localdomain)")

    # Module toggles
    p.add_argument("--all", action="store_true",
                   help="Run every module (banner, starttls, auth, enum, relay, internal-relay)")
    p.add_argument("--banner", action="store_true", help="Banner grab + EHLO fingerprint")
    p.add_argument("--starttls", action="store_true", help="STARTTLS / TLS probe")
    p.add_argument("--auth", action="store_true", help="Enumerate AUTH mechanisms")
    p.add_argument("--enum", action="store_true", help="User enumeration via VRFY/EXPN/RCPT")
    p.add_argument("--relay", action="store_true", help="External open-relay tests (16+ vectors)")
    p.add_argument("--internal-relay", action="store_true",
                   help="Internal open-relay tests (backend abuse paths)")

    # Inputs
    p.add_argument("--users", help="File of usernames for enumeration (one per line)")
    p.add_argument("--from-addr", default="test@example.com",
                   help="MAIL FROM address used in relay tests")
    p.add_argument("--to-addr",
                   help="Recipient address you control (REQUIRED for relay tests "
                        "— this is where successful relays will be delivered)")
    p.add_argument("--internal-domain",
                   help="Internal domain the target serves (e.g. corp.local). "
                        "Required for internal-relay tests.")

    # Output
    p.add_argument("-o", "--output", help="Write JSON report to this path")
    p.add_argument("--html", help="Write HTML report to this path")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose SMTP transcripts")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress banner & info chatter")
    return p.parse_args()


def main():
    args = parse_args()
    if not args.quiet:
        print(BANNER)

    # Default to --all if no module flag set
    selected = any([args.banner, args.starttls, args.auth, args.enum,
                    args.relay, args.internal_relay])
    if args.all or not selected:
        args.banner = args.starttls = args.auth = args.enum = True
        args.relay = args.internal_relay = True

    reporter = Reporter(target=args.target, port=args.port)
    reporter.start()

    session = SMTPSession(
        host=args.target,
        port=args.port,
        timeout=args.timeout,
        helo_domain=args.helo,
        verbose=args.verbose,
    )

    try:
        if args.banner:
            reporter.add("banner", banner.run(session))
        if args.starttls:
            reporter.add("starttls", starttls.run(session))
        if args.auth:
            reporter.add("auth", auth_probe.run(session))
        if args.enum:
            users = _load_users(args.users)
            reporter.add("enumeration", enumeration.run(session, users))
        if args.relay:
            if not args.to_addr:
                print("[!] --relay skipped: --to-addr is required to validate delivery.")
            else:
                reporter.add("relay", relay.run(
                    session,
                    from_addr=args.from_addr,
                    to_addr=args.to_addr,
                ))
        if args.internal_relay:
            if not args.internal_domain:
                print("[!] --internal-relay skipped: --internal-domain is required.")
            else:
                reporter.add("internal_relay", internal_relay.run(
                    session,
                    internal_domain=args.internal_domain,
                    from_addr=args.from_addr,
                    to_addr=args.to_addr,
                ))
    finally:
        session.close()

    reporter.finish()
    reporter.print_summary()

    if args.output:
        reporter.write_json(args.output)
        print(f"[+] JSON report saved: {args.output}")
    if args.html:
        reporter.write_html(args.html)
        print(f"[+] HTML report saved: {args.html}")

    if not args.quiet:
        print(f"\n[ done ]  {TOOL_NAME} v{VERSION}  ·  by {AUTHOR}\n")


def _load_users(path):
    if not path:
        return ["root", "admin", "administrator", "postmaster",
                "webmaster", "mail", "test", "user", "guest"]
    with open(path) as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(130)
