"""
modules.relay
=============
External Open Relay Testing.

An "open relay" is an SMTP server that accepts mail from arbitrary senders
to arbitrary external recipients (i.e. neither the MAIL FROM nor RCPT TO
belongs to a domain the server is authoritative for).

This module implements the canonical 17-test matrix used by nmap's
smtp-open-relay NSE script and most commercial scanners. The matrix exists
because broken/legacy MTAs sometimes reject the naive form
("MAIL FROM:<a@x>", "RCPT TO:<b@y>") but accept obfuscated variants:

  - source-routed addresses           (@hop:user@dest)
  - percent-hack                      (user%dest@hop)
  - bang paths                        (hop!user)
  - quoted local-parts                ("user@dest")
  - IP-literal recipients             (user@[1.2.3.4])
  - HELO/MAIL-domain reflection       (re-use target's own domain)
  - missing/empty MAIL FROM           (<>, the bounce sender)

For each test we issue the RCPT TO and check the server's reply:
  2xx        -> relay candidate
  550/553/554 with "relay denied" / "not allowed" -> properly closed
  others     -> inconclusive (note it, no exploit attempt)

If --to-addr is supplied we go one step further and complete a DATA stage
with a benign payload so the operator can confirm out-of-band delivery.

DO NOT run this without written authorization.
"""
import time


def _local_user_for(host):
    """A recipient that is definitely NOT the target server's domain."""
    return f"relay-test-{int(time.time())}"


def build_test_matrix(target_host, from_addr, to_addr):
    """
    Returns a list of (label, mail_from, rcpt_to, description) tuples.

    `to_addr` should be a mailbox the operator controls, on a domain the
    target is NOT authoritative for. The MAIL FROM is varied to also detect
    SPF/return-path-based relay decisions.
    """
    # Decompose to_addr into user + domain
    if "@" not in to_addr:
        raise ValueError("--to-addr must be a full email address (user@domain)")
    to_user, to_domain = to_addr.split("@", 1)
    target_domain = target_host
    src_user, src_domain = (from_addr.split("@", 1) + ["example.com"])[:2]

    tests = [
        # 1. The naive case: arbitrary sender, arbitrary recipient
        ("T1_basic",
         f"<{from_addr}>",
         f"<{to_addr}>",
         "Direct external -> external relay"),

        # 2. Empty MAIL FROM (bounce / null sender) — sometimes whitelisted
        ("T2_null_sender",
         "<>",
         f"<{to_addr}>",
         "Null sender (bounce) to external recipient"),

        # 3. Sender forged to look local (target's own domain)
        ("T3_forged_local_sender",
         f"<{src_user}@{target_domain}>",
         f"<{to_addr}>",
         "Forged local sender, external recipient"),

        # 4. Sender forged to look like postmaster
        ("T4_postmaster_sender",
         f"<postmaster@{target_domain}>",
         f"<{to_addr}>",
         "Forged postmaster sender, external recipient"),

        # 5. Source-routed recipient: @target:user@external
        ("T5_source_route",
         f"<{from_addr}>",
         f"<@{target_domain}:{to_addr}>",
         "Source-routed recipient via target (RFC 821 deprecated, often abused)"),

        # 6. Percent-hack: user%destdomain@targetdomain
        ("T6_percent_hack",
         f"<{from_addr}>",
         f"<{to_user}%{to_domain}@{target_domain}>",
         "Percent-hack obfuscation (legacy sendmail vector)"),

        # 7. Bang path: targetdomain!destdomain!user
        ("T7_bang_path",
         f"<{from_addr}>",
         f"<{target_domain}!{to_domain}!{to_user}>",
         "UUCP-style bang-path routing"),

        # 8. Double @: user@destdomain@targetdomain
        ("T8_double_at",
         f"<{from_addr}>",
         f"<{to_user}@{to_domain}@{target_domain}>",
         "Double-@ rewrite trick"),

        # 9. Quoted local-part containing destination
        ("T9_quoted_localpart",
         f"<{from_addr}>",
         f"<\"{to_addr}\"@{target_domain}>",
         "Quoted local-part hiding external recipient"),

        # 10. Quoted recipient (RFC 5321 quoted form)
        ("T10_quoted_recipient",
         f"<{from_addr}>",
         f"<\"{to_user}@{to_domain}\">",
         "Quoted-string recipient form"),

        # 11. Recipient with no angle brackets (some legacy MTAs)
        ("T11_no_brackets",
         f"{from_addr}",
         f"{to_addr}",
         "RCPT TO without angle brackets"),

        # 12. Recipient with extra brackets / whitespace
        ("T12_whitespace",
         f"<{from_addr}>",
         f"< {to_addr} >",
         "Whitespace padding inside angle brackets"),

        # 13. IP literal as routing host
        ("T13_ip_literal_route",
         f"<{from_addr}>",
         f"<@[{target_domain}]:{to_addr}>",
         "Source route with IP literal"),

        # 14. Backslash escape
        ("T14_backslash",
         f"<{from_addr}>",
         f"<{to_user}\\@{to_domain}@{target_domain}>",
         "Backslash-escaped @ in local part"),

        # 15. Trailing dot domain
        ("T15_trailing_dot",
         f"<{from_addr}>",
         f"<{to_user}@{to_domain}.>",
         "Trailing-dot FQDN recipient"),

        # 16. Mixed-case domain (some filters are case-sensitive)
        ("T16_mixed_case",
         f"<{from_addr}>",
         f"<{to_user}@{to_domain.upper()}>",
         "Uppercased recipient domain"),

        # 17. Postmaster recipient at external domain (almost always required by RFC,
        #     can reveal whether server distinguishes "required" from "relay")
        ("T17_external_postmaster",
         f"<{from_addr}>",
         f"<postmaster@{to_domain}>",
         "External postmaster recipient"),
    ]
    return tests


def run(session, from_addr, to_addr):
    findings = []
    data = {"tests": [], "open_relay": False, "delivered": []}
    print("\n[*] Module: External Open Relay Tests (17 vectors)")
    print(f"    Will probe relay  {from_addr}  ->  {to_addr}  via {session.host}")

    try:
        tests = build_test_matrix(session.host, from_addr, to_addr)
    except ValueError as e:
        findings.append({"severity": "info", "title": "Relay tests skipped",
                         "detail": str(e)})
        return {"data": data, "findings": findings}

    accepted_labels = []

    for label, mail_from, rcpt_to, desc in tests:
        result = {"label": label, "description": desc,
                  "mail_from": mail_from, "rcpt_to": rcpt_to,
                  "mail_from_code": None, "rcpt_code": None,
                  "rcpt_reply": None, "data_code": None,
                  "accepted": False, "delivered_attempt": False}
        try:
            session.reconnect()
            session.ehlo()
            mf = session.cmd(f"MAIL FROM:{mail_from}")
            result["mail_from_code"] = session.code(mf)
            if result["mail_from_code"] not in (250,):
                result["rcpt_reply"] = f"(MAIL FROM rejected: {mf.strip()})"
                data["tests"].append(result)
                print(f"    [-] {label:<26} MAIL FROM rejected ({result['mail_from_code']})")
                continue
            rc = session.cmd(f"RCPT TO:{rcpt_to}")
            result["rcpt_code"] = session.code(rc)
            result["rcpt_reply"] = rc.strip().splitlines()[-1] if rc else ""
            if result["rcpt_code"] in (250, 251):
                result["accepted"] = True
                accepted_labels.append(label)
                print(f"    [+] {label:<26} RCPT accepted ({result['rcpt_code']}) — relay candidate")
                # Attempt DATA so the operator can confirm via the inbox
                msg = _make_test_message(from_addr, to_addr, label, session.host)
                dr = session.data(msg)
                result["data_code"] = session.code(dr)
                result["delivered_attempt"] = result["data_code"] in (250,)
                if result["delivered_attempt"]:
                    data["delivered"].append(label)
                    print(f"        DATA accepted ({result['data_code']}) — CHECK INBOX for {label}")
            else:
                print(f"    [-] {label:<26} RCPT rejected ({result['rcpt_code']})")
        except Exception as e:
            result["error"] = str(e)
            print(f"    [!] {label:<26} ERROR: {e}")
        data["tests"].append(result)

    data["open_relay"] = bool(accepted_labels)

    # ---------- findings ----------
    if data["open_relay"]:
        sev = "critical" if data["delivered"] else "high"
        findings.append({
            "severity": sev,
            "title": "Open relay detected" if data["delivered"]
                     else "Open relay candidate (RCPT-stage accept)",
            "detail": (f"{len(accepted_labels)} test vector(s) accepted: "
                       f"{', '.join(accepted_labels)}. "
                       + (f"Delivery confirmed via DATA stage for: "
                          f"{', '.join(data['delivered'])}." if data['delivered']
                          else "DATA not accepted, but RCPT acceptance still indicates "
                               "policy weakness; verify out-of-band.")),
        })
    else:
        findings.append({
            "severity": "info",
            "title": "No external open-relay vectors succeeded",
            "detail": "All 17 relay tests were rejected at MAIL FROM or RCPT TO.",
        })

    return {"data": data, "findings": findings}


def _make_test_message(from_addr, to_addr, label, host):
    return (
        f"From: {from_addr}\r\n"
        f"To: {to_addr}\r\n"
        f"Subject: Relay Test [{label}] via {host}\r\n"
        f"X-Test-ID: {label}\r\n"
        f"\r\n"
        f"This is an authorized open-relay verification message.\r\n"
        f"Test vector: {label}\r\n"
        f"\r\n"
        f"If you received this and did not authorize the test, please contact your\r\n"
        f"mail administrator -- your MTA may be acting as an open relay.\r\n"
    )
