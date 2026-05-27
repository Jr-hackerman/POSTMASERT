"""
modules.internal_relay
======================
Internal Open Relay Testing.

WHY THIS IS A SEPARATE MODULE
-----------------------------
A server is correctly "closed" against the internet relay tests in modules.relay
but can still be abused from INSIDE the perimeter or from any host whose IP
the MTA trusts. Common real-world misconfigurations:

  1. trusted_networks / mynetworks too broad
     (e.g. Postfix `mynetworks = 0.0.0.0/0` or 10.0.0.0/8 on a cloud host
     that has a public IP in that range due to NAT/peering).

  2. "Internal-only" relays that authenticate by source IP rather than by
     SMTP AUTH — once a foothold is established, attacker can spray email to
     ANY internal domain (great for phishing the CEO from "it-support@corp.local").

  3. Spoofing of any internal address.
     Internal SMTP is frequently configured to accept ANY MAIL FROM, enabling
     intra-domain phishing ("CEO -> CFO" wire-fraud BEC pattern) without
     authentication.

  4. Cross-tenant / cross-domain leakage on shared mail infrastructure
     (Exchange hub transport, Postfix with multiple `virtual_mailbox_domains`,
     Microsoft 365 hybrid connectors).

  5. Backconnect to internal services
     The mail server accepts mail to URL-like or pipe-like recipients that
     trigger internal automation (e.g. `+cmd@host`, ticketing-system
     auto-create addresses).

This module ASSUMES the tester has explicit authorization and is positioned
to probe the target as an "internal" host. Pair it with --internal-domain
(e.g. corp.local) so we can build realistic-looking internal addresses.

WHAT WE TEST
------------
  IR1  Spoof internal -> internal      (intra-domain phishing)
  IR2  Spoof CEO/exec -> employee     (BEC pattern)
  IR3  Internal -> external w/o AUTH  (exfil / spam relay from inside)
  IR4  Cross-subdomain spoof          (corp.local -> finance.corp.local)
  IR5  Anonymous postmaster spoof
  IR6  Null-sender to internal        (bounce-bomb amplification)
  IR7  External -> internal acceptance with NO authentication
       (validates that the server isn't an internal-facing accept-all MX)
  IR8  Multi-recipient amplification (one MAIL FROM, many internal RCPTs)
  IR9  Plus-addressing & ext_addr backdoors  (admin+anything@internal)
  IR10 IP-literal recipient on internal name
"""
import time
import socket


def _src_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def run(session, internal_domain, from_addr, to_addr=None):
    findings = []
    data = {"source_ip": _src_ip(), "internal_domain": internal_domain,
            "tests": [], "vulnerabilities": []}
    print(f"\n[*] Module: Internal Open Relay Tests (source IP: {data['source_ip']})")
    print(f"    Internal domain: {internal_domain}")

    # Build realistic internal recipients
    spoof_sender = f"ceo@{internal_domain}"
    spoof_recipient = f"cfo@{internal_domain}"
    sub_recipient = f"admin@finance.{internal_domain}"
    multi_recipients = [f"user{i}@{internal_domain}" for i in range(1, 6)]
    plus_addr = f"admin+sysadmin@{internal_domain}"

    tests = [
        {
            "label": "IR1_intra_domain_spoof",
            "desc": "Spoofed internal sender to internal recipient (no AUTH)",
            "mail_from": f"<random.user@{internal_domain}>",
            "rcpt_tos": [f"<{spoof_recipient}>"],
            "vuln_on_accept": "INTRA-DOMAIN SPOOFING — anyone in network range can "
                              "impersonate any colleague.",
            "severity_on_accept": "high",
        },
        {
            "label": "IR2_bec_exec_spoof",
            "desc": "Spoofed CEO -> CFO (BEC / wire fraud pattern)",
            "mail_from": f"<{spoof_sender}>",
            "rcpt_tos": [f"<{spoof_recipient}>"],
            "vuln_on_accept": "EXECUTIVE IMPERSONATION — server accepts unauthenticated "
                              "mail claiming to be from a senior internal address. "
                              "Classic Business Email Compromise pre-condition.",
            "severity_on_accept": "critical",
        },
        {
            "label": "IR3_internal_to_external",
            "desc": "Internal-looking sender -> external recipient (unauth relay)",
            "mail_from": f"<{spoof_sender}>",
            "rcpt_tos": [f"<{to_addr}>"] if to_addr else None,
            "vuln_on_accept": "INTERNAL-TO-EXTERNAL RELAY — attacker can relay spam / "
                              "exfil mail through the MTA by simply claiming an "
                              "internal MAIL FROM.",
            "severity_on_accept": "critical",
        },
        {
            "label": "IR4_subdomain_spoof",
            "desc": "Cross-subdomain spoof (corp -> finance.corp)",
            "mail_from": f"<security@{internal_domain}>",
            "rcpt_tos": [f"<{sub_recipient}>"],
            "vuln_on_accept": "CROSS-SUBDOMAIN SPOOF — corporate-tier sender accepted "
                              "for subsidiary/department mailbox.",
            "severity_on_accept": "high",
        },
        {
            "label": "IR5_anonymous_postmaster",
            "desc": "Spoofed postmaster@internal sender",
            "mail_from": f"<postmaster@{internal_domain}>",
            "rcpt_tos": [f"<{spoof_recipient}>"],
            "vuln_on_accept": "POSTMASTER IMPERSONATION — high-trust address can be "
                              "forged, useful for password-reset/lure pretexts.",
            "severity_on_accept": "high",
        },
        {
            "label": "IR6_null_sender_internal",
            "desc": "Null-sender bounce to internal recipient",
            "mail_from": "<>",
            "rcpt_tos": [f"<{spoof_recipient}>"],
            "vuln_on_accept": "NULL-SENDER ACCEPT — enables backscatter/bounce-bomb "
                              "amplification against internal mailboxes.",
            "severity_on_accept": "medium",
        },
        {
            "label": "IR7_unauth_external_to_internal",
            "desc": "External sender -> internal recipient (no AUTH)",
            "mail_from": f"<{from_addr}>",
            "rcpt_tos": [f"<{spoof_recipient}>"],
            "vuln_on_accept": "Server accepts external mail for internal users. "
                              "Expected for an MX, but only acceptable if anti-spoof "
                              "(SPF/DKIM/DMARC) and recipient-domain ACLs are enforced.",
            "severity_on_accept": "info",
        },
        {
            "label": "IR8_multi_recipient_amplification",
            "desc": "One MAIL FROM, multiple internal RCPTs (amplification check)",
            "mail_from": f"<{spoof_sender}>",
            "rcpt_tos": [f"<{r}>" for r in multi_recipients],
            "vuln_on_accept": "MULTI-RCPT AMPLIFICATION — server accepts large recipient "
                              "lists from a spoofed internal sender; suitable for mass "
                              "internal phishing in one TCP session.",
            "severity_on_accept": "high",
        },
        {
            "label": "IR9_plus_addressing",
            "desc": "Plus-addressing / ext_addr backdoor (admin+anything@internal)",
            "mail_from": f"<{from_addr}>",
            "rcpt_tos": [f"<{plus_addr}>"],
            "vuln_on_accept": "Plus-addressing accepted — usually benign, but verify "
                              "downstream filters don't trust the base address blindly "
                              "(e.g. allow-listing 'admin@' lets 'admin+x@' through).",
            "severity_on_accept": "low",
        },
        {
            "label": "IR10_ip_literal_internal",
            "desc": "IP-literal recipient mapped to internal name",
            "mail_from": f"<{spoof_sender}>",
            "rcpt_tos": [f"<user@[{session.host}]>"],
            "vuln_on_accept": "IP-literal recipient accepted — some MTAs treat "
                              "[ip] as 'this server', enabling delivery without "
                              "matching virtual-domain ACLs.",
            "severity_on_accept": "medium",
        },
    ]

    for t in tests:
        if t["rcpt_tos"] is None:
            print(f"    [-] {t['label']:<32} skipped (--to-addr not provided)")
            continue
        result = _run_one(session, t)
        data["tests"].append(result)

        if result.get("any_accepted"):
            data["vulnerabilities"].append(t["label"])
            findings.append({
                "severity": t["severity_on_accept"],
                "title": f"{t['label']}: {t['desc']}",
                "detail": t["vuln_on_accept"] +
                          f"  Accepted RCPTs: {result['accepted_rcpts']}.",
            })

    if not data["vulnerabilities"]:
        findings.append({
            "severity": "info",
            "title": "No internal open-relay weaknesses detected",
            "detail": "All internal-relay vectors were rejected from this source IP. "
                      "Re-run from other network segments (DMZ, VLAN, VPN) to confirm.",
        })
    else:
        findings.append({
            "severity": "info",
            "title": "Source-IP context",
            "detail": f"All internal-relay results are relative to source IP "
                      f"{data['source_ip']}. Re-test from each network segment "
                      "that should NOT have relay privileges (guest WiFi, "
                      "developer VLAN, etc.) to map the full trust boundary.",
        })

    return {"data": data, "findings": findings}


def _run_one(session, t):
    out = {"label": t["label"], "desc": t["desc"],
           "mail_from": t["mail_from"], "rcpts": t["rcpt_tos"],
           "mail_from_code": None, "rcpt_results": [],
           "any_accepted": False, "accepted_rcpts": []}
    try:
        session.reconnect()
        session.ehlo()
        mf = session.cmd(f"MAIL FROM:{t['mail_from']}")
        out["mail_from_code"] = session.code(mf)
        if out["mail_from_code"] != 250:
            print(f"    [-] {t['label']:<32} MAIL FROM rejected ({out['mail_from_code']})")
            return out
        for rcpt in t["rcpt_tos"]:
            rc = session.cmd(f"RCPT TO:{rcpt}")
            code = session.code(rc)
            reply = rc.strip().splitlines()[-1] if rc else ""
            entry = {"rcpt": rcpt, "code": code, "reply": reply}
            out["rcpt_results"].append(entry)
            if code in (250, 251):
                out["any_accepted"] = True
                out["accepted_rcpts"].append(rcpt)
        if out["any_accepted"]:
            print(f"    [+] {t['label']:<32} ACCEPTED — {out['accepted_rcpts']}")
        else:
            codes = sorted({r['code'] for r in out['rcpt_results']})
            print(f"    [-] {t['label']:<32} rejected ({codes})")
    except Exception as e:
        out["error"] = str(e)
        print(f"    [!] {t['label']:<32} ERROR: {e}")
    return out
