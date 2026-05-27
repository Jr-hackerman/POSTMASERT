"""
modules.auth_probe
==================
Enumerate SMTP AUTH mechanisms and check their security posture.
Does NOT perform brute-force — that requires explicit, separate
authorization and is intentionally not included in this framework.
"""

WEAK_MECHS = {"LOGIN", "PLAIN"}
STRONG_MECHS = {"CRAM-MD5", "SCRAM-SHA-1", "SCRAM-SHA-256", "GSSAPI", "XOAUTH2"}


def run(session):
    findings = []
    data = {"mechanisms_pre_tls": [], "mechanisms_post_tls": []}

    print("\n[*] Module: AUTH mechanism enumeration")
    try:
        session.reconnect()
        session.ehlo()
    except Exception as e:
        findings.append({"severity": "info", "title": "AUTH probe skipped",
                         "detail": str(e)})
        return {"data": data, "findings": findings}

    pre = session.ehlo_features.get("AUTH", [])
    data["mechanisms_pre_tls"] = pre
    print(f"    Pre-TLS AUTH: {pre or '(none advertised)'}")

    if pre and (WEAK_MECHS & set(m.upper() for m in pre)):
        findings.append({
            "severity": "high",
            "title": "Cleartext-capable AUTH offered before TLS",
            "detail": f"Mechanisms {sorted(WEAK_MECHS & set(m.upper() for m in pre))} "
                      "are exposed before STARTTLS. Credentials sent on this channel "
                      "are interceptable.",
        })

    # Try after STARTTLS
    if "STARTTLS" in session.ehlo_features:
        try:
            ok, _ = session.starttls()
            if ok:
                post = session.ehlo_features.get("AUTH", [])
                data["mechanisms_post_tls"] = post
                print(f"    Post-TLS AUTH: {post or '(none advertised)'}")
                post_up = set(m.upper() for m in post)
                if post_up and not (post_up & STRONG_MECHS):
                    findings.append({
                        "severity": "low",
                        "title": "Only weak AUTH mechanisms inside TLS",
                        "detail": f"Server offers {sorted(post_up)} even after TLS. "
                                  "Consider enabling CRAM-MD5/SCRAM/GSSAPI for defense in depth.",
                    })
        except Exception as e:
            findings.append({"severity": "info", "title": "STARTTLS during AUTH probe failed",
                             "detail": str(e)})

    if not pre and not data["mechanisms_post_tls"]:
        findings.append({"severity": "info",
                         "title": "AUTH not advertised",
                         "detail": "Server does not require/offer authentication. "
                                   "Acceptable for inbound MX, suspicious for submission."})

    return {"data": data, "findings": findings}
