"""
modules.banner
==============
Banner grab + EHLO feature fingerprint.

Detects:
  - Server software disclosure in banner
  - Verbose version strings
  - EHLO-advertised features (size, auth, pipelining, chunking, etc.)
"""
import re


SOFTWARE_PATTERNS = [
    (r"postfix", "Postfix"),
    (r"sendmail", "Sendmail"),
    (r"exim", "Exim"),
    (r"exchange|microsoft.*esmtp", "Microsoft Exchange"),
    (r"smtpsvc", "Microsoft IIS SMTP"),
    (r"opensmtpd", "OpenSMTPD"),
    (r"zimbra", "Zimbra"),
    (r"haraka", "Haraka"),
    (r"mailenable", "MailEnable"),
    (r"qmail", "qmail"),
]


def run(session):
    findings = []
    data = {"banner": None, "ehlo": None, "features": {},
            "detected_software": None, "version_disclosed": None}

    print("\n[*] Module: banner / fingerprint")
    try:
        banner = session.connect()
    except Exception as e:
        findings.append({"severity": "info", "title": "Connection failed",
                         "detail": f"Could not connect: {e}"})
        return {"data": data, "findings": findings}

    data["banner"] = banner.strip()
    print(f"    Banner: {banner.strip()}")

    low = banner.lower()
    for pat, name in SOFTWARE_PATTERNS:
        if re.search(pat, low):
            data["detected_software"] = name
            findings.append({"severity": "info",
                             "title": f"Server software identified: {name}",
                             "detail": banner.strip()})
            break

    version = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", banner)
    if version:
        data["version_disclosed"] = version.group(1)
        findings.append({"severity": "low",
                         "title": "Version string disclosed in banner",
                         "detail": f"Version {version.group(1)} exposed — aids attacker "
                                   "in matching known CVEs."})

    try:
        ehlo = session.ehlo()
        data["ehlo"] = ehlo.strip()
        data["features"] = {k: v for k, v in session.ehlo_features.items()}
        print(f"    EHLO advertised features: {', '.join(data['features'].keys()) or '(none)'}")
    except Exception as e:
        findings.append({"severity": "info", "title": "EHLO failed",
                         "detail": str(e)})
        return {"data": data, "findings": findings}

    # Feature-specific notes
    feats = data["features"]
    if "STARTTLS" not in feats:
        findings.append({"severity": "medium",
                         "title": "STARTTLS not advertised",
                         "detail": "Server does not offer opportunistic TLS on port 25; "
                                   "mail in transit may travel cleartext."})
    if "AUTH" in feats and not session.tls_active:
        mechs = " ".join(feats["AUTH"])
        if any(m.upper() in ("LOGIN", "PLAIN") for m in feats["AUTH"]):
            findings.append({"severity": "high",
                             "title": "AUTH LOGIN/PLAIN offered before TLS",
                             "detail": f"AUTH mechanisms advertised in cleartext: {mechs}. "
                                       "Credentials transmitted without TLS are interceptable."})
    if "VRFY" in feats:
        findings.append({"severity": "medium",
                         "title": "VRFY command enabled",
                         "detail": "VRFY allows user enumeration. RFC 5321 §3.5.2 recommends "
                                   "disabling or restricting."})
    if "EXPN" in feats:
        findings.append({"severity": "medium",
                         "title": "EXPN command enabled",
                         "detail": "EXPN exposes mailing-list membership."})

    return {"data": data, "findings": findings}
