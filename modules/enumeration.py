"""
modules.enumeration
===================
User enumeration via VRFY, EXPN, and RCPT TO timing/response diff.

Technique reference: PTES / OWASP Testing Guide.
"""
import time


def run(session, users):
    findings = []
    data = {"vrfy": {}, "expn": {}, "rcpt": {}, "valid_users": []}
    print(f"\n[*] Module: user enumeration ({len(users)} candidates)")

    try:
        session.reconnect()
        session.ehlo()
    except Exception as e:
        findings.append({"severity": "info", "title": "Enumeration skipped",
                         "detail": str(e)})
        return {"data": data, "findings": findings}

    valid = set()

    # -------- VRFY --------
    if "VRFY" in session.ehlo_features or True:  # Try even if not advertised
        print("    [VRFY] testing ...")
        for u in users:
            try:
                reply = session.cmd(f"VRFY {u}")
                code = session.code(reply)
                data["vrfy"][u] = {"code": code, "reply": reply.strip()}
                if code in (250, 251, 252):
                    valid.add(u)
                    print(f"        [+] {u} -> {code}")
            except Exception as e:
                data["vrfy"][u] = {"error": str(e)}
                try:
                    session.reconnect(); session.ehlo()
                except Exception:
                    break
        if data["vrfy"] and any(v.get("code", 0) in (250, 251, 252) for v in data["vrfy"].values()):
            findings.append({"severity": "medium",
                             "title": "VRFY user enumeration successful",
                             "detail": f"{len([v for v in data['vrfy'].values() if v.get('code',0) in (250,251,252)])}"
                                       f" of {len(users)} probed names accepted."})

    # -------- EXPN --------
    print("    [EXPN] testing ...")
    for u in users:
        try:
            reply = session.cmd(f"EXPN {u}")
            code = session.code(reply)
            data["expn"][u] = {"code": code, "reply": reply.strip()}
            if code == 250:
                valid.add(u)
                print(f"        [+] {u} -> 250")
        except Exception as e:
            data["expn"][u] = {"error": str(e)}
            try:
                session.reconnect(); session.ehlo()
            except Exception:
                break
    if any(v.get("code") == 250 for v in data["expn"].values()):
        findings.append({"severity": "medium",
                         "title": "EXPN user/list enumeration successful",
                         "detail": "Server returned membership for at least one alias."})

    # -------- RCPT TO --------
    # Most reliable enumeration: differentiate 250 (accept) vs 550/553 (reject).
    print("    [RCPT TO] testing ...")
    try:
        session.reconnect(); session.ehlo()
        session.mail("probe@example.com")
        for u in users:
            local = u if "@" in u else f"{u}@{session.host}"
            try:
                reply = session.cmd(f"RCPT TO:<{local}>")
                code = session.code(reply)
                data["rcpt"][u] = {"code": code, "reply": reply.strip()}
                if code in (250, 251):
                    valid.add(u)
                    print(f"        [+] {local} -> {code}")
                # Reset so each probe is independent
                session.rset()
                session.mail("probe@example.com")
            except Exception as e:
                data["rcpt"][u] = {"error": str(e)}
                try:
                    session.reconnect(); session.ehlo()
                    session.mail("probe@example.com")
                except Exception:
                    break
    except Exception as e:
        data["rcpt"]["_error"] = str(e)

    accepted = [u for u, v in data["rcpt"].items()
                if isinstance(v, dict) and v.get("code") in (250, 251)]
    rejected = [u for u, v in data["rcpt"].items()
                if isinstance(v, dict) and v.get("code") in (550, 551, 553, 554)]
    if accepted and rejected:
        findings.append({"severity": "medium",
                         "title": "RCPT TO response differential enables user enumeration",
                         "detail": f"{len(accepted)} accepted vs {len(rejected)} rejected — "
                                   "attacker can distinguish valid mailboxes."})

    data["valid_users"] = sorted(valid)
    if data["valid_users"]:
        print(f"    Discovered users: {', '.join(data['valid_users'])}")

    return {"data": data, "findings": findings}
