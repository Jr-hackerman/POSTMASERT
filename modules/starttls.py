"""
modules.starttls
================
STARTTLS negotiation + TLS posture check.

Detects:
  - STARTTLS missing
  - STARTTLS offered but failing to negotiate
  - Weak / outdated TLS versions
  - Certificate issues (self-signed, expired, hostname mismatch)
"""
import ssl
import socket
from datetime import datetime, timezone


def run(session):
    findings = []
    data = {"starttls_supported": False, "negotiated_version": None,
            "cert": None, "cert_issues": []}

    print("\n[*] Module: STARTTLS / TLS probe")
    try:
        session.reconnect()
        session.ehlo()
    except Exception as e:
        findings.append({"severity": "info", "title": "STARTTLS probe skipped",
                         "detail": f"Reconnect failed: {e}"})
        return {"data": data, "findings": findings}

    if "STARTTLS" not in session.ehlo_features:
        findings.append({"severity": "medium",
                         "title": "STARTTLS not supported",
                         "detail": "Server does not advertise STARTTLS; mail relayed via "
                                   "this MTA traverses the internet in cleartext."})
        return {"data": data, "findings": findings}

    data["starttls_supported"] = True

    # Open a fresh raw socket for a clean TLS handshake and cert inspection
    try:
        raw = socket.create_connection((session.host, session.port), timeout=session.timeout)
        _recv_until_220(raw, session.timeout)
        raw.sendall(f"EHLO {session.helo_domain}\r\n".encode())
        _recv_until_final(raw, session.timeout)
        raw.sendall(b"STARTTLS\r\n")
        reply = _recv_until_final(raw, session.timeout)
        if not reply.startswith("220"):
            findings.append({"severity": "high",
                             "title": "STARTTLS advertised but refused",
                             "detail": f"Server replied: {reply.strip()}"})
            raw.close()
            return {"data": data, "findings": findings}

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname=session.host)
        version = tls.version()
        data["negotiated_version"] = version
        print(f"    Negotiated TLS: {version}")
        if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.append({"severity": "high",
                             "title": f"Weak TLS version negotiated: {version}",
                             "detail": "TLS <1.2 is deprecated and vulnerable to known attacks "
                                       "(POODLE, BEAST, etc.)."})
        elif version == "TLSv1.2":
            findings.append({"severity": "low",
                             "title": "TLS 1.2 in use",
                             "detail": "Consider enabling TLS 1.3."})

        # Cert inspection
        der = tls.getpeercert(binary_form=True)
        cert_text = ssl.DER_cert_to_PEM_cert(der)
        data["cert"] = {"pem_length": len(cert_text)}
        try:
            tls.close()
        except Exception:
            pass

        # Re-open with verification for trust check
        try:
            v_ctx = ssl.create_default_context()
            v_raw = socket.create_connection((session.host, session.port), timeout=session.timeout)
            _recv_until_220(v_raw, session.timeout)
            v_raw.sendall(f"EHLO {session.helo_domain}\r\n".encode())
            _recv_until_final(v_raw, session.timeout)
            v_raw.sendall(b"STARTTLS\r\n")
            _recv_until_final(v_raw, session.timeout)
            v_tls = v_ctx.wrap_socket(v_raw, server_hostname=session.host)
            v_tls.close()
        except ssl.SSLCertVerificationError as e:
            data["cert_issues"].append(str(e))
            findings.append({"severity": "medium",
                             "title": "TLS certificate not trusted",
                             "detail": f"Verification failed: {e}"})
        except Exception as e:
            data["cert_issues"].append(str(e))

    except Exception as e:
        findings.append({"severity": "info",
                         "title": "TLS probe error",
                         "detail": str(e)})

    return {"data": data, "findings": findings}


def _recv_until_220(sock, timeout):
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n" not in buf:
        buf += sock.recv(4096)
    return buf.decode(errors="replace")


def _recv_until_final(sock, timeout):
    sock.settimeout(timeout)
    buf = b""
    while True:
        buf += sock.recv(4096)
        lines = buf.split(b"\r\n")
        if buf.endswith(b"\r\n") and len(lines) >= 2:
            last = lines[-2]
            if len(last) >= 4 and last[3:4] == b" ":
                break
    return buf.decode(errors="replace")
