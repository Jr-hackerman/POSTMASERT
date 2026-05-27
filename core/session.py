"""
core.session
============
Raw-socket SMTP session wrapper.

Why a raw socket instead of smtplib?
  smtplib enforces RFC-compliant command order and rewrites addresses,
  which would mask exactly the misconfigurations we are trying to detect
  (malformed RCPT TO, percent-hack, source routing, etc.).

This class gives us low-level control while still providing helpers
(ehlo, helo, mail, rcpt, data, quit, starttls).
"""
import socket
import ssl
import re


class SMTPError(Exception):
    pass


class SMTPSession:
    def __init__(self, host, port=25, timeout=10, helo_domain="example.com", verbose=False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.helo_domain = helo_domain
        self.verbose = verbose
        self.sock = None
        self.banner = None
        self.ehlo_features = {}   # feature -> list of params
        self.tls_active = False

    # ---------- connection management ----------
    def connect(self):
        if self.sock:
            return self.banner
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.banner = self._read_response()
        self._log(f"<<< {self.banner.strip()}")
        return self.banner

    def reconnect(self):
        self.close()
        return self.connect()

    def close(self):
        if self.sock:
            try:
                self._send_raw("QUIT\r\n")
                self._read_response()
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.ehlo_features = {}
            self.tls_active = False

    # ---------- low-level I/O ----------
    def _send_raw(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        self._log(f">>> {data.decode(errors='replace').rstrip()}")
        self.sock.sendall(data)

    def _read_response(self):
        """Read a (potentially multi-line) SMTP reply."""
        if not self.sock:
            raise SMTPError("Not connected")
        self.sock.settimeout(self.timeout)
        buf = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # SMTP multi-line continuation: "250-...\r\n"; final: "250 ...\r\n"
            lines = buf.split(b"\r\n")
            # Last element is "" if buffer ended with CRLF
            if buf.endswith(b"\r\n") and len(lines) >= 2:
                last = lines[-2]
                if len(last) >= 4 and last[3:4] == b" ":
                    break
        return buf.decode("utf-8", errors="replace")

    def cmd(self, command):
        """Send a single raw command (no CRLF needed) and return reply text."""
        if not self.sock:
            self.connect()
        if not command.endswith("\r\n"):
            command += "\r\n"
        self._send_raw(command)
        reply = self._read_response()
        self._log(f"<<< {reply.strip()}")
        return reply

    # ---------- helpers ----------
    @staticmethod
    def code(reply):
        """Extract numeric SMTP code from a reply (first 3 chars). Returns 0 on failure."""
        if not reply or len(reply) < 3:
            return 0
        try:
            return int(reply[:3])
        except ValueError:
            return 0

    def ehlo(self, domain=None):
        domain = domain or self.helo_domain
        reply = self.cmd(f"EHLO {domain}")
        self.ehlo_features = self._parse_ehlo(reply)
        return reply

    def helo(self, domain=None):
        domain = domain or self.helo_domain
        return self.cmd(f"HELO {domain}")

    def mail(self, addr):
        return self.cmd(f"MAIL FROM:<{addr}>")

    def rcpt(self, addr):
        return self.cmd(f"RCPT TO:<{addr}>")

    def data(self, body):
        reply = self.cmd("DATA")
        if not reply.startswith("354"):
            return reply
        # Dot-stuff and terminate with CRLF.CRLF
        body = body.replace("\r\n.\r\n", "\r\n..\r\n")
        if not body.endswith("\r\n"):
            body += "\r\n"
        self._send_raw(body + ".\r\n")
        final = self._read_response()
        self._log(f"<<< {final.strip()}")
        return final

    def rset(self):
        return self.cmd("RSET")

    @staticmethod
    def _parse_ehlo(reply):
        feats = {}
        for line in reply.splitlines():
            m = re.match(r"^\d{3}[- ](.+)$", line)
            if not m:
                continue
            parts = m.group(1).split()
            if not parts:
                continue
            key = parts[0].upper()
            feats[key] = parts[1:]
        return feats

    # ---------- STARTTLS ----------
    def starttls(self):
        reply = self.cmd("STARTTLS")
        if not reply.startswith("220"):
            return False, reply
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
        self.tls_active = True
        # Re-EHLO after TLS per RFC 3207
        self.ehlo()
        return True, reply

    def _log(self, msg):
        if self.verbose:
            print(msg)
