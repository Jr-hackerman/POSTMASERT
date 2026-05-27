# POSTMaster

**SMTP Penetration Testing Framework**

Tool created by **jrhackerman**  ·  v1.0

A modular framework for assessing SMTP services (port 25 by default) against
the full set of misconfigurations the offensive-security industry has been
finding for the last 25+ years — including the often-overlooked **internal
open relay** condition.

> **⚠️ LEGAL.** Penetration testing without explicit, written authorization
> is illegal in most jurisdictions. Use POSTMaster only against systems for
> which you have a current Rules-of-Engagement document. The author accepts
> no liability for misuse.

---

## Modules

| Module           | What it does                                                          |
|------------------|-----------------------------------------------------------------------|
| `banner`         | Banner grab, server fingerprint, EHLO feature enumeration             |
| `starttls`       | STARTTLS negotiation, TLS version, certificate trust check            |
| `auth`           | AUTH mechanism enumeration (pre- and post-TLS posture)                |
| `enum`           | User enumeration via VRFY / EXPN / RCPT TO response differential      |
| `relay`          | **External open relay** — full 17-vector test matrix + DATA verify    |
| `internal_relay` | **Internal open relay** — 10 backend-abuse paths (BEC, intra-spoof)   |

The `relay` matrix covers the canonical obfuscation vectors used by nmap's
`smtp-open-relay.nse` and most commercial scanners:

1. naive `from -> to`   2. null sender   3. forged local sender
4. forged postmaster   5. source-routed `@host:user@dest`
6. percent-hack `user%dest@host`   7. UUCP bang-path
8. double-@ rewrite   9. quoted local-part   10. quoted recipient
11. brackets stripped   12. whitespace padding
13. IP-literal source route   14. backslash-escaped @
15. trailing-dot FQDN   16. mixed-case domain
17. external postmaster

The `internal_relay` module exists because closed-to-the-internet relays
are routinely **open-to-the-LAN**, enabling the most common Business Email
Compromise pre-condition — unauthenticated CEO-to-CFO spoofing from inside
the perimeter. Tests include:

- `IR1` intra-domain spoof
- `IR2` exec-impersonation (BEC pattern)
- `IR3` internal-looking sender -> external (unauth relay-from-inside)
- `IR4` cross-subdomain spoof
- `IR5` postmaster impersonation
- `IR6` null-sender to internal mailbox
- `IR7` external -> internal accept (with no AUTH / SPF check)
- `IR8` multi-recipient amplification in one session
- `IR9` plus-addressing backdoor
- `IR10` IP-literal-as-host recipient

---

## Install

Pure Python 3.8+, no dependencies.

```bash
git clone <this repo> postmaster
cd postmaster
python postmaster.py --help
```

## Usage

```bash
# Quick everything (defaults to --all if no module flag given)
python postmaster.py -t mail.example.com

# Targeted: only relay + internal relay, with confirmed delivery
python postmaster.py -t mail.example.com \
    --relay --internal-relay \
    --to-addr you@yourdomain.tld \
    --internal-domain corp.example.com

# User enumeration with custom wordlist
python postmaster.py -t mail.example.com --enum --users wordlists/users.txt

# Full assessment with reports
python postmaster.py -t 10.0.0.25 --all \
    --to-addr proofbox@your-domain.tld \
    --internal-domain corp.local \
    -o reports/scan.json --html reports/scan.html -v
```

### Required for relay tests

- `--to-addr` — a mailbox **you control** on a domain the target is NOT
  authoritative for. POSTMaster completes the DATA stage so you can confirm
  out-of-band delivery (the strongest possible evidence).
- `--internal-domain` (for internal-relay) — the domain the target serves
  internally (e.g. `corp.local`). The framework uses it to synthesize
  realistic spoofed senders and recipients.

### Operational notes

- Default HELO is `mail.localdomain` and default MAIL FROM is
  `test@example.com` so server logs don't immediately flag the test.
  Override with `--helo` and `--from-addr` to match your engagement profile.
- Relay-test emails carry only a neutral `X-Test-ID` header — no tool name
  or operator identity is embedded in outbound mail headers.

---

## Output

- Live colour-coded findings on stdout
- `-o report.json` — full structured findings (every command, every reply)
- `--html report.html` — sharable HTML report with severity styling

## Severity scale

| Level     | Meaning                                                            |
|-----------|--------------------------------------------------------------------|
| critical  | Confirmed open relay (DATA accepted), or unauth BEC impersonation  |
| high      | Open-relay candidate (RCPT accepted), cleartext AUTH, weak TLS     |
| medium    | User enum, missing STARTTLS, weak/untrusted cert, null-sender DoS  |
| low       | Version disclosure, weak-but-TLS-protected AUTH                    |
| info      | Server fingerprint, feature inventory                              |

---

## File map

```
postmaster/
├── postmaster.py            # CLI entry point
├── core/
│   ├── session.py           # raw-socket SMTP wrapper
│   └── reporter.py          # findings aggregation + JSON/HTML output
├── modules/
│   ├── banner.py            # banner / EHLO / fingerprint
│   ├── starttls.py          # STARTTLS + cert posture
│   ├── auth_probe.py        # AUTH mechanism inventory
│   ├── enumeration.py       # VRFY / EXPN / RCPT enumeration
│   ├── relay.py             # 17-vector external open-relay matrix
│   └── internal_relay.py    # 10 internal-relay / BEC vectors
└── wordlists/users.txt
```

## Extending

Adding a module = drop a file in `modules/` with a `run(session, ...)`
function returning `{"data": {...}, "findings": [...]}`, then wire it
into `postmaster.py`. Findings are dicts with keys
`severity`, `title`, and optional `detail`.

---

```
   ╔══════════════════════════════════════════════════════╗
   ║      POSTMaster  v1.0  ·  tool created by           ║
   ║                  jrhackerman                         ║
   ╚══════════════════════════════════════════════════════╝
```
