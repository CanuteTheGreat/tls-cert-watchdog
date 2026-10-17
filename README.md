# TLS Certificate Watchdog

A single-file, dependency-free Python script that checks TLS certificate expiry,
weak protocol versions, and common misconfigurations across any number of
hosts. No dependencies beyond the Python standard library (`ssl`, `socket`).

By **Errant Solutions** (errant.solutions), makers of [Rustinion](https://rustinion.com)
(device provisioning & monitoring), [/Dev/Out Digital](https://devout.digital) (security
awareness training), [OOPS!](https://oops.codes) (hands-on security labs), and [SSHerpa](https://ssherpa.app) (Android SSH client).

## Why

"Set a calendar reminder for cert renewal" doesn't scale past a handful of
domains, and most monitoring suites are overkill if all you want is "tell me
before something expires." This is a real, runnable, testable check — pipe it
into cron/CI and get a non-zero exit code before your customers see a browser
warning page.

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/tls-cert-watchdog.git        # latest release branch; puts `tls-cert-watchdog` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/tls-cert-watchdog.git@v1.2.0  # a pinned release
brew install canutethegreat/errant-tools/tls-cert-watchdog   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/tls-cert-watchdog                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.8+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/cert_watch.py && python3 cert_watch.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/tls-cert-watchdog/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install tls-cert-watchdog` doesn't work until it's published there.

## Usage

```bash
tls-cert-watchdog example.com                          # default port 443
tls-cert-watchdog example.com:8443 api.example.com
tls-cert-watchdog --warn-days 21 example.com
tls-cert-watchdog smtp://mail.example.com              # STARTTLS on 25 (also: submission:// 587)
tls-cert-watchdog imap://mail.example.com pop3://mail.example.com ftp://files.example.com
tls-cert-watchdog postgres://db.example.com            # PostgreSQL SSLRequest on 5432
tls-cert-watchdog --starttls smtp mx.example.com:2525  # force a STARTTLS dialect
tls-cert-watchdog --file hosts.txt                     # one [scheme://]host[:port] per line
tls-cert-watchdog --json example.com                   # machine-readable
tls-cert-watchdog --fail-on medium example.com         # stricter CI gate
```

STARTTLS is picked automatically from the scheme or the well-known port (25/587
SMTP, 143 IMAP, 110 POP3, 21 FTP, 5432 PostgreSQL); `--starttls none` turns it off.

Exit codes (same convention as every Errant Solutions tool):

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `high`) on any host |
| 1 | at least one such finding (expired, expiring soon, untrusted, legacy protocol accepted, weak cipher/signature/key...) |
| 2 | usage error |

## What it checks

- Certificate expiry, with a configurable warning window (`--warn-days`,
  default 14) and a MEDIUM-severity heads-up at 2x that window
- Verification failures (expired, self-signed, hostname mismatch, broken chain)
- **Every protocol version the server accepts**: TLS 1.0, 1.1, 1.2 and 1.3 are each
  tried on their own connection, so a server offering TLS 1.3 *and* TLS 1.0 is caught
  (HIGH; MEDIUM on opportunistic STARTTLS services); no TLS 1.3 is LOW.
  `--no-protocol-scan` does a single handshake instead.
- Negotiated protocol and cipher — flags SSLv3/TLS 1.0/1.1 and RC4/DES/EXPORT/NULL/MD5 suites
- **Key type and size** — RSA under 2048 bits, DSA and weak EC curves are HIGH
- Certificate signature algorithm — flags MD5/SHA-1 signatures
- **The chain the server sends** (Python 3.13+): every certificate's subject, issuer
  and expiry, and an intermediate that expires within `--warn-days` is HIGH
- Missing Subject Alternative Names (legacy CN-only certs)

Expiry, SAN, key and signature details are reported even when verification fails
(expired, self-signed, wrong hostname). `--timeout SECONDS` sets the
per-connection timeout (default 10). Hosts can be `host`, `host:port`,
`[ipv6]` or `[ipv6]:port`, optionally with a scheme; `--file` accepts `#` comments.

## Example cron entry

```cron
0 6 * * * tls-cert-watchdog --file /etc/cert-watch/hosts.txt || mail -s "Cert issue" you@example.com < /dev/null
```

## License

MIT — see LICENSE. Free to use, modify, and redistribute. If it saves
you time, [pay what you think it's worth here](https://buy.stripe.com/9B6eVdgKB43dd1Je081VK02) —
or check out [Rustinion](https://rustinion.com) for full fleet-wide monitoring
with alerting, dashboards, and SLOs.

## Roadmap ideas (not yet built)
- Webhook/Slack notification mode
- OCSP stapling / revocation checks
- (HSTS and other security headers: see http-header-auditor)

## Tests

`tests/` runs every check against real local TLS servers (expired,
expiring, self-signed, wrong-host, CN-only, SHA-1-signed, TLS 1.0/1.1-only,
NULL-cipher) on Python 3.8 and current Python in Forgejo CI:
`sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).
