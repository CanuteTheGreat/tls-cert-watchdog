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

## Usage

```bash
# Check one or more hosts (default port 443)
python3 cert_watch.py example.com

# Custom port
python3 cert_watch.py example.com:8443

# Multiple hosts, custom warning window (days)
python3 cert_watch.py --warn-days 21 example.com api.example.com

# From a file, one host[:port] per line
python3 cert_watch.py --file hosts.txt

# Machine-readable output for alerting pipelines
python3 cert_watch.py --json example.com
```

Exit code is 0 if every host is healthy, 1 if any host has a HIGH-severity
finding (expired, expiring soon, weak protocol/cipher, or a broken chain) —
drop straight into a cron job or CI pipeline.

## What it checks

- Certificate expiry, with a configurable warning window (`--warn-days`,
  default 14) and a MEDIUM-severity heads-up at 2x that window
- Verification failures (expired, self-signed, hostname mismatch, broken chain)
- Negotiated protocol version — flags SSLv2/v3, TLSv1.0/1.1 (a server that
  only speaks a legacy protocol is still identified and reported, not just
  shown as a handshake failure)
- Negotiated cipher — flags RC4/DES/EXPORT/NULL/MD5-based suites
- Certificate signature algorithm — flags MD5/SHA-1 signatures
- Missing Subject Alternative Names (legacy CN-only certs)

Expiry, SAN and signature details are reported even when verification fails
(expired, self-signed, wrong hostname). `--timeout SECONDS` sets the
per-connection timeout (default 10). Hosts can be `host`, `host:port`,
`[ipv6]` or `[ipv6]:port`; `--file` accepts `#` comments.

## Example cron entry

```cron
0 6 * * * /usr/bin/python3 /opt/cert_watch.py --file /etc/cert-watch/hosts.txt || mail -s "Cert issue" you@example.com < /dev/null
```

## License

Free to use, modify, and redistribute for any purpose (MIT-style). If it saves
you time, [pay what you think it's worth here](https://buy.stripe.com/9B6eVdgKB43dd1Je081VK02) —
or check out [Rustinion](https://rustinion.com) for full fleet-wide monitoring
with alerting, dashboards, and SLOs.

## Roadmap ideas (not yet built)
- Webhook/Slack notification mode
- OCSP stapling / revocation checks
- HSTS and other security-header checks alongside the cert check

## Tests

`tests/` runs every check against real local TLS servers (expired,
expiring, self-signed, wrong-host, CN-only, SHA-1-signed, TLS 1.0/1.1-only,
NULL-cipher) on Python 3.8 and current Python in Forgejo CI:
`sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).
