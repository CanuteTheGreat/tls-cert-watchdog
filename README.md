# TLS Certificate Watchdog

A single-file, dependency-free Python script that checks TLS certificate expiry,
weak protocol versions, and common misconfigurations across any number of
hosts. No dependencies beyond the Python standard library (`ssl`, `socket`).

By **Errant Solutions** (errant.solutions), makers of [Rustinion](https://rustinion.com)
(device provisioning & monitoring), [Big Double D](https://oops.codes) (security
awareness training), and [SSHerpa](https://ssherpa.app) (Android SSH client).

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
- Negotiated protocol version — flags SSLv2/v3, TLSv1.0/1.1
- Negotiated cipher — flags RC4/DES/EXPORT/NULL/MD5-based suites
- Missing Subject Alternative Names (legacy CN-only certs)

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
