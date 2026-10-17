# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## Unreleased

- Tests: accuracy suite against `openssl s_client` (9 certificate variants incl. a missing intermediate and a full chain; 6 server protocol ranges, every version compared), mutation testing (nightly), claims ledger. No detection differences were found.

## 1.2.0 - 2026-10-16

- **Protocol enumeration**: TLS 1.0, 1.1, 1.2 and 1.3 are each tried separately, so a server that offers
  TLS 1.3 *and* still accepts TLS 1.0/1.1 is flagged (HIGH; MEDIUM on STARTTLS services). Missing TLS 1.3 is LOW.
  `--no-protocol-scan` skips it.
- **STARTTLS**: SMTP/submission, IMAP, POP3, FTP (AUTH TLS) and PostgreSQL (SSLRequest), chosen by
  `smtp://`-style schemes, the well-known port, or `--starttls`.
- Key type and size (RSA < 2048, DSA, weak EC curves are HIGH).
- The served chain (Python 3.13+) with each certificate's subject/issuer/expiry; expiring intermediates are HIGH.
- `--fail-on` (default `high`, the previous behaviour).
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/tls-cert-watchdog.git`
  puts a `tls-cert-watchdog` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Report details for unverifiable certs, detect legacy TLS and SHA-1, add CI tests

## 1.0.0 - 2026-09-13

- First public release.
