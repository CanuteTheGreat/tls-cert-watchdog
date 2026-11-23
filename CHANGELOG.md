# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## Unreleased

## 2.0.0 - 2026-11-23

- Shared CLI contract across the Errant Solutions tools ([docs/CLI-CONTRACT.md](docs/CLI-CONTRACT.md)): exit 0 clean, 1 findings, 2 usage/input error, 3 unexpected runtime error (an uncaught exception used to be a traceback with exit 1). Exit codes this tool already documented for other cases are kept and marked legacy in the README.
- New `--quiet` / `-q`: no stdout, exit code only (errors stay on stderr).
- **Changed (breaking for `--json` consumers):** `--json` now prints one object `{"schema_version": 1, "tool", "version", "exit_code", "results": [...]}`; the previous top-level list is now the `results` value, unchanged. Major version bump for that reason.
- The JSON Schema of the `--json` output is in `schema/`; contract tests (exit codes, JSON against the schema, quiet, stderr) run on every push, and the push trigger now covers every branch.

## 1.4.0 - 2026-11-16

- **`--chain`** prints every certificate the server sent (subject, issuer, expiry) in the text report.
- **`--webhook URL`** POSTs a JSON summary (`text` for Slack/Mattermost, `content` for Discord, plus a `findings` list) when there are findings at or above `--fail-on`; a failed POST is reported on stderr and never changes the exit code.

## 1.3.0 - 2026-11-10

- **OCSP and must-staple**: every certificate's OCSP responder URL (Authority Information Access) and
  its TLS Feature must-staple flag are now reported (`ocsp` in `--json`, an `OCSP:` line in the text
  report). New `--ocsp` flag asks the responder whether the certificate is revoked (HIGH when revoked,
  MEDIUM when the responder does not know it, LOW when the check cannot be made, e.g. the server's
  chain is unavailable before Python 3.13). A must-staple certificate with no responder is MEDIUM.
  The responder's signature is not verified (stdlib only); verdicts are tested against `openssl ocsp`.

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
