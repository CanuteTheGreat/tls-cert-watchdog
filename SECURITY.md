# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities in tls-cert-watchdog by email to security@errant.solutions (see also
https://errant.solutions/.well-known/security.txt). Include the version (`tls-cert-watchdog --version`), what you
ran, and what you expected to happen. Please do not open a public issue for a vulnerability.

You will get an acknowledgement within 3 working days, and a fix or a mitigation plan within 30 days
for anything that is a real vulnerability. We credit reporters who want to be credited.

## Supported versions

Only the latest release is supported. Fixes ship as a new release; there are no back-ports.

## Verifying a download

Every release publishes a `SHA256SUMS` file with a detached OpenPGP signature `SHA256SUMS.asc`.
The signing key is "Errant Solutions Release Signing <security@errant.solutions>", fingerprint

    5439 3549 39B9 C055 2A68  E9BB E323 A6A3 AC0A 6506

The public key is in `keys/release-signing.asc` in this repository and at
https://errant.solutions/signing-key.asc. Check the key's fingerprint first, then verify with gpg:

    gpg --import release-signing.asc
    gpg --verify SHA256SUMS.asc SHA256SUMS
    sha256sum -c SHA256SUMS --ignore-missing

## Dependency and supply-chain checks

Every push and every night CI installs the package the way a user does and runs `pip-audit`
against it; a known vulnerability fails the build (`ci/pip-audit.sh`).
