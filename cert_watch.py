#!/usr/bin/env python3
"""
cert-watch — TLS certificate expiry & config watchdog
========================================================

Checks one or more hosts for TLS certificate expiry, weak protocol versions
and ciphers, and common misconfigurations (missing SAN entries, self-signed /
untrusted / hostname-mismatched certs, MD5/SHA-1 signature algorithms).
Stdlib only (ssl + socket), no dependencies.

Usage:
    python3 cert_watch.py example.com
    python3 cert_watch.py example.com:8443 another.example.com
    python3 cert_watch.py --warn-days 21 example.com
    python3 cert_watch.py --json example.com
    python3 cert_watch.py --file hosts.txt      # one host[:port] per line

Exit code: 0 if all hosts are healthy, 1 if any host has a HIGH-severity
finding (expired, expiring within --warn-days, untrusted/mismatched, weak
protocol, cipher or signature algorithm) — CI/cron friendly for a nightly check that emails/alerts on failure.

Copyright (c) 2026 Errant Solutions. MIT licensed.
"""
import argparse
import datetime
import json
import os
import socket
import ssl
import sys
import tempfile

# Signature algorithms that should no longer appear on a served certificate.
WEAK_SIG_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "DES", "EXPORT", "NULL", "MD5")


def _der_read(der: bytes, i: int):
    """Read one DER TLV at offset i -> (tag, content_start, content_end)."""
    tag = der[i]
    length = der[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(der[i:i + n], "big")
        i += n
    return tag, i, i + length


def _oid_to_str(raw: bytes) -> str:
    parts = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def signature_oid(der: bytes):
    """OID of Certificate.signatureAlgorithm (RFC 5280 s4.1.1.2), or None."""
    try:
        _, start, _ = _der_read(der, 0)               # Certificate SEQUENCE
        _, _, tbs_end = _der_read(der, start)          # tbsCertificate
        _, alg_start, _ = _der_read(der, tbs_end)      # signatureAlgorithm SEQUENCE
        tag, o_start, o_end = _der_read(der, alg_start)
        return _oid_to_str(der[o_start:o_end]) if tag == 0x06 else None
    except (IndexError, ValueError):
        return None


def decode_der_cert(der: bytes) -> dict:
    """Decode a DER certificate into the same dict shape getpeercert() returns.

    getpeercert() returns an EMPTY dict whenever verification was disabled,
    which is exactly the case we need it for (expired/self-signed/mismatched
    certs), so decode the raw certificate ourselves via the stdlib's own
    decoder instead.
    """
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return {}
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        return decoder(path)
    except Exception:
        return {}
    finally:
        os.unlink(path)


def _handshake(host, port, ctx, timeout):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            return der, ssock.version(), ssock.cipher()


def _permissive_context():
    """Accept anything the server offers, so legacy protocols/ciphers can be
    identified and reported instead of surfacing as a bare handshake error."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def check_host(host: str, port: int, warn_days: int, timeout: float = 10) -> dict:
    result = {"host": host, "port": port, "findings": [], "ok": True}
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    def finding(severity, message):
        result["findings"].append({"severity": severity, "message": message})
        if severity == "HIGH":
            result["ok"] = False

    # First pass: full verification (catches self-signed / untrusted chain /
    # hostname mismatch / expiry) with the platform's modern defaults.
    first_error = None
    try:
        der, proto, cipher = _handshake(host, port, ctx, timeout)
    except ssl.SSLCertVerificationError as e:
        finding("HIGH", f"Certificate verification failed: {e.verify_message}")
        der = None
    except ssl.SSLError as e:
        # Handshake refused under modern defaults -- usually a server that
        # only speaks a legacy protocol/cipher. Identified below.
        der = None
        first_error = e
    except (socket.timeout, OSError) as e:
        finding("HIGH", f"Connection failed: {e}")
        return result

    if der is None:
        # Retry without verification and with legacy protocols allowed, just
        # to still report expiry/protocol/cipher information.
        try:
            der, proto, cipher = _handshake(host, port, _permissive_context(), timeout)
        except Exception as e2:
            if first_error is not None:
                finding("HIGH", f"TLS handshake failed: {first_error}")
            else:
                finding("HIGH", f"Could not retrieve certificate at all: {e2}")
            return result
        if first_error is not None and proto not in WEAK_PROTOCOLS and not (
                cipher and any(m in cipher[0] for m in WEAK_CIPHER_MARKERS)):
            finding("HIGH", f"TLS handshake failed with modern client defaults: {first_error}")

    cert = decode_der_cert(der) if der else {}

    # Expiry check
    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (expiry - now).days
        result["expires"] = expiry.isoformat()
        result["days_left"] = days_left
        if days_left < 0:
            finding("HIGH", f"Certificate EXPIRED {-days_left} day(s) ago ({expiry.date()}).")
        elif days_left <= warn_days:
            finding("HIGH", f"Certificate expires in {days_left} day(s) ({expiry.date()}) — inside the {warn_days}-day warning window.")
        elif days_left <= warn_days * 2:
            finding("MEDIUM", f"Certificate expires in {days_left} day(s) ({expiry.date()}).")
    elif der:
        finding("MEDIUM", "Could not decode the certificate's validity dates.")

    # Protocol version check
    if proto in WEAK_PROTOCOLS:
        finding("HIGH", f"Negotiated weak/legacy protocol: {proto}.")
    result["protocol"] = proto

    # Cipher check (very old/export-grade ciphers)
    if cipher:
        cipher_name = cipher[0]
        result["cipher"] = cipher_name
        if any(m in cipher_name for m in WEAK_CIPHER_MARKERS):
            finding("HIGH", f"Weak cipher negotiated: {cipher_name}.")

    # Signature algorithm check
    oid = signature_oid(der) if der else None
    if oid in WEAK_SIG_OIDS:
        finding("HIGH", f"Certificate is signed with a weak algorithm: {WEAK_SIG_OIDS[oid]}.")
    if oid:
        result["signature_oid"] = oid

    # SAN sanity check
    if cert:
        san = cert.get("subjectAltName", ())
        san_names = [v for k, v in san if k == "DNS"]
        result["san"] = san_names
        if not san_names:
            finding("MEDIUM", "No Subject Alternative Names present (legacy CN-only cert).")

    return result


def render_text(results: list) -> str:
    lines = ["TLS Certificate Watchdog Report", "=" * 40, ""]
    for r in results:
        status = "OK" if r["ok"] else "ISSUES FOUND"
        lines.append(f"{r['host']}:{r['port']}  [{status}]")
        if "days_left" in r:
            lines.append(f"  Expires: {r['expires']}  ({r['days_left']} days left)")
        if "protocol" in r:
            lines.append(f"  Protocol: {r['protocol']}   Cipher: {r.get('cipher', '?')}")
        for f in r["findings"]:
            lines.append(f"  [{f['severity']}] {f['message']}")
        lines.append("")
    n_bad = sum(1 for r in results if not r["ok"])
    lines.append(f"Summary: {n_bad}/{len(results)} host(s) with HIGH-severity findings.")
    return "\n".join(lines)


def parse_host(spec: str):
    """host, host:port, [v6addr], [v6addr]:port, or a bare IPv6 address."""
    spec = spec.strip()
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else 443
    if spec.count(":") == 1:
        host, port = spec.rsplit(":", 1)
        return host, int(port)
    return spec, 443


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", nargs="*", help="host or host:port to check")
    ap.add_argument("--file", help="file with one host[:port] per line")
    ap.add_argument("--warn-days", type=int, default=14, help="HIGH-severity threshold for days until expiry (default 14)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("--timeout", type=float, default=10, help="per-connection timeout in seconds (default 10)")
    args = ap.parse_args()

    specs = list(args.hosts)
    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    specs.append(line)

    if not specs:
        ap.error("no hosts given (pass as arguments or via --file)")

    try:
        parsed = [parse_host(s) for s in specs]
    except ValueError as e:
        ap.error(f"bad host[:port]: {e}")
    results = [check_host(h, p, args.warn_days, args.timeout) for h, p in parsed]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render_text(results))

    sys.exit(1 if any(not r["ok"] for r in results) else 0)


if __name__ == "__main__":
    main()
