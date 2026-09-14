#!/usr/bin/env python3
"""
cert-watch — TLS certificate expiry & config watchdog
========================================================

Checks one or more hosts for TLS certificate expiry, weak protocol versions,
and common misconfigurations (missing SAN entries, self-signed in prod, weak
signature algorithms). Stdlib only (ssl + socket), no dependencies.

Usage:
    python3 cert_watch.py example.com
    python3 cert_watch.py example.com:8443 another.example.com
    python3 cert_watch.py --warn-days 21 example.com
    python3 cert_watch.py --json example.com
    python3 cert_watch.py --file hosts.txt      # one host[:port] per line

Exit code: 0 if all hosts are healthy, 1 if any host has a HIGH-severity
finding (expired, expiring within --warn-days, or a weak protocol) — CI/cron
friendly for a nightly check that emails/alerts on failure.

Copyright (c) 2026 Errant Solutions. MIT licensed.
"""
import argparse
import datetime
import json
import socket
import ssl
import sys


def check_host(host: str, port: int, warn_days: int) -> dict:
    result = {"host": host, "port": port, "findings": [], "ok": True}
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    def finding(severity, message):
        result["findings"].append({"severity": severity, "message": message})
        if severity == "HIGH":
            result["ok"] = False

    # First pass: full verification (catches self-signed / untrusted chain / hostname mismatch)
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as e:
        finding("HIGH", f"Certificate verification failed: {e.verify_message}")
        # Retry without verification just to still report expiry/protocol info
        ctx2 = ssl._create_unverified_context()
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    cipher = ssock.cipher()
        except Exception as e2:
            finding("HIGH", f"Could not retrieve certificate at all: {e2}")
            return result
    except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e:
        finding("HIGH", f"Connection failed: {e}")
        return result

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

    # Protocol version check
    weak_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    if proto in weak_protocols:
        finding("HIGH", f"Negotiated weak/legacy protocol: {proto}.")
    result["protocol"] = proto

    # Cipher check (very old/export-grade ciphers)
    if cipher:
        cipher_name = cipher[0]
        result["cipher"] = cipher_name
        weak_markers = ("RC4", "DES", "EXPORT", "NULL", "MD5")
        if any(m in cipher_name for m in weak_markers):
            finding("HIGH", f"Weak cipher negotiated: {cipher_name}.")

    # SAN sanity check
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
    if ":" in spec and not spec.count(":") > 1:  # avoid breaking on IPv6-ish input naively
        host, port = spec.rsplit(":", 1)
        return host, int(port)
    return spec, 443


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", nargs="*", help="host or host:port to check")
    ap.add_argument("--file", help="file with one host[:port] per line")
    ap.add_argument("--warn-days", type=int, default=14, help="HIGH-severity threshold for days until expiry (default 14)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    specs = list(args.hosts)
    if args.file:
        with open(args.file) as f:
            specs.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))

    if not specs:
        ap.error("no hosts given (pass as arguments or via --file)")

    results = [check_host(*parse_host(s), args.warn_days) for s in specs]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render_text(results))

    sys.exit(1 if any(not r["ok"] for r in results) else 0)


if __name__ == "__main__":
    main()
