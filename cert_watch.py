#!/usr/bin/env python3
"""
cert-watch — TLS certificate expiry & config watchdog
========================================================

Checks one or more hosts for TLS certificate expiry, the protocol versions
the server accepts (TLS 1.0-1.3, each tried separately), weak ciphers, key
size, intermediate-certificate expiry and common misconfigurations (missing
SAN entries, self-signed / untrusted / hostname-mismatched certs, MD5/SHA-1
signature algorithms). Works on STARTTLS services too: SMTP, submission,
IMAP, POP3, FTP and PostgreSQL. Stdlib only (ssl + socket), no dependencies.

Usage:
    tls-cert-watchdog example.com
    tls-cert-watchdog example.com:8443 another.example.com
    tls-cert-watchdog --starttls smtp mail.example.com:25     # or smtp://mail.example.com
    tls-cert-watchdog imap://mail.example.com postgres://db.example.com
    tls-cert-watchdog --warn-days 21 --json example.com
    tls-cert-watchdog --file hosts.txt      # one [scheme://]host[:port] per line

STARTTLS is used automatically for smtp:// submission:// imap:// pop3:// ftp://
postgres:// targets and for the well-known ports 25, 587, 143, 110, 21 and 5432.

Exit code: 0 if no host has a finding at or above --fail-on (default high:
expired, expiring within --warn-days, untrusted/mismatched, a legacy protocol
accepted, weak cipher, signature algorithm or key), 1 otherwise, 2 on usage
errors -- CI/cron friendly.

Copyright (c) 2026 Errant Solutions. MIT licensed.
"""
__version__ = "1.2.0"

import argparse
import datetime
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import warnings

# Signature algorithms that should no longer appear on a served certificate.
WEAK_SIG_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
PROTOCOL_VERSIONS = [("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")]
STARTTLS_PORTS = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3", 21: "ftp", 5432: "postgres"}
SCHEMES = {"https": ("", 443), "tls": ("", 443), "smtp": ("smtp", 25), "submission": ("smtp", 587),
           "imap": ("imap", 143), "pop3": ("pop3", 110), "ftp": ("ftp", 21), "postgres": ("postgres", 5432),
           "postgresql": ("postgres", 5432)}
KEY_OIDS = {"1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519",
            "1.3.101.113": "Ed448", "1.2.840.10040.4.1": "DSA"}
EC_CURVES = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384), "1.3.132.0.35": ("P-521", 521),
             "1.3.132.0.10": ("secp256k1", 256), "1.2.840.10045.3.1.1": ("P-192", 192), "1.3.132.0.33": ("P-224", 224)}
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


def public_key_info(der: bytes):
    """(algorithm, bits, curve) of the certificate's SubjectPublicKeyInfo, or None."""
    try:
        _, start, _ = _der_read(der, 0)                 # Certificate
        tag, i, tbs_end = _der_read(der, start)          # tbsCertificate
        tag, _, end = _der_read(der, i)
        if tag == 0xA0:                                  # [0] version
            i = end
        for _ in range(5):                               # serial, signature, issuer, validity, subject
            _, _, i = _der_read(der, i)
        _, spki_start, _ = _der_read(der, i)             # SubjectPublicKeyInfo
        _, alg_start, alg_end = _der_read(der, spki_start)
        _, o_start, o_end = _der_read(der, alg_start)
        alg = KEY_OIDS.get(_oid_to_str(der[o_start:o_end]), _oid_to_str(der[o_start:o_end]))
        if alg == "RSA":
            _, b_start, b_end = _der_read(der, alg_end)  # BIT STRING
            _, r_start, _ = _der_read(der, b_start + 1)  # RSAPublicKey
            _, n_start, n_end = _der_read(der, r_start)
            return alg, int.from_bytes(der[n_start:n_end], "big").bit_length(), None
        if alg == "EC":
            tag, p_start, p_end = _der_read(der, o_end)
            curve, bits = EC_CURVES.get(_oid_to_str(der[p_start:p_end]), (_oid_to_str(der[p_start:p_end]), None))
            return alg, bits, curve
        if alg in ("Ed25519", "Ed448"):
            return alg, 256 if alg == "Ed25519" else 456, None
        return alg, None, None
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


class StartTLSError(OSError):
    pass


def _reply(f):
    """One (possibly multi-line) SMTP/FTP reply -> (code, lines)."""
    lines = []
    while True:
        line = f.readline(4096).decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            raise StartTLSError("server closed the connection")
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            return line[:3], lines


def _negotiate_starttls(sock, starttls):
    f = sock.makefile("rb")
    if starttls == "smtp":
        code, _ = _reply(f)
        if code != "220":
            raise StartTLSError("SMTP greeting was %s" % code)
        sock.sendall(b"EHLO cert-watch.invalid\r\n")
        code, lines = _reply(f)
        if code != "250" or not any(l[4:].strip().upper() == "STARTTLS" for l in lines):
            raise StartTLSError("SMTP server does not offer STARTTLS")
        sock.sendall(b"STARTTLS\r\n")
        code, _ = _reply(f)
        if code != "220":
            raise StartTLSError("SMTP STARTTLS refused (%s)" % code)
    elif starttls == "imap":
        if not f.readline(4096).startswith(b"* OK"):
            raise StartTLSError("unexpected IMAP greeting")
        sock.sendall(b"a1 STARTTLS\r\n")
        while True:
            line = f.readline(4096)
            if not line:
                raise StartTLSError("server closed the connection")
            if line.startswith(b"a1 "):
                if not line.startswith(b"a1 OK"):
                    raise StartTLSError("IMAP STARTTLS refused: %s" % line.decode("utf-8", "replace").strip())
                break
    elif starttls == "pop3":
        if not f.readline(4096).startswith(b"+OK"):
            raise StartTLSError("unexpected POP3 greeting")
        sock.sendall(b"STLS\r\n")
        if not f.readline(4096).startswith(b"+OK"):
            raise StartTLSError("POP3 STLS refused")
    elif starttls == "ftp":
        code, _ = _reply(f)
        if code != "220":
            raise StartTLSError("FTP greeting was %s" % code)
        sock.sendall(b"AUTH TLS\r\n")
        code, _ = _reply(f)
        if code != "234":
            raise StartTLSError("FTP AUTH TLS refused (%s)" % code)
    elif starttls == "postgres":
        sock.sendall(struct.pack("!ii", 8, 80877103))  # SSLRequest
        if sock.recv(1) != b"S":
            raise StartTLSError("PostgreSQL server does not accept SSL")
    elif starttls:
        raise StartTLSError("unknown STARTTLS protocol %r" % starttls)


def _connect(host, port, timeout, starttls=""):
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        _negotiate_starttls(sock, starttls)
    except Exception:
        sock.close()
        raise
    return sock


def _chain_ders(ssock):
    """Certificates the server sent (Python 3.13+), as DER bytes."""
    get = getattr(ssock, "get_unverified_chain", None)
    if get is None:
        return None
    try:
        return [c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER) for c in (get() or [])]
    except Exception:
        return None


def _handshake(host, port, ctx, timeout, starttls=""):
    with _connect(host, port, timeout, starttls) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            return der, ssock.version(), ssock.cipher(), _chain_ders(ssock)


def probe_protocols(host, port, timeout, starttls=""):
    """Try each TLS version on its own. True = accepted, False = refused,
    None = this client's OpenSSL can't speak that version, so it couldn't be tested."""
    out = {}
    for name, attr in PROTOCOL_VERSIONS:
        version = getattr(ssl.TLSVersion, attr, None)
        ctx = _permissive_context()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)  # TLS 1.0/1.1 are deprecated: that's the point
                ctx.minimum_version = version
                ctx.maximum_version = version
        except (ValueError, AttributeError, ssl.SSLError):
            out[name] = None
            continue
        if attr == "TLSv1_3" and not getattr(ssl, "HAS_TLSv1_3", False):
            out[name] = None
            continue
        try:
            _, got, _, _ = _handshake(host, port, ctx, timeout, starttls)
            out[name] = got == name
        except ssl.SSLError as e:
            msg = str(e).lower()
            out[name] = None if ("no protocols available" in msg or "no ciphers available" in msg) else False
        except StartTLSError:
            out[name] = False
        except OSError:
            out[name] = False
    return out


def _permissive_context():
    """Accept anything the server offers, so legacy protocols/ciphers can be
    identified and reported instead of surfacing as a bare handshake error."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def check_host(host: str, port: int, warn_days: int, timeout: float = 10, starttls: str = "",
               scan_protocols: bool = True) -> dict:
    result = {"host": host, "port": port, "starttls": starttls or None, "findings": [], "ok": True}
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
        der, proto, cipher, chain = _handshake(host, port, ctx, timeout, starttls)
    except StartTLSError as e:
        finding("HIGH", f"STARTTLS ({starttls}) failed: {e}")
        return result
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
            der, proto, cipher, chain = _handshake(host, port, _permissive_context(), timeout, starttls)
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

    # Public key type and size
    key = public_key_info(der) if der else None
    if key:
        alg, bits, curve = key
        result["key"] = {"type": alg, "bits": bits, "curve": curve}
        if alg == "RSA" and bits and bits < 2048:
            finding("HIGH", f"RSA key is only {bits} bits (2048 is the minimum CAs and browsers accept).")
        elif alg == "EC" and bits and bits < 256:
            finding("HIGH", f"EC key on weak curve {curve} ({bits} bits).")
        elif alg == "EC" and curve not in ("P-256", "P-384", "P-521"):
            finding("MEDIUM", f"EC key on non-standard curve {curve}.")
        elif alg == "DSA":
            finding("HIGH", "DSA certificate key (no longer accepted by browsers).")

    # Chain the server sent (Python 3.13+): intermediates about to expire break every client
    if chain:
        result["chain"] = []
        for i, c in enumerate(chain):
            info = decode_der_cert(c)
            entry = {"subject": _dn(info.get("subject")), "issuer": _dn(info.get("issuer")),
                     "not_after": info.get("notAfter")}
            result["chain"].append(entry)
            if i == 0 or not info.get("notAfter"):
                continue
            exp = datetime.datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc)
            left = (exp - datetime.datetime.now(datetime.timezone.utc)).days
            if left < 0:
                finding("HIGH", f"Chain certificate '{entry['subject']}' EXPIRED {-left} day(s) ago.")
            elif left <= warn_days:
                finding("HIGH", f"Chain certificate '{entry['subject']}' expires in {left} day(s).")

    # Every protocol version the server accepts, not just the negotiated one
    if scan_protocols:
        offered = probe_protocols(host, port, timeout, starttls)
        result["protocols"] = offered
        legacy = [v for v in ("TLSv1", "TLSv1.1") if offered.get(v)]
        if legacy and proto not in WEAK_PROTOCOLS:
            # opportunistic STARTTLS mail/db: legacy TLS still beats plaintext, so one notch lower
            finding("MEDIUM" if starttls else "HIGH", f"Server still accepts legacy {' and '.join(legacy)} (negotiated {proto} only because "
                            f"this client prefers it; old clients and downgrade attacks get the legacy version).")
        if offered.get("TLSv1.3") is False and offered.get("TLSv1.2"):
            finding("LOW", "TLS 1.3 is not offered.")
        untested = [v for v, ok in offered.items() if ok is None]
        if untested:
            result["protocols_untested"] = untested

    return result


def _dn(parts):
    if not parts:
        return ""
    return ", ".join("%s=%s" % kv for rdn in parts for kv in rdn)


def render_text(results: list) -> str:
    lines = ["TLS Certificate Watchdog Report", "=" * 40, ""]
    for r in results:
        status = "OK" if r["ok"] else "ISSUES FOUND"
        lines.append(f"{r['host']}:{r['port']}  [{status}]")
        if "days_left" in r:
            lines.append(f"  Expires: {r['expires']}  ({r['days_left']} days left)")
        if "protocol" in r:
            lines.append(f"  Protocol: {r['protocol']}   Cipher: {r.get('cipher', '?')}"
                         + (f"   (STARTTLS {r['starttls']})" if r.get("starttls") else ""))
        if r.get("protocols"):
            lines.append("  Accepts: " + ", ".join(
                f"{v} {'yes' if ok else ('no' if ok is False else 'untested')}" for v, ok in r["protocols"].items()))
        if r.get("key"):
            k = r["key"]
            lines.append(f"  Key: {k['type']} {k['bits'] or '?'} bits" + (f" ({k['curve']})" if k.get("curve") else ""))
        for f in r["findings"]:
            lines.append(f"  [{f['severity']}] {f['message']}")
        lines.append("")
    n_bad = sum(1 for r in results if not r["ok"])
    lines.append(f"Summary: {n_bad}/{len(results)} host(s) with HIGH-severity findings.")
    return "\n".join(lines)


def parse_target(spec: str, starttls=None):
    """[scheme://]host[:port] -> (host, port, starttls protocol or "")."""
    spec = spec.strip()
    scheme = None
    if "://" in spec:
        scheme, spec = spec.split("://", 1)
        scheme = scheme.lower()
        if scheme not in SCHEMES:
            raise ValueError("unknown scheme %s:// (use %s)" % (scheme, ", ".join(sorted(SCHEMES))))
        spec = spec.rstrip("/")
    host, port = parse_host(spec, SCHEMES[scheme][1] if scheme else 443)
    if starttls is not None:
        proto = "" if starttls == "none" else starttls
    elif scheme:
        proto = SCHEMES[scheme][0]
    else:
        proto = STARTTLS_PORTS.get(port, "")
    return host, port, proto


def parse_host(spec: str, default_port: int = 443):
    """host, host:port, [v6addr], [v6addr]:port, or a bare IPv6 address."""
    spec = spec.strip()
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if spec.count(":") == 1:
        host, port = spec.rsplit(":", 1)
        return host, int(port)
    return spec, default_port


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tls-cert-watchdog", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("hosts", nargs="*", help="[scheme://]host[:port] to check (schemes: smtp, submission, imap, pop3, ftp, postgres, https)")
    ap.add_argument("--file", help="file with one [scheme://]host[:port] per line")
    ap.add_argument("--starttls", choices=["smtp", "imap", "pop3", "ftp", "postgres", "none"],
                    help="force a STARTTLS protocol for every target (default: from the scheme or well-known port)")
    ap.add_argument("--warn-days", type=int, default=14, help="HIGH-severity threshold for days until expiry (default 14)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("--timeout", type=float, default=10, help="per-connection timeout in seconds (default 10)")
    ap.add_argument("--no-protocol-scan", action="store_true",
                    help="don't try each TLS version separately (one handshake per host instead of five)")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                    help="lowest severity that makes the exit code 1 (default: high)")
    args = ap.parse_args(argv)

    specs = list(args.hosts)
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        specs.append(line)
        except OSError as e:
            ap.error(f"can't read --file: {e}")

    if not specs:
        ap.error("no hosts given (pass as arguments or via --file)")

    try:
        parsed = [parse_target(s, args.starttls) for s in specs]
    except ValueError as e:
        ap.error(f"bad [scheme://]host[:port]: {e}")
    results = [check_host(h, p, args.warn_days, args.timeout, st, not args.no_protocol_scan) for h, p, st in parsed]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render_text(results))

    gate = {"high": ("HIGH",), "medium": ("HIGH", "MEDIUM"), "low": ("HIGH", "MEDIUM", "LOW"), "never": ()}[args.fail_on]
    return 1 if any(f["severity"] in gate for r in results for f in r["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
