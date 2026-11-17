#!/bin/sh
# sign-sha256sums.sh <path/to/SHA256SUMS>
# Writes a detached, ASCII-armoured OpenPGP signature <path>.asc with the Errant Solutions release key.
#   RELEASE_SIGNING_KEY  armoured SECRET key (a CI secret); only ever lives in a 0700 temp GNUPGHOME
#   keys/release-signing.asc  the PUBLIC key committed to this repo; the signing key must match it and
#                             the fresh signature is verified against it with gpgv
# Any problem exits non-zero and leaves no .asc behind, so an unsigned release is never published.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PUB=${RELEASE_PUBKEY:-$ROOT/keys/release-signing.asc}
[ $# -eq 1 ] || { echo "usage: sign-sha256sums.sh <SHA256SUMS>" >&2; exit 2; }
F=$1
rm -f "$F.asc"
[ -n "${RELEASE_SIGNING_KEY:-}" ] || { echo "sign-sha256sums: RELEASE_SIGNING_KEY is not set: refusing to publish an unsigned release" >&2; exit 1; }
[ -s "$PUB" ] || { echo "sign-sha256sums: no public key at $PUB" >&2; exit 1; }
[ -f "$F" ] || { echo "sign-sha256sums: no such file: $F" >&2; exit 1; }
if ! command -v gpg >/dev/null 2>&1 || ! command -v gpgv >/dev/null 2>&1; then
  SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
  { $SUDO apt-get update -qq && $SUDO apt-get install -y -qq gnupg gpgv; } >/dev/null 2>&1 \
    || { echo "sign-sha256sums: gpg/gpgv missing and could not be installed" >&2; exit 1; }
fi
G=$(mktemp -d "${TMPDIR:-/tmp}/relsign.XXXXXX"); chmod 700 "$G"
cleanup() { gpgconf --homedir "$G" --kill all >/dev/null 2>&1 || true; rm -rf "$G"; }
fail() { echo "sign-sha256sums: $*" >&2; rm -f "$F.asc"; exit 1; }
trap cleanup EXIT
printf '%s\n' "$RELEASE_SIGNING_KEY" | gpg --homedir "$G" --batch --quiet --import 2>/dev/null || fail "cannot import RELEASE_SIGNING_KEY"
fpr=$(gpg --homedir "$G" --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
want=$(gpg --homedir "$G" --batch --with-colons --show-keys "$PUB" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
[ -n "$fpr" ] || fail "RELEASE_SIGNING_KEY holds no secret key"
[ -n "$want" ] || fail "cannot read the fingerprint of $PUB"
[ "$fpr" = "$want" ] || fail "the signing key ($fpr) is not the committed release key ($want)"
gpg --homedir "$G" --batch --yes --quiet --pinentry-mode loopback --passphrase '' \
    --armor --detach-sign --output "$F.asc" "$F" 2>/dev/null || fail "signing $F failed"
# verify against ONLY the committed public key
mkdir "$G/v"; chmod 700 "$G/v"
gpg --homedir "$G/v" --batch --quiet --import "$PUB" 2>/dev/null || fail "cannot import $PUB"
gpg --homedir "$G/v" --batch --export > "$G/pub.gpg" 2>/dev/null
gpgv --keyring "$G/pub.gpg" "$F.asc" "$F" >/dev/null 2>&1 || fail "the fresh signature does not verify against $PUB"
echo "signed $F with $fpr (verified with gpgv)"
