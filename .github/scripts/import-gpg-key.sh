#!/usr/bin/env bash
# Imports the release signing key and proves it can sign.
#
#   GPG_PRIVATE_KEY   the armored private key (the RELEASE_GPG_PRIVATE_KEY secret)
#   GPG_PASSPHRASE    its passphrase; empty for an unprotected key
#
# It prints only public information (key ids), never the key or the
# passphrase, and fails with a message that says what is wrong with the secret.
set -uo pipefail

fail() {
    echo "::error::$*"
    exit 1
}

one_line() { tr '\n' ' ' <<<"$1"; }

key="${GPG_PRIVATE_KEY:-}"
passphrase="${GPG_PASSPHRASE-}"

if [ -z "${key//[[:space:]]/}" ]; then
    fail "RELEASE_GPG_PRIVATE_KEY is empty or not visible to this job. Check that it is a repository secret (not an environment or Dependabot secret) with exactly that name."
fi

import_output="$(printf '%s\n' "$key" | gpg --batch --import 2>&1)"
import_status=$?
if [ "$import_status" -ne 0 ]; then
    if grep -q "no valid OpenPGP data" <<<"$import_output"; then
        fail "RELEASE_GPG_PRIVATE_KEY is not an ASCII-armored key block. If it was stored on one line with a literal backslash-n between lines, store it again with real line breaks: the whole text from -----BEGIN PGP PRIVATE KEY BLOCK----- to -----END PGP PRIVATE KEY BLOCK-----."
    fi
    fail "gpg could not import RELEASE_GPG_PRIVATE_KEY (exit $import_status): $(one_line "$import_output")"
fi

secret_records="$(gpg --list-secret-keys --with-colons 2>/dev/null)"

if ! grep -q '^sec:' <<<"$secret_records"; then
    fail "gpg read RELEASE_GPG_PRIVATE_KEY but no secret key was imported from it. It probably holds a PUBLIC key, or secret subkeys without the primary key that signs. Export the private key with: gpg --armor --export-secret-keys <KEYID>  (not --export)."
fi

# A key can only sign if the secret part of a key with the signing capability
# is present. In the colon listing, field 12 holds a key's own capabilities
# (a lowercase s means it can sign) and field 15 is # when the secret part is
# missing, a stub. That is what --export-secret-subkeys leaves of the primary
# key, so a primary that signs shows up as "sec#" and nothing can sign.
if ! awk -F: '($1 == "sec" || $1 == "ssb") && $15 != "#" && $12 ~ /s/ { found = 1 } END { exit !found }' <<<"$secret_records"; then
    listing="$(gpg --list-secret-keys --keyid-format long 2>/dev/null | grep -E '^(sec|ssb)' | tr -s ' ' | paste -sd ';' -)"
    fail "RELEASE_GPG_PRIVATE_KEY holds no secret key that can sign. gpg sees: $listing. A line starting with sec# means the secret part of the primary key is missing, which is what gpg --export-secret-subkeys produces. Export the full private key with: gpg --armor --export-secret-keys --output secureguard-release-signing-key.asc <KEYID>  and store that file's whole contents as RELEASE_GPG_PRIVATE_KEY."
fi

probe_dir="$(mktemp -d)"
trap 'rm -rf "$probe_dir"' EXIT
echo "signing check" >"$probe_dir/probe"

if ! sign_output="$(printf '%s' "$passphrase" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --armor --detach-sign -o "$probe_dir/probe.asc" "$probe_dir/probe" 2>&1)"; then
    if grep -qi "passphrase" <<<"$sign_output"; then
        fail "RELEASE_GPG_PASSPHRASE does not unlock the imported key."
    fi
    fail "the imported key cannot sign: $(one_line "$sign_output")"
fi

echo "Signing key OK. The secret keys now available (public information only):"
gpg --list-secret-keys --keyid-format long 2>/dev/null
