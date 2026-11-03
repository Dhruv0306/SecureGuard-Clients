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

if ! gpg --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec:'; then
    fail "gpg read RELEASE_GPG_PRIVATE_KEY but no secret key was imported from it. It probably holds a PUBLIC key, or secret subkeys without the primary key that signs. Export the private key with: gpg --armor --export-secret-keys <KEYID>  (not --export)."
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
