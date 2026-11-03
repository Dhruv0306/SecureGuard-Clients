#!/usr/bin/env bash
# Signs a file with the key in the keyring (see import-gpg-key.sh) and checks
# the signature it just made.
#
#   sign-checksums.sh <file>
#   GPG_PASSPHRASE  the key's passphrase; empty for an unprotected key
#
# The signature is written next to the file as <file>.asc. An older signature
# is overwritten, and none is left behind when signing fails.
set -euo pipefail

file="${1:-}"
if [ -z "$file" ]; then
    echo "usage: sign-checksums.sh <file>" >&2
    exit 2
fi
if [ ! -f "$file" ]; then
    echo "::error::$file does not exist, so there is nothing to sign" >&2
    exit 1
fi

if ! printf '%s' "${GPG_PASSPHRASE-}" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --armor --detach-sign "$file"; then
    rm -f "$file.asc"
    echo "::error::signing $file failed; see the gpg message above" >&2
    exit 1
fi

gpg --verify "$file.asc" "$file"
