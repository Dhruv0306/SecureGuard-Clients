#!/usr/bin/env bash
# Tests for import-gpg-key.sh and sign-checksums.sh, with throwaway keys.
# Run from the repo root: bash .github/scripts/test-gpg-scripts.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
import_script="$here/import-gpg-key.sh"
sign_script="$here/sign-checksums.sh"
work="$(mktemp -d)"
failures=0

cleanup() {
    local home
    for home in "$work"/home-*; do
        [ -d "$home" ] && gpgconf --homedir "$home" --kill all >/dev/null 2>&1
    done
    rm -rf "$work"
}
trap cleanup EXIT

check() { # check <description> <command...>
    local description=$1
    shift
    if "$@"; then
        echo "ok   - $description"
    else
        echo "FAIL - $description"
        failures=$((failures + 1))
    fi
}

newhome() { # a fresh, empty GNUPGHOME (the agent caches passphrases per home)
    mktemp -d "$work/home-XXXXXX"
}

# --- throwaway keys, made once in one home
gen="$(newhome)"
g() { GNUPGHOME="$gen" gpg --batch --quiet --pinentry-mode loopback "$@"; }

g --passphrase 'pw-one' --quick-generate-key "One <one@example.test>" ed25519 sign never 2>/dev/null
g --passphrase 'pw-one' --armor --export-secret-keys >"$work/protected.asc" 2>/dev/null
g --armor --export >"$work/public.asc" 2>/dev/null
g --passphrase 'pw-one' --armor --export-secret-subkeys >"$work/subkeys-of-signing-primary.asc" 2>/dev/null
key_id="$(GNUPGHOME="$gen" gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/ {print $5; exit}')"

gen2="$(newhome)"
g2() { GNUPGHOME="$gen2" gpg --batch --quiet --pinentry-mode loopback "$@"; }
g2 --passphrase '' --quick-generate-key "Two <two@example.test>" ed25519 sign never 2>/dev/null
g2 --passphrase '' --armor --export-secret-keys >"$work/unprotected.asc" 2>/dev/null

gen3="$(newhome)"
g3() { GNUPGHOME="$gen3" gpg --batch --quiet --pinentry-mode loopback "$@"; }
g3 --passphrase 'pw-three' --quick-generate-key "Three <three@example.test>" ed25519 cert never 2>/dev/null
fpr3="$(GNUPGHOME="$gen3" gpg --list-keys --with-colons 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')"
g3 --passphrase 'pw-three' --quick-add-key "$fpr3" ed25519 sign never 2>/dev/null
g3 --passphrase 'pw-three' --armor --export-secret-subkeys >"$work/subkeys-with-signing-subkey.asc" 2>/dev/null

check "the test keys were made" test -s "$work/protected.asc" -a -s "$work/public.asc" -a -s "$work/unprotected.asc" -a -s "$work/subkeys-with-signing-subkey.asc"

# run <script> <key file or text> <passphrase>: output in $out, status in $status
run_import() { # run_import <key text> <passphrase>
    local home
    home="$(newhome)"
    out="$(GNUPGHOME="$home" GPG_PRIVATE_KEY="$1" GPG_PASSPHRASE="$2" bash "$import_script" 2>&1)"
    status=$?
}

has() { grep -qi -- "$1" <<<"$out"; }

# 1. a good, passphrase-protected secret key
run_import "$(cat "$work/protected.asc")" 'pw-one'
check "a protected secret key imports and can sign" test "$status" -eq 0
check "it reports that the signing key works" has "Signing key OK"
check "it prints the key id, which is public" has "$key_id"
check "it never prints the key block or the passphrase" bash -c "! grep -q 'BEGIN PGP PRIVATE' <<<\"\$1\" && ! grep -q 'pw-one' <<<\"\$1\"" _ "$out"
second_line="$(sed -n 3p "$work/protected.asc")"
check "it never prints a line of the key's body" bash -c "! grep -qF -- \"\$2\" <<<\"\$1\"" _ "$out" "$second_line"

# 2. other good shapes
run_import "$(cat "$work/unprotected.asc")" ''
check "an unprotected key with an empty passphrase works" test "$status" -eq 0
run_import "$(sed 's/$/\r/' "$work/protected.asc")" 'pw-one'
check "a key pasted with Windows line endings works" test "$status" -eq 0
run_import "$(cat "$work/subkeys-with-signing-subkey.asc")" 'pw-three'
check "secret subkeys of a key with a signing subkey work" test "$status" -eq 0

# 3. the bad secrets, each with a message that says what to do
run_import "" 'pw-one'
check "an empty secret fails" test "$status" -ne 0
check "an empty secret says it is empty or not visible" has "empty or not visible"
run_import "   " 'pw-one'
check "a blank secret fails the same way" has "empty or not visible"

run_import "$(cat "$work/public.asc")" 'pw-one'
check "a public key in the secret fails" test "$status" -ne 0
check "it says no secret key was imported" has "no secret key"
check "it points at export-secret-keys" has "export-secret-keys"

run_import "$(cat "$work/subkeys-of-signing-primary.asc")" 'pw-one'
check "subkeys only, where the primary key signs, fails" test "$status" -ne 0
check "it says no secret key was imported and how to export" has "export-secret-keys"

run_import "$(awk '{printf "%s\\n", $0}' "$work/protected.asc")" 'pw-one'
check "a key on one line with literal backslash-n fails" test "$status" -ne 0
check "it says to store the key with real line breaks" has "line breaks"

run_import "$(cat "$work/protected.asc")" 'not-the-passphrase'
check "a wrong passphrase fails" test "$status" -ne 0
check "it says the passphrase secret is the problem" has "RELEASE_GPG_PASSPHRASE does not unlock"
check "it does not print the wrong passphrase" bash -c "! grep -q 'not-the-passphrase' <<<\"\$1\"" _ "$out"

run_import "garbage that is not a key" 'pw-one'
check "garbage fails" test "$status" -ne 0

# 4. sign-checksums.sh
home="$(newhome)"
GNUPGHOME="$home" GPG_PRIVATE_KEY="$(cat "$work/protected.asc")" GPG_PASSPHRASE='pw-one' bash "$import_script" >/dev/null 2>&1
echo "abc  file" >"$work/checksums.txt"
signed="$(GNUPGHOME="$home" GPG_PASSPHRASE='pw-one' bash "$sign_script" "$work/checksums.txt" 2>&1)"
sign_status=$?
check "signing the checksums works" test "$sign_status" -eq 0
check "it writes checksums.txt.asc" test -s "$work/checksums.txt.asc"
verify_home="$(newhome)"
GNUPGHOME="$verify_home" gpg --batch --quiet --import "$work/public.asc" 2>/dev/null
check "the signature verifies with only the public key" \
    bash -c "GNUPGHOME='$verify_home' gpg --verify '$work/checksums.txt.asc' '$work/checksums.txt' 2>&1 | grep -q 'Good signature'"
check "it says the signature is good" grep -qi "good signature" <<<"$signed"
check "an old signature is replaced, not reused" bash -c "echo changed >'$work/checksums.txt' && GNUPGHOME='$home' GPG_PASSPHRASE='pw-one' bash '$sign_script' '$work/checksums.txt' >/dev/null 2>&1 && GNUPGHOME='$verify_home' gpg --verify '$work/checksums.txt.asc' '$work/checksums.txt' 2>&1 | grep -q 'Good signature'"

out="$(GNUPGHOME="$home" GPG_PASSPHRASE='pw-one' bash "$sign_script" "$work/does-not-exist.txt" 2>&1)"
status=$?
check "a missing file fails" test "$status" -ne 0
check "a missing file says so" has "does not exist"
empty_home="$(newhome)"
out="$(GNUPGHOME="$empty_home" GPG_PASSPHRASE='pw-one' bash "$sign_script" "$work/checksums.txt" 2>&1)"
status=$?
check "signing with no key in the keyring fails" test "$status" -ne 0
check "it leaves no signature behind when it fails" test ! -e "$work/checksums.txt.asc"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
