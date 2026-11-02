#!/usr/bin/env bash
# Tests for make-checksums.sh. Run from the repo root: bash .github/scripts/test-make-checksums.sh
set -uo pipefail

script="$(cd "$(dirname "$0")" && pwd)/make-checksums.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

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

fresh() { # fresh <name>: an empty folder under the work dir
    rm -rf "${work:?}/${1:?}"
    mkdir -p "$work/$1"
    echo "$work/$1"
}

release_files="SecureGuard_0.2.0_amd64.AppImage
SecureGuard_0.2.0_amd64.deb
SecureGuard_0.2.0_x64-setup.exe
SecureGuard_0.2.0_x64_en-US.msi
scg-scan-x86_64-pc-windows-msvc.exe
scg-scan-x86_64-unknown-linux-gnu"

fill() { # fill <folder>: the real release files, each with distinct content
    local folder=$1 name
    while IFS= read -r name; do
        printf 'content of %s' "$name" >"$folder/$name"
    done <<<"$release_files"
}

# 1. exactly the release files, by bare name, sorted
dir=$(fresh basic)
fill "$dir"
check "a normal release folder succeeds" bash "$script" "$dir" "$work/basic.txt"
names=$(cut -c67- "$work/basic.txt")
check "lists exactly the release files, sorted" test "$names" = "$(LC_ALL=C sort <<<"$release_files")"
check "every line is a 64 character hash and two spaces" \
    test "$(grep -cE '^[0-9a-f]{64}  [^/]' "$work/basic.txt")" = "6"
check "no line carries a folder part" bash -c "! grep -qE '  (\./|/)' '$work/basic.txt'"

# 2. the hash is right
expected=$(sha256sum <"$dir/SecureGuard_0.2.0_amd64.deb" | cut -d' ' -f1)
check "a hash is the file's SHA-256" grep -q "^$expected  SecureGuard_0.2.0_amd64.deb\$" "$work/basic.txt"

# 3. it verifies the way a user would run it
check "sha256sum -c passes inside the folder" bash -c "cd '$dir' && sha256sum -c '$work/basic.txt' >/dev/null"

# 4. build leftovers are left out
dir=$(fresh leftovers)
fill "$dir"
for junk in secureguard-helper.d scg-scan.pdb libsomething.rlib libsomething.rmeta scg-scan.exp scg-scan.lib something.sig; do
    echo x >"$dir/$junk"
done
check "a folder with leftovers succeeds" bash "$script" "$dir" "$work/leftovers.txt"
check "leftovers are excluded" test "$(wc -l <"$work/leftovers.txt")" = "6"

# 5. sub folders are not searched
dir=$(fresh nested)
fill "$dir"
mkdir "$dir/sub" && echo x >"$dir/sub/Hidden.msi"
check "a folder with a sub folder succeeds" bash "$script" "$dir" "$work/nested.txt"
check "files in sub folders are ignored and the rest are listed" \
    bash -c "test \"\$(wc -l <'$work/nested.txt')\" = 6 && ! grep -q Hidden '$work/nested.txt'"

# 6. a name with a space works
dir=$(fresh space)
echo data >"$dir/My Setup.exe"
check "a folder with a space in a name succeeds" bash "$script" "$dir" "$work/space.txt"
check "a name with a space is listed and verifies" bash -c "grep -q '  My Setup.exe\$' '$work/space.txt' && cd '$dir' && sha256sum -c '$work/space.txt' >/dev/null"

# 7. nothing to checksum is an error with a message, and no output file
dir=$(fresh empty)
message=$(bash "$script" "$dir" "$work/empty.txt" 2>&1)
status=$?
check "an empty folder fails" test "$status" -ne 0
check "the failure says why" bash -c "echo '$message' | grep -q 'no release files'"
check "no output file is left behind" test ! -e "$work/empty.txt"

dir=$(fresh only-junk)
echo x >"$dir/a.d" && echo x >"$dir/b.pdb"
bash "$script" "$dir" "$work/only-junk.txt" >/dev/null 2>&1
check "a folder with only leftovers fails" test "$?" -ne 0

# 8. bad usage
bash "$script" "$work/does-not-exist" "$work/x.txt" >/dev/null 2>&1
check "a missing folder fails" test "$?" -ne 0
bash "$script" >/dev/null 2>&1
check "no arguments fails" test "$?" -ne 0

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
