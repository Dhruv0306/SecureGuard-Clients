#!/usr/bin/env bash
# Tests for attach-release-assets.sh, with a fake gh that logs every call.
# Run from the repo root: bash .github/scripts/test-attach-release-assets.sh
set -uo pipefail

script="$(cd "$(dirname "$0")" && pwd)/attach-release-assets.sh"
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

mkdir "$work/bin" "$work/files"
cat >"$work/bin/gh" <<'FAKE'
#!/usr/bin/env bash
# A fake gh: logs every call and answers from canned files.
echo "gh $*" >>"$FAKE_GH_LOG"
[ "${1:-}" = "api" ] || { echo "fake gh: only 'api' is supported" >&2; exit 1; }
shift
method=GET
endpoint=""
input=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --method) method=$2; shift 2 ;;
        -H) shift 2 ;;
        --input) input=$2; shift 2 ;;
        --paginate) shift ;;
        *) endpoint=$1; shift ;;
    esac
done
case "$method $endpoint" in
    "GET repos/owner/repo/releases?per_page=100")
        cat "$FAKE_RELEASES_FILE"
        ;;
    "DELETE repos/owner/repo/releases/assets/"*)
        if [ -n "${FAKE_FAIL_DELETE:-}" ]; then
            echo "gh: Resource not accessible by integration (HTTP 403)" >&2
            exit 1
        fi
        ;;
    "POST https://uploads.github.com/repos/owner/repo/releases/"*"/assets?name="*)
        [ -f "$input" ] || { echo "fake gh: --input file missing: $input" >&2; exit 1; }
        name=${endpoint##*name=}
        if [ "${FAKE_FAIL_UPLOAD_FOR:-}" = "$name" ]; then
            echo "gh: Resource not accessible by integration (HTTP 403)" >&2
            exit 1
        fi
        echo "{\"id\":999,\"name\":\"$name\"}"
        ;;
    *)
        echo "fake gh: unexpected call: $method $endpoint" >&2
        exit 1
        ;;
esac
FAKE
chmod +x "$work/bin/gh"

printf 'a' >"$work/files/checksums.txt"
printf 'b' >"$work/files/checksums.txt.asc"
printf 'c' >"$work/files/scg-scan-x86_64-unknown-linux-gnu"
printf 'd' >"$work/files/my file.txt"

extra_env=()
repo="owner/repo"
log="$work/gh.log"

run() { # run <releases json> <args...>: sets out and status; the log is $log
    printf '%s' "$1" >"$work/releases.json"
    shift
    : >"$log"
    out="$(cd "$work/files" && env PATH="$work/bin:$PATH" FAKE_GH_LOG="$log" FAKE_RELEASES_FILE="$work/releases.json" \
        ${repo:+GITHUB_REPOSITORY="$repo"} ${extra_env[@]+"${extra_env[@]}"} bash "$script" "$@" 2>&1)"
    status=$?
}

has() { grep -qi -- "$1" <<<"$out"; }
logged() { grep -q -- "$1" "$log"; }
line_of() { grep -n -- "$1" "$log" | head -1 | cut -d: -f1; }

default='[
 {"id":111,"tag_name":"v0.1.0","draft":false,"assets":[{"id":5,"name":"old.msi"}]},
 {"id":222,"tag_name":"v0.2.0-1","draft":true,"assets":[{"id":7,"name":"checksums.txt"}]}
]'
files=(checksums.txt checksums.txt.asc scg-scan-x86_64-unknown-linux-gnu)

# 1. the normal case
run "$default" v0.2.0-1 "${files[@]}"
check "attaching to the draft succeeds" test "$status" -eq 0
check "every file is uploaded once" test "$(grep -c '^gh api --method POST' "$log")" = "3"
check "uploads go to the draft with id 222" bash -c "[ \$(grep -c 'releases/222/assets?name=' '$log') = 3 ]"
check "nothing is uploaded to the other release" bash -c "! grep -q 'releases/111' '$log'"
check "an old asset with the same name is removed first" bash -c "[ \$(grep -n 'assets/7' '$log' | head -1 | cut -d: -f1) -lt \$(grep -n 'name=checksums.txt -H' '$log' | head -1 | cut -d: -f1) ]"
check "the other assets are not deleted" test "$(grep -c '^gh api --method DELETE' "$log")" = "1"
check "the release itself is never edited" bash -c "! grep -qiE 'PATCH|release edit|--method PUT' '$log'"
check "it reports the release id" has "222"
check "it names each uploaded file" bash -c "grep -q 'checksums.txt.asc' <<<\"\$1\" && grep -q 'scg-scan-x86_64-unknown-linux-gnu' <<<\"\$1\"" _ "$out"

# 2. finding the draft
run '[{"id":111,"tag_name":"v0.1.0","draft":false,"assets":[]}][{"id":222,"tag_name":"v0.2.0-1","draft":true,"assets":[]}]' v0.2.0-1 checksums.txt
check "a draft on a second page of results is found" test "$status" -eq 0
check "...and used" logged 'releases/222/assets'

run '[{"id":444,"tag_name":"v0.2.0-1","draft":true,"assets":[]},{"id":222,"tag_name":"v0.2.0-1","draft":true,"assets":[]}]' v0.2.0-1 checksums.txt
check "with two drafts for one tag the first (newest) is used" logged 'releases/444/assets'
check "...and it warns about the second" has "more than one"

run '[]' v0.2.0-1 checksums.txt
check "no release for the tag fails" test "$status" -ne 0
check "...and says so" has "no release"
check "...without uploading anything" bash -c "! grep -q 'POST' '$log'"

run '[{"id":333,"tag_name":"v0.2.0-1","draft":false,"assets":[]}]' v0.2.0-1 checksums.txt
check "a published release is refused" test "$status" -ne 0
check "...with a reason" has "not a draft"
check "...and nothing is uploaded or deleted" bash -c "! grep -qE 'POST|DELETE' '$log'"

# 3. the files
run "$default" v0.2.0-1 checksums.txt does-not-exist.txt
check "a missing file fails" test "$status" -ne 0
check "...naming the file" has "does-not-exist.txt"
check "...before any call is made" test ! -s "$log"

run "$default" v0.2.0-1 'release-assets/scg-scan-*'
check "a glob that matched nothing fails like a missing file" test "$status" -ne 0

run "$default" v0.2.0-1 "my file.txt"
check "a name with a space is uploaded" test "$status" -eq 0
check "...with the space encoded in the url" logged 'name=my%20file.txt'

# 4. failures along the way
extra_env=(FAKE_FAIL_UPLOAD_FOR=checksums.txt.asc)
run "$default" v0.2.0-1 "${files[@]}"
check "a failed upload fails the script" test "$status" -ne 0
check "...naming the file and gh's reason" bash -c "grep -q 'checksums.txt.asc' <<<\"\$1\" && grep -q '403' <<<\"\$1\"" _ "$out"
check "...and stops there" bash -c "! grep -q 'name=scg-scan' '$log'"
extra_env=(FAKE_FAIL_DELETE=1)
run "$default" v0.2.0-1 "${files[@]}"
check "a failed removal of an old asset fails the script" test "$status" -ne 0
check "...with a reason" has "old asset"
extra_env=()

# 5. usage
repo=""
run "$default" v0.2.0-1 checksums.txt
check "no GITHUB_REPOSITORY fails" test "$status" -ne 0
check "...and says which variable" has "GITHUB_REPOSITORY"
repo="owner/repo"
run "$default"
check "no arguments is a usage error" test "$status" -eq 2
run "$default" v0.2.0-1
check "a tag with no files is a usage error" test "$status" -eq 2

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
