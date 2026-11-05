#!/usr/bin/env bash
# Attaches files to the DRAFT release of a tag, using upload calls only.
#
#   attach-release-assets.sh <tag> <file>...
#
# Needs gh and jq, and GH_TOKEN and GITHUB_REPOSITORY (Actions sets the latter).
# ATTACH_LOOKUP_ATTEMPTS (default 3) and ATTACH_LOOKUP_WAIT_SECONDS (default 5)
# say how often, and how far apart, to look for the release: a list of
# releases can lag just after one is created. When it is not found, the
# failure lists the releases that were seen.
#
# It never edits the release itself, so it cannot publish it or change its
# title, notes or state, and it refuses a release that is not a draft. A file
# with the same name as an asset already on the draft replaces that asset.
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: attach-release-assets.sh <tag> <file>..." >&2
    exit 2
fi
tag=$1
shift

if [ -z "${GITHUB_REPOSITORY:-}" ]; then
    echo "::error::GITHUB_REPOSITORY is not set" >&2
    exit 1
fi
repo=$GITHUB_REPOSITORY

error() {
    echo "::error::$*" >&2
    exit 1
}

attempts="${ATTACH_LOOKUP_ATTEMPTS-3}"
wait_seconds="${ATTACH_LOOKUP_WAIT_SECONDS-5}"
case "$attempts" in
    '' | *[!0-9]* | 0)
        echo "::error::ATTACH_LOOKUP_ATTEMPTS must be a whole number of at least 1, not '$attempts'" >&2
        exit 2
        ;;
esac
case "$wait_seconds" in
    '' | *[!0-9]*)
        echo "::error::ATTACH_LOOKUP_WAIT_SECONDS must be a whole number, not '$wait_seconds'" >&2
        exit 2
        ;;
esac

# Check every file before any call is made.
for file in "$@"; do
    [ -f "$file" ] || error "$file does not exist, so it cannot be attached"
done

err="$(mktemp)"
trap 'rm -f "$err"' EXIT

attempt=1
while :; do
    if ! raw="$(gh api --paginate "repos/$repo/releases?per_page=100" 2>"$err")"; then
        error "Could not list the releases: $(tr '\n' ' ' <"$err")"
    fi
    releases="$(jq -s 'add // []' <<<"$raw")"
    matching="$(jq --arg tag "$tag" '[.[] | select(.tag_name == $tag)]' <<<"$releases")"
    [ "$(jq length <<<"$matching")" -gt 0 ] && break

    if [ "$attempt" -ge "$attempts" ]; then
        seen="$(jq -r '[.[:10][] | "\(.id) \(.tag_name) draft=\(.draft)"] | join("; ")' <<<"$releases")"
        error "There is no release (draft or published) for the tag $tag after $attempts look(s). Releases seen: ${seen:-none}"
    fi
    echo "No release for $tag yet (look $attempt of $attempts); waiting $wait_seconds s"
    sleep "$wait_seconds"
    attempt=$((attempt + 1))
done

drafts="$(jq '[.[] | select(.draft == true)]' <<<"$matching")"
if [ "$(jq length <<<"$drafts")" -eq 0 ]; then
    error "The release for the tag $tag is not a draft, so it is left alone"
fi
if [ "$(jq length <<<"$drafts")" -gt 1 ]; then
    echo "::warning::There is more than one draft release for $tag; using the newest"
fi
release="$(jq '.[0]' <<<"$drafts")"
id="$(jq -r '.id' <<<"$release")"
echo "Attaching to the draft release $id for $tag"

for file in "$@"; do
    name="$(basename "$file")"

    old_ids="$(jq -r --arg name "$name" '.assets[]? | select(.name == $name) | .id' <<<"$release")"
    for old in $old_ids; do
        if ! gh api --method DELETE "repos/$repo/releases/assets/$old" >/dev/null 2>"$err"; then
            error "Could not remove the old asset $name (id $old): $(tr '\n' ' ' <"$err")"
        fi
    done

    encoded="$(jq -rn --arg name "$name" '$name | @uri')"
    if ! gh api --method POST "https://uploads.github.com/repos/$repo/releases/$id/assets?name=$encoded" \
        -H "Content-Type: application/octet-stream" --input "$file" >/dev/null 2>"$err"; then
        error "Uploading $name failed: $(tr '\n' ' ' <"$err")"
    fi
    echo "  attached $name"
done
