#!/usr/bin/env bash
# Writes SHA-256 checksums for the files of a release.
#
#   make-checksums.sh <folder> <output file>
#
# Every regular file directly in <folder> is listed (sub folders are not
# searched), by bare name and sorted, so a user can run
# `sha256sum -c --ignore-missing checksums.txt` in the folder they downloaded
# to. Build leftovers are skipped. It fails, and writes nothing, when there is
# nothing to list.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: make-checksums.sh <folder> <output file>" >&2
    exit 2
fi
folder=$1
output=$2

if [ ! -d "$folder" ]; then
    echo "make-checksums: $folder is not a folder" >&2
    exit 1
fi

output_abs="$(cd "$(dirname "$output")" && pwd)/$(basename "$output")"
temp="$(mktemp)"
trap 'rm -f "$temp"' EXIT

(
    cd "$folder"
    count=0
    while IFS= read -r -d '' name; do
        case "$name" in
            *.d | *.pdb | *.rlib | *.rmeta | *.exp | *.lib | *.sig) continue ;;
        esac
        sha256sum -- "$name"
        count=$((count + 1))
    done < <(find . -maxdepth 1 -type f -printf '%f\0' | LC_ALL=C sort -z)
    if [ "$count" -eq 0 ]; then
        echo "make-checksums: no release files in $folder" >&2
        exit 1
    fi
) >"$temp"

mv "$temp" "$output_abs"
