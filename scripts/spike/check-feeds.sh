#!/usr/bin/env bash
# Phase 5.3 spike, Test 1: do the abuse.ch feeds need an Auth-Key?
# Usage: scripts/spike/check-feeds.sh            (no key)
#        ABUSE_CH_AUTH_KEY=xxxx scripts/spike/check-feeds.sh   (also tries with key)
set -u
UA="ureq/3.4"   # mimic the default User-Agent of the ureq client the app uses
declare -A FEEDS=(
  ["Feodo recommended IPs"]="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
  ["MalwareBazaar recent SHA256"]="https://bazaar.abuse.ch/export/txt/sha256/recent/"
)
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

probe() { # name url mode
  local name="$1" url="$2" mode="$3" code
  local hdr=()
  [ "$mode" = "with key" ] && hdr=(-H "Auth-Key: ${ABUSE_CH_AUTH_KEY}")
  code="$(curl -sS -L -m 30 -A "$UA" "${hdr[@]}" -o "$tmp" -w '%{http_code}' "$url" 2>&1)"
  local total comments data v6
  total="$(wc -l < "$tmp" | tr -d ' ')"
  comments="$(grep -c '^#' "$tmp" || true)"
  data=$(( total - comments ))
  v6="$(grep -v '^#' "$tmp" | grep -c ':' || true)"
  printf '%-30s %-9s HTTP %-4s lines=%s comments=%s data=%s data-with-colon=%s\n' \
    "$name" "$mode" "$code" "$total" "$comments" "$data" "$v6"
  echo "  first data lines:"; grep -v '^#' "$tmp" | head -3 | sed 's/^/    /'
}

for name in "${!FEEDS[@]}"; do
  probe "$name" "${FEEDS[$name]}" "no key"
  [ -n "${ABUSE_CH_AUTH_KEY:-}" ] && probe "$name" "${FEEDS[$name]}" "with key"
done
echo
echo "200 = usable. 401/403 = key required. 429 = rate limited. HTML/JSON body = parser would misread it."
