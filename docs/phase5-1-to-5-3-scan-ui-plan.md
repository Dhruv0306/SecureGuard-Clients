# Phase 5.1–5.3: Missing Desktop UI — Plan

Grounded in the web app's actual implementations, not assumed from feature names.

## 5.1: Domain blocking UI

Backend fully exists (Phase 4): `block_domain_cmd`/`unblock_domain_cmd`/
`list_blocked_domains_cmd`, tested. This sub-phase is UI only: an input field, block/
unblock buttons, a live list, mirroring how scan/sync already work in `desktop/src/`.

**Real end-to-end testing needs the helper running elevated** (it writes the OS hosts
file). Documented as a manual step, not something this UI can bypass.

## 5.2: Directory and system scan

Confirmed from `SecurityServiceImpl.java`:
- **Directory scan**: user-specified path, optional recursive flag, synchronous, walks
  and scans every file.
- **System scan**: same walk, rooted at every filesystem root (all drives on Windows,
  `/` on Unix), skipping a fixed set of OS directories (`Windows`, `Program Files`,
  `$Recycle.Bin`, `System Volume Information`, etc.), async with a time budget and
  stop-mid-scan support in Java.

**Scope decision for this pass**: implement directory/system scan as a new
`core::dir_scan` module (`scan_directory(path, recursive, signatures, rules) ->
Vec<ScanResult>`, reusing the existing per-file `scoring::score_file` logic, no new
detection logic needed) plus a Tauri command, run **synchronously with a progress
event stream** rather than Java's full async-job/poll-status model. A genuinely
async, cancellable, resumable scan session (matching Java's `SystemScanSession`
exactly) is more than this pass should take on; a progress-emitting synchronous scan
gets real usability for both directory and system scan without that added complexity.
Flagged explicitly rather than silently simplified.

Root enumeration is the one platform-specific piece: Windows drive letters need a
WinAPI call or a small helper crate (`std::fs` has no built-in enumerator), Unix is
just `/`. Skip-list matches Java's exactly, ported, not re-derived.

## 5.3: Network scan

Confirmed real, not simulated: `NetworkSecurityServiceImpl.scanNetwork()` enumerates
actual network interfaces (`NetworkInterface.getNetworkInterfaces()`), checks real
open/listening ports, flags suspicious connections, reports firewall/web-protection
status.

**Not scoped in detail yet**, deliberately, per the sequencing decision. Porting real
interface enumeration and listening-port detection to Rust needs its own crate
research (cross-platform port/connection enumeration is meaningfully more
OS-specific than anything built so far in this project) before a real plan can be
written, not something to improvise inline with 5.1/5.2.

## Work order

1. **5.1** now: UI only, no new backend.
2. **5.2** next: new `core::dir_scan` module + command + UI, scoped down from Java's
   async-job model as described above.
3. **5.3** last, separately planned: needs its own crate/design research before
   implementation starts.
