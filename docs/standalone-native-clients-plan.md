# Standalone Desktop and Mobile Clients: Design Plan (v2)

## Why this replaces the earlier plan

The first version of this plan assumed a thin desktop/mobile shell calling the existing
Spring Boot backend's `/api/**` endpoints, either over a network or via a bundled local
sidecar. That's been rejected: the desktop and mobile apps are meant to be fully
standalone, no embedded backend, no server dependency at runtime. Detection logic runs
natively in the client itself.

Everything about the privilege-split architecture (see the original desktop plan's
threat-model reasoning) still holds, hosts-file/firewall/DNS operations still need a
narrowly-scoped OS-specific helper, never a fully elevated main process. What changes is
that the "main process" no longer talks to a backend over HTTP, it contains the
detection engine in-process.

## Core problem: one engine, not three

`SecurityServiceImpl.java` (2,065 lines) plus `ThreatIntelSignatureService.java`
implement the weighted 0-100 scoring engine, Shannon entropy packer detection, and
MalwareBazaar-based signature sync that the web app already relies on. Rewriting that
independently for desktop and for Android would mean three copies of the same logic, and
three places to fix the same bug, exactly the drift risk that produced the EICAR-hash
and filename-vs-temp-name bugs already found once.

**Decision:** write the detection core once in Rust, reused directly by the desktop app
(Tauri already uses Rust) and exposed to Android via UniFFI-generated Kotlin bindings.
This is the same pattern Firefox and 1Password use to share one native core across
desktop and mobile. Net result: two implementations to maintain (the existing Java one
for the web app, one shared Rust core for both standalone clients) instead of three.

**Signature matching is not written from scratch.** VirusTotal maintains YARA-X, a
production-grade Rust reimplementation of YARA, as a dependency, not a hobby project.
The Rust core uses it directly for pattern-based matching, SecureGuard's own layer on
top is the weighted 0-100 scoring and Shannon-entropy packer detection, that's the actual
differentiator worth building custom, not the matching engine underneath it. Existing
Rust security projects surveyed for this plan (Owlyshield, Sanctum) are explicitly
labeled experimental or proof-of-concept by their own authors, that's not the quality bar
this ships at, and it's a reason to lean on YARA-X's maturity rather than one of them.

For Android, UniFFI cross-compiles the core to a `cdylib` per ABI via `cargo-ndk`, and
Kotlin binding generation itself only needs the compiled library's embedded metadata, so
it can run from a plain Linux CI job, no Android toolchain required just to generate
bindings, only to produce the per-ABI binaries.

The Rust core is not a line-by-line translation of the Java source. It's an independent
implementation of the same rules (weighted scoring, `THRESHOLD_HIGH_ENTROPY = 7.2`,
signature matching), verified against the same test corpus already built for the backend:
known-malware IOCs (WannaCry, NotPetya), the known-good false-positive set, and EICAR.
That test suite is the spec both implementations must satisfy, not a Java-to-Rust port.

## Local storage

No shared server DB exists for these clients. Each install carries its own local
embedded SQLite database (via Rust's `rusqlite`), holding the subset of the current
Flyway schema relevant to a single-device install: scan history, cached threat-intel
signatures, blocked-domain list. No multi-user auth model is needed, this is single-device
local software, not a shared server.

## Threat-intel sync

`ThreatIntelSignatureService` currently fetches MalwareBazaar's recent-hashes export
directly. That fetch-and-cache logic is ported into the Rust core as-is, since it's a
straightforward HTTP GET and parse, the complexity lives entirely in the detection logic,
not the sync. Each standalone install runs this fetch on its own schedule, directly, no
longer proxied through a shared backend.

## Privileged operations (unchanged in principle)

Same reasoning as before: never run the whole app elevated.

| OS | Elevation mechanism | Runtime privilege |
|---|---|---|
| Windows | Signed Windows service, installed via one UAC prompt | Service runs under a dedicated low-rights service account |
| macOS | Privileged helper tool via SMJobBless / Service Management | Helper runs under its own launchd job |
| Linux | systemd unit + polkit policy | Same shape as system-agent's current deployment |

The main app (Rust core + UI) talks to its local helper over local IPC, same boundary as
before, just no longer relevant to detection logic itself, only to hosts/firewall/DNS
writes.

## Distribution

GitHub Releases only, no app store fees. Checksums, GPG-signed release notes, consistent
Android signing key across releases, README/release-note warning that GitHub is the only
official source. iOS remains out of scope without a paid Apple Developer account.

## Repository

This plan lives in its own repository (`SecureGuard-Clients`), separate from
`Dhruv0306/Antivirus`. The original reason for keeping clients in the main repo, sharing
the `/api/**` contract with the web app, no longer applies: the Rust core doesn't call
the backend at all. What's left coupling them was thin (a test corpus, this plan's docs
history), and the toolchain mismatch cuts the other way, mixing Maven/npm CI with cargo,
`cargo-ndk`, and an Android Gradle project in one config is more complexity than two
repos, not less.

```
SecureGuard-Clients/
├── core/            # Rust crate: YARA-X + weighted scoring + entropy detection
├── desktop/         # Tauri shell (src-tauri/ + its own frontend, no React reuse)
├── android/         # Kotlin app + UniFFI-generated bindings
├── .github/workflows/
└── docs/            # this plan lives here as the living architecture doc
```

**Test corpus sync:** rather than a git submodule pointing back at the main repo (more
"correct" but a maintenance chore for a solo maintainer to keep updated), CI in this repo
fetches the corpus files directly from `raw.githubusercontent.com` at a pinned commit
SHA in the main repo. The corpus is test fixtures, not code, drift risk is low and
visible, tests fail loudly if the fetch breaks or the pinned SHA goes stale.

`phaseN-description` branch naming and one-branch-one-PR still apply.

## Implementation phases

One branch, one PR per phase, strict dependency order except where marked flexible.

| Phase | Branch | Scope | Depends on | Test gate |
|---|---|---|---|---|
| 1 | `phase1-detection-core` | Rust crate built on YARA-X for pattern matching, plus SecureGuard's own weighted-scoring and entropy-detection layer on top, and the local SQLite schema | none | Corpus validated in both engines in the same CI run, with verdicts diffed against the Java backend, not just independently green; not a signature-matching engine written from scratch |
| 2 | `phase2-threat-intel-sync` | Port MalwareBazaar fetch-and-cache into the Rust core, scheduled local sync | Phase 1 | Local DB populates from a real fetch; stale-cache and fetch-failure behavior tested explicitly |
| 3 | `phase3-desktop-shell` | Tauri UI wrapping the Rust core directly (in-process calls, no HTTP), scan UI and history view | Phase 2 | Manual scan against the same corpus produces matching verdicts through the UI |
| 4 | `phase4-desktop-privileged-helper` | OS-specific helper for hosts/firewall/DNS, local IPC to the main app | Phase 3 | Uninstall-leaves-nothing-running test; IPC permission test |
| 5 | `phase5-release-workflow` | GitHub Actions workflow on `v*` tags: builds desktop artifacts, checksums, GPG signing | Phase 4 | Verified against one real tagged release |
| 6 | `phase6-android-bindings` | UniFFI Kotlin bindings for the Rust core, Android shell, scoped-storage file scanning | Phase 5 | Same corpus verdicts reproduced through the Android UI; standard install/uninstall cycle |
| 7 | `phase7-android-vpn-blocking` | `VpnService`-based domain blocking | Phase 6 | Killswitch test: killing the VPN process must not silently fall back to unfiltered traffic |
| 8 | `phase8-android-device-admin` | Narrow Device Admin policy against tampering/uninstall bypass | Phase 6 | Uninstall fully clears the policy |

Phases 7 and 8 are the one flexible pair, both only need Phase 6, order between them
doesn't matter.

## Security risk register

| Risk | Where it applies | Mitigation / test |
|---|---|---|
| Detection logic drifts between Java backend and Rust core | Core engine | Both implementations validated against the same shared test corpus, not against each other |
| Orphaned elevated helper survives app uninstall | Desktop privileged helper | Uninstaller must remove the Windows service / macOS launchd job explicitly |
| Weak local IPC permissions between app and helper | Desktop app-to-helper channel | Only the expected user/process can open the socket/pipe |
| VPN tunnel fails open instead of closed on crash | Android domain-blocking | Killing the VPN process must not silently fall back to unfiltered |
| Repackaged/fake APK impersonating SecureGuard | Android distribution | Consistent signing key, checksums, GPG-signed release notes, "GitHub only" warning |
| Local SQLite DB tampering (no server-side integrity check anymore) | Local storage | Worth a dedicated look once Phase 1 lands: verdicts and signature cache are now fully client-side and locally writable |
| Supply-chain exposure from YARA-X and any archive/file-type crates it depends on | Detection core | `cargo` ecosystem tracked under Dependabot alongside the existing four (root Maven, system-agent Maven, frontend npm, GitHub Actions) |
| Detection core parses adversarial, attacker-crafted input by design | Detection core | Fuzz the SecureGuard-specific parsing/extraction code sitting around YARA-X; YARA-X itself is already extensively fuzzed by VirusTotal, the gap is in code we write, not code we depend on |

## Market context

Surveyed existing Rust security tooling before committing to build-from-scratch:
YARA-X (VirusTotal, production-grade pattern matching), Owlyshield (Rust, behavior-based,
explicitly research-oriented), Sanctum (Rust EDR, self-described proof-of-concept). No
existing project combines a production-quality Rust core with GitHub-Releases-only
distribution the way this plan does, that's the gap. It's also why the plan leans on
YARA-X for matching rather than treating the existing hobby/research projects as a
template, they don't claim the quality bar this needs to ship at.

## Open questions

- UniFFI vs a hand-rolled JNI bridge for Android bindings: UniFFI is less work and battle-tested elsewhere, worth confirming it covers everything the core needs before committing.
- Whether the Rust core's threat-intel corpus (Phase 2) should also be usable as an offline seed bundled at install time, so a fresh install has some coverage before its first successful sync.
- Whether iOS gets revisited later if a paid Apple Developer account becomes worthwhile.
