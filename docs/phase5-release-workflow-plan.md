# Phase 5: Release Workflow — Detailed Plan

Branch: `phase5-release-workflow`.

## Scope boundary

A GitHub Actions workflow triggered on `v*` tags that builds desktop artifacts across
Windows/macOS/Linux, computes checksums, GPG-signs them, and attaches everything to the
GitHub Release. Per the original distribution plan: GitHub Releases only, no app store
submission, "GitHub is the only official source" stated explicitly in the release.

**What this phase does not solve**, carried over honestly from Phase 4's own deferral:
the `helper` binary has no service-registration or installer-integration story yet, no
dedicated account provisioning, nothing installs it as a running service. Phase 5
builds and ships the `helper` binary as an artifact, it does not make it
self-installing. That gap stays open until Phase 4's deferred steps 4-5 land.

## What's already there to build on

- `tauri.conf.json` already lists bundle targets: `msi`, `nsis`, `dmg`, `appimage`,
  `deb`.
- Placeholder icons already committed (Phase 3's fix), so a fresh checkout can build a
  bundle immediately, no manual pre-step needed.
- `core`'s CLI (`scg-scan`) is also a legitimate standalone downloadable tool in its own
  right, not just a dev harness, worth releasing alongside the desktop app, not only
  bundled invisibly inside it.

## Versioning: one source of truth, not three independent guesses

Right now `core`, `desktop/src-tauri`, and `helper` each have their own
`version = "0.1.0"` in `Cargo.toml`, entirely unsynced. A release tag like `v1.0.0`
means nothing enforceable against three crates that could each claim a different
version. Fix: `[workspace.package] version = "..."` in the root `Cargo.toml`, each
crate's `Cargo.toml` changed to `version.workspace = true`. The release workflow then
verifies the pushed tag matches that single version before building anything, and fails
loudly on mismatch rather than shipping a release whose artifacts don't agree with its
own tag.

## Build strategy: the official `tauri-apps/tauri-action`, not a hand-rolled matrix

Tauri bundling is inherently platform-native, a `.dmg` can't be produced on Linux, an
`.msi` can't be produced on macOS, so this needs a build matrix across
`windows-latest`/`macos-latest`/`ubuntu-latest` runners regardless of approach. Rather
than hand-rolling each platform's bundle invocation and upload step (real risk of
getting platform-specific flags wrong, same category of risk as this phase's own
Linux-GTK-dependency lesson from Phase 3's CI fix), use the official
`tauri-apps/tauri-action`, which already solves exactly this problem and handles
creating/attaching to the GitHub Release directly. Reduces this phase's own risk
surface by leaning on a well-maintained action for the trickiest, most
platform-specific part instead of reinventing it.

The `helper` binary isn't part of Tauri's own bundle process (it's a separate crate,
not the Tauri app), so it needs its own build-and-upload steps per platform, run
alongside the `tauri-action` step in the same matrix job.

## Checksums and GPG signing

After all artifacts exist (desktop bundles + helper binaries, all platforms):
1. A final job (depending on the full matrix completing) downloads every artifact,
   computes SHA-256 for each, writes a single `checksums.txt`.
2. GPG-signs `checksums.txt` (not each artifact individually, signing the manifest is
   sufficient, verifying a listed hash against a downloaded file is what actually
   proves integrity for that file).
3. Both `checksums.txt` and `checksums.txt.asc` (the signature) get attached to the
   release alongside the binaries.

**Requires a one-time manual step from you, not something I can do**: generating a GPG
keypair and storing the private key (and its passphrase, if any) as GitHub Actions
secrets. See `docs/release-gpg-setup.md` for the exact commands, key generation and
initial secret storage has to happen on your machine, not mine, a private signing key
should never pass through a sandbox that isn't the one actually holding it long-term.

## Release notes template

Every release body includes, not just the changelog: a statement that GitHub is the
only official distribution source (matching the "repackaged/fake APK" risk entry from
the original plan's risk register, same reasoning applies to a fake desktop installer),
and the `checksums.txt`/`.asc` verification instructions.

## Work breakdown

1. **Workspace version unification**: `[workspace.package]`, all three crates switch to
   `version.workspace = true`.
2. **`release.yml` workflow**: triggered on `v*` tags, matrix across the three OSes,
   `tauri-action` for the desktop bundle, separate steps for building and uploading the
   `helper` and `scg-scan` binaries per platform.
3. **Checksum + signing job**: depends on the matrix, downloads all artifacts, produces
   and signs `checksums.txt`.
4. **Release notes template**: the "GitHub only" statement and verification
   instructions, either a static template file the workflow injects, or written inline
   in the workflow.
5. **GPG key setup** (your side): key generation, secret storage, documented as exact
   commands but not something I execute.

## Test gate (from the original plan doc)

"Verified against one real tagged release." Unlike every previous phase's test gate,
this one is fundamentally not verifiable by writing more tests, it's verified by
actually pushing a tag and watching the workflow run. I can write the workflow
carefully and reason about each step, but the real signal only comes from you pushing
`v0.1.0` (or whatever the first tag ends up being) and watching what happens in the
Actions tab.

## Explicit non-goals for Phase 5

- No `helper` service registration or installer integration (Phase 4's deferred work,
  still deferred).
- No code signing certificates for the desktop installers themselves (separate from
  GPG-signing the checksums file), Windows SmartScreen and macOS Gatekeeper warnings on
  unsigned binaries are an accepted, already-documented tradeoff from the original
  distribution plan, not something this phase changes.
- No auto-update mechanism, this phase only gets artifacts onto a GitHub Release, it
  doesn't make the app check for or install new versions.

## Honest risk assessment

Lower code-risk than Phase 4 (no exotic IPC crate, no new unverified Rust APIs), but
higher process-risk: this is the first phase whose entire test gate depends on a live
GitHub Actions run across three separate OS runners, plus a real, currently-nonexistent
GPG key that only you can create. Expect the actual `.yml` syntax to need iteration
(matrix job output-passing between the build and sign jobs is a common source of
GitHub Actions bugs, not a Tauri or Rust-specific risk) and expect the first real tag
push to surface something this plan didn't anticipate.

## Implementation notes (post-planning)

- `tauri.conf.json` turned out to have its own independent `version` field, a fourth
  place version lived beyond the three Cargo.toml files. Tauri's own CLI syncs it
  automatically from Cargo.toml, but only when invoked via `tauri build`/`tauri dev`,
  not a plain `cargo build`, confirmed via other real projects hitting the identical
  issue. Fixed with a `build.rs` step that syncs it from `CARGO_PKG_VERSION` before
  `tauri_build::build()` runs.
- Every matrix entry (including the two "native" platforms, Windows and Linux) was
  given an explicit target triple, not just the two macOS cross-compile entries,
  specifically so the helper/CLI binary output path
  (`target/<triple>/release/...`) is uniform across all four entries rather than
  needing two different code paths (default `target/release/` for native vs.
  `target/<triple>/release/` for cross-compiled).
- Releases are created as drafts (`releaseDraft: true`), not published automatically,
  so there's a manual review-and-publish step after the workflow completes, worth
  keeping even once this workflow is trusted, a bad release is much cheaper to catch
  before it's public than after.
- Release notes are pulled from `CHANGELOG.md`, matching the main Antivirus repo's own
  `release.yml` pattern exactly: an `awk` extraction of the `## [VERSION]` section up
  to the next `## [` heading, failing loudly if no matching section exists rather than
  shipping an empty or stale body. This means the `## [Unreleased]` heading in
  `CHANGELOG.md` must be renamed to `## [VERSION] - DATE` before tagging a real
  release, the tag push itself doesn't do this automatically.
