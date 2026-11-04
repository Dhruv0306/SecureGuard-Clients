# Shipping the helper: site blocking that works from the download

Date: 01/11/2026. Status: written for review, not yet planned or built.

Item 2 of the next-steps order (release v0.2.0), widened after a real test: Dhruv downloaded a
build, site blocking did not work, and it worked once the helper was run separately. Decisions
from Dhruv: the helper ships inside the installer and the app starts it on demand through the
operating system's own prompt (not a permanently installed service), and macOS is removed from
the release for now, entirely.

## Problem

Three separate things stop site blocking working from a download:

1. **The helper is never published.** `release.yml` builds `secureguard-helper` and `scg-scan`
   per platform but uploads them only as workflow artifacts. What reaches the GitHub Release is
   the Tauri bundles plus `checksums.txt` and its signature.
2. **The installer does not contain it.** `tauri.conf.json` has no `externalBin` or `resources`.
3. **Nothing starts it.** The app connects to a local pipe or socket and fails with "is it
   installed and running?". The helper needs administrator or root rights. The Phase 4 plan
   deferred "register the helper as a service", and the Phase 5 release plan repeated it as a
   non-goal.

A fourth problem was found while reading the workflow. The signed `checksums.txt` is computed
from the downloaded workflow artifacts, and the only workflow artifacts are the helper and
`scg-scan` binaries. The installers are attached to the release by `tauri-action` and, as far
as can be told without a run, are not covered by `checksums.txt`. The dry run in PR 1 confirms
or refutes this.

## Goal and success criteria

A user downloads the installer for Windows or Linux, clicks "Enable site blocking", approves
the system prompt once, and blocking works. Nothing stays installed with elevated rights, and
the helper only ever runs from a place that ordinary programs running as the user cannot change.

- A block or unblock when the helper is not running ends in a clear offer to enable it, not a
  raw connection error.
- The helper exits when the app closes and after 30 minutes without a request.
- Where blocking cannot be made safe, the page says so and why, in plain words.
- `checksums.txt` covers every file attached to the release, and its signature verifies.
- `cargo build --workspace`, `cargo tauri dev` and CI still build with no helper file present.

## Scope

### Support matrix for v0.2.0

| Target | Release builds | Site blocking |
|---|---|---|
| Windows, all-users install (MSI, or NSIS `perMachine`) | yes | yes, UAC prompt |
| Windows, per-user install | yes | no: "reinstall for all users" |
| Linux `.deb` | yes | yes, `pkexec` prompt |
| Linux AppImage | yes | no: "install the .deb" |
| macOS | removed | not applicable |

### macOS is removed from the release

- `release.yml`: the two macOS matrix entries (`aarch64-apple-darwin`, `x86_64-apple-darwin`)
  are deleted.
- `tauri.conf.json`: `dmg` is removed from `bundle.targets`. The `.icns` icon file stays.
- Docs and `CHANGELOG.md` say macOS builds are removed for now, and why.
- Stays: the `macos` job in `rust-ci.yml` (it only runs the core tests and keeps the code
  portable), and all platform-neutral code.
- To bring macOS back later, three things are needed first: Apple code signing and
  notarization (a non-goal of the release plan today), a safe privileged install location for
  the helper (a `.app` copied from a disk image is normally owned by the user, so its helper
  could be swapped before it is elevated), and a Mac to test on. Apple's license only permits
  macOS in a VM on Apple hardware, as far as is known.

### Not in this work

A permanently installed service, a dedicated low-rights account for the helper, code signing
of any kind (so Windows will show "Unknown publisher" on the prompt), automatic update of the
helper, removing hosts-file entries on uninstall, and the abuse.ch key (done).

## Verified facts this design rests on

- With `externalBin` set and no file present, the build fails: "resource path
  `binaries/secureguard-helper-x86_64-unknown-linux-gnu` doesn't exist". With a file present,
  `tauri-build` copies it next to the app executable as `secureguard-helper`, without the target
  triple. (Tested in a scratch copy with Rust 1.91.)
- Tauri's NSIS installer defaults to a per-user install without elevation. `perMachine`
  installs into Program Files and asks for administrator rights once, at install time.
- `interprocess` 2.4.7 offers `peer_creds()` on Unix streams. On Unix a "namespaced" socket name
  becomes a file under `/tmp/` where abstract sockets are unavailable, and the security model
  says it is an abstract socket on Linux, which has no file permissions.
- The app already sends the whole active list on every block or unblock, and rolls the database
  change back when the helper cannot be reached.

## Design

### Release packaging (PR 1)

- In `build-desktop`, before `tauri-action`, build the helper for the matrix target
  (`cargo build --release -p secureguard-helper --target <triple>`) and copy it to
  `desktop/src-tauri/binaries/secureguard-helper-<triple>[.exe]`. That folder is git-ignored.
- Add `desktop/src-tauri/tauri.release.conf.json` holding only
  `{ "bundle": { "externalBin": ["binaries/secureguard-helper"] } }`, passed to `tauri-action`
  with `--config`. The base config does not list `externalBin`, so ordinary builds are unchanged.
- Set `bundle.windows.nsis.installMode` to `perMachine` in the base config.
- Remove the standalone helper from the extra-binaries upload. Keep `scg-scan`, attach it to the
  release with a per-target file name (`scg-scan-<triple>[.exe]`).
- Rework the checksums so installers and `scg-scan` are all covered. Each build job copies the
  installers it found under `target/<triple>/release/bundle` (the same files `tauri-action`
  attached to the draft release) and `scg-scan-<triple>` into one folder and uploads it as the
  workflow artifact `release-assets-<triple>`. `checksum-and-sign` downloads those, runs the
  tested `make-checksums.sh`, signs as today, and attaches the checksums, the signature and the
  `scg-scan` files. It does not use `gh release download`, which may not see a draft release.
- Remove the macOS matrix entries and the `dmg` target, as above.
- The dry run is a real tag. `tauri-action` already creates a draft release, so nothing is
  public until Dhruv publishes it. A failed attempt is a deleted draft and tag.

### Helper changes (PR 2, in `secureguard-core` and `secureguard-helper`)

- A new `quit` request. The helper answers success and then exits.
- An idle limit of 30 minutes without a request, after which the helper exits.
- On Unix, the helper accepts a connection only from root or from one allowed user id. The id
  comes from `--allow-uid <uid>`, or from `PKEXEC_UID` when started by `pkexec`. With neither,
  the Unix helper refuses to start. Windows keeps the pipe access list it has.
- The desktop's `helper_client` returns a typed "unreachable" result, and the block and unblock
  commands put a stable marker at the start of their error text so the page can recognize it.
- A `helper_status_cmd` command returns `{ supported, running, reason }`, where `reason` is
  plain text when `supported` is false.

### Starting the helper (PR 3 Windows, PR 4 Linux)

- A pure check decides whether the helper file is somewhere only administrators can write:
  under `%ProgramFiles%` or `%ProgramW6432%` on Windows; owned by root and not group- or
  world-writable on Linux; and not running as an AppImage (the `APPIMAGE` variable is set).
  Debug builds skip the check, so `cargo tauri dev` keeps working.
- `start_helper_cmd` asks the operating system to elevate:
  - Windows: `ShellExecuteExW` with the `runas` verb, window hidden, through `windows-sys`
    (one new Windows-only dependency).
  - Linux: `pkexec <helper> --allow-uid <current uid>`.
  Then it waits a few seconds for the helper to answer. A dismissed prompt is reported as
  "cancelled", not as a failure.
- The app sends `quit` when it closes, but only to a helper it started itself. A helper started
  by hand in an administrator shell is left alone.
- On the page, "Site blocking" shows the helper state and an "Enable site blocking" button.
  A block or unblock that finds the helper missing shows the same offer. After it is enabled the
  page says so and the user repeats the action; there is no automatic retry.

### The release itself (after PR 4)

Bump `[workspace.package].version` to `0.2.0`, turn the `[Unreleased]` changelog section into
`## [0.2.0]` (the version check in `release.yml` fails without it), and push the tag `v0.2.0`.
`tauri.conf.json` follows by itself: the desktop `build.rs` syncs its `version` to the Cargo one.
The workflow creates a draft release. Dhruv runs the checklists above on the draft and
publishes it only when they pass. Each PR before that carries its own changelog entry.

### Security model

`helper-security-model.md` gains the rules above: the helper runs only from an admin-only
location, only after the system prompt, only for the user who asked, and exits on its own.
What stays unsolved is stated: the prompt shows "Unknown publisher" because nothing is signed,
and a user who approves the prompt for a swapped file in an admin-only location is outside
what this design can prevent.

## Testing

I can build and test the Linux side here. The Windows prompt, the release run and the VM are
Dhruv's.

- **PR 1.** Dry run with a tag. Checklist: the draft release lists the Windows installers, the
  `.deb`, the AppImage and `scg-scan-*`, and no macOS or standalone helper; `dpkg -c` on the
  `.deb` shows `/usr/bin/secureguard-helper`; the Windows installer puts
  `secureguard-helper.exe` in Program Files; `sha256sum -c --ignore-missing checksums.txt` passes on the
  downloaded files and `gpg --verify` passes on the signature.
- **PR 2.** Unit tests with an injectable clock for idle exit; `quit` ends the helper; on Linux
  an integration test connects as the allowed user (accepted) and as another user (rejected,
  using a child process that drops to `nobody`; the sandbox runs as root); no allowed user and no
  `PKEXEC_UID` means a refusal to start; the unreachable marker and `helper_status_cmd`.
- **PR 3 and 4.** Unit tests for the location check (a table of paths per platform) and for the
  status logic. Manual: Windows all-users install, Enable, approve UAC, block a domain, confirm
  the hosts file, close the app, confirm the helper exited; cancel the prompt; a per-user
  install shows the reinstall message. Linux `.deb` in an Ubuntu desktop VM, the same steps with
  `pkexec`; the AppImage shows its message.

## Risks and unverified assumptions

| Assumption | How it gets checked |
|---|---|
| `--config` with the overlay file works in `tauri-action` on every runner | PR 1 dry run |
| The `.deb` puts the helper at `/usr/bin/secureguard-helper` | `dpkg -c` in the dry run |
| The MSI installs per machine by default | Inspect the installed path in the dry run |
| `peer_creds()` works on the socket kind the helper listens on | First test in PR 2 |
| `ShellExecuteExW` `runas` from a Tauri app shows the prompt with no console flash | Windows manual test |
| `pkexec` finds an authentication agent in an Ubuntu desktop VM and its exit codes mean what the code expects | Linux VM manual test |
| Checksums really miss the installers today | PR 1 dry run |
| The files collected under `target/<triple>/release/bundle` are exactly the installers `tauri-action` attached | PR 1 dry run |
| The workflow token may create a draft, attach files to it, and read it back with upload calls only (the attach script never edits the release) | The manual "Check attaching files to a draft release" workflow, then the PR 1 dry run |
| A Program Files prefix check is enough on Windows | Reviewed in PR 3; an install elsewhere is refused, not trusted |

## Open decisions

1. `windows-sys` against a PowerShell `Start-Process -Verb RunAs` call for the Windows prompt.
   Default: `windows-sys`, one small Windows-only dependency and no quoting to get wrong.
2. The idle limit of 30 minutes. Default stays unless it proves annoying.
