# Shipping the helper: site blocking that works from the download

Date: 01/11/2026. Status: PR 1 (release packaging) is built and was proved by a dry run on 05/11/2026. PR 2 (helper lifecycle) is built, see "Helper changes (PR 2)". PR 3 (Windows "Enable site blocking") is built, see "Built in PR 3". PR 4a (Unix access control, the Linux install rule, launch plumbing) is built, see "Built in PR 4a". PR 4b (the `pkexec` start on Linux) is built, see "Built in PR 4b". The release itself is still to do.

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
- Dry run of the release workflow, 05/11/2026 (tag `v0.2.0-1`): the draft held the Windows
  installers, the `.deb`, the AppImage and both `scg-scan` files, and no macOS file and no
  standalone helper. `checksums.txt` listed exactly those six by plain name and every hash
  matched the downloaded file. `gpg --verify` reported a good signature by the release key,
  fingerprint `22BF 18D2 1862 BB6C B7D0 FEE0 EB1D 6289 4E8B 6121`. Both Windows installers
  register under `HKEY_LOCAL_MACHINE`, so both install per machine, and both installed to
  `D:\Program Files\SecureGuard` on that computer, not to `C:\Program Files`. The MSI shows version
  `0.2.0.1` for `0.2.0-1`. Both uninstalled cleanly.
- The helper is inside every package. Extracting the MSI with `msiexec /a` and installing the NSIS
  setup both show `secureguard-helper.exe` (4,902,400 bytes) next to `secureguard-desktop.exe`,
  and the `.deb` lists `usr/bin/secureguard-helper` and `usr/bin/secureguard-desktop`, owned by
  root, mode 755. On that computer `%ProgramFiles%` is `C:\Program Files`, yet both installers
  registered `D:\Program Files\SecureGuard`, which a prefix check on `%ProgramFiles%` would
  have refused. The release overlay config, the collected files, the checksums and the attach
  step all worked in that run.

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

- A new `quit` request. The request is an untagged enum with `deny_unknown_fields`: a set-domains
  request stays exactly `{"active_domains":[...]}` and a quit is `{"quit":true}`. A mixed shape is
  a parse error, and an older helper rejects `{"quit":true}` as a missing `active_domains`, so it
  can never mistake a quit for an empty list. The helper answers success and then exits. A quit
  never touches the hosts file.
- An idle limit of 30 minutes without a request, after which the helper exits. Any request that
  is read, including one that is rejected, restarts it. A client that connects and sends nothing
  does not.
- Each connection is read on its own short-lived thread and only the finished line goes back to
  the accept loop, so a client that connects and sends nothing cannot block a quit or the idle
  exit. Requests are handled one at a time, because the hosts file write is not atomic. At most
  16 connections are read at once, and a request line is limited to 2 MB (the largest legal
  list is about 1.3 MB).
- The desktop's `helper_client` returns a typed error. Only a missing or refused connection
  means "not running"; the block and unblock commands put the marker `helper-unreachable:` at the
  start of their error text for that case, and the page shows a plain explanation. Every other
  failure keeps its own text.

Moved out of PR 2 by the plan of 05/11/2026, because only the Linux start-up needs it or nothing
in PR 2 would use it (the desktop crate rejects unused code):

- PR 3 (done): the `helper_status_cmd` command (`{ supported, running, reason }`) and the client's
  `quit` call.
- PR 4a (done): on Unix, the helper accepts a connection only from root or from one allowed user id. The
  id comes from `--allow-uid <uid>`, or from `PKEXEC_UID` when started by `pkexec`. With neither,
  the Unix helper refuses to start. Windows keeps the pipe access list it has.

### Starting the helper (PR 3 Windows, PR 4 Linux)

- A check decides whether ordinary programs could replace the helper. On Windows it runs as the
  current, non-elevated user and refuses the helper if it can open the helper file for writing
  or create a file in the helper's folder. It does not look at where the program is installed:
  the dry run installed to `D:\Program Files\SecureGuard`, which a `%ProgramFiles%` prefix check
  would have refused although the install is per machine. On Linux the helper and its folder
  must be owned by root and not group- or world-writable. It also refuses an AppImage (the
  `APPIMAGE` variable is set). Debug builds skip the check, so `cargo tauri dev` keeps working.
- `enable_blocking_cmd` asks the operating system to elevate:
  - Windows: `ShellExecuteExW` with the `runas` verb, window hidden, through `windows-sys`
    (already a dependency of `core`; PR 3 adds four features, no new crate).
  - Linux: `pkexec <helper>` with no arguments; the helper reads `PKEXEC_UID`, which pkexec sets.
  Then it waits for the helper to answer: 10 seconds on Windows (the call returns once the prompt
  has been answered), 120 seconds on Linux (the password prompt is still open while it waits),
  and a Linux wait ends at once if `pkexec` exits (126 means the dialog was dismissed, 127 not
  authorized or an error). A dismissed prompt is reported as "cancelled", not as a failure.
- The app sends `quit` when it closes, but only to a helper it started itself. A helper started
  by hand in an administrator shell is left alone.
- On the page, "Site blocking" shows the helper state and an "Enable site blocking" button.
  A block or unblock that finds the helper missing shows the same offer. After it is enabled the
  page says so and the user repeats the action; there is no automatic retry.

### Built in PR 3 (Windows)

- `core::helper_launch` holds the decisions as plain functions: the location rule
  (`check_location`, `check_helper_location`), the status (`helper_status`), the wait loop
  (`wait_until`, which counts its own sleeps so tests need no clock), and the whole flow with the
  outside world passed in (`enable_with`). Only `launch_elevated` is Windows-only. It lives in
  `core` so the `windows-latest` CI job compiles it; the `desktop` crate is not built on Windows
  by CI before a release tag.
- The desktop crate's `helper_control` module connects those to the real socket, the real helper
  path (next to the app's own executable) and the real prompt, and keeps `helper_started_by_app`
  in `AppState`. `main.rs` builds the app and handles `RunEvent::Exit`, which both closing the
  window and `exit_app_cmd` end in; the quit waits at most 2 seconds.
- The write checks run only in release builds (`target/debug` is user-writable by design) and
  only when the helper is not running: a running executable cannot be opened for writing even
  when its permissions allow it, which would read as "safe".
- The page's text for a missing helper no longer tells the user to start it as an
  administrator; the status line and the button do that.

### Built in PR 4a (Unix access control and the Linux install rule)

- `helper`: `Access` (`Anyone` or `Uid`) in `ServeOptions`; `serve` reads `peer_creds().euid()` of
  each accepted connection and closes it unless it is root or the allowed user. `parse_allowed_uid`
  and `main.rs` take the user from `--allow-uid` or `PKEXEC_UID` and refuse to start without one
  on Unix. Windows is unchanged (`Access::Anyone`, the pipe access list).
- `desktop`: `ServerTrust`; on Unix the app talks only to a socket owned by root. The trust is a
  parameter so tests can use a fake helper run as the test user.
- `core::helper_launch`: `check_unix_location` (owner and mode, symlinks resolved),
  `appimage_refusal`, `check_install`, new `Refusal` cases, and `Launch { timeout, watch }` so a
  launcher can set its own wait and report an early failure. The Windows write-probe rule is kept
  as `check_writable_location`.
- Tested in the Linux sandbox as root (another user is a child process running as `nobody`) and
  again as `nobody`, which is what CI sees. The Linux start through `pkexec` is PR 4b.

### Built in PR 4b (the `pkexec` start on Linux)

- `core::helper_launch`: `launch_pkexec(program, helper)` (Unix only) starts `pkexec` with the
  helper's path as its only argument and null stdio, and returns a `Launch` with a 120 second wait
  and a watch on the launcher exiting. `pkexec_exit_error` maps exit 126 to `Declined` and 127 to
  the new `NotAuthorized`; a missing program is `MissingLauncher`. The launcher is reaped in the
  background when the launch is dropped. `PKEXEC_PATH` is `/usr/bin/pkexec`.
- `desktop`: Linux uses it as its `platform_launch`; macOS still reports that starting the helper
  is not available.
- Tested in the Linux sandbox with fake `pkexec` scripts (exit 126, 127, still waiting, the exact
  arguments, null stdio, no zombie), as root and as `nobody`. The real polkit dialog needs an
  Ubuntu desktop (see "Manual checks on Ubuntu" in the security model).

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
  `secureguard-helper.exe` in the install folder; `sha256sum -c --ignore-missing checksums.txt` passes on the
  downloaded files and `gpg --verify` passes on the signature.
- **PR 2.** Unit tests with an injectable clock for idle exit, and the same limit on a real
  socket with short timings; `quit` ends the helper and leaves the hosts file byte for byte
  unchanged; a client that says nothing blocks neither a quit nor the idle exit; the request size
  limit and the reader limit; the unreachable marker on the Rust side and the page text under
  Node.
- **PR 4.** On Linux an integration test connects as the allowed user (accepted) and as another
  user (rejected, using a child process that drops to `nobody`; the sandbox runs as root); no
  allowed user and no `PKEXEC_UID` means a refusal to start.
- **PR 3 and 4.** Unit tests for the location check (a table of paths per platform) and for the
  status logic. Manual: Windows all-users install, Enable, approve UAC, block a domain, confirm
  the hosts file, close the app, confirm the helper exited; cancel the prompt; a per-user
  install shows the reinstall message. Linux `.deb` in an Ubuntu desktop VM, the same steps with
  `pkexec`; the AppImage shows its message.

## Risks and unverified assumptions

| Assumption | How it gets checked |
|---|---|
| `peer_creds()` works on the socket kind the helper listens on | Done in PR 4a: it reports the user on Linux, tested with a client running as another user |
| `ShellExecuteExW` `runas` from a Tauri app shows the prompt with no console flash | Windows manual test |
| `pkexec` finds an authentication agent in an Ubuntu desktop VM and its exit codes mean what the code expects | Linux VM manual test |
| "The current user cannot write to the helper or its folder" is a good proxy for "ordinary programs cannot replace it" on Windows | PR 3 tests it on a normal install folder and on a user-writable folder |

## Open decisions

1. `windows-sys` against a PowerShell `Start-Process -Verb RunAs` call for the Windows prompt.
   Default: `windows-sys`, one small Windows-only dependency and no quoting to get wrong.
2. The idle limit of 30 minutes. Default stays unless it proves annoying.
