# Phase 4: Desktop Privileged Helper — Detailed Plan

Branch: `phase4-desktop-privileged-helper`.

## Source of truth

Grounded in the main repo's actual privileged code, not assumed from the interface
name. `NetworkSecurityServiceImpl.java` (the web app's `NetworkSecurityService`) is a
dead end for this phase: `blockDomain`/`toggleFirewall`/etc. are pure in-memory
simulation (a `Set<String>`, boolean flags), no real OS calls at all, nothing to port.

The real privileged logic lives in `system-agent/`, a genuinely separate OS process
built for exactly the reason this phase exists: never let the process that parses
untrusted input (scanned files, web uploads) also hold filesystem privilege. Three
pieces matter here:

- **`HostsFileWriter`**: marker-based (`# ANTIVIRUS_BLOCKED_DOMAIN`) rewrite of the
  hosts file, backup-before-write, restore-from-backup on failure. This code itself
  needs no privilege, any process that *can* write the file can run it; the privilege
  is entirely about who's allowed to write that specific file.
- **`AgentConfig.getHostsFilePath()`**: `C:\Windows\System32\drivers\etc\hosts` on
  Windows, `/etc/hosts` elsewhere. Exact values, not assumed.
- **`provision-hosts-acl.ps1`/`.sh`**: grants a *specific account* Modify rights on the
  hosts file specifically via `icacls`/`setfacl`, not admin/root generally. This is the
  concrete mechanism behind "narrow grant, not blanket elevation," already built and
  documented for the server deployment, adapted here for a desktop context.

DNS-level blocking via dnsmasq is Linux-only (no Windows equivalent exists, per the
PowerShell script's own comment) and explicitly out of scope, see Non-goals.

## The core design question

Java's system-agent is a separate OS process because the web app is network-facing
(higher attack surface) and must never hold filesystem privilege itself. **The same
argument applies identically to the desktop app**: it parses arbitrary, untrusted,
user-supplied files, exactly the kind of process a privilege split exists to protect
against. A memory-safety bug in the scanning path (however unlikely in safe Rust,
still possible in `unsafe` blocks or a dependency) must not translate into hosts-file
write access.

**Rejected alternative**: grant the interactive user's own account an ACL on the hosts
file (skip a separate process entirely, since Rust processes under the same user
account could all use it). This is simpler but breaks the security property Java's
architecture was built for: the *desktop app's own process*, not just "the user," would
then be able to write the hosts file, and that's the exact process handling untrusted
file content. Rejected for the same reason Java never lets the web app hold this
capability directly.

**Chosen design**: a genuinely separate helper process, own crate, own OS identity,
holding the ACL grant alone. The main app talks to it over local IPC, event-driven
(only when the user actually changes a blocked domain), not Java's 30-second poll,
that polling design exists in Java because the web app and agent coordinate through a
shared database with no other channel; our desktop app and helper can talk directly.

## Architecture

```
helper/                         # new crate, root of the workspace, sibling to core/desktop
├── Cargo.toml                  # depends on core (path) for hosts_writer logic
└── src/
    └── main.rs                 # IPC server: receive domain list, write, report back

core/src/hosts_writer.rs        # ported HostsFileWriter logic, shared, no privilege
                                 # of its own, testable against a throwaway file exactly
                                 # like the Java tests do

desktop/src-tauri/src/
└── commands.rs                 # gains block_domain_cmd/unblock_domain_cmd, talks to
                                 # helper/ over IPC, not a direct file write
```

## `hosts_writer.rs`: ported once, used by both the helper and tests

Same marker constant, same backup-then-write, same restore-on-write-failure. Lives in
`core` (not `helper`) specifically so its correctness is testable the same way
`entropy.rs`/`extension.rs` etc. already are, against a throwaway file, no elevation,
no real hosts file touched by `cargo test`. The `helper` crate is the only thing that
ever calls it against the *real* hosts file path.

## IPC: local, narrow, not a shared database

Java's shared-DB coordination is a consequence of the web app and agent being
unrelated processes with no other channel. Our desktop app and helper are both parts of
one product; a direct local IPC channel (named pipe on Windows, Unix domain socket on
macOS/Linux) is simpler and avoids introducing a database dependency into `helper` at
all. Protocol: main app connects, sends the current full domain list (matching Java's
"always send the full active set, not deltas" approach, same reasoning: simpler,
harder to get out of sync), helper writes, reports success/failure/error string back,
connection closes. No persistent connection, no polling.

## Privilege setup: adapted from the existing scripts, not invented fresh

At install time (Phase 5's installer, or a first-run setup step ahead of it):
1. Create a dedicated, low-rights local account for the helper (matching
   `provision-agent-user.sh`'s Linux precedent, needs a Windows equivalent via
   `New-LocalUser`, not yet scripted anywhere in this repo).
2. Run the adapted `provision-hosts-acl` grant against that account specifically, not
   the interactive user (see "core design question" above for why).
3. Register the helper as a service (Windows service / launchd job / systemd unit)
   running under that account, matching the OS table from the original standalone
   plan's "Privileged operations" section.

This is real, substantial, platform-specific work, more installer/OS-integration work
than any previous phase, and honestly the part of this plan I'm least able to verify
without actually running it on each OS.

## `blocked_domains` schema: simpler than Java's, deliberately

Java's schema has an `is_active` flag; ours doesn't. Rather than add one, active =
present in the table, inactive = deleted, no flag needed. Simpler for a single-user
local tool with no need to preserve deactivated-domain history the way a multi-tenant
server might.

## Work breakdown

1. **`core::hosts_writer`**: port `HostsFileWriter` exactly, tested against a temp file.
2. **`helper` crate**: IPC server skeleton, wires to `hosts_writer`, platform-specific
   hosts file path resolution (matching `AgentConfig.getHostsFilePath()` exactly).
3. **IPC client in `desktop/src-tauri`**: `block_domain_cmd`/`unblock_domain_cmd`
   commands, persist to `blocked_domains` locally, then send the updated full list to
   the helper.
4. **Platform provisioning scripts**: adapt `provision-hosts-acl.ps1`/`.sh` for a
   dedicated helper-service account rather than a server-deployment agent account.
5. **Service registration**: Windows service install (via the installer, Phase 5
   territory, but the service *definition* belongs here), launchd/systemd equivalents.

## Test gate (from the original plan doc, now concrete)

- **Uninstall-leaves-nothing-running**: after uninstall, the helper service/process
  must not still be running, and the dedicated account's ACL grant should be revoked,
  not left as an orphaned capability on the machine.
- **IPC permission test**: only the desktop app's own process (or a process authorized
  the same way) can open the helper's IPC endpoint, not an arbitrary local process. On
  Windows this is a named pipe ACL; on Unix, socket file permissions.

## Explicit non-goals for Phase 4

- No DNS-level blocking (dnsmasq), Linux-only mechanism, no cross-platform equivalent.
- No firewall rule management, nothing in the Java source actually implements this
  beyond a boolean flag; there's no real behavior to port.
- No installer packaging itself (Phase 5), only the service/account definitions this
  phase's setup needs, which the installer will invoke.

## Honest risk assessment

This is the first phase touching OS service registration, dedicated account creation,
and named-pipe/socket IPC, none of which existed anywhere in this codebase before, and
none of which I can meaningfully verify without a real OS to test service installation
and ACL grants against. Expect this phase to need more iteration than any previous one,
and expect me to get platform-specific details wrong that only surface once actually
run.

## Implementation notes (post-planning)

Scoped the first implementation pass to steps 1–3 only (portable hosts-writer, helper
skeleton, desktop-side IPC client), all testable without touching real system accounts
or services. Steps 4–5 (dedicated account provisioning, service registration) are a
deliberate follow-up, not attempted here, since they can't be meaningfully verified
without a real OS to test against, unlike everything else in this repo so far.

- `interprocess` crate (2.x) chosen for cross-platform local-socket IPC rather than
  hand-rolling platform-specific named-pipe/Unix-socket FFI. Its current API
  (`ListenerOptions`/`ToNsName`/`GenericNamespaced`) was confirmed via the crate's own
  documentation before writing against it, not compiled here (no working toolchain in
  the sandbox for a dependency tree this size), so this is the single highest-risk,
  least-verified piece of this phase.
- `helper` is a lib+bin crate (matching `core`'s own split), specifically so the actual
  request-handling logic is testable via a real IPC round-trip in an integration test,
  pointed at a temp file, never the real hosts file.
- `block_domain_cmd`/`unblock_domain_cmd` separate their DB step (fully unit-testable)
  from their IPC step (not safely unit-testable against a real hosts file); on a helper
  failure, the DB change is rolled back so local state never claims a domain is blocked
  when the real hosts file demonstrably wasn't updated.
- `blocked_domains` gained real CRUD (`add_blocked_domain`/`remove_blocked_domain`/
  `list_blocked_domains`) in `core::storage`; only the table schema existed before,
  the same "buildable but never actually built" gap `record_scan` had before Phase 3.

## Follow-up reminder: no UI wired up yet

The backend for domain blocking (Tauri commands, helper process, IPC round-trip) is
fully implemented and tested, but nothing in `desktop/src/` calls
`block_domain_cmd`/`unblock_domain_cmd`/`list_blocked_domains_cmd` yet, there's no
input field, button, or list view for this feature. As a result, this has never been
exercised end-to-end against a real hosts file, only against temp files in tests.
Adding that UI (mirroring how scan/sync already work) is a small, separate follow-up,
and should happen before considering domain blocking actually done from a user's
perspective, not just from a "the code exists and is tested" perspective.
