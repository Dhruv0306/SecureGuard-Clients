# Privileged helper: who can talk to it, and what it will accept

The helper is the only process that writes the hosts file, so it runs with elevated
rights. Anything that can send it a request borrows those rights. Two controls limit
that: who may connect, and what the helper accepts once connected.

## Who may connect (Windows)

The helper creates its named pipe with an explicit security descriptor
(`PIPE_SDDL` in `helper/src/lib.rs`):

```
D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
```

| Who | Code | Access | Why |
|---|---|---|---|
| SYSTEM | `SY` | Full | The account services run as. Can already edit the hosts file, so this adds no power. Covers a service-style install |
| Administrators | `BA` | Full | An elevated administrator session, for example an elevated helper and app during development. Can already edit the hosts file |
| Interactive user | `IU` | Generic read and write | Whoever is logged on at the machine. This is the identity of the desktop app, which is not elevated |

Everyone else gets no access: services, scheduled tasks without a logon, network
logons, and the Everyone group. The library rejects remote pipe clients by default.

Before this change the pipe used default permissions, which Microsoft documents as
giving write access only to SYSTEM, administrators and the creator. A normal desktop app
was refused with "Access is denied (os error 5)", and blocking worked only when the app
and the helper were both elevated (confirmed by testing both ways).

### What this does not prevent

- **Any interactive user can send requests**, including other accounts on a shared PC
  and any program running as the logged-on user. The hosts file is machine-wide, so
  the blocklist already is. Because the helper validates every request, the worst such a
  caller can do is map valid hostnames to `127.0.0.1`.
- **A look-alike pipe server.** The Windows client opens the pipe with generic read and
  write, and generic write includes the right to create another instance of a pipe. So
  the interactive user's entry cannot withhold it. The helper creates the first
  instance with the "first instance" flag, so a process that already owns the name makes
  the helper refuse to start rather than share it. A process could still add an instance
  after the helper is running and answer some requests. Closing that needs the app to
  check who it is talking to (for example `GetNamedPipeServerProcessId`) and is not done.
- **Which program is calling.** Windows access rules cannot tell the SecureGuard app from
  another program run by the same user. A stricter option is for the helper to check the
  caller's executable with `GetNamedPipeClientProcessId`; not done.

## Who may connect (Linux and macOS)

A Unix socket has no access list. On Linux the helper's name is an abstract socket, which has no
file permissions at all, so any local user can connect (`interprocess` 2.4.7 documents this).
The access control is therefore a check of the connecting process's user id.

- **The helper checks the client.** Each accepted connection is asked for its peer credentials
  (`SO_PEERCRED` on Linux). It is kept only if the effective user id is root or the one allowed
  user; otherwise it is closed unread, with no reply, no reader thread and no change to the
  hosts file. If the platform cannot report the user, the connection is refused.
- **Which user.** `--allow-uid <n>` (or `--allow-uid=<n>`) wins; otherwise `PKEXEC_UID`, which
  pkexec sets to the user who started it, so the app can run `pkexec <helper>` with no arguments
  (pkexec does no validation of arguments). With neither, a Unix helper refuses to start (exit
  status 2). Only plain decimal numbers are accepted; a repeated or unknown argument is an error.
- **The app checks the helper.** Another local user could bind the abstract name before the
  helper does and wait for requests. On Unix the app reads the user id behind the socket and
  sends nothing, not even a quit, unless that user is root. A refused socket is reported as its
  own error ("not owned by the expected user"), not as a helper that is not running.
- **The install rule on Linux.** The helper file and its folder must be owned by root, and
  neither may be writable by group or others. Root ownership is required even for mode 555,
  because the owner can change the mode back. Links are resolved first, so a link in a root-owned
  folder to a file in a writable folder is refused. An AppImage (the `APPIMAGE` variable is set)
  is refused with "install the .deb". Debug builds skip the ownership rule but not the AppImage
  refusal.
- **What this does not cover.**
  - `SO_PEERCRED` reports the credentials from when the socket was connected or began listening.
    A setuid program, or a socket handed to another user, can be confused with its owner. The same
    trust model as any local Unix socket.
  - Abstract sockets belong to a network namespace, so an app in a sandbox with its own namespace
    (Snap, Flatpak) cannot reach the helper. The `.deb` app is not sandboxed.
  - An app run as root can write the helper and is allowed in, so the rule and the check say
    little for it.
  - Windows has no equivalent of the app's check of the helper; its pipe uses a first-instance
    flag and an access list on the helper's side only.
- **Not started yet.** Nothing in the app starts the helper on Linux in this change; the start
  through `pkexec` is the next one. Until then the checks above protect a helper someone starts by
  hand with `sudo secureguard-helper --allow-uid $(id -u)`.

## Quit, idle exit and silent clients

- A `{"quit":true}` request makes the helper answer and exit. It never touches the hosts file.
  The helper also exits by itself after 30 minutes without a request. Any request that is read
  restarts the limit, including a rejected one. On Windows the app starts the helper on request
  (see "Starting the helper from the app") and sends it a quit when the app closes, but only a
  helper it started itself. Linux start-up is still to come.
- A client that connects and sends nothing is read on its own short-lived thread, so it blocks
  neither a quit nor the idle exit, and it does not count as activity. At most 16 connections are
  read at once; one over that is closed. A request line over 2 MB is rejected without reading
  the rest.
- **What this adds to "what this does not prevent":** the pipe's access list is unchanged, so any
  interactive user can send a quit and stop the helper. That is a denial of service only, with no
  effect on the hosts file. Holding 16 silent connections open does the same until they close.
  Either way blocking from the app stops until the helper is started again.
- Nothing here changes who may connect on Windows. Who may connect on Linux and macOS is the next
  section.

## What the helper accepts

Hostnames go through `BlockedDomain::parse` (`core/src/blocked_domain.rs`):

- ASCII letters, digits, `-` and `.` only; internationalized names must be given in
  their `xn--` form
- at least two labels (so `localhost` is refused), each 1 to 63 characters, not starting
  or ending with `-`, at most 253 characters in all
- the last label may not be all digits (so IP addresses are refused)
- no whitespace, `#`, control characters or anything else
- lowercased, one trailing dot dropped
- at most 5,000 entries per request

`HostsFileWriter::write` takes `BlockedDomain`, not `String`, so a name that was not
checked cannot be written. The helper validates the whole list and rejects the request
if any entry is bad, leaving the hosts file untouched. The desktop app validates what
the user types too, so the reason is shown straight away.

An entry stored by an older version that no longer passes (for example one containing a
space) makes the helper reject the request. Unblock it in the app to clear it; unblocking
does not re-validate.

## Starting the helper from the app (Windows)

- "Enable site blocking" asks Windows to start the helper elevated, and Windows shows its
  approval prompt. Nothing is started without that approval. Declining is reported as
  "cancelled".
- **The rule before asking.** The app runs as the ordinary user and refuses to ask if that user
  can open the helper file for writing or create a file in the helper's folder. Then an ordinary
  program running as the user could replace the helper before it is given administrator rights.
  A per-user install under the user's own profile fails this rule, and so does an install in a
  folder the user can write; the page says to reinstall for all users. The helper is expected
  next to the app's own executable. The rule is skipped in developer builds, and not applied
  when the helper is already running (a running executable cannot be opened for writing, so the
  probe would say nothing).
- **What the rule does not cover.**
  - Folders above the helper's folder are not checked. A user-writable parent that can be renamed
    or replaced is not caught. Checking every parent would refuse a valid all-users install on a
    drive where the user can create folders (the release dry run installed to
    `D:\Program Files\SecureGuard`, and `D:\` is user-writable on that machine).
  - Between the check and the start there is a short window. An attacker who could use it
    already had write access somewhere the check did not look.
  - The approval prompt names "Unknown publisher", because nothing is code signed.
  - An app that is itself running as administrator, or on a PC with the approval prompts turned
    off, can write the helper, so the rule refuses it and the page shows the reinstall message
    although the install is fine. Starting the helper by hand in an Administrator shell works
    around it: the app then finds it running.
- **Quit on exit.** Only a helper the app started is asked to quit when the app closes. A helper
  started by hand, or already running when the app opened, is left running. The quit waits at
  most 2 seconds, so a helper that does not answer never holds up closing the app.

## Not covered

- **macOS.** Out of the release. The Unix checks apply to it, but the app has no way to start
  the helper there.
- **Firewall and network state.** Out of scope for the helper.

## Manual checks on Windows

Helper in an Administrator PowerShell (`cargo run -p secureguard-helper`), app in a
normal window (`cargo tauri dev`).

1. Block `scg-smoke-test.example` in the app. It succeeds, and the hosts file gains
   `127.0.0.1 scg-smoke-test.example # SECUREGUARD_BLOCKED_DOMAIN`. Unblock removes it.
2. From a normal (non-elevated) PowerShell, send a request that tries to add a second
   hosts line. The reply must be `success: false` with `rejected request`, and the hosts
   file must be unchanged:

   ```powershell
   $c = [IO.Pipes.NamedPipeClientStream]::new('.', 'secureguard-helper', 'InOut')
   $c.Connect(3000)
   $w = [IO.StreamWriter]::new($c); $r = [IO.StreamReader]::new($c)
   $w.WriteLine('{"active_domains":["ok.example.com\n93.184.216.34 bank.example"]}'); $w.Flush()
   $r.ReadLine()
   ```
3. Start a second helper while the first is running. It must refuse to start.

4. In an installed all-users build with no helper running, the Blocked domains section says site
   blocking is off and shows "Enable site blocking". Click it and approve the Windows prompt.
   The section says site blocking is on. Block `scg-smoke-test.example`; the hosts file gains the
   line. Close the app. The `secureguard-helper` process is gone.
5. Click "Enable site blocking" and cancel the prompt. The page says approval was cancelled, no
   helper process exists, and the button is still there.
6. In a per-user install (or any folder the user can write to), the section shows the reinstall
   message and no button.
7. Start the helper by hand in an Administrator PowerShell, open the app (it shows site blocking
   is on), then close the app. The helper keeps running.
