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

## Not covered

- **Linux and macOS.** The same socket name is used, but access control for it is not
  set. On Linux a namespaced local socket is, as far as I know, an abstract socket with
  no file permissions. This needs checking and a fix before the helper is shipped there.
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
