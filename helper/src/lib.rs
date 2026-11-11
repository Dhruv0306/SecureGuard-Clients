//! The privileged helper's actual logic, split into a library so it's
//! testable (integration tests can only link a crate's lib target, not its
//! bin), with a thin main.rs binary wrapper. Same verification caveat as
//! before: the `interprocess` API usage here is written against that
//! crate's documented API, not compiled against here.

use interprocess::local_socket::{
    prelude::*,
    GenericNamespaced,
    Listener,
    ListenerNonblockingMode,
    ListenerOptions,
    ToNsName,
};
use secureguard_core::blocked_domain::parse_domain_list;
use secureguard_core::helper_protocol::{ HelperRequest, HelperResponse };
use secureguard_core::hosts_writer::HostsFileWriter;
use std::io::{ BufRead, BufReader, Read, Write };
use std::sync::atomic::{ AtomicUsize, Ordering };
use std::sync::{ mpsc, Arc };
use std::time::{ Duration, Instant };

/// Who may open the helper's named pipe on Windows, as a security descriptor
/// string. Without an explicit one, a pipe created by an elevated process lets
/// only SYSTEM, administrators and its creator write to it, so an ordinary
/// (non-elevated) desktop app is refused with "Access is denied".
///
/// - `SY` SYSTEM and `BA` administrators: full control (they can already edit
///   the hosts file themselves).
/// - `IU` the interactive user, who runs the desktop app: generic read and
///   write, enough to connect, send a request and read the reply.
///
/// Everyone else, including services and network logons, is denied. The
/// client opens the pipe with generic read and write, so the right to add
/// pipe instances comes with it; see docs/helper-security-model.md for what
/// that does and does not allow. Every request is validated regardless of who
/// sent it.
#[cfg(windows)]
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Creates the helper's listener. The first pipe instance is created with
/// the "first instance" flag, so if another process already owns this pipe
/// name the call fails instead of the helper silently sharing it.
pub fn bind_listener(socket_name: &str) -> std::io::Result<Listener> {
    let name = socket_name.to_ns_name::<GenericNamespaced>()?;
    let options = ListenerOptions::new().name(name);

    #[cfg(windows)]
    let options = {
        use interprocess::os::windows::local_socket::ListenerOptionsExt;
        use interprocess::os::windows::security_descriptor::SecurityDescriptor;

        let sddl = widestring::U16CString::from_str(PIPE_SDDL).map_err(|e|
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        )?;
        options.security_descriptor(SecurityDescriptor::deserialize(&sddl)?)
    };

    options.create_sync()
}

/// The longest request line the helper reads. The largest legal request, 5,000
/// names of 253 characters as JSON, is about 1.3 MB, so 2 MB leaves room. A
/// longer line is rejected without reading the rest, so a client cannot make
/// the helper buffer without limit.
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;

/// What the helper does after one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Continue,
    Quit,
}

/// Why `serve` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// A client sent a quit request.
    Quit,
    /// No request arrived for the whole idle limit.
    Idle,
}

/// How long the helper waits without a request before it exits. The app starts
/// the helper on demand, so a helper nobody is using should not stay running
/// with administrator rights.
pub const DEFAULT_IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);

/// How often the accept loop looks for a new connection and for the idle limit.
/// A request waits at most this long before it is picked up.
pub const DEFAULT_POLL: Duration = Duration::from_millis(200);

/// At most this many connections are being read at once. A connection that
/// never sends a line holds a reader thread until the client closes it, so the
/// number is bounded; a connection over it is closed straight away.
pub const MAX_READERS: usize = 16;

/// Tracks when the helper last did something, with the time passed in so tests
/// need no clock.
#[derive(Debug, Clone, Copy)]
pub struct IdleTimer {
    limit: Duration,
    last_activity: Instant,
}

impl IdleTimer {
    pub fn new(limit: Duration, now: Instant) -> Self {
        Self { limit, last_activity: now }
    }

    pub fn touch(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// True once the whole limit has passed since the last touch. A clock that
    /// reads earlier than the last touch counts as no time passed.
    pub fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= self.limit
    }
}

/// Who may talk to the helper, decided from the user id of the connecting
/// process. On Windows the pipe has an access list, so `Anyone` is used there.
/// On Unix the socket has no file permissions (on Linux it is an abstract
/// socket), so this check is the only access control and a user must be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Anyone,
    /// Root and this user.
    Uid(u32),
}

impl Access {
    /// `peer_euid` is the connecting process's effective user id, or None when
    /// the platform could not tell. With a user named, None is refused: no
    /// answer means no access. Root is always allowed because it can already do
    /// everything the helper can.
    pub fn permits(&self, peer_euid: Option<u32>) -> bool {
        match self {
            Access::Anyone => true,
            Access::Uid(allowed) => peer_euid == Some(0) || peer_euid == Some(*allowed),
        }
    }
}

/// A Unix helper must be told which user to allow; refusing to start is safer
/// than serving every local user. Windows must not be asked to.
pub fn check_access_for_platform(access: Access, unix: bool) -> Result<(), String> {
    if unix && access == Access::Anyone {
        Err(
            "no user is allowed to use this helper: pass --allow-uid <uid>, or start it through pkexec"
                .to_string()
        )
    } else {
        Ok(())
    }
}

/// The user to allow, from the arguments (everything after the program name)
/// and the `PKEXEC_UID` variable that pkexec sets to the user who started it.
/// `--allow-uid <n>` or `--allow-uid=<n>` wins; the variable is read only
/// without it; with neither the answer is an error and the helper does not
/// start. Only plain decimal numbers that fit a `u32` are accepted.
pub fn parse_allowed_uid(args: &[String], pkexec_uid: Option<&str>) -> Result<u32, String> {
    let mut named: Option<String> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let value = if arg == "--allow-uid" {
            rest.next().ok_or("--allow-uid needs a user id")?.clone()
        } else if let Some(value) = arg.strip_prefix("--allow-uid=") {
            value.to_string()
        } else {
            return Err(format!("unknown argument: {arg}"));
        };
        if named.replace(value).is_some() {
            return Err("--allow-uid was given more than once".to_string());
        }
    }

    match (named, pkexec_uid) {
        (Some(value), _) => uid_from_text(&value).map_err(|e| format!("--allow-uid: {e}")),
        (None, Some(value)) => uid_from_text(value).map_err(|e| format!("PKEXEC_UID: {e}")),
        (None, None) => check_access_for_platform(Access::Anyone, true).map(|()| 0),
    }
}

fn uid_from_text(text: &str) -> Result<u32, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{text:?} is not a user id (digits only)"));
    }
    text.parse::<u32>().map_err(|_| format!("{text:?} is too large for a user id"))
}

#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    pub idle_limit: Duration,
    pub poll: Duration,
    pub access: Access,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self { idle_limit: DEFAULT_IDLE_LIMIT, poll: DEFAULT_POLL, access: Access::Anyone }
    }
}

/// The effective user id of the process on the other end of the connection.
#[cfg(unix)]
fn peer_euid(conn: &interprocess::local_socket::Stream) -> Option<u32> {
    use interprocess::local_socket::traits::StreamCommon;
    conn.peer_creds().ok().and_then(|creds| creds.euid())
}

/// Windows has no user id to read; it never names a user, so this is only
/// reached with `Access::Anyone`.
#[cfg(not(unix))]
fn peer_euid(_conn: &interprocess::local_socket::Stream) -> Option<u32> {
    None
}

/// Binds the given socket name and serves requests until a quit request
/// arrives or the helper has been idle for the default limit, then exits the
/// process (status 0). Exits with status 2 on a Unix platform if `access` names
/// no user. Blocking, meant to be the entire body of `main()`.
pub fn run_helper_server(socket_name: &str, writer: HostsFileWriter, access: Access) -> ! {
    if let Err(e) = check_access_for_platform(access, cfg!(unix)) {
        eprintln!("secureguard-helper: {e}");
        std::process::exit(2);
    }

    let listener = bind_listener(socket_name).unwrap_or_else(|e| {
        eprintln!(
            "failed to bind helper socket (already running elsewhere, or a \
             permissions problem): {e}"
        );
        std::process::exit(1);
    });

    eprintln!("secureguard-helper listening on '{socket_name}'");

    match serve(&listener, &writer, &(ServeOptions { access, ..ServeOptions::default() })) {
        Ok(ExitReason::Quit) => eprintln!("secureguard-helper: quit requested, exiting"),
        Ok(ExitReason::Idle) => eprintln!("secureguard-helper: idle, exiting"),
        Err(e) => {
            eprintln!("secureguard-helper: cannot serve: {e}");
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}

/// A connection whose request line has been read (or has failed to arrive).
type Pending<S> = (BufReader<S>, Received);

/// Serves requests on an already-bound listener until a quit request arrives
/// or `options.idle_limit` passes without one. Public so integration tests can
/// run the real loop on a real socket.
///
/// Reading a request can wait on the client, so each connection is read on its
/// own short-lived thread and only the finished line comes back here. Requests
/// are handled one at a time on this thread, which keeps the hosts file writes
/// in order and means a quit is never acted on in the middle of one. A client
/// that connects and sends nothing therefore delays nothing, and does not count
/// as activity.
pub fn serve(
    listener: &Listener,
    writer: &HostsFileWriter,
    options: &ServeOptions
) -> std::io::Result<ExitReason> {
    listener.set_nonblocking(ListenerNonblockingMode::Accept)?;

    let (sender, receiver) = mpsc::channel::<Pending<interprocess::local_socket::Stream>>();
    let readers = Arc::new(AtomicUsize::new(0));
    let mut idle = IdleTimer::new(options.idle_limit, Instant::now());

    loop {
        // Requests that finished reading since the last pass come first, so a
        // request that arrived just before the limit is not lost to it.
        while let Ok((reader, request)) = receiver.try_recv() {
            if matches!(request, Received::Gone) {
                continue; // nothing was sent, so nothing to answer and no activity
            }
            idle.touch(Instant::now());
            if respond(reader, request, writer) == Outcome::Quit {
                return Ok(ExitReason::Quit);
            }
        }

        match listener.accept() {
            Ok(conn) => {
                if options.access.permits(peer_euid(&conn)) {
                    start_reader(conn, &sender, &readers);
                } else {
                    // Closed unread: no reader thread, no reply, no activity.
                    eprintln!("refused a connection from a user that is not allowed");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if idle.expired(Instant::now()) {
                    return Ok(ExitReason::Idle);
                }
                std::thread::sleep(options.poll);
            }
            Err(e) => {
                eprintln!("failed to accept a connection: {e}");
                // Do not spin if accept keeps failing.
                std::thread::sleep(options.poll);
            }
        }
    }
}

/// Decrements the reader count when the reader thread ends, however it ends.
struct ReaderSlot(Arc<AtomicUsize>);

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn start_reader<S>(conn: S, sender: &mpsc::Sender<Pending<S>>, readers: &Arc<AtomicUsize>)
    where S: Read + Write + Send + 'static
{
    if readers.fetch_add(1, Ordering::SeqCst) >= MAX_READERS {
        readers.fetch_sub(1, Ordering::SeqCst);
        eprintln!("too many connections waiting to send a request, closing one");
        return; // `conn` drops here and closes
    }

    let slot = ReaderSlot(Arc::clone(readers));
    let sender = sender.clone();
    let spawned = std::thread::Builder::new().name("helper-reader".to_string()).spawn(move || {
        let _slot = slot;
        let mut reader = BufReader::new(conn);
        let request = read_request(&mut reader);
        let _ = sender.send((reader, request)); // the loop may have ended; nothing to do then
    });
    if let Err(e) = spawned {
        // The closure, and the slot with it, was dropped by the failed spawn.
        eprintln!("failed to start a reader thread: {e}");
    }
}

/// What a connection sent.
enum Received {
    /// One line, with its newline if there was one.
    Line(String),
    /// A line longer than `MAX_REQUEST_BYTES`.
    TooLong,
    /// The client closed without sending anything, or reading failed.
    Gone,
}

/// Reads the one request line. Reads at most one byte more than the limit, so
/// an over-long line is noticed without buffering it all.
fn read_request<R: Read>(reader: &mut BufReader<R>) -> Received {
    let mut line = String::new();
    match reader.take(MAX_REQUEST_BYTES + 1).read_line(&mut line) {
        Ok(0) | Err(_) => Received::Gone,
        Ok(_) if (line.len() as u64) > MAX_REQUEST_BYTES => Received::TooLong,
        Ok(_) => Received::Line(line),
    }
}

fn rejected(message: impl std::fmt::Display) -> HelperResponse {
    HelperResponse { success: false, error: Some(format!("rejected request: {message}")) }
}

/// Handles exactly one request-response exchange on an already-accepted
/// connection, then returns (the connection closes when dropped). Public so
/// integration tests can drive it directly against a real local socket
/// without needing the full accept loop.
///
/// A quit request is answered with success and returns `Outcome::Quit`; the
/// caller decides when to exit, so the reply is already written by then. It
/// never touches the hosts file.
pub fn handle_connection(conn: impl std::io::Read + std::io::Write, writer: &HostsFileWriter) -> Outcome {
    let mut reader = BufReader::new(conn);
    let request = read_request(&mut reader);
    respond(reader, request, writer)
}

/// Acts on a request that has been read and writes the reply.
fn respond<S: Read + Write>(reader: BufReader<S>, request: Received, writer: &HostsFileWriter) -> Outcome {
    let (response, outcome) = match request {
        Received::Gone => {
            return Outcome::Continue;
        }
        Received::TooLong =>
            (rejected(format!("request is longer than {MAX_REQUEST_BYTES} bytes")), Outcome::Continue),
        Received::Line(line) =>
            match serde_json::from_str::<HelperRequest>(&line) {
                // The helper is the trust boundary: it checks every name itself and
                // rejects the whole request, untouched file included, if any is bad.
                Ok(HelperRequest::SetDomains { active_domains }) =>
                    (
                        match parse_domain_list(&active_domains) {
                            Err(e) => rejected(e),
                            Ok(domains) =>
                                match writer.write(&domains) {
                                    Ok(()) => HelperResponse { success: true, error: None },
                                    Err(e) =>
                                        HelperResponse {
                                            success: false,
                                            error: Some(format!("failed to write hosts file: {e}")),
                                        },
                                }
                        },
                        Outcome::Continue,
                    ),
                Ok(HelperRequest::Quit { quit: true }) =>
                    (HelperResponse { success: true, error: None }, Outcome::Quit),
                Ok(HelperRequest::Quit { quit: false }) =>
                    (rejected("quit must be true"), Outcome::Continue),
                Err(e) =>
                    (
                        HelperResponse {
                            success: false,
                            error: Some(format!("malformed request: {e}")),
                        },
                        Outcome::Continue,
                    ),
            }
    };

    let Ok(mut response_json) = serde_json::to_string(&response) else {
        eprintln!("failed to serialize response, dropping connection");
        return Outcome::Continue;
    };
    response_json.push('\n');

    let mut stream = reader.into_inner();
    if let Err(e) = stream.write_all(response_json.as_bytes()) {
        eprintln!("failed to write response to client: {e}");
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ Cursor, Read, Write };
    use std::time::{ Duration, Instant };

    /// An in-memory connection: reads the request from `input`, collects the
    /// reply in `output`. Lets the request handling be tested without sockets.
    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const ORIGINAL_HOSTS: &str = "127.0.0.1 localhost\n";

    fn hosts_file() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), ORIGINAL_HOSTS).unwrap();
        file
    }

    /// Sends one raw line and returns the reply (None when the helper sent
    /// nothing) with the outcome.
    fn exchange(raw: &[u8], hosts: &tempfile::NamedTempFile) -> (Option<HelperResponse>, Outcome) {
        let mut conn = Duplex { input: Cursor::new(raw.to_vec()), output: Vec::new() };
        let outcome = handle_connection(&mut conn, &HostsFileWriter::new(hosts.path()));
        let reply = if conn.output.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&conn.output).unwrap())
        };
        (reply, outcome)
    }

    fn send(domains: Vec<String>, hosts: &tempfile::NamedTempFile) -> HelperResponse {
        let request = HelperRequest::SetDomains { active_domains: domains };
        let mut line = serde_json::to_string(&request).unwrap();
        line.push('\n');

        let (reply, outcome) = exchange(line.as_bytes(), hosts);
        assert_eq!(outcome, Outcome::Continue, "a domain request never ends the helper");
        reply.expect("a request gets a reply")
    }

    #[test]
    fn a_valid_request_is_written() {
        let hosts = hosts_file();
        let response = send(vec!["Malware.Example.com".to_string()], &hosts);

        assert!(response.success, "{:?}", response.error);
        let content = std::fs::read_to_string(hosts.path()).unwrap();
        assert!(content.contains("127.0.0.1 malware.example.com # SECUREGUARD_BLOCKED_DOMAIN"));
    }

    #[test]
    fn a_newline_injection_is_rejected_and_the_file_is_untouched() {
        let hosts = hosts_file();
        let response = send(vec!["ok.example.com\n93.184.216.34 bank.example".to_string()], &hosts);

        assert!(!response.success);
        assert!(response.error.unwrap().starts_with("rejected request:"));
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn one_bad_entry_rejects_the_whole_request_with_no_partial_write() {
        let hosts = hosts_file();
        let response = send(vec!["good.example.com".to_string(), "bad domain.example.com".to_string()], &hosts);

        assert!(!response.success);
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn a_comment_marker_and_a_carriage_return_are_rejected() {
        for bad in ["evil.example.com # trick", "evil.example.com\r\n1.2.3.4 x.example"] {
            let hosts = hosts_file();
            let response = send(vec![bad.to_string()], &hosts);
            assert!(!response.success, "must reject {bad:?}");
            assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
        }
    }

    #[test]
    fn an_oversized_list_is_rejected() {
        let hosts = hosts_file();
        let many = (0..=secureguard_core::blocked_domain::MAX_BLOCKED_DOMAINS)
            .map(|i| format!("d{i}.example.com"))
            .collect();
        let response = send(many, &hosts);

        assert!(!response.success);
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn an_empty_list_clears_our_entries_but_keeps_system_ones() {
        let hosts = hosts_file();
        send(vec!["blocked.example.com".to_string()], &hosts);
        let response = send(vec![], &hosts);

        assert!(response.success);
        let content = std::fs::read_to_string(hosts.path()).unwrap();
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(!content.contains("SECUREGUARD_BLOCKED_DOMAIN"));
    }

    #[test]
    fn a_quit_request_is_answered_and_ends_the_helper_without_touching_the_hosts_file() {
        let hosts = hosts_file();
        send(vec!["blocked.example.com".to_string()], &hosts);
        let before = std::fs::read(hosts.path()).unwrap();

        let (reply, outcome) = exchange(b"{\"quit\":true}\n", &hosts);

        let reply = reply.expect("quit gets a reply before the helper exits");
        assert!(reply.success, "{:?}", reply.error);
        assert_eq!(outcome, Outcome::Quit);
        assert_eq!(std::fs::read(hosts.path()).unwrap(), before, "quit must not change the hosts file");
    }

    #[test]
    fn quit_false_is_a_bad_request_and_the_helper_keeps_running() {
        let hosts = hosts_file();
        let (reply, outcome) = exchange(b"{\"quit\":false}\n", &hosts);

        let reply = reply.unwrap();
        assert!(!reply.success);
        assert!(reply.error.unwrap().starts_with("rejected request:"));
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn a_mixed_request_neither_quits_nor_writes() {
        let hosts = hosts_file();
        let (reply, outcome) = exchange(b"{\"active_domains\":[],\"quit\":true}\n", &hosts);

        let reply = reply.unwrap();
        assert!(!reply.success);
        assert!(reply.error.unwrap().starts_with("malformed request:"));
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn a_malformed_line_and_a_silent_client_keep_the_helper_running() {
        let hosts = hosts_file();
        let (reply, outcome) = exchange(b"not json\n", &hosts);
        assert!(!reply.unwrap().success);
        assert_eq!(outcome, Outcome::Continue);

        let (reply, outcome) = exchange(b"", &hosts);
        assert!(reply.is_none(), "a client that sent nothing gets nothing");
        assert_eq!(outcome, Outcome::Continue);
    }

    /// A client that never sends a newline and never stops. The test fails
    /// (panics) if the helper reads far past the limit.
    struct Endless {
        served: u64,
        output: Vec<u8>,
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.served += buf.len() as u64;
            assert!(self.served < 2 * MAX_REQUEST_BYTES, "the helper kept reading past the limit");
            buf.fill(b'x');
            Ok(buf.len())
        }
    }

    impl Write for Endless {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_request_over_the_size_limit_is_rejected_without_reading_it_all() {
        let hosts = hosts_file();
        let mut conn = Endless { served: 0, output: Vec::new() };
        let outcome = handle_connection(&mut conn, &HostsFileWriter::new(hosts.path()));

        let reply: HelperResponse = serde_json::from_slice(&conn.output).unwrap();
        assert!(!reply.success);
        assert!(reply.error.unwrap().starts_with("rejected request:"));
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn the_largest_allowed_list_fits_under_the_size_limit() {
        // 5,000 names of the maximum length, as the JSON a client would send.
        let longest = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61));
        assert_eq!(longest.len(), 253);
        let request = HelperRequest::SetDomains {
            active_domains: vec![longest; secureguard_core::blocked_domain::MAX_BLOCKED_DOMAINS],
        };
        let line = serde_json::to_string(&request).unwrap();
        assert!(
            (line.len() as u64) < MAX_REQUEST_BYTES,
            "a legal request of {} bytes must fit under the {MAX_REQUEST_BYTES} limit",
            line.len()
        );
    }

    // IdleTimer takes the time as an argument, so these tests need no sleeping.

    #[test]
    fn the_idle_timer_is_not_expired_before_its_limit_and_is_at_it() {
        let start = Instant::now();
        let timer = IdleTimer::new(Duration::from_secs(10), start);

        assert!(!timer.expired(start));
        assert!(!timer.expired(start + Duration::from_millis(9_999)));
        assert!(timer.expired(start + Duration::from_secs(10)));
        assert!(timer.expired(start + Duration::from_secs(3600)));
    }

    #[test]
    fn touching_the_idle_timer_restarts_the_full_limit() {
        let start = Instant::now();
        let mut timer = IdleTimer::new(Duration::from_secs(10), start);

        timer.touch(start + Duration::from_secs(8));

        assert!(!timer.expired(start + Duration::from_secs(10)));
        assert!(!timer.expired(start + Duration::from_millis(17_999)));
        assert!(timer.expired(start + Duration::from_secs(18)));
    }

    #[test]
    fn a_clock_that_reads_earlier_than_the_last_touch_does_not_expire_or_panic() {
        let start = Instant::now();
        let mut timer = IdleTimer::new(Duration::from_secs(10), start + Duration::from_secs(5));
        timer.touch(start + Duration::from_secs(6));

        assert!(!timer.expired(start));
    }

    #[test]
    fn the_default_idle_limit_is_thirty_minutes() {
        assert_eq!(DEFAULT_IDLE_LIMIT, Duration::from_secs(30 * 60));
        assert_eq!(ServeOptions::default().idle_limit, DEFAULT_IDLE_LIMIT);
    }

    // ---- who may connect (Unix) ----

    #[test]
    fn anyone_means_anyone_even_when_the_peer_is_unknown() {
        assert!(Access::Anyone.permits(Some(0)));
        assert!(Access::Anyone.permits(Some(1000)));
        assert!(Access::Anyone.permits(None));
    }

    #[test]
    fn a_named_user_and_root_are_allowed_and_nobody_else() {
        let access = Access::Uid(1000);
        assert!(access.permits(Some(1000)));
        assert!(access.permits(Some(0)), "root can already do everything the helper can");
        assert!(!access.permits(Some(1001)));
        assert!(!access.permits(Some(65534)));
    }

    #[test]
    fn a_peer_whose_user_cannot_be_read_is_refused_when_a_user_is_named() {
        assert!(!Access::Uid(1000).permits(None));
    }

    #[test]
    fn naming_root_allows_only_root() {
        let access = Access::Uid(0);
        assert!(access.permits(Some(0)));
        assert!(!access.permits(Some(1000)));
    }

    #[test]
    fn the_default_options_allow_anyone_because_windows_uses_the_pipe_access_list() {
        assert_eq!(ServeOptions::default().access, Access::Anyone);
    }

    #[test]
    fn a_unix_helper_must_name_a_user_and_a_windows_helper_must_not_be_told_to() {
        assert!(check_access_for_platform(Access::Uid(1000), true).is_ok());
        assert!(check_access_for_platform(Access::Anyone, true).unwrap_err().contains("--allow-uid"));
        assert!(check_access_for_platform(Access::Anyone, false).is_ok());
    }

    // ---- which user to allow ----

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn the_allowed_user_comes_from_the_argument_in_either_spelling() {
        assert_eq!(parse_allowed_uid(&args(&["--allow-uid", "1000"]), None), Ok(1000));
        assert_eq!(parse_allowed_uid(&args(&["--allow-uid=1000"]), None), Ok(1000));
        assert_eq!(parse_allowed_uid(&args(&["--allow-uid", "0"]), None), Ok(0));
    }

    #[test]
    fn without_an_argument_the_user_pkexec_names_is_used() {
        assert_eq!(parse_allowed_uid(&[], Some("1000")), Ok(1000));
    }

    #[test]
    fn the_argument_wins_over_the_pkexec_variable_even_if_that_is_garbage() {
        assert_eq!(parse_allowed_uid(&args(&["--allow-uid", "1000"]), Some("2000")), Ok(1000));
        assert_eq!(parse_allowed_uid(&args(&["--allow-uid", "1000"]), Some("junk")), Ok(1000));
    }

    #[test]
    fn with_neither_the_helper_says_how_to_start_it() {
        let error = parse_allowed_uid(&[], None).unwrap_err();
        assert!(error.contains("--allow-uid") && error.contains("pkexec"), "{error}");
    }

    #[test]
    fn only_plain_decimal_numbers_that_fit_are_accepted() {
        for bad in ["", " 1000", "1000 ", "abc", "-1", "+5", "1e3", "1000x", "0x10", "4294967296", "99999999999"] {
            assert!(parse_allowed_uid(&args(&["--allow-uid", bad]), None).is_err(), "argument {bad:?}");
            assert!(parse_allowed_uid(&[], Some(bad)).is_err(), "variable {bad:?}");
        }
        assert_eq!(parse_allowed_uid(&args(&["--allow-uid", "4294967295"]), None), Ok(u32::MAX));
    }

    #[test]
    fn a_bad_pkexec_variable_is_named_in_the_error() {
        assert!(parse_allowed_uid(&[], Some("junk")).unwrap_err().contains("PKEXEC_UID"));
    }

    #[test]
    fn unknown_missing_or_repeated_arguments_are_errors() {
        assert!(parse_allowed_uid(&args(&["--bogus"]), Some("1000")).unwrap_err().contains("unknown argument"));
        assert!(parse_allowed_uid(&args(&["--allow-uid"]), Some("1000")).is_err());
        assert!(parse_allowed_uid(&args(&["--allow-uid", "1", "--allow-uid", "2"]), None).is_err());
        assert!(parse_allowed_uid(&args(&["1000"]), None).is_err());
    }
}
