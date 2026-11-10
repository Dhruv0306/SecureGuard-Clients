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

#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    pub idle_limit: Duration,
    pub poll: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self { idle_limit: DEFAULT_IDLE_LIMIT, poll: DEFAULT_POLL }
    }
}

/// Binds the given socket name and serves requests until a quit request
/// arrives or the helper has been idle for the default limit, then exits the
/// process (status 0). Blocking, meant to be the entire body of `main()`.
pub fn run_helper_server(socket_name: &str, writer: HostsFileWriter) -> ! {
    let listener = bind_listener(socket_name).unwrap_or_else(|e| {
        eprintln!(
            "failed to bind helper socket (already running elsewhere, or a \
             permissions problem): {e}"
        );
        std::process::exit(1);
    });

    eprintln!("secureguard-helper listening on '{socket_name}'");

    match serve(&listener, &writer, &ServeOptions::default()) {
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
            Ok(conn) => start_reader(conn, &sender, &readers),
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
}
