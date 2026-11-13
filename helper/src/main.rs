use secureguard_core::helper_protocol::HELPER_SOCKET_NAME;
use secureguard_core::hosts_writer::{ default_hosts_path, HostsFileWriter };
use secureguard_helper::Access;

fn main() {
    let writer = HostsFileWriter::new(default_hosts_path());
    secureguard_helper::run_helper_server(HELPER_SOCKET_NAME, writer, access_from_the_environment());
}

/// Unix sockets have no access list, so the helper is told which user to
/// serve (see `parse_allowed_uid`) and refuses to start without one. Windows
/// pipes have an access list, so no user is named there.
#[cfg(unix)]
fn access_from_the_environment() -> Access {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pkexec_uid = std::env::var("PKEXEC_UID").ok();
    match secureguard_helper::parse_allowed_uid(&args, pkexec_uid.as_deref()) {
        Ok(uid) => Access::Uid(uid),
        Err(e) => {
            eprintln!("secureguard-helper: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(not(unix))]
fn access_from_the_environment() -> Access {
    Access::Anyone
}
