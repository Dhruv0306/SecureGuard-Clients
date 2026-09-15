use secureguard_core::helper_protocol::HELPER_SOCKET_NAME;
use secureguard_core::hosts_writer::{ default_hosts_path, HostsFileWriter };

fn main() {
    let writer = HostsFileWriter::new(default_hosts_path());
    secureguard_helper::run_helper_server(HELPER_SOCKET_NAME, writer);
}
