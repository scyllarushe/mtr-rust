use std::io;

fn main() {
    // AF_INET tells the kernel we want an IPv4 socket.
    // SOCK_RAW asks for direct access to raw network packets instead of a
    // higher-level protocol like TCP or UDP.
    // IPPROTO_ICMP selects the ICMP protocol, which is what tools like ping
    // and mtr eventually build on.
    //
    // On macOS, creating a raw socket usually requires root privileges
    // because raw sockets can craft and inspect packets at a very low level.
    // That is why this program is expected to be run with sudo.
    let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };

    if socket_fd < 0 {
        let error = io::Error::last_os_error();
        eprintln!("Failed to create ICMP raw socket: {error}");
        std::process::exit(1);
    }

    println!("Successfully created ICMP raw socket with fd: {socket_fd}");

    let close_result = unsafe { libc::close(socket_fd) };
    if close_result != 0 {
        let error = io::Error::last_os_error();
        eprintln!("Failed to close socket fd {socket_fd}: {error}");
        std::process::exit(1);
    }
}
