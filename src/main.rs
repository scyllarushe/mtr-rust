use std::env;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::process;
use std::time::{Duration, Instant};

use mtr_rust::icmp::EchoRequest;

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);

fn main() {
    let target = parse_target_argument();

    let socket_fd = match create_icmp_socket() {
        Ok(socket_fd) => socket_fd,
        Err(error) => {
            eprintln!("Failed to create ICMP raw socket: {error}");
            process::exit(1);
        }
    };

    let probe_result = send_one_echo_request(socket_fd, target);

    let close_result = unsafe { libc::close(socket_fd) };
    if close_result != 0 {
        let error = io::Error::last_os_error();
        eprintln!("Failed to close socket fd {socket_fd}: {error}");
        process::exit(1);
    }

    if let Err(error) = probe_result {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn parse_target_argument() -> Ipv4Addr {
    let mut args = env::args();
    let program_name = args.next().unwrap_or_else(|| String::from("mtr-rust"));

    let Some(target_arg) = args.next() else {
        eprintln!("Usage: {program_name} <target-ipv4>");
        process::exit(1);
    };

    if args.next().is_some() {
        eprintln!("Usage: {program_name} <target-ipv4>");
        process::exit(1);
    }

    match target_arg.parse::<Ipv4Addr>() {
        Ok(target) => target,
        Err(error) => {
            eprintln!("Invalid IPv4 address '{target_arg}': {error}");
            process::exit(1);
        }
    }
}

fn create_icmp_socket() -> io::Result<RawFd> {
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
        return Err(io::Error::last_os_error());
    }

    Ok(socket_fd)
}

fn send_one_echo_request(socket_fd: RawFd, target: Ipv4Addr) -> io::Result<()> {
    set_receive_timeout(socket_fd, RECEIVE_TIMEOUT)?;

    let identifier = process::id() as u16;
    let sequence_number = 1;
    let packet = EchoRequest::new(identifier, sequence_number, b"mtr-rust".to_vec()).to_bytes();
    let destination = ipv4_sockaddr(target);

    let started_at = Instant::now();
    let sent_bytes = unsafe {
        libc::sendto(
            socket_fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &destination as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if sent_bytes < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to send ICMP Echo Request to {target}: {}", io::Error::last_os_error()),
        ));
    }

    let mut receive_buffer = [0_u8; 1500];
    let mut source = zeroed_sockaddr_in();
    let mut source_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let received_bytes = unsafe {
        libc::recvfrom(
            socket_fd,
            receive_buffer.as_mut_ptr() as *mut libc::c_void,
            receive_buffer.len(),
            0,
            &mut source as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut source_len,
        )
    };

    if received_bytes < 0 {
        let error = io::Error::last_os_error();
        if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Timed out waiting for an ICMP reply from {target}"),
            ));
        }

        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to receive ICMP reply from {target}: {error}"),
        ));
    }

    let source_ip = ipv4_from_sockaddr(&source);
    let rtt = started_at.elapsed();
    let reply = &receive_buffer[..received_bytes as usize];

    match extract_icmp_header(reply) {
        Some(header) => {
            println!(
                "Reply from {source_ip}: type={} code={} id={} seq={} time={:.2?}",
                header.icmp_type,
                header.code,
                header.identifier,
                header.sequence_number,
                rtt
            );
        }
        None => {
            println!(
                "Reply from {source_ip}: received {} bytes in {:.2?}",
                received_bytes, rtt
            );
        }
    }

    Ok(())
}

fn set_receive_timeout(socket_fd: RawFd, timeout: Duration) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };

    if result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to set receive timeout: {}", io::Error::last_os_error()),
        ));
    }

    Ok(())
}

fn ipv4_sockaddr(target: Ipv4Addr) -> libc::sockaddr_in {
    let mut address = zeroed_sockaddr_in();

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
    }

    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_port = 0;
    address.sin_addr = libc::in_addr {
        s_addr: u32::from(target).to_be(),
    };

    address
}

fn zeroed_sockaddr_in() -> libc::sockaddr_in {
    unsafe { mem::zeroed() }
}

fn ipv4_from_sockaddr(address: &libc::sockaddr_in) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))
}

fn extract_icmp_header(packet: &[u8]) -> Option<IcmpHeader> {
    let icmp_offset = if packet.first().is_some_and(|first_byte| first_byte >> 4 == 4) {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if packet.len() < header_len {
            return None;
        }
        header_len
    } else {
        0
    };

    let icmp_packet = packet.get(icmp_offset..)?;
    if icmp_packet.len() < 8 {
        return None;
    }

    Some(IcmpHeader {
        icmp_type: icmp_packet[0],
        code: icmp_packet[1],
        identifier: u16::from_be_bytes([icmp_packet[4], icmp_packet[5]]),
        sequence_number: u16::from_be_bytes([icmp_packet[6], icmp_packet[7]]),
    })
}

struct IcmpHeader {
    icmp_type: u8,
    code: u8,
    identifier: u16,
    sequence_number: u16,
}
