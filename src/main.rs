use std::env;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::process;
use std::time::{Duration, Instant};

use mtr_rust::icmp::{
    ECHO_REPLY_TYPE, EchoRequest, parse_icmp_response,
};
use mtr_rust::stats::ProbeStatistics;

const DEFAULT_PROBE_COUNT: u16 = 10;
const DEFAULT_MAX_TTL: u8 = 30;
const PER_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    match parse_command(env::args()) {
        Command::Version => println!("mtr-rust {VERSION}"),
        Command::Trace(config) => run_trace(config),
    }
}

fn run_trace(config: ProbeConfig) {
    println!(
        "Starting mtr-rust target={} count={} max_ttl={} timeout={:.1}s",
        config.target,
        config.count,
        config.max_ttl,
        PER_PROBE_TIMEOUT.as_secs_f64()
    );

    let socket_fd = match create_icmp_socket() {
        Ok(socket_fd) => socket_fd,
        Err(error) => {
            eprintln!("Failed to create ICMP raw socket: {error}");
            process::exit(1);
        }
    };

    let trace_result = collect_hop_reports(socket_fd, &config);

    let close_result = unsafe { libc::close(socket_fd) };
    if close_result != 0 {
        let error = io::Error::last_os_error();
        eprintln!("Failed to close socket fd {socket_fd}: {error}");
        process::exit(1);
    }

    match trace_result {
        Ok(reports) => print_hop_table(&reports),
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn collect_hop_reports(socket_fd: RawFd, config: &ProbeConfig) -> io::Result<Vec<HopReport>> {
    let identifier = process::id() as u16;
    let destination = ipv4_sockaddr(config.target);
    let mut next_sequence = 1u16;
    let mut reports = Vec::new();

    for ttl in 1..=config.max_ttl {
        set_socket_ttl(socket_fd, ttl)?;

        let mut report = HopReport::new(ttl);
        let mut reached_target = false;

        for _ in 0..config.count {
            report.statistics.record_probe_sent();
            if config.verbose {
                eprintln!("Probing ttl={ttl} seq={next_sequence}...");
            }

            let packet = EchoRequest::new(identifier, next_sequence, b"mtr-rust".to_vec()).to_bytes();
            let started_at = Instant::now();

            send_icmp_echo_request(socket_fd, &destination, &packet, config.target)?;

            if let Some(reply) =
                receive_matching_reply(
                    socket_fd,
                    ttl,
                    identifier,
                    next_sequence,
                    started_at,
                    config.target,
                    config.verbose,
                )?
            {
                report.record_reply(reply.source_ip, reply.rtt);

                if reply.icmp_type == ECHO_REPLY_TYPE && reply.source_ip == config.target {
                    reached_target = true;
                }
            } else if config.verbose {
                eprintln!("Timeout ttl={ttl} seq={next_sequence}");
            }

            next_sequence = next_sequence.wrapping_add(1);
            if next_sequence == 0 {
                next_sequence = 1;
            }
        }

        reports.push(report);

        if reached_target {
            break;
        }
    }

    Ok(reports)
}

fn send_icmp_echo_request(
    socket_fd: RawFd,
    destination: &libc::sockaddr_in,
    packet: &[u8],
    target: Ipv4Addr,
) -> io::Result<()> {
    let sent_bytes = unsafe {
        libc::sendto(
            socket_fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            destination as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if sent_bytes < 0 {
        return Err(io::Error::other(format!(
            "Failed to send ICMP Echo Request to {target}: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn receive_matching_reply(
    socket_fd: RawFd,
    ttl: u8,
    identifier: u16,
    sequence_number: u16,
    started_at: Instant,
    target: Ipv4Addr,
    verbose: bool,
) -> io::Result<Option<MatchedReply>> {
    loop {
        let elapsed = started_at.elapsed();
        if elapsed >= PER_PROBE_TIMEOUT {
            return Ok(None);
        }

        let remaining = PER_PROBE_TIMEOUT.saturating_sub(elapsed);
        set_receive_timeout(socket_fd, remaining)?;

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
                return Ok(None);
            }

            return Err(io::Error::other(format!(
                "Failed to receive ICMP reply from {target}: {error}"
            )));
        }

        let reply = &receive_buffer[..received_bytes as usize];
        let source_ip = ipv4_from_sockaddr(&source);

        let Some(parsed_reply) = parse_icmp_response(reply) else {
            continue;
        };

        let matched =
            parsed_reply.identifier == identifier && parsed_reply.sequence_number == sequence_number;

        if verbose {
            if matched {
                eprintln!(
                    "Reply type={} from {} ttl={} seq={} matched=yes rtt={}ms",
                    parsed_reply.icmp_type,
                    source_ip,
                    ttl,
                    parsed_reply.sequence_number,
                    format_duration_ms(started_at.elapsed())
                );
            } else {
                eprintln!(
                    "Reply type={} from {} ttl={} seq={} matched=no",
                    parsed_reply.icmp_type, source_ip, ttl, parsed_reply.sequence_number
                );
            }
        }

        if !matched {
            continue;
        }

        return Ok(Some(MatchedReply {
            source_ip,
            icmp_type: parsed_reply.icmp_type,
            rtt: started_at.elapsed(),
        }));
    }
}

fn print_hop_table(reports: &[HopReport]) {
    println!(
        "{:<4} {:<15} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>6}",
        "Hop", "Host", "Loss%", "Sent", "Recv", "Last", "Avg", "Best", "Wrst"
    );

    for report in reports {
        println!(
            "{:<4} {:<15} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>6}",
            report.ttl,
            report.host_label(),
            format!("{:.1}%", report.statistics.loss_percentage()),
            report.statistics.sent(),
            report.statistics.received(),
            format_rtt(report.statistics.last_rtt_ms()),
            format_rtt(report.statistics.average_rtt_ms()),
            format_rtt(report.statistics.best_rtt_ms()),
            format_rtt(report.statistics.worst_rtt_ms()),
        );
    }
}

fn format_rtt(rtt_ms: Option<f64>) -> String {
    match rtt_ms {
        Some(value) => format!("{value:.1}"),
        None => String::from("-"),
    }
}

fn format_duration_ms(duration: Duration) -> String {
    format!("{:.1}", duration.as_secs_f64() * 1000.0)
}

fn parse_command(args: impl IntoIterator<Item = String>) -> Command {
    let mut args = args.into_iter();
    let program_name = args.next().unwrap_or_else(|| String::from("mtr-rust"));

    let Some(first_arg) = args.next() else {
        print_usage_and_exit(&program_name);
    };

    if matches!(first_arg.as_str(), "--version" | "-V") {
        if args.next().is_some() {
            print_usage_and_exit(&program_name);
        }

        return Command::Version;
    }

    let target = match first_arg.parse::<Ipv4Addr>() {
        Ok(target) => target,
        Err(error) => {
            eprintln!("Invalid IPv4 address '{first_arg}': {error}");
            print_usage_and_exit(&program_name);
        }
    };

    let mut count = DEFAULT_PROBE_COUNT;
    let mut max_ttl = DEFAULT_MAX_TTL;
    let mut verbose = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--count" => {
                let Some(value) = args.next() else {
                    eprintln!("Missing value after --count");
                    print_usage_and_exit(&program_name);
                };

                match value.parse::<u16>() {
                    Ok(parsed_count) if parsed_count > 0 => count = parsed_count,
                    Ok(_) => {
                        eprintln!("Probe count must be greater than zero");
                        print_usage_and_exit(&program_name);
                    }
                    Err(error) => {
                        eprintln!("Invalid probe count '{value}': {error}");
                        print_usage_and_exit(&program_name);
                    }
                }
            }
            "--max-ttl" => {
                let Some(value) = args.next() else {
                    eprintln!("Missing value after --max-ttl");
                    print_usage_and_exit(&program_name);
                };

                match value.parse::<u8>() {
                    Ok(parsed_max_ttl) if parsed_max_ttl > 0 => max_ttl = parsed_max_ttl,
                    Ok(_) => {
                        eprintln!("Max TTL must be greater than zero");
                        print_usage_and_exit(&program_name);
                    }
                    Err(error) => {
                        eprintln!("Invalid max TTL '{value}': {error}");
                        print_usage_and_exit(&program_name);
                    }
                }
            }
            "--verbose" => verbose = true,
            _ => print_usage_and_exit(&program_name),
        }
    }

    Command::Trace(ProbeConfig {
        target,
        count,
        max_ttl,
        verbose,
    })
}

fn print_usage_and_exit(program_name: &str) -> ! {
    eprintln!(
        "Usage: {program_name} <target-ipv4> [--count <probes>] [--max-ttl <hops>] [--verbose]"
    );
    eprintln!("       {program_name} --version");
    process::exit(1);
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Version,
    Trace(ProbeConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeConfig {
    target: Ipv4Addr,
    count: u16,
    max_ttl: u8,
    verbose: bool,
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
        return Err(io::Error::other(format!(
            "Failed to set receive timeout: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn set_socket_ttl(socket_fd: RawFd, ttl: u8) -> io::Result<()> {
    let ttl_value = i32::from(ttl);
    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl_value as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result != 0 {
        return Err(io::Error::other(format!(
            "Failed to set TTL to {ttl}: {}",
            io::Error::last_os_error()
        )));
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

struct MatchedReply {
    source_ip: Ipv4Addr,
    icmp_type: u8,
    rtt: Duration,
}

struct HopReport {
    ttl: u8,
    host: Option<Ipv4Addr>,
    statistics: ProbeStatistics,
}

impl HopReport {
    fn new(ttl: u8) -> Self {
        Self {
            ttl,
            host: None,
            statistics: ProbeStatistics::default(),
        }
    }

    fn record_reply(&mut self, source_ip: Ipv4Addr, rtt: Duration) {
        if self.host.is_none() {
            self.host = Some(source_ip);
        }

        self.statistics.record_reply(rtt);
    }

    fn host_label(&self) -> String {
        self.host
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| String::from("*"))
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, DEFAULT_MAX_TTL, DEFAULT_PROBE_COUNT, ProbeConfig, parse_command};
    use std::net::Ipv4Addr;

    #[test]
    fn parse_command_accepts_version_flag() {
        let command = parse_command([String::from("mtr-rust"), String::from("--version")]);

        assert_eq!(command, Command::Version);
    }

    #[test]
    fn parse_command_defaults_probe_count_to_ten() {
        let command = parse_command([String::from("mtr-rust"), String::from("8.8.8.8")]);

        assert_eq!(
            command,
            Command::Trace(ProbeConfig {
                target: Ipv4Addr::new(8, 8, 8, 8),
                count: DEFAULT_PROBE_COUNT,
                max_ttl: DEFAULT_MAX_TTL,
                verbose: false,
            })
        );
    }

    #[test]
    fn parse_command_accepts_custom_probe_count_max_ttl_and_verbose() {
        let command = parse_command([
            String::from("mtr-rust"),
            String::from("8.8.8.8"),
            String::from("--count"),
            String::from("3"),
            String::from("--max-ttl"),
            String::from("5"),
            String::from("--verbose"),
        ]);

        assert_eq!(
            command,
            Command::Trace(ProbeConfig {
                target: Ipv4Addr::new(8, 8, 8, 8),
                count: 3,
                max_ttl: 5,
                verbose: true,
            })
        );
    }
}
