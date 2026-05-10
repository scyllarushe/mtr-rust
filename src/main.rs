use std::env;
use std::io;
use std::io::Write;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::os::fd::RawFd;
use std::process;
use std::thread;
use std::time::{Duration, Instant};

use rttmeter::icmp::{
    ECHO_REPLY_TYPE, EchoRequest, parse_icmp_response,
};
use rttmeter::stats::ProbeStatistics;

const DEFAULT_PROBE_COUNT: u16 = 1;
const DEFAULT_MAX_TTL: u8 = 30;
const DEFAULT_INTERVAL: Duration = Duration::from_millis(500);
const PER_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const TREND_WIDTH: usize = 16;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    match parse_command(env::args()) {
        Command::Version => println!("rttmeter {VERSION}"),
        Command::Trace(config) => run_trace(config),
    }
}

fn run_trace(config: ProbeConfig) {
    println!(
        "Starting rttmeter target={} resolved={} count={}{} timeout={:.1}s interval={:.1}s mode={} run={} output={}",
        config.original_target,
        config.resolved_target,
        config.count,
        startup_scope_display(&config),
        PER_PROBE_TIMEOUT.as_secs_f64(),
        config.interval.as_secs_f64(),
        mode_name(&config),
        run_mode_name(&config),
        output_mode_name(&config)
    );

    let socket_fd = match create_icmp_socket() {
        Ok(socket_fd) => socket_fd,
        Err(error) => {
            eprintln!("Failed to create ICMP raw socket: {error}");
            process::exit(1);
        }
    };

    let trace_result = if config.continuous {
        run_continuous_trace(socket_fd, &config).map(|_| None)
    } else {
        collect_hop_reports(socket_fd, &config).map(Some)
    };

    let close_result = unsafe { libc::close(socket_fd) };
    if close_result != 0 {
        let error = io::Error::last_os_error();
        eprintln!("Failed to close socket fd {socket_fd}: {error}");
        process::exit(1);
    }

    match trace_result {
        Ok(Some(reports)) => print_hop_table(&reports),
        Ok(None) => {}
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn collect_hop_reports(socket_fd: RawFd, config: &ProbeConfig) -> io::Result<Vec<HopReport>> {
    let mut next_sequence = 1u16;
    let mut reports = prepare_reports(socket_fd, config, &mut next_sequence)?;

    run_probe_sweep(socket_fd, config, &mut reports, &mut next_sequence)?;
    truncate_after_target(&mut reports, config.resolved_target);

    Ok(reports)
}

fn run_continuous_trace(socket_fd: RawFd, config: &ProbeConfig) -> io::Result<()> {
    let mut next_sequence = 1u16;
    let mut reports = prepare_reports(socket_fd, config, &mut next_sequence)?;
    let mut previous_table_lines = None;
    let mut previous_snapshots = Vec::new();

    loop {
        run_probe_sweep(socket_fd, config, &mut reports, &mut next_sequence)?;

        let mut visible_reports = reports.clone();
        truncate_after_target(&mut visible_reports, config.resolved_target);
        let monitor_block = render_monitor_block(&visible_reports);
        let events = if should_emit_events(config) {
            classify_events(&visible_reports, &previous_snapshots)
        } else {
            Vec::new()
        };

        if should_use_live_refresh(config) {
            let stdout = io::stdout();
            let mut handle = stdout.lock();

            if let Some(line_count) = previous_table_lines {
                write!(handle, "\x1b[{line_count}A\x1b[J")?;
            }

            write!(handle, "{monitor_block}")?;
            handle.flush()?;
            previous_table_lines = Some(count_lines(&monitor_block));
        } else {
            println!();
            print!("{monitor_block}");

            for event in &events {
                println!("Event: {event}");
            }
        }

        previous_snapshots = capture_event_snapshots(&visible_reports);
        thread::sleep(config.interval);
    }
}

fn prepare_reports(
    socket_fd: RawFd,
    config: &ProbeConfig,
    next_sequence: &mut u16,
) -> io::Result<Vec<HopReport>> {
    match selected_mode(config) {
        ProbeMode::AutoTtl => {
            let discovered_ttl = discover_target_ttl(socket_fd, config, next_sequence)?;
            Ok(vec![HopReport::new(discovered_ttl)])
        }
        ProbeMode::SingleTtl(ttl) => Ok(vec![HopReport::new(ttl)]),
        ProbeMode::Trace => Ok((1..=config.max_ttl).map(HopReport::new).collect()),
    }
}

fn discover_target_ttl(
    socket_fd: RawFd,
    config: &ProbeConfig,
    next_sequence: &mut u16,
) -> io::Result<u8> {
    let identifier = process::id() as u16;
    let destination = ipv4_sockaddr(config.resolved_target);

    println!("Discovering target TTL up to {}...", config.max_ttl);

    for ttl in 1..=config.max_ttl {
        set_socket_ttl(socket_fd, ttl)?;

        if config.verbose {
            eprintln!("Probing ttl={ttl} seq={}...", *next_sequence);
        }

        let packet = EchoRequest::new(identifier, *next_sequence, b"rttmeter".to_vec()).to_bytes();
        let started_at = Instant::now();

        send_icmp_echo_request(socket_fd, &destination, &packet, config.resolved_target)?;

        if let Some(reply) = receive_matching_reply(
            socket_fd,
            ttl,
            identifier,
            *next_sequence,
            started_at,
            config.resolved_target,
            config.verbose,
        )? {
            println!("{}", render_discovery_line(ttl, Some(reply.source_ip), Some(reply.rtt)));

            if reply.icmp_type == ECHO_REPLY_TYPE && reply.source_ip == config.resolved_target {
                println!("Target reached at ttl={ttl}. Switching to target monitoring.");
                *next_sequence = next_sequence.wrapping_add(1);
                if *next_sequence == 0 {
                    *next_sequence = 1;
                }
                return Ok(ttl);
            }
        } else {
            println!("{}", render_discovery_line(ttl, None, None));

            if config.verbose {
                eprintln!("Timeout ttl={ttl} seq={}", *next_sequence);
            }
        }

        *next_sequence = next_sequence.wrapping_add(1);
        if *next_sequence == 0 {
            *next_sequence = 1;
        }
    }

    Err(io::Error::other(format!(
        "Could not reach target within max_ttl={}. Try --trace --max-ttl <n>.",
        config.max_ttl
    )))
}

fn run_probe_sweep(
    socket_fd: RawFd,
    config: &ProbeConfig,
    reports: &mut [HopReport],
    next_sequence: &mut u16,
) -> io::Result<()> {
    let identifier = process::id() as u16;
    let destination = ipv4_sockaddr(config.resolved_target);

    for report in reports.iter_mut() {
        let ttl = report.ttl;
        set_socket_ttl(socket_fd, ttl)?;

        let mut reached_target = false;
        report.begin_sweep();

        for _ in 0..config.count {
            report.record_probe_sent();
            if config.verbose {
                eprintln!("Probing ttl={ttl} seq={}...", *next_sequence);
            }

            let packet = EchoRequest::new(identifier, *next_sequence, b"rttmeter".to_vec()).to_bytes();
            let started_at = Instant::now();

            send_icmp_echo_request(socket_fd, &destination, &packet, config.resolved_target)?;

            if let Some(reply) = receive_matching_reply(
                socket_fd,
                ttl,
                identifier,
                *next_sequence,
                started_at,
                config.resolved_target,
                config.verbose,
            )? {
                report.record_reply(reply.source_ip, reply.rtt);

                if reply.icmp_type == ECHO_REPLY_TYPE && reply.source_ip == config.resolved_target {
                    reached_target = true;
                }
            } else if config.verbose {
                eprintln!("Timeout ttl={ttl} seq={}", *next_sequence);
            }

            *next_sequence = next_sequence.wrapping_add(1);
            if *next_sequence == 0 {
                *next_sequence = 1;
            }
        }

        if reached_target {
            break;
        }
    }

    Ok(())
}

fn truncate_after_target(reports: &mut Vec<HopReport>, target: Ipv4Addr) {
    if let Some(target_index) = reports.iter().position(|report| report.host == Some(target)) {
        reports.truncate(target_index + 1);
    }
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
    print!("{}", render_monitor_block(reports));
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

fn render_discovery_line(ttl: u8, source_ip: Option<Ipv4Addr>, rtt: Option<Duration>) -> String {
    match (source_ip, rtt) {
        (Some(source_ip), Some(rtt)) => {
            format!(
                "ttl={ttl:<2}  {:<14}  {}ms",
                source_ip,
                format_duration_ms(rtt)
            )
        }
        _ => format!("ttl={ttl:<2}  *"),
    }
}

fn render_hop_table(reports: &[HopReport]) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{:<4} {:<15} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:<16}\n",
        "Hop", "Host", "Loss%", "Sent", "Recv", "Last", "Avg", "Best", "Wrst", "StDev", "Jttr", "Trend"
    ));

    for report in reports {
        output.push_str(&format!(
            "{:<4} {:<15} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:<16}\n",
            report.ttl,
            report.host_label(),
            format!("{:.1}%", report.statistics.loss_percentage()),
            report.statistics.sent(),
            report.statistics.received(),
            format_rtt(report.statistics.last_rtt_ms()),
            format_rtt(report.statistics.average_rtt_ms()),
            format_rtt(report.statistics.best_rtt_ms()),
            format_rtt(report.statistics.worst_rtt_ms()),
            format_rtt(report.statistics.stdev_rtt_ms()),
            format_rtt(report.statistics.jitter_rtt_ms()),
            render_sparkline(report.statistics.rtt_samples_ms(), TREND_WIDTH),
        ));
    }

    output
}

fn render_monitor_block(reports: &[HopReport]) -> String {
    let mut output = render_hop_table(reports);
    output.push_str(&render_status_line(reports));
    output.push('\n');
    output
}

fn render_status_line(reports: &[HopReport]) -> String {
    let status = classify_status(reports);
    format!("Status: {} - {}", status.label(), status.message())
}

fn render_sparkline(samples: &[f64], width: usize) -> String {
    const BLOCKS: &[char; 8] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    if samples.is_empty() || width == 0 {
        return String::from("-");
    }

    let min = samples
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min);
    let max = samples
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max);

    if (max - min).abs() < f64::EPSILON {
        return std::iter::repeat_n('▄', width).collect();
    }

    let mut sparkline = String::with_capacity(width);
    for index in 0..width {
        let sample_index = index * samples.len() / width;
        let sample = samples[sample_index.min(samples.len() - 1)];
        let normalized = ((sample - min) / (max - min)).clamp(0.0, 1.0);
        let block_index = (normalized * (BLOCKS.len() - 1) as f64).round() as usize;
        sparkline.push(BLOCKS[block_index]);
    }

    sparkline
}

fn should_emit_events(config: &ProbeConfig) -> bool {
    config.continuous && !should_use_live_refresh(config)
}

fn classify_status(reports: &[HopReport]) -> MonitorStatus {
    if reports
        .iter()
        .any(|report| report.statistics.loss_percentage() > 5.0)
    {
        return MonitorStatus::Lossy;
    }

    if reports
        .iter()
        .any(|report| report.statistics.jitter_rtt_ms().unwrap_or(0.0) > 50.0)
    {
        return MonitorStatus::Jittery;
    }

    if reports.iter().any(HopReport::has_latency_spike) {
        return MonitorStatus::Spiky;
    }

    MonitorStatus::Calm
}

fn capture_event_snapshots(reports: &[HopReport]) -> Vec<HopEventSnapshot> {
    reports
        .iter()
        .map(|report| HopEventSnapshot {
            ttl: report.ttl,
            had_loss_ever: report.statistics.loss_percentage() > 0.0,
            worst_rtt_ms: report.statistics.worst_rtt_ms(),
            spiky: report.has_latency_spike(),
            sweep_had_loss: report.sweep_had_loss(),
        })
        .collect()
}

fn classify_events(reports: &[HopReport], previous_snapshots: &[HopEventSnapshot]) -> Vec<String> {
    let mut events = Vec::new();

    for report in reports {
        let previous = previous_snapshots
            .iter()
            .find(|snapshot| snapshot.ttl == report.ttl);

        if report.sweep_had_loss() && previous.is_none_or(|snapshot| !snapshot.had_loss_ever) {
            events.push(format!("hop {} saw its first packet loss", report.ttl));
        }

        if report.sweep_fully_replied()
            && previous.is_some_and(|snapshot| snapshot.sweep_had_loss)
        {
            events.push(format!("hop {} recovered after loss", report.ttl));
        }

        if let Some(current_worst) = report.statistics.worst_rtt_ms() {
            if let Some(previous_worst) = previous.and_then(|snapshot| snapshot.worst_rtt_ms) {
                if current_worst > previous_worst + 0.05 {
                    events.push(format!(
                        "hop {} set a new worst RTT at {:.1}ms",
                        report.ttl, current_worst
                    ));
                }
            }
        }

        if report.has_latency_spike() && previous.is_some_and(|snapshot| !snapshot.spiky) {
            events.push(format!("hop {} latency spike detected", report.ttl));
        }
    }

    events
}

fn count_lines(rendered_table: &str) -> u16 {
    rendered_table.lines().count() as u16
}

fn should_use_live_refresh(config: &ProbeConfig) -> bool {
    config.continuous && !config.scroll && !config.verbose
}

fn run_mode_name(config: &ProbeConfig) -> &'static str {
    if config.continuous { "continuous" } else { "once" }
}

fn output_mode_name(config: &ProbeConfig) -> &'static str {
    if should_use_live_refresh(config) {
        "live"
    } else {
        "scroll"
    }
}

fn startup_scope_display(config: &ProbeConfig) -> String {
    match selected_mode(config) {
        ProbeMode::SingleTtl(ttl) => format!(" ttl={ttl}"),
        ProbeMode::AutoTtl => String::new(),
        ProbeMode::Trace => format!(" max_ttl={}", config.max_ttl),
    }
}

fn mode_name(config: &ProbeConfig) -> &'static str {
    match selected_mode(config) {
        ProbeMode::AutoTtl => "auto-ttl",
        ProbeMode::SingleTtl(_) => "single-ttl",
        ProbeMode::Trace => "trace",
    }
}

fn selected_mode(config: &ProbeConfig) -> ProbeMode {
    match (config.ttl, config.trace) {
        (Some(ttl), _) => ProbeMode::SingleTtl(ttl),
        (None, true) => ProbeMode::Trace,
        (None, false) => ProbeMode::AutoTtl,
    }
}

fn parse_command(args: impl IntoIterator<Item = String>) -> Command {
    let mut args = args.into_iter();
    let program_name = args.next().unwrap_or_else(|| String::from("rttmeter"));

    let Some(first_arg) = args.next() else {
        print_usage_and_exit(&program_name);
    };

    if matches!(first_arg.as_str(), "--version" | "-V") {
        if args.next().is_some() {
            print_usage_and_exit(&program_name);
        }

        return Command::Version;
    }

    let resolved_target = match resolve_target(&first_arg) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    };

    let mut count = DEFAULT_PROBE_COUNT;
    let mut max_ttl = DEFAULT_MAX_TTL;
    let mut explicit_max_ttl = false;
    let mut ttl = None;
    let mut trace = false;
    let mut verbose = false;
    let mut continuous = true;
    let mut scroll = true;
    let mut interval = DEFAULT_INTERVAL;

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
                    Ok(parsed_max_ttl) if parsed_max_ttl > 0 => {
                        max_ttl = parsed_max_ttl;
                        explicit_max_ttl = true;
                    }
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
            "--ttl" => {
                let Some(value) = args.next() else {
                    eprintln!("Missing value after --ttl");
                    print_usage_and_exit(&program_name);
                };

                match value.parse::<u8>() {
                    Ok(parsed_ttl) if parsed_ttl > 0 => ttl = Some(parsed_ttl),
                    Ok(_) => {
                        eprintln!("TTL must be greater than zero");
                        print_usage_and_exit(&program_name);
                    }
                    Err(error) => {
                        eprintln!("Invalid TTL '{value}': {error}");
                        print_usage_and_exit(&program_name);
                    }
                }
            }
            "--trace" => trace = true,
            "--once" => continuous = false,
            "--verbose" => verbose = true,
            "--continuous" => continuous = true,
            "--live" => scroll = false,
            "--scroll" => scroll = true,
            "--interval" => {
                let Some(value) = args.next() else {
                    eprintln!("Missing value after --interval");
                    print_usage_and_exit(&program_name);
                };

                match value.parse::<f64>() {
                    Ok(parsed_interval) if parsed_interval > 0.0 => {
                        interval = Duration::from_secs_f64(parsed_interval);
                    }
                    Ok(_) => {
                        eprintln!("Interval must be greater than zero");
                        print_usage_and_exit(&program_name);
                    }
                    Err(error) => {
                        eprintln!("Invalid interval '{value}': {error}");
                        print_usage_and_exit(&program_name);
                    }
                }
            }
            _ => print_usage_and_exit(&program_name),
        }
    }

    if ttl.is_some() && explicit_max_ttl {
        eprintln!("--ttl cannot be used with --max-ttl");
        print_usage_and_exit(&program_name);
    }

    if ttl.is_some() && trace {
        eprintln!("--ttl cannot be used with --trace");
        print_usage_and_exit(&program_name);
    }

    Command::Trace(ProbeConfig {
        original_target: first_arg,
        resolved_target,
        count,
        max_ttl,
        ttl,
        trace,
        verbose,
        continuous,
        scroll,
        interval,
    })
}

fn print_usage_and_exit(program_name: &str) -> ! {
    eprintln!(
        "Usage: {program_name} <target> [--count <probes>] [--max-ttl <hops> | --ttl <hop>] [--trace] [--interval <seconds>] [--verbose] [--continuous | --once] [--scroll | --live]"
    );
    eprintln!("       {program_name} --version");
    process::exit(1);
}

fn resolve_target(target: &str) -> io::Result<Ipv4Addr> {
    if let Ok(ipv4) = target.parse::<Ipv4Addr>() {
        return Ok(ipv4);
    }

    let addresses = (target, 0)
        .to_socket_addrs()
        .map_err(|error| io::Error::other(format!("Failed to resolve target '{target}': {error}")))?;

    for address in addresses {
        if let SocketAddr::V4(ipv4_address) = address {
            return Ok(*ipv4_address.ip());
        }
    }

    Err(io::Error::other(format!(
        "Target '{target}' did not resolve to an IPv4 address"
    )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Version,
    Trace(ProbeConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeConfig {
    original_target: String,
    resolved_target: Ipv4Addr,
    count: u16,
    max_ttl: u8,
    ttl: Option<u8>,
    trace: bool,
    verbose: bool,
    continuous: bool,
    scroll: bool,
    interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeMode {
    AutoTtl,
    SingleTtl(u8),
    Trace,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorStatus {
    Calm,
    Spiky,
    Jittery,
    Lossy,
}

impl MonitorStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Calm => "calm",
            Self::Spiky => "spiky",
            Self::Jittery => "jittery",
            Self::Lossy => "lossy",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Calm => "RTT is stable",
            Self::Spiky => "latency spike detected",
            Self::Jittery => "RTT is moving around",
            Self::Lossy => "packet loss observed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HopEventSnapshot {
    ttl: u8,
    had_loss_ever: bool,
    worst_rtt_ms: Option<f64>,
    spiky: bool,
    sweep_had_loss: bool,
}

#[derive(Clone)]
struct HopReport {
    ttl: u8,
    host: Option<Ipv4Addr>,
    statistics: ProbeStatistics,
    sweep_sent: u16,
    sweep_received: u16,
}

impl HopReport {
    fn new(ttl: u8) -> Self {
        Self {
            ttl,
            host: None,
            statistics: ProbeStatistics::default(),
            sweep_sent: 0,
            sweep_received: 0,
        }
    }

    fn begin_sweep(&mut self) {
        self.sweep_sent = 0;
        self.sweep_received = 0;
    }

    fn record_probe_sent(&mut self) {
        self.sweep_sent += 1;
        self.statistics.record_probe_sent();
    }

    fn record_reply(&mut self, source_ip: Ipv4Addr, rtt: Duration) {
        if self.host.is_none() {
            self.host = Some(source_ip);
        }

        self.sweep_received += 1;
        self.statistics.record_reply(rtt);
    }

    fn host_label(&self) -> String {
        self.host
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| String::from("*"))
    }

    fn sweep_had_loss(&self) -> bool {
        self.sweep_sent > self.sweep_received
    }

    fn sweep_fully_replied(&self) -> bool {
        self.sweep_sent > 0 && self.sweep_sent == self.sweep_received
    }

    fn has_latency_spike(&self) -> bool {
        let Some(last) = self.statistics.last_rtt_ms() else {
            return false;
        };
        let Some(avg) = self.statistics.average_rtt_ms() else {
            return false;
        };

        last > avg * 1.8 && last - avg > 30.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Command, DEFAULT_INTERVAL, DEFAULT_MAX_TTL, DEFAULT_PROBE_COUNT, HopReport,
        MonitorStatus, ProbeConfig, capture_event_snapshots, classify_events, classify_status,
        parse_command, render_discovery_line, render_sparkline,
    };
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn report_from_rtts(ttl: u8, rtts_ms: &[u64]) -> HopReport {
        let mut report = HopReport::new(ttl);
        report.begin_sweep();

        for rtt_ms in rtts_ms {
            report.record_probe_sent();
            report.record_reply(Ipv4Addr::new(8, 8, 8, 8), Duration::from_millis(*rtt_ms));
        }

        report
    }

    #[test]
    fn parse_command_accepts_version_flag() {
        let command = parse_command([String::from("rttmeter"), String::from("--version")]);

        assert_eq!(command, Command::Version);
    }

    #[test]
    fn parse_command_defaults_probe_count_to_one_and_continuous_scroll() {
        let command = parse_command([String::from("rttmeter"), String::from("8.8.8.8")]);

        assert_eq!(
            command,
            Command::Trace(ProbeConfig {
                original_target: String::from("8.8.8.8"),
                resolved_target: Ipv4Addr::new(8, 8, 8, 8),
                count: DEFAULT_PROBE_COUNT,
                max_ttl: DEFAULT_MAX_TTL,
                ttl: None,
                trace: false,
                verbose: false,
                continuous: true,
                scroll: true,
                interval: DEFAULT_INTERVAL,
            })
        );
    }

    #[test]
    fn parse_command_accepts_trace_mode_with_custom_options() {
        let command = parse_command([
            String::from("rttmeter"),
            String::from("8.8.8.8"),
            String::from("--trace"),
            String::from("--count"),
            String::from("3"),
            String::from("--max-ttl"),
            String::from("5"),
            String::from("--verbose"),
            String::from("--continuous"),
            String::from("--scroll"),
            String::from("--interval"),
            String::from("2.5"),
        ]);

        assert_eq!(
            command,
            Command::Trace(ProbeConfig {
                original_target: String::from("8.8.8.8"),
                resolved_target: Ipv4Addr::new(8, 8, 8, 8),
                count: 3,
                max_ttl: 5,
                ttl: None,
                trace: true,
                verbose: true,
                continuous: true,
                scroll: true,
                interval: Duration::from_secs_f64(2.5),
            })
        );
    }

    #[test]
    fn parse_command_accepts_single_ttl_mode() {
        let command = parse_command([
            String::from("rttmeter"),
            String::from("8.8.8.8"),
            String::from("--ttl"),
            String::from("12"),
            String::from("--count"),
            String::from("1"),
            String::from("--verbose"),
        ]);

        assert_eq!(
            command,
            Command::Trace(ProbeConfig {
                original_target: String::from("8.8.8.8"),
                resolved_target: Ipv4Addr::new(8, 8, 8, 8),
                count: 1,
                max_ttl: DEFAULT_MAX_TTL,
                ttl: Some(12),
                trace: false,
                verbose: true,
                continuous: true,
                scroll: true,
                interval: DEFAULT_INTERVAL,
            })
        );
    }

    #[test]
    fn parse_command_accepts_decimal_interval() {
        let command = parse_command([
            String::from("rttmeter"),
            String::from("8.8.8.8"),
            String::from("--interval"),
            String::from("0.5"),
        ]);

        match command {
            Command::Trace(config) => assert_eq!(config.interval, Duration::from_secs_f64(0.5)),
            Command::Version => panic!("expected trace command"),
        }
    }

    #[test]
    fn parse_command_accepts_once_and_live_overrides() {
        let command = parse_command([
            String::from("rttmeter"),
            String::from("8.8.8.8"),
            String::from("--once"),
            String::from("--live"),
        ]);

        match command {
            Command::Trace(config) => {
                assert!(!config.continuous);
                assert!(!config.scroll);
                assert_eq!(config.count, DEFAULT_PROBE_COUNT);
                assert_eq!(config.interval, DEFAULT_INTERVAL);
            }
            Command::Version => panic!("expected trace command"),
        }
    }

    #[test]
    fn parse_command_accepts_explicit_trace_mode() {
        let command = parse_command([
            String::from("rttmeter"),
            String::from("8.8.8.8"),
            String::from("--trace"),
        ]);

        match command {
            Command::Trace(config) => {
                assert!(config.trace);
                assert_eq!(config.ttl, None);
                assert_eq!(config.max_ttl, DEFAULT_MAX_TTL);
            }
            Command::Version => panic!("expected trace command"),
        }
    }

    #[test]
    fn parse_command_accepts_hostname_targets() {
        let command = parse_command([String::from("rttmeter"), String::from("localhost")]);

        match command {
            Command::Trace(config) => {
                assert_eq!(config.original_target, "localhost");
                assert!(config.resolved_target.is_loopback());
                assert_eq!(config.count, DEFAULT_PROBE_COUNT);
                assert_eq!(config.max_ttl, DEFAULT_MAX_TTL);
                assert_eq!(config.ttl, None);
                assert!(!config.trace);
                assert!(!config.verbose);
                assert!(config.continuous);
                assert!(config.scroll);
                assert_eq!(config.interval, DEFAULT_INTERVAL);
            }
            Command::Version => panic!("expected trace command"),
        }
    }

    #[test]
    fn discovery_line_formats_reply_and_timeout_cases() {
        assert_eq!(
            render_discovery_line(
                3,
                Some(Ipv4Addr::new(10, 136, 70, 179)),
                Some(Duration::from_micros(22_800))
            ),
            "ttl=3   10.136.70.179   22.8ms"
        );
        assert_eq!(render_discovery_line(2, None, None), "ttl=2   *");
    }

    #[test]
    fn sparkline_formats_compact_trend_blocks() {
        assert_eq!(render_sparkline(&[], 8), "-");
        assert_eq!(render_sparkline(&[10.0, 20.0, 30.0, 40.0], 4), "▁▃▆█");
    }

    #[test]
    fn status_classification_prefers_loss_then_jitter_then_spike() {
        let mut lossy = HopReport::new(1);
        lossy.begin_sweep();
        lossy.record_probe_sent();
        lossy.record_probe_sent();
        lossy.record_reply(Ipv4Addr::new(1, 1, 1, 1), Duration::from_millis(10));
        assert_eq!(classify_status(&[lossy]), MonitorStatus::Lossy);

        let jittery = report_from_rtts(2, &[10, 110, 20]);
        assert_eq!(classify_status(&[jittery]), MonitorStatus::Jittery);

        let spiky = report_from_rtts(3, &[10, 10, 100]);
        assert_eq!(classify_status(&[spiky]), MonitorStatus::Spiky);

        let calm = report_from_rtts(4, &[20, 21, 20]);
        assert_eq!(classify_status(&[calm]), MonitorStatus::Calm);
    }

    #[test]
    fn event_classification_detects_loss_and_recovery() {
        let mut loss_report = HopReport::new(5);
        loss_report.begin_sweep();
        loss_report.record_probe_sent();
        let events = classify_events(&[loss_report.clone()], &[]);
        assert!(events.iter().any(|event| event.contains("first packet loss")));

        let mut recovered = report_from_rtts(5, &[12]);
        recovered.begin_sweep();
        recovered.record_probe_sent();
        recovered.record_reply(Ipv4Addr::new(8, 8, 8, 8), Duration::from_millis(12));
        let previous = capture_event_snapshots(&[loss_report]);
        let recovery_events = classify_events(&[recovered], &previous);
        assert!(recovery_events
            .iter()
            .any(|event| event.contains("recovered after loss")));
    }
}
