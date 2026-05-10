# mtr-rust

A learning-focused Rust implementation of `mtr`.

The current step is a small, educational `v0.9`:

1. Build ICMP Echo Request packets in Rust.
2. Send repeated IPv4 ICMP probes with a raw socket on macOS.
3. Walk TTL values one hop at a time.
4. Print a simple `mtr`-style summary table with per-hop packet loss and RTT
   statistics.
5. Keep the default output quiet: a startup line plus the final statistics
   table.
6. Offer `--verbose` when you want to see each probe, reply, and timeout.
7. Match ICMP replies more carefully by identifier and sequence number,
   including `Time Exceeded` packets that contain the embedded original probe.
8. Accept either a hostname or an IPv4 address as the target and resolve
   hostnames to IPv4 before probing.
9. Offer a `--continuous` mode that keeps running until you stop it.

It is still intentionally limited:

1. IPv4 only.
2. No reverse DNS yet.
3. No full-screen TUI yet.
4. No long-running live refresh loop yet.

## Build

```bash
cargo build
```

## Version

```bash
./target/debug/mtr-rust --version
```

## Run

Raw sockets usually require elevated privileges on macOS, so run the binary
with `sudo`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8
```

By default, the program sends `10` probes per hop:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8
```

You can choose a different probe count:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5
```

If you want it to keep running until you press `Ctrl+C`, use
`--continuous`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5 --max-ttl 5 --continuous
```

Hostnames work too, as long as they resolve to IPv4:

```bash
sudo ./target/debug/mtr-rust example.com --count 5
```

By default, the program probes up to `30` TTLs. You can lower that while
experimenting:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5 --max-ttl 5
```

If socket creation fails, the program prints the operating system error so you
can see whether it is a permissions issue or something else. Each probe uses a
`1` second timeout. If no reply arrives before that timeout, the probe counts
as lost for the hop.

By default, the program prints a startup line and the final table only.

If you want to watch each probe while learning or debugging, use `--verbose`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5 --max-ttl 5 --verbose
```

You can combine `--verbose` with `--continuous`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5 --max-ttl 5 --verbose --continuous
```

Verbose mode prints progress lines such as:

```text
Starting mtr-rust target=example.com resolved=93.184.216.34 count=5 max_ttl=5 timeout=1.0s mode=continuous
Probing ttl=1 seq=1...
Reply type=11 from 192.168.1.1 ttl=1 seq=1 matched=yes rtt=2.3ms
Probing ttl=1 seq=2...
Timeout ttl=1 seq=2
```

Example output:

```text
Starting mtr-rust target=8.8.8.8 resolved=8.8.8.8 count=10 max_ttl=30 timeout=1.0s mode=once
Hop  Host            Loss%  Sent  Recv  Last   Avg   Best   Wrst
1    192.168.1.1      0.0%    10    10    2.1    2.3    1.8    4.9
2    10.0.0.1        10.0%    10     9    8.2    9.1    7.8   13.4
```

## Roadmap

1. `v0.1`: Create and close a macOS ICMP raw socket.
2. `v0.2`: Build ICMP Echo Request packets and test checksum logic.
3. `v0.3`: Send one Echo Request and receive one reply.
4. `v0.4`: Add a tiny `--version` command.
5. `v0.5`: Add basic repeated probing and per-hop statistics.
6. `v0.6`: Add quiet default output and opt-in verbose probe logging.
7. `v0.7`: Make ICMP reply matching more robust and test `Time Exceeded`
   parsing.
8. `v0.8`: Resolve hostnames to IPv4 and display both original and resolved
   targets.
9. `v0.9`: Add a continuous probing mode for ping-like repeated sweeps.
10. Next: Refresh the table in place instead of printing a new snapshot each
    sweep.
11. Later: Add reverse DNS lookups as an optional display feature.
12. Later: Grow that into a small, readable `mtr` implementation.
