# mtr-rust

A learning-focused Rust implementation of `mtr`.

The current step is a small, educational `v0.13`:

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
10. Offer a `--ttl` mode for probing exactly one hop without walking earlier
    TTLs first.
11. Offer both live-refresh and scrolling output styles for continuous mode.
12. Offer `--interval` to control the delay between continuous sweeps.
13. Make auto target-TTL discovery the default mode, with `--trace` for full
    path probing.

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

By default, the program now discovers the TTL where the target responds and
then probes only that target TTL.

You can choose a different probe count:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5
```

If you want it to keep running until you press `Ctrl+C`, use
`--continuous`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5 --continuous
```

In continuous mode, the default output style is a live refreshed table.
The default interval between sweeps is `1.0` seconds.

If you want the older scrolling behavior instead, add `--scroll`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5 --max-ttl 5 --continuous --scroll
```

You can change the delay between sweeps with `--interval`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --count 5 --continuous --interval 0.5
```

If you want to probe only one hop, use `--ttl`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --ttl 12 --count 1 --verbose
```

If you want the full path, use `--trace`:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --trace --max-ttl 12
```

Hostnames work too, as long as they resolve to IPv4:

```bash
sudo ./target/debug/mtr-rust example.com --count 5
```

By default, the program probes up to `30` TTLs. You can lower that while
experimenting during discovery or tracing:

```bash
sudo ./target/debug/mtr-rust 8.8.8.8 --trace --count 5 --max-ttl 5
```

`--ttl 12` probes only TTL 12. It does not probe TTL 1 through 12 first.
In once mode, `--interval` does not change behavior.
If automatic target TTL discovery fails, try `--trace --max-ttl <n>`.

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

When `--verbose` is enabled, the program uses normal scrolling output instead
of live refresh so the per-probe logs stay readable.

Verbose mode prints progress lines such as:

```text
Starting mtr-rust target=example.com resolved=93.184.216.34 count=5 max_ttl=30 timeout=1.0s interval=1.0s mode=auto-ttl
Probing ttl=1 seq=1...
Reply type=11 from 192.168.1.1 ttl=1 seq=1 matched=yes rtt=2.3ms
Probing ttl=1 seq=2...
Timeout ttl=1 seq=2
```

Example output:

```text
Starting mtr-rust target=8.8.8.8 resolved=8.8.8.8 count=10 max_ttl=30 timeout=1.0s interval=1.0s mode=auto-ttl
Hop  Host            Loss%  Sent  Recv  Last   Avg   Best   Wrst
12   8.8.8.8          0.0%    10    10   34.2   33.8   31.7   36.5
```

Trace mode example:

```text
Starting mtr-rust target=8.8.8.8 resolved=8.8.8.8 count=10 max_ttl=30 timeout=1.0s interval=1.0s mode=trace
Hop  Host            Loss%  Sent  Recv  Last   Avg   Best   Wrst
1    192.168.1.1      0.0%    10    10    2.1    2.3    1.8    4.9
2    10.0.0.1        10.0%    10     9    8.2    9.1    7.8   13.4
```

Usage:

```text
<target> [--count <probes>] [--max-ttl <hops> | --ttl <hop>] [--trace] [--interval <seconds>] [--verbose] [--continuous] [--scroll]
```

Output styles:

1. Once mode: one final table.
2. Continuous mode: live refreshed table.
3. Continuous `--scroll`: append a new table after every sweep.
4. `--verbose`: detailed per-probe logs with scrolling output.

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
10. `v0.10`: Add `--ttl` for single-hop probing.
11. `v0.11`: Add live refresh and scrolling output modes for continuous
    probing.
12. `v0.12`: Add `--interval` for continuous sweep pacing.
13. `v0.13`: Make auto target-TTL discovery the default and add `--trace`.
14. Next: Improve the in-place refresh presentation further.
15. Later: Add reverse DNS lookups as an optional display feature.
16. Later: Grow that into a small, readable `mtr` implementation.
