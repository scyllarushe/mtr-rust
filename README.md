# rttmeter

A lightweight Rust RTT, packet loss, and network path monitor inspired by `mtr`.

RTT means Round-Trip Time, the time for a probe packet to travel to the target
and back.

Clone:

```bash
git clone https://github.com/scyllarushe/rttmeter
cd rttmeter
```

The current step is a small, educational `v0.16`:

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
14. Default to continuous scrolling output, with `--once` and `--live` as
    explicit runtime overrides.
15. Add RTT stability metrics with standard deviation and jitter.
16. Show auto-TTL discovery progress before switching to monitoring.
17. Add RTT trend sparklines and simple network mood/status messages.

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
./target/debug/rttmeter --version
```

## Run

Raw sockets usually require elevated privileges on macOS, so run the binary
with `sudo`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8
```

By default, the program sends `1` probe per sweep and keeps running:

```bash
sudo ./target/debug/rttmeter 8.8.8.8
```

By default, the program now discovers the TTL where the target responds and
then probes only that target TTL.
It first shows the discovery progress before switching into normal monitoring.
By default, that run is equivalent to:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --continuous --scroll --count 1 --interval 0.5
```

You can choose a different probe count:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --count 5
```

`--continuous` is accepted for compatibility, but it is already the default:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --count 5 --continuous
```

If you want a one-shot run instead, use `--once`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --once
```

In continuous mode, the default output style is scrolling output.
The default interval between sweeps is `0.5` seconds.

`--scroll` is accepted for compatibility, but it is already the default:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --count 5 --max-ttl 5 --continuous --scroll
```

If you want live refresh instead, add `--live`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --count 5 --continuous --live
```

You can change the delay between sweeps with `--interval`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --count 5 --continuous --interval 0.5
```

If you want to probe only one hop, use `--ttl`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --ttl 12 --count 1 --verbose
```

If you want that single-hop probe to run only once, add `--once`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --ttl 12 --count 1 --verbose --once
```

If you want the full path, use `--trace`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --trace --max-ttl 12
```

If you want a one-shot full-path run, add `--once`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --trace --max-ttl 12 --once
```

Hostnames work too, as long as they resolve to IPv4:

```bash
sudo ./target/debug/rttmeter example.com --count 5
```

By default, the program probes up to `30` TTLs. You can lower that while
experimenting during discovery or tracing:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --trace --count 5 --max-ttl 5
```

`--ttl 12` probes only TTL 12. It does not probe TTL 1 through 12 first.
In once mode, `--interval` does not change behavior.
If automatic target TTL discovery fails, try `--trace --max-ttl <n>`.

If socket creation fails, the program prints the operating system error so you
can see whether it is a permissions issue or something else. The default count
is `1`, the default timeout is `1.0` second, and the default interval is
`0.5` seconds. If no reply arrives before the timeout, the probe counts as
lost for the hop.

By default, the program prints a startup line and then keeps appending updated
tables in scrolling mode.

If you want to watch each probe while learning or debugging, use `--verbose`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --count 5 --max-ttl 5 --verbose
```

You can combine `--verbose` with `--continuous`:

```bash
sudo ./target/debug/rttmeter 8.8.8.8 --count 5 --max-ttl 5 --verbose --continuous
```

When `--verbose` is enabled, the program uses normal scrolling output instead
of live refresh so the per-probe logs stay readable.

Verbose mode prints progress lines such as:

```text
Starting rttmeter target=example.com resolved=93.184.216.34 count=5 timeout=1.0s interval=0.5s mode=auto-ttl run=continuous output=scroll
Probing ttl=1 seq=1...
Reply type=11 from 192.168.1.1 ttl=1 seq=1 matched=yes rtt=2.3ms
Probing ttl=1 seq=2...
Timeout ttl=1 seq=2
```

`StDev` shows how spread out RTT values are from the average.
`Jttr` shows how much RTT changes between consecutive replies.
`Trend` shows a compact sparkline from recent RTT samples for that hop.

After each monitoring table, `rttmeter` also prints a simple status line such
as `calm`, `spiky`, `jittery`, or `lossy`.

Example output:

```text
Starting rttmeter target=8.8.8.8 resolved=8.8.8.8 count=1 timeout=1.0s interval=0.5s mode=auto-ttl run=continuous output=scroll
Discovering target TTL up to 30...
ttl=1   192.168.1.1      2.1ms
ttl=2   10.0.0.1         8.4ms
ttl=3   *
ttl=12  8.8.8.8         34.2ms
Target reached at ttl=12. Switching to target monitoring.
Hop  Host            Loss%  Sent  Recv  Last   Avg   Best   Wrst  StDev   Jttr Trend
12   8.8.8.8          0.0%     1     1   34.2   34.2   34.2   34.2    0.0    0.0 ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
Status: calm - RTT is stable
```

Trace mode example:

```text
Starting rttmeter target=8.8.8.8 resolved=8.8.8.8 count=1 max_ttl=30 timeout=1.0s interval=0.5s mode=trace run=continuous output=scroll
Hop  Host            Loss%  Sent  Recv  Last   Avg   Best   Wrst  StDev   Jttr Trend
1    192.168.1.1      0.0%     1     1    2.1    2.1    2.1    2.1    0.0    0.0 ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
2    10.0.0.1        100.0%     1     0      -      -      -      -      -      - -
Status: lossy - packet loss observed
```

Usage:

```text
<target> [--count <probes>] [--max-ttl <hops> | --ttl <hop>] [--trace] [--interval <seconds>] [--verbose] [--continuous | --once] [--scroll | --live]
```

Output styles:

1. Default mode: continuous scrolling tables.
2. `--once`: one final table.
3. `--continuous --live`: continuous live-refreshed table.
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
14. `v0.14`: Add RTT stability metrics with `StDev` and `Jttr`.
15. `v0.15`: Show auto-TTL discovery progress before monitoring.
16. `v0.16`: Add RTT trend sparklines and simple network mood/status messages.
17. Later: Add optional reverse DNS so the path can show names when that helps more than raw IPs.
18. Later: Keep evolving `rttmeter` into a compact, readable network path monitor you can actually enjoy using.
