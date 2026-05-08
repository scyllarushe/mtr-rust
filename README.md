# mtr-rust

A learning-focused Rust implementation of `mtr`.

This first step intentionally stays small and educational. The program does not
implement ping, traceroute, or full `mtr` yet. It only tries to create an IPv4
ICMP raw socket on macOS, prints either the OS error or the socket file
descriptor, and then closes the socket.

The repository now also includes a small ICMP packet-building module for
learning how Echo Request packets are laid out in memory. It builds bytes and
tests checksum logic, but it still does not send packets yet.

The current step sends one ICMP Echo Request to an IPv4 address, waits once for
one reply, and prints the source IP plus a round-trip time. It still does not
implement traceroute logic or `mtr` statistics yet.

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

If socket creation fails, the program prints the operating system error so you
can see whether it is a permissions issue or something else. If no reply
arrives before the receive timeout, the program reports a timeout instead.

## Roadmap

1. `v0.1`: Create and close a macOS ICMP raw socket.
2. `v0.2`: Build ICMP Echo Request packets and test checksum logic.
3. `v0.3`: Send one Echo Request and receive one reply.
4. Next: Add TTL control for traceroute-style probing.
5. Later: Loop over hops and collect simple timing statistics.
6. Later: Grow that into a small, readable `mtr` implementation.
