# mtr-rust

A learning-focused Rust implementation of `mtr`.

This first step intentionally stays small and educational. The program does not
implement ping, traceroute, or full `mtr` yet. It only tries to create an IPv4
ICMP raw socket on macOS, prints either the OS error or the socket file
descriptor, and then closes the socket.

## Build

```bash
cargo build
```

## Run

Raw sockets usually require elevated privileges on macOS, so run the binary
with `sudo`:

```bash
sudo ./target/debug/mtr-rust
```

If socket creation fails, the program prints the operating system error so you
can see whether it is a permissions issue or something else.
