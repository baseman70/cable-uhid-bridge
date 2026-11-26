# Contributing

## Building and Testing

Install the required system libraries (`pkg-config`, `dbus`, `clang`, `libxkbcommon`), then run:

```bash
cargo build
cargo test
cargo fmt -- --check
cargo clippy -- -D warnings
```

Please make sure tests and `clippy` pass before opening a pull request.

Unit tests cover CBOR parsing, CTAPHID framing, and the engine's request handling, but not browser or phone behaviour. For changes to the request flow, please also describe which browser, phone, and site you tested against.

## Reporting Issues

When opening a bug report, please include:

- Linux distribution, kernel version, and compositor/desktop environment
- Browser package source (native package vs. Snap or Flatpak)
- Output of `fido2-token -L` and `ls -la /dev/uhid`
- Daemon log output from `journalctl --user -u cable-uhid-bridge -n 50 --no-pager` (or foreground `RUST_LOG=debug cable-uhid-bridge`)

Debug logs contain credential IDs and account identifiers (user names and user handles). Redact them before posting.
