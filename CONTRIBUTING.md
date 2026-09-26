# Contributing to cable-uhid-bridge

Thank you for your interest in contributing to `cable-uhid-bridge`! Contributions from the community—whether bug reports, documentation updates, or pull requests—are warmly welcomed.

---

## Code of Conduct

Please treat everyone with respect, kindness, and constructive feedback.

---

## Development Setup

### 1. Prerequisites
Ensure you have the required build dependencies installed:

**Debian / Ubuntu / Pop!_OS:**
```bash
sudo apt update && sudo apt install -y build-essential pkg-config libdbus-1-dev libclang-dev libxkbcommon-dev
```

**Arch Linux / Manjaro:**
```bash
sudo pacman -S --needed base-devel pkgconf dbus clang libxkbcommon
```

**Fedora:**
```bash
sudo dnf install -y gcc pkgconf-pkg-config dbus-devel clang-devel libxkbcommon-devel
```

### 2. Building and Testing
```bash
# Clone the repository
git clone https://github.com/baseman70/cable-uhid-bridge.git
cd cable-uhid-bridge

# Build in debug mode
cargo build

# Run the automated unit test suite
cargo test

# Check code formatting
cargo fmt -- --check

# Run linter
cargo clippy -- -D warnings
```

All 57+ automated unit tests and Clippy checks must pass before opening a pull request.

---

## Submitting Pull Requests

1. **Fork & Branch:** Create a feature or bugfix branch off `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. **Formatting & Linting:** Run `cargo fmt` and `cargo clippy -- -D warnings` to ensure consistency.
3. **Tests:** Add unit tests for any new CTAPHID packet handling, CTAP2 parsing, or engine state transitions.
4. **Pull Request:** Open a PR against `main` on GitHub. GitHub Actions CI will automatically build, lint, and test your code.

---

## Reporting Issues

When reporting an issue, please include:
1. **Linux Distribution & Desktop Environment:** (e.g., Ubuntu 24.04 Wayland, Arch Hyprland, Fedora GNOME).
2. **Browser & Installation Source:** (e.g., Firefox from Mozilla APT vs Snap vs Flatpak; Chromium from Google Chrome `.deb` vs Snap).
3. **Device Node Info:** Output of `fido2-token -L` and `ls -la /dev/uhid`.
4. **Service Logs:** Output of `journalctl --user -u cable-uhid-bridge -n 50 --no-pager` or foreground trace output via `RUST_LOG=trace cable-uhid-bridge`.
