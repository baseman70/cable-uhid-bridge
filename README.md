# cable-uhid-bridge

`cable-uhid-bridge` is a Linux user-space daemon that emulates a USB FIDO2 / CTAP2 security key via `/dev/uhid` and forwards WebAuthn requests to a phone (iOS or Android) over FIDO Hybrid Transport (caBLE v2).

<p align="center">
  <img src="docs/demo.gif" alt="cable-uhid-bridge demo on WebAuthn.io" width="760">
</p>

## Overview

Linux browsers (particularly Firefox) and `libfido2` CLI tools do not implement an OS-level FIDO hybrid transport authenticator. When a site requests a passkey stored in iCloud Keychain or Google Password Manager, the client falls back to polling `/dev/hidraw*` for a physical USB security key.

`cable-uhid-bridge` registers a virtual CTAPHID device on `/dev/uhid`. When a browser or `libfido2` client sends a `authenticatorMakeCredential` or `authenticatorGetAssertion` request:

1. The daemon spawns a transient Wayland/X11 window displaying a `FIDO:/...` QR code.
2. Scanning the QR code with an iPhone or Android camera broadcasts a BLE proximity advertisement.
3. The daemon receives the BLE advertisement via BlueZ D-Bus, establishes the encrypted P-256 Noise WebSocket tunnel to the FIDO relay specified by the phone, and returns the signed CTAP2 response over `/dev/uhid`.

If a physical USB security key (such as a YubiKey) is plugged in at the same time, both devices are polled concurrently by the browser. Using either one cancels the pending request on the other via `CTAP2_ERR_KEEPALIVE_CANCEL` (`0x2D`).

Tested with iOS (iCloud Keychain / Face ID) and Android (Google Password Manager) on GitHub, Google Accounts, and WebAuthn.io.

## Installation

### Arch Linux

Install the prebuilt package from the [latest release](https://github.com/baseman70/cable-uhid-bridge/releases), or build from `contrib/arch`:

```bash
# Prebuilt package
sudo pacman -U https://github.com/baseman70/cable-uhid-bridge/releases/download/v0.1.1/cable-uhid-bridge-bin-0.1.1-1-x86_64.pkg.tar.zst
systemctl --user enable --now cable-uhid-bridge

# Or build via makepkg
cd contrib/arch/cable-uhid-bridge-bin
makepkg -si
systemctl --user enable --now cable-uhid-bridge
```

### Debian / Ubuntu

Download the `.deb` package from the [latest release](https://github.com/baseman70/cable-uhid-bridge/releases):

```bash
sudo apt install ./cable-uhid-bridge_*_amd64.deb
systemctl --user enable --now cable-uhid-bridge
```

### Install Script (Arch, Debian, Ubuntu, Fedora)

The included `install.sh` script loads the `uhid` kernel module, installs `/etc/udev/rules.d/70-uhid.rules` (`TAG+="uaccess"` so the daemon runs unprivileged), builds the binary, and enables the systemd user service:

```bash
git clone https://github.com/baseman70/cable-uhid-bridge.git
cd cable-uhid-bridge
./install.sh
```

To remove the service, binary, and udev rule:

```bash
./install.sh --uninstall
```

### Manual Build from Source

Dependencies: Rust toolchain (`cargo`), `pkg-config`, `dbus`, `clang`, and `libxkbcommon`.

```bash
# 1. Load uhid and grant uaccess permissions to the active seat user
sudo modprobe uhid
echo "uhid" | sudo tee /etc/modules-load.d/uhid.conf
echo 'KERNEL=="uhid", TAG+="uaccess"' | sudo tee /etc/udev/rules.d/70-uhid.rules
sudo udevadm control --reload-rules && sudo udevadm trigger -s misc -a name=uhid

# 2. Build and install binary
cargo build --release
install -Dm755 target/release/cable-uhid-bridge ~/.local/bin/cable-uhid-bridge

# 3. Enable systemd user service
mkdir -p ~/.config/systemd/user
cp contrib/cable-uhid-bridge.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now cable-uhid-bridge.service
```

## Verification and Debugging

Check that `libfido2` sees the virtual device:

```bash
fido2-token -L
# /dev/hidrawX: vendor=0x1209, product=0x0001 (caBLE Virtual Passkey Token)
```

Preview the QR window directly without triggering a WebAuthn request:

```bash
cable-uhid-bridge --ui --rp "github.com" --url "FIDO:/01234567890123456789"
```

Run the daemon in the foreground with debug logging:

```bash
systemctl --user stop cable-uhid-bridge
RUST_LOG=debug cable-uhid-bridge
```

## Window Manager Configuration

The QR prompt sets `app_id="cable-uhid-bridge"` (Wayland) and `WM_CLASS="cable-uhid-bridge"` (X11) with a fixed `340x410` window size. On tiling compositors, add a float rule if it is not floated automatically:

Hyprland (`hyprland.conf`):
```ini
windowrulev2 = float, class:^(cable-uhid-bridge)$
windowrulev2 = center, class:^(cable-uhid-bridge)$
```

Omarchy (`~/.config/hypr/`):
```lua
o.window("cable-uhid-bridge", { tag = "+floating-window" })
```

Sway / i3:
```ini
for_window [app_id="cable-uhid-bridge"] floating enable, move position center
```

On Omarchy systems, the UI reads `~/.local/state/omarchy/current/theme/colors.toml` to match the active desktop color palette, falling back to a dark palette if not present. Colors can also be overridden with `CABLE_THEME_FILE`, `CABLE_THEME_BG`, `CABLE_THEME_FG`, and `CABLE_THEME_ACCENT`.

## Notes on Ubuntu Snap Browsers

Default Firefox and Chromium packages on Ubuntu run inside Snap confinement. Snap's `u2f-devices` interface currently restricts AppArmor report descriptor paths to physical `/sys/devices/**/usb*` and `/sys/devices/**/i2c*` buses, which blocks access to `/sys/devices/virtual/misc/uhid/...` devices.

An upstream patch ([canonical/snapd#17727](https://github.com/canonical/snapd/pull/17727) / [LP #2168777](https://bugs.launchpad.net/snapd/+bug/2168777)) has been approved to permit virtual UHID report descriptors in `u2f-devices`. Until that change lands in a stable `snapd` release, use native `.deb` browser packages on Ubuntu.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
