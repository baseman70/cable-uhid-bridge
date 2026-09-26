---
name: Bug Report
about: Create a report to help us fix a bug or issue
title: '[Bug]: '
labels: bug
assignees: ''
---

## Description
A clear and concise description of the bug.

## Environment Information
- **OS & Version:** (e.g. Ubuntu 24.04 LTS, Arch Linux, Fedora 40)
- **Desktop Environment & Display Server:** (e.g. GNOME Wayland, Hyprland, KDE X11)
- **Browser & Package Type:** (e.g. Firefox 130 Snap, Google Chrome .deb, Brave Flatpak)
- **Mobile Device:** (e.g. iPhone 15 Pro iOS 18, Google Pixel 8 Android 14)

## Installation Method
- [ ] Automated installer (`install.sh`)
- [ ] Debian package (`.deb`)
- [ ] Arch Linux (`PKGBUILD` / AUR)
- [ ] Built manually from source (`cargo build --release`)

## Verification Steps
Please provide the output of:
```bash
fido2-token -L
```

## Logs
Please run the daemon with trace logging or provide recent journal logs:
```bash
journalctl --user -u cable-uhid-bridge -n 50 --no-pager
```
Or foreground output:
```bash
systemctl --user stop cable-uhid-bridge
RUST_LOG=trace cable-uhid-bridge
```

## Steps to Reproduce
1. Navigate to '...'
2. Click on '...'
3. See error
