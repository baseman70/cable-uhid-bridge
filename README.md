# cable-uhid-bridge

A lightweight Linux daemon providing **cross-device WebAuthn / Passkey authentication via caBLE v2 (QR code)** by emulating a virtual USB FIDO2 token over `/dev/uhid`.

---

## The Problem Solved

Firefox and Chromium on Linux lack an OS-level platform authenticator with Hybrid Transport (caBLE). When logging into websites like GitHub or Google with a mobile passkey (stored in iCloud Keychain, Google Password Manager, or 1Password), Linux browsers fall back to `libfido2`, which only looks for physical USB security keys.

`cable-uhid-bridge` bridges this gap completely without requiring browser modifications or patches:

```
┌────────────────────────────────────────────────────────┐
│  Browser / OS Client (Firefox, Chromium, PAM)          │
└───────────────────────────┬────────────────────────────┘
                            │ libfido2 / CTAPHID (USB)
                            ▼
┌────────────────────────────────────────────────────────┐
│  cable-uhid-bridge (/dev/uhid)                         │
│  Emulates a physical FIDO2 USB Security Key            │
└───────────────────────────┬────────────────────────────┘
                            │ On GetAssertion / MakeCredential
                            ▼
┌────────────────────────────────────────────────────────┐
│  caBLE v2 Engine                                       │
│  - Displays QR code in terminal                        │
│  - Verifies Bluetooth LE physical proximity (BlueZ)    │
│  - E2EE Noise WebSocket tunnel to Apple / Google relay │
└───────────────────────────┬────────────────────────────┘
                            │ Relayed CTAP2 Request
                            ▼
┌────────────────────────────────────────────────────────┐
│  Mobile Device (iPhone / Android)                      │
│  Biometric Verification (Face ID / Touch ID)           │
│  Returns signed WebAuthn assertion                     │
└────────────────────────────────────────────────────────┘
```

---

## Verification Status
> **Verified Working on GitHub!**  
> Successfully authenticated to **GitHub (`github.com`) in Firefox on Linux** using an iPhone passkey (iCloud Keychain / caBLE v2) via QR code scan and Face ID.

---

## Permissions Setup

Accessing the Linux kernel user-space HID interface (`/dev/uhid`) requires appropriate permissions.

### Option A: One-Line Udev Rule (Recommended)
Allow any logged-in desktop user to access `/dev/uhid` via systemd ACLs:

```bash
# Ensure uhid module loads at boot
echo 'uhid' | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid

# Grant logged-in desktop user access via ACL
echo 'KERNEL=="uhid", TAG+="uaccess"' | sudo tee /etc/udev/rules.d/70-uhid.rules
sudo udevadm control --reload-rules && sudo udevadm trigger -s misc -a name=uhid
```

### Option B: Run with `sudo`
```bash
sudo ./target/debug/cable-uhid-bridge
```

---

## How to Test

### 1. Launch the Bridge
In one terminal window:

```bash
cd ~/Projects/cable-uhid-bridge
sudo cargo run
```

### 2. Verify Kernel Device Detection
In a second terminal window, verify that `libfido2` detects the virtual token:

```bash
fido2-token -L
```
Output will show your virtual token registered as a FIDO2 device!

### 3. Test in Firefox / Browser
1. Open **Firefox** and navigate to:
   * **[webauthn.io](https://webauthn.io)** or **[github.com/login](https://github.com/login)**
2. Click **"Authenticate"** or **"Sign in with a passkey"**.
3. Firefox will communicate with `/dev/uhid`, which automatically prompts the QR code in your terminal.
4. Scan the QR code with your iPhone or Android camera, verify with Face ID / Fingerprint, and complete the sign-in!
