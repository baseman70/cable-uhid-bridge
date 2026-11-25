# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`cable-uhid-bridge` is a Linux user-space daemon that registers a virtual USB FIDO2 token on `/dev/uhid` and forwards the browser's CTAP2 requests to a phone over FIDO hybrid transport (caBLE v2: QR code, BLE advertisement, encrypted WebSocket tunnel). See `README.md` for the user-facing description.

## Commands

```bash
cargo build
cargo test
cargo fmt -- --check
cargo clippy -- -D warnings      # exactly what CI runs; must stay clean
```

`cargo clippy --all-targets` reports about 38 `vec_init_then_push` warnings in existing test code. They are not part of CI; do not "fix" them as part of unrelated work.

System libraries needed to build: `pkg-config`, `dbus`, `clang` (bindgen), `libxkbcommon`.

## Layout

| File | Role |
|---|---|
| `src/main.rs` | Daemon loop: reads CTAPHID events, dispatches CBOR to the engine, runs the caBLE transaction (`handle_cable_transaction`), sends keepalives. Also the `--ui` entry point. |
| `src/engine.rs` | `BridgeEngine`: the state machine. Decides per request whether to answer locally, replay a cached assertion, or start a caBLE transaction. Pure logic, no I/O; most tests live here. |
| `src/ctap2.rs` | CTAP2 constants, CBOR parsing, and request sanitising for the phone (`prepare_*_for_cable`, `replace_allow_list`). |
| `src/ctaphid.rs` | CTAPHID framing over the UHID device (packet assembly, INIT, responses). |
| `src/vhid.rs` | Thin wrapper over the kernel UHID interface. |
| `src/bridge_ui.rs` | `UiCallback` implementation; spawns the QR window as a child process (`--ui`) and talks to it over stdin. |
| `src/ui.rs` | The eframe QR window. Exits with `EXIT_CODE_CANCEL` (2) when the user cancels. |
| `vendor/webauthn-authenticator-rs/` | Vendored copy wired in through `[patch.crates-io]`. The bridge relies on `cable::connect_cable_tunnel` and `Tunnel::transmit_cbor` from it. Treat it as third-party code and change it only when necessary. |
| `contrib/`, `install.sh` | udev rule, systemd user unit, Arch and Debian packaging, installer. |

## How a sign-in actually flows

This is not obvious from the code alone and was established by testing against Firefox:

1. The browser sends `GetInfo`. The bridge advertises `maxCredentialCountInList: 32` so the browser batches the `allowList` instead of sending one credential at a time.
2. The browser sends a silent `GetAssertion` (`up: false`) carrying the full `allowList`. The bridge cannot know which credentials are on the phone, so it answers with a synthetic assertion for the first one. It also remembers the full list (`ProbedAllowList`).
3. The browser sends the interactive `GetAssertion` with the `allowList` narrowed to that first credential. The engine restores the remembered list (`replace_allow_list`) and forwards it to the phone, which signs with the credential it holds.
4. Firefox and the relying party accept an assertion from a credential other than the narrowed one, as long as it belongs to the signed-in user.

Consequences:

- The silent probe is where credential selection happens. Returning `CTAP2_ERR_NO_CREDENTIALS` to the interactive request does not make Firefox try another credential; declining the probe makes it give up and send a `make.me.blink` dummy `MakeCredential`.
- If the relying party itself offers only one credential and the phone does not hold it, the bridge cannot fix that. `CABLE_DROP_ALLOW_LIST=1` forwards the request without an `allowList` so the phone offers its own discoverable passkey; the relying party still has to accept it for that account.
- After the phone answers, the tunnel must be closed with `Token::close` (Shutdown frame plus WebSocket close). Dropping it leaves Android stuck on "Adding passkey...".

## CTAP status codes

Defined in `src/ctap2.rs`. Easy to mix up:

- `0x27` `CTAP2_ERR_OPERATION_DENIED`
- `0x2D` `CTAP2_ERR_KEEPALIVE_CANCEL` (what the bridge returns on cancel or failure; the browser aborts the ceremony)
- `0x2E` `CTAP2_ERR_NO_CREDENTIALS`

Every cancel or failure starts a 5 second cooldown (`BridgeEngine::record_cancellation`) so the browser does not retry in a loop. Keep that behaviour unless there is a tested reason to change it.

## Testing

- Unit tests cover CBOR parsing, CTAPHID framing and engine decisions. Add engine tests for any change in request handling; `engine.rs` has helpers for building test requests.
- Unit tests cannot show what a browser or phone will do. Changes to the request flow need a live run with a real browser and phone, which only the user can perform. Say clearly when something is only unit-tested.

Live test recipe:

```bash
./install.sh -y                           # builds, installs to ~/.local/bin, enables and starts the user service
systemctl --user stop cable-uhid-bridge   # the service holds /dev/uhid; stop it first
RUST_LOG=debug ~/.local/bin/cable-uhid-bridge
```

`install.sh` uses `sudo` for udev rules and always enables and starts the systemd user service, including on machines where it was not running before. Restart the service afterwards with `systemctl --user start cable-uhid-bridge`.

At debug level the daemon logs every `GetAssertion` with its `allowList`, the phone's failure reason, the authData flags (including backup-eligible and backed-up) and the assertion's user handle. These logs identify the user's accounts and credentials; keep them out of commits and issue reports unless redacted.

## Conventions

- Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore(scope):`).
- Environment variables are prefixed `CABLE_` (`CABLE_DROP_ALLOW_LIST`, `CABLE_THEME_*`).
- Keep request-handling decisions in `engine.rs` and CBOR manipulation in `ctap2.rs`; `main.rs` only wires them to I/O.
