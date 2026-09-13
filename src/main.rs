mod ctap2;
mod ctaphid;
mod vhid;

use anyhow::Result;
use ctaphid_types::Command;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use webauthn_authenticator_rs::{
    cable::connect_cable_tunnel,
    types::CableRequestType,
    ui::Cli,
};

use ctap2::*;
use ctaphid::CtapHid;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .compact()
        .init();

    println!("==========================================================");
    println!("  cable-uhid-bridge: FIDO2 Virtual USB Passkey Token");
    println!("==========================================================");

    let mut token = match CtapHid::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("\n❌ Failed to open /dev/uhid: {}", e);
            eprintln!("\n👉 To run cable-uhid-bridge, either run with sudo:");
            eprintln!("   sudo ./target/debug/cable-uhid-bridge");
            eprintln!("\n👉 Or configure a udev rule for your user:");
            eprintln!("   echo 'KERNEL==\"uhid\", TAG+=\"uaccess\"' | sudo tee /etc/udev/rules.d/70-uhid.rules");
            eprintln!("   sudo modprobe uhid && sudo udevadm trigger -s misc -a name=uhid\n");
            return Err(e);
        }
    };

    println!("\n✅ Virtual USB FIDO2 token is active in the Linux kernel!");
    println!("   Browsers (Firefox, Chrome, Edge) will recognize it as a physical FIDO2 key.");
    println!("   Awaiting WebAuthn requests...\n");

    let ui = Cli {};

    loop {
        match token.read_event() {
            Ok(Some((channel, command, data))) => {
                match command {
                    Command::Init => {
                        info!("Handling CTAPHID_INIT from browser on channel {:?}", channel);
                        if let Err(e) = token.handle_init(channel, &data) {
                            error!("Error handling CTAPHID_INIT: {:?}", e);
                        }
                    }
                    Command::Ping => {
                        info!("Handling CTAPHID_PING ({} bytes)", data.len());
                        let _ = token.send_response(channel, Command::Ping, data);
                    }
                    Command::Wink => {
                        info!("Handling CTAPHID_WINK");
                        let _ = token.send_single_packet(channel, Command::Wink, &[]);
                    }
                    Command::Cbor => {
                        if data.is_empty() {
                            warn!("Received empty CBOR request");
                            continue;
                        }

                        let ctap_cmd = data[0];

                        match ctap_cmd {
                            CTAP_CMD_GET_INFO => {
                                info!("Received CTAP2 authenticatorGetInfo (0x04) request from browser");
                                let get_info_cbor = build_get_info_response();
                                if let Err(e) = token.send_cbor_response(channel, CTAP2_OK, &get_info_cbor) {
                                    error!("Failed to send GetInfo response: {:?}", e);
                                } else {
                                    info!("Sent CTAP2 GetInfo response to browser (supported: FIDO_2_1, rk, uv)");
                                }
                            }
                            CTAP_CMD_GET_ASSERTION => {
                                println!("\n🔑 Received CTAP2 authenticatorGetAssertion (0x02) request from browser!");
                                println!("   Triggering caBLE v2 (Hybrid Transport) session with your phone...\n");

                                match connect_cable_tunnel(CableRequestType::GetAssertion, &ui).await {
                                    Ok(mut tunnel) => {
                                        println!("\n🎉 Mobile authenticator connected via caBLE v2!");
                                        info!("Relaying GetAssertion request ({} bytes) to mobile authenticator...", data.len());
                                        match tunnel.transmit_cbor(&data, &ui).await {
                                            Ok(resp) => {
                                                info!("Received signed CTAP assertion ({} bytes) from phone!", resp.len());
                                                if let Err(e) = token.send_response(channel, Command::Cbor, resp) {
                                                    error!("Failed to send assertion back to browser: {:?}", e);
                                                } else {
                                                    println!("\n✅ Successfully returned signed passkey assertion to browser!\n");
                                                }
                                            }
                                            Err(e) => {
                                                error!("Error executing GetAssertion on phone: {:?}", e);
                                                let _ = token.send_cbor_status(channel, CTAP2_ERR_OPERATION_DENIED);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("caBLE session failed: {:?}", e);
                                        let _ = token.send_cbor_status(channel, CTAP2_ERR_OPERATION_DENIED);
                                    }
                                }
                            }
                            CTAP_CMD_MAKE_CREDENTIAL => {
                                println!("\n📝 Received CTAP2 authenticatorMakeCredential (0x01) request from browser!");
                                println!("   Triggering caBLE v2 (Hybrid Transport) registration with your phone...\n");

                                match connect_cable_tunnel(CableRequestType::MakeCredential, &ui).await {
                                    Ok(mut tunnel) => {
                                        println!("\n🎉 Mobile authenticator connected via caBLE v2!");
                                        info!("Relaying MakeCredential request ({} bytes) to mobile authenticator...", data.len());
                                        match tunnel.transmit_cbor(&data, &ui).await {
                                            Ok(resp) => {
                                                info!("Received created credential ({} bytes) from phone!", resp.len());
                                                if let Err(e) = token.send_response(channel, Command::Cbor, resp) {
                                                    error!("Failed to send credential back to browser: {:?}", e);
                                                } else {
                                                    println!("\n✅ Successfully returned new passkey credential to browser!\n");
                                                }
                                            }
                                            Err(e) => {
                                                error!("Error executing MakeCredential on phone: {:?}", e);
                                                let _ = token.send_cbor_status(channel, CTAP2_ERR_OPERATION_DENIED);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("caBLE session failed: {:?}", e);
                                        let _ = token.send_cbor_status(channel, CTAP2_ERR_OPERATION_DENIED);
                                    }
                                }
                            }
                            other => {
                                warn!("Unhandled CTAP2 command: 0x{:02x}", other);
                                let _ = token.send_cbor_status(channel, CTAP2_ERR_UNSUPPORTED_OPTION);
                            }
                        }
                    }
                    other_cmd => {
                        debug!("Ignoring CTAPHID command: {:?}", other_cmd);
                    }
                }
            }
            Ok(None) => {
                // Yield briefly to avoid busy-spinning
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            }
            Err(e) => {
                error!("UHID read error: {:?}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }
}
