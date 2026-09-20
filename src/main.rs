mod bridge_ui;
mod ctap2;
mod ctaphid;
mod engine;
mod ui;
mod vhid;

use anyhow::Result;
use ctaphid_types::{Channel, Command};
use tracing::{debug, error, info};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use webauthn_authenticator_rs::{cable::connect_cable_tunnel, types::CableRequestType};

use bridge_ui::BridgeUi;
use ctap2::*;
use ctaphid::CtapHid;
use engine::*;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Check if invoked as the UI modal
    if args.contains(&"--ui".to_string()) {
        let mut rp = "Passkey".to_string();
        let mut url = "".to_string();
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--rp" && i + 1 < args.len() {
                rp = args[i + 1].clone();
                i += 2;
            } else if args[i] == "--url" && i + 1 < args.len() {
                url = args[i + 1].clone();
                i += 2;
            } else {
                i += 1;
            }
        }
        return ui::run_ui(rp, url);
    }

    // Default: Daemon mode
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

    let mut engine = BridgeEngine::new();

    loop {
        match token.read_event() {
            Ok(Some((channel, command, data))) => match command {
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
                    match engine.handle_cbor_request(&data) {
                        EngineCborAction::SendStatus(status) => {
                            let _ = token.send_cbor_status(channel, status);
                        }
                        EngineCborAction::SendResponse(resp) => {
                            let _ = token.send_cbor_response(channel, CTAP2_OK, &resp);
                        }
                        EngineCborAction::StartCableTransaction {
                            req_type,
                            rp_id,
                            cable_payload,
                        } => {
                            handle_cable_transaction(
                                &mut token,
                                &mut engine,
                                channel,
                                &cable_payload,
                                req_type,
                                &rp_id,
                            )
                            .await;
                        }
                        EngineCborAction::Ignore => {}
                    }
                }
                other_cmd => {
                    debug!("Unsupported CTAPHID command: {:?}", other_cmd);
                    let _ = token.send_error(channel, ctaphid_types::DeviceError::InvalidCommand);
                }
            },
            Ok(None) => {
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            }
            Err(e) => {
                error!("UHID read error: {:?}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle_cable_transaction(
    token: &mut CtapHid,
    engine: &mut BridgeEngine,
    channel: Channel,
    data: &[u8],
    req_type: CableRequestType,
    rp_id: &str,
) {
    let is_make_cred = req_type == CableRequestType::DiscoverableMakeCredential
        || req_type == CableRequestType::MakeCredential;

    if is_make_cred {
        println!("\n📝 Received CTAP2 authenticatorMakeCredential request for: {}", rp_id);
        println!("   Launching caBLE v2 (Hybrid Transport) registration modal with your phone...\n");
    } else {
        println!("\n🔑 Received CTAP2 authenticatorGetAssertion request for: {}", rp_id);
        let assertion_req = parse_assertion_request(data);
        if assertion_req.allow_list.is_empty() {
            println!("   allowList is empty: searching for discoverable passkeys (resident keys)...");
        } else {
            println!("   Searching allowList ({} credential(s) requested):", assertion_req.allow_list.len());
            for (idx, cred_id) in assertion_req.allow_list.iter().enumerate() {
                println!("     [{}] {}", idx + 1, hex::encode(cred_id));
            }
        }
        println!("   Launching caBLE v2 (Hybrid Transport) modal with your phone...\n");
    }

    let bridge_ui = BridgeUi::new(rp_id.to_string());
    let ui_clone = bridge_ui.clone();
    let data_vec = data.to_vec();

    let cable_task = tokio::spawn(async move {
        let mut tunnel = connect_cable_tunnel(req_type, &ui_clone).await?;
        let resp = tunnel.transmit_cbor(&data_vec, &ui_clone).await?;
        Ok::<Vec<u8>, anyhow::Error>(resp)
    });

    let mut last_keepalive = std::time::Instant::now();

    let tx_result = loop {
        if cable_task.is_finished() {
            match cable_task.await {
                Ok(Ok(resp)) => break TransactionResult::Success(resp),
                Ok(Err(e)) => break TransactionResult::Failed(e.to_string()),
                Err(e) => break TransactionResult::Failed(format!("caBLE worker task panicked: {:?}", e)),
            }
        }

        if bridge_ui.is_cancelled() {
            info!("caBLE session cancelled by user via UI modal");
            cable_task.abort();
            break TransactionResult::UserCancelled;
        }

        // Send keepalive every 100ms per FIDO CTAPHID specification to keep browser responsive
        if last_keepalive.elapsed() >= std::time::Duration::from_millis(100) {
            let _ = token.send_single_packet(channel, Command::KeepAlive, &[0x02]);
            last_keepalive = std::time::Instant::now();
        }

        // Non-blocking poll for incoming commands from host/browser
        if let Ok(Some((in_ch, in_cmd, in_data))) = token.try_read_event() {
            match in_cmd {
                Command::Cancel => {
                    if in_ch == channel {
                        info!("Host cancelled WebAuthn session on channel {:?} via CTAPHID_CANCEL", in_ch);
                        cable_task.abort();
                        break TransactionResult::HostCancelled;
                    }
                }
                Command::Init => {
                    if in_ch == channel {
                        info!("Host sent CTAPHID_INIT on active channel {:?}; resetting session", in_ch);
                        let _ = token.handle_init(in_ch, &in_data);
                        cable_task.abort();
                        break TransactionResult::HostReset;
                    } else {
                        // Init on broadcast or different channel (e.g. concurrent background scan)
                        let _ = token.handle_init(in_ch, &in_data);
                    }
                }
                Command::Ping => {
                    let _ = token.send_response(in_ch, Command::Ping, in_data);
                }
                Command::Wink => {
                    let _ = token.send_single_packet(in_ch, Command::Wink, &[]);
                }
                _ => {
                    debug!("Ignoring CTAPHID command {:?} during caBLE wait", in_cmd);
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    };

    if let Some(action) = engine.handle_transaction_outcome(req_type, rp_id, tx_result) {
        match action {
            EngineCborAction::SendResponse(resp) => {
                bridge_ui.notify_done();
                if is_make_cred {
                    info!("Received created credential ({} bytes) from phone!", resp.len());
                    let cred_id_hex = extract_make_credential_id(&resp)
                        .map(|id| hex::encode(&id))
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("\n✅ Successfully registered new passkey with phone!");
                    println!("   Created Credential ID: {}", cred_id_hex);
                    println!("   Relying Party: {}\n", rp_id);
                } else {
                    info!("Received signed CTAP assertion ({} bytes) from phone!", resp.len());
                    let cred_id_hex = extract_assertion_credential_id(&resp)
                        .map(|id| hex::encode(&id))
                        .unwrap_or_else(|| "unspecified (discoverable passkey)".to_string());
                    println!("\n✅ Successfully authenticated with phone passkey!");
                    println!("   Authenticated Credential ID: {}", cred_id_hex);
                    println!("   Relying Party: {}\n", rp_id);
                }
                if let Err(e) = token.send_cbor_response(channel, CTAP2_OK, &resp) {
                    error!("Failed to send response back to browser: {:?}", e);
                }
                // Allow UI modal 300ms to render the success checkmark animation before closing
                tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            }
            EngineCborAction::SendStatus(status) => {
                bridge_ui.close();
                info!("Sending CTAP status 0x{:02x} to browser", status);
                let _ = token.send_cbor_status(channel, status);
            }
            _ => {
                bridge_ui.close();
            }
        }
    } else {
        bridge_ui.close();
    }
}

