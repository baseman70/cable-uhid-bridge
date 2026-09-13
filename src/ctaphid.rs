use anyhow::Result;
use ctaphid_types::{
    Capabilities, Channel, Command, DeviceError, DeviceVersion, InitResponse, InitializationPacket,
    Message, Packet,
};
use std::collections::HashMap;
use std::fs::File;
use tracing::{debug, error, info};

use crate::vhid::{create_fido_hid, OutputEvent, UHIDDevice};

pub struct ChannelPayload {
    pub data: Vec<u8>,
    pub next_expected_sequence: u8,
}

pub struct CtapHid {
    pub hid: UHIDDevice<File>,
    pub payload_stack: HashMap<u32, ChannelPayload>,
}

impl CtapHid {
    pub fn new() -> Result<Self> {
        info!("Creating virtual FIDO USB device node via /dev/uhid...");
        let hid = create_fido_hid().map_err(|e| {
            error!("Failed to create virtual HID token via /dev/uhid: {}", e);
            e
        })?;
        info!("Virtual FIDO USB token successfully created and registered with kernel!");

        Ok(Self {
            hid,
            payload_stack: HashMap::new(),
        })
    }

    pub fn read_event(&mut self) -> Result<Option<(Channel, Command, Vec<u8>)>> {
        let event = match self.hid.read() {
            Ok(ev) => ev,
            Err(e) => {
                debug!("Error or EOF reading UHID event: {:?}", e);
                return Ok(None);
            }
        };

        match event {
            OutputEvent::Output { data: report_bytes } => {
                if report_bytes.is_empty() {
                    return Ok(None);
                }
                // Skip the report ID byte if present (report_bytes[0])
                let raw_payload = if report_bytes.len() == 65 {
                    &report_bytes[1..]
                } else {
                    &report_bytes[..]
                };

                let packet = match Packet::<Vec<u8>>::try_from(raw_payload) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("Failed to parse CTAPHID packet: {:?}", e);
                        return Ok(None);
                    }
                };

                match packet {
                    Packet::Initialization(init) => {
                        let cid = u32::from(init.channel);
                        let total_len = init.length as usize;

                        if init.data.len() >= total_len {
                            // Single packet message!
                            let mut data = init.data;
                            data.truncate(total_len);
                            return Ok(Some((init.channel, init.command, data)));
                        } else {
                            // Multi-packet message, accumulate
                            let mut buf = Vec::with_capacity(total_len);
                            buf.extend_from_slice(&init.data);
                            self.payload_stack.insert(
                                cid,
                                ChannelPayload {
                                    data: buf,
                                    next_expected_sequence: 0,
                                },
                            );
                            return Ok(None);
                        }
                    }
                    Packet::Continuation(cont) => {
                        let cid = u32::from(cont.channel);
                        if let Some(payload) = self.payload_stack.get_mut(&cid) {
                            if cont.sequence != payload.next_expected_sequence {
                                error!(
                                    "CTAPHID sequence mismatch on CID {:08x}: got {}, expected {}",
                                    cid, cont.sequence, payload.next_expected_sequence
                                );
                                self.payload_stack.remove(&cid);
                                self.send_error(cont.channel, DeviceError::InvalidSequence)?;
                                return Ok(None);
                            }

                            let remaining = payload.data.capacity() - payload.data.len();
                            let to_copy = cont.data.len().min(remaining);
                            payload.data.extend_from_slice(&cont.data[..to_copy]);
                            payload.next_expected_sequence += 1;

                            if payload.data.len() >= payload.data.capacity() {
                                let completed = self.payload_stack.remove(&cid).unwrap();
                                // We don't have the original command in the continuation packet,
                                // but for passkey WebAuthn this is always CBOR (0x10)
                                return Ok(Some((cont.channel, Command::Cbor, completed.data)));
                            }
                        }
                        return Ok(None);
                    }
                }
            }
            OutputEvent::Start { .. } => {
                debug!("Kernel sent UHID_START event");
                Ok(None)
            }
            OutputEvent::Open => {
                debug!("Kernel sent UHID_OPEN (client opened virtual device)");
                Ok(None)
            }
            OutputEvent::Close => {
                debug!("Kernel sent UHID_CLOSE (client closed virtual device)");
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    pub fn handle_init(&mut self, channel: Channel, data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return self.send_error(channel, DeviceError::InvalidLength);
        }

        let nonce: [u8; 8] = data[0..8].try_into()?;
        let mut new_cid = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_cid);
        // Avoid reserved channel IDs
        if new_cid == [0, 0, 0, 0] || new_cid == [0xff, 0xff, 0xff, 0xff] {
            new_cid = [0x01, 0x02, 0x03, 0x04];
        }

        let init_reply = InitResponse {
            nonce,
            channel: Channel::from(new_cid),
            protocol_version: 0x02, // CTAP 2.x
            device_version: DeviceVersion {
                major: 0x01,
                minor: 0x00,
                build: 0x00,
            },
            // Announce CBOR support
            capabilities: Capabilities::CBOR | Capabilities::NMSG,
            rest: [0u8; 0],
        };

        let mut reply_bytes = [0u8; 17];
        init_reply.serialize(&mut reply_bytes)?;

        info!(
            "CTAPHID_INIT: allocated new channel CID 0x{:02x}{:02x}{:02x}{:02x} for browser",
            new_cid[0], new_cid[1], new_cid[2], new_cid[3]
        );

        self.send_single_packet(Channel::BROADCAST, Command::Init, &reply_bytes)
    }

    pub fn send_cbor_response(&mut self, channel: Channel, ctap_status: u8, cbor_data: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(1 + cbor_data.len());
        payload.push(ctap_status);
        payload.extend_from_slice(cbor_data);
        self.send_response(channel, Command::Cbor, payload)
    }

    pub fn send_cbor_status(&mut self, channel: Channel, status: u8) -> Result<()> {
        self.send_single_packet(channel, Command::Cbor, &[status])
    }

    pub fn send_single_packet(&mut self, channel: Channel, command: Command, data: &[u8]) -> Result<()> {
        let packet = InitializationPacket {
            channel,
            command,
            length: data.len() as u16,
            data,
        };
        let mut report = [0u8; 64];
        packet.serialize(&mut report)?;
        self.hid.write(&report)?;
        Ok(())
    }

    pub fn send_response(&mut self, channel: Channel, command: Command, data: Vec<u8>) -> Result<()> {
        let message = Message {
            channel,
            command,
            data,
        };
        let fragments = message.fragments(64).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        let mut report = [0u8; 64];
        for packet in fragments {
            packet.serialize(&mut report)?;
            self.hid.write(&report)?;
        }
        Ok(())
    }

    pub fn send_error(&mut self, channel: Channel, error: DeviceError) -> Result<()> {
        let err_code = match error {
            DeviceError::InvalidCommand => 0x01,
            DeviceError::InvalidParameter => 0x02,
            DeviceError::InvalidLength => 0x03,
            DeviceError::InvalidSequence => 0x04,
            DeviceError::MessageTimeout => 0x05,
            DeviceError::ChannelBusy => 0x06,
            DeviceError::LockRequired => 0x0a,
            DeviceError::InvalidChannel => 0x0b,
            DeviceError::Other => 0x7f,
            DeviceError::Unknown(e) => e,
        };
        self.send_single_packet(channel, Command::Error, &[err_code])
    }
}
