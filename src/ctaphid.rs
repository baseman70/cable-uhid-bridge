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
    pub command: Command,
    pub total_len: usize,
    pub data: Vec<u8>,
    pub next_expected_sequence: u8,
    pub started_at: std::time::Instant,
}

pub struct CtapHid<T: std::io::Read + std::io::Write = File> {
    pub hid: UHIDDevice<T>,
    pub payload_stack: HashMap<u32, ChannelPayload>,
}

impl CtapHid<File> {
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

    pub fn is_readable(&self) -> bool {
        use std::os::unix::io::AsRawFd;
        let mut pfd = libc::pollfd {
            fd: self.hid.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        ret > 0 && (pfd.revents & libc::POLLIN != 0)
    }

    pub fn try_read_event(&mut self) -> Result<Option<(Channel, Command, Vec<u8>)>> {
        if !self.is_readable() {
            return Ok(None);
        }
        self.read_event()
    }
}

impl<T: std::io::Read + std::io::Write> CtapHid<T> {
    #[allow(dead_code)]
    pub fn from_device(hid: UHIDDevice<T>) -> Self {
        Self {
            hid,
            payload_stack: HashMap::new(),
        }
    }

    pub fn process_report_bytes(
        &mut self,
        report_bytes: &[u8],
    ) -> Result<Option<(Channel, Command, Vec<u8>)>> {
        if report_bytes.is_empty() {
            return Ok(None);
        }

        // Evict stale incomplete multi-packet payloads older than 3 seconds (CTAPHID timeout)
        self.payload_stack
            .retain(|_, p| p.started_at.elapsed() < std::time::Duration::from_secs(3));

        // Skip the report ID byte if present (report_bytes[0])
        let raw_payload = if report_bytes.len() == 65 {
            &report_bytes[1..]
        } else {
            report_bytes
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
                    Ok(Some((init.channel, init.command, data)))
                } else {
                    // Multi-packet message, accumulate
                    let mut buf = Vec::with_capacity(total_len);
                    buf.extend_from_slice(&init.data);
                    self.payload_stack.insert(
                        cid,
                        ChannelPayload {
                            command: init.command,
                            total_len,
                            data: buf,
                            next_expected_sequence: 0,
                            started_at: std::time::Instant::now(),
                        },
                    );
                    Ok(None)
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

                    let remaining = payload.total_len.saturating_sub(payload.data.len());
                    let to_copy = cont.data.len().min(remaining);
                    payload.data.extend_from_slice(&cont.data[..to_copy]);
                    payload.next_expected_sequence += 1;

                    if payload.data.len() >= payload.total_len {
                        let completed = self.payload_stack.remove(&cid).unwrap();
                        return Ok(Some((cont.channel, completed.command, completed.data)));
                    }
                }
                Ok(None)
            }
        }
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
            OutputEvent::Output { data: report_bytes } => self.process_report_bytes(&report_bytes),
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

        let (assigned_channel, reply_destination) = if channel == Channel::BROADCAST {
            let mut new_cid = [0u8; 4];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_cid);
            // Avoid reserved channel IDs
            if new_cid == [0, 0, 0, 0] || new_cid == [0xff, 0xff, 0xff, 0xff] {
                new_cid = [0x01, 0x02, 0x03, 0x04];
            }
            let new_ch = Channel::from(new_cid);
            info!(
                "CTAPHID_INIT: allocated new channel CID 0x{:08x} for browser",
                u32::from(new_ch)
            );
            (new_ch, Channel::BROADCAST)
        } else {
            // Per CTAPHID spec Section 2.4.1: INIT on an existing channel is a channel sync/reset
            self.payload_stack.remove(&u32::from(channel));
            info!(
                "CTAPHID_INIT: syncing/resetting existing channel CID 0x{:08x}",
                u32::from(channel)
            );
            (channel, channel)
        };

        let init_reply = InitResponse {
            nonce,
            channel: assigned_channel,
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

        self.send_single_packet(reply_destination, Command::Init, &reply_bytes)
    }

    pub fn send_cbor_response(
        &mut self,
        channel: Channel,
        ctap_status: u8,
        cbor_data: &[u8],
    ) -> Result<()> {
        let mut payload = Vec::with_capacity(1 + cbor_data.len());
        payload.push(ctap_status);
        payload.extend_from_slice(cbor_data);
        self.send_response(channel, Command::Cbor, payload)
    }

    pub fn send_cbor_status(&mut self, channel: Channel, status: u8) -> Result<()> {
        self.send_single_packet(channel, Command::Cbor, &[status])
    }

    pub fn send_single_packet(
        &mut self,
        channel: Channel,
        command: Command,
        data: &[u8],
    ) -> Result<()> {
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

    pub fn send_response(
        &mut self,
        channel: Channel,
        command: Command,
        data: Vec<u8>,
    ) -> Result<()> {
        let message = Message {
            channel,
            command,
            data,
        };
        let fragments = message
            .fragments(64)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ctaphid_types::ContinuationPacket;
    use std::io::Cursor;

    fn make_test_ctaphid() -> CtapHid<Cursor<Vec<u8>>> {
        let cursor = Cursor::new(Vec::new());
        let device = UHIDDevice::from_handle(cursor);
        CtapHid::from_device(device)
    }

    #[test]
    fn test_process_report_single_packet() {
        let mut ctaphid = make_test_ctaphid();
        let channel = Channel::from([0x11, 0x22, 0x33, 0x44]);
        let data = vec![0x04]; // CTAP_CMD_GET_INFO

        let init = InitializationPacket {
            channel,
            command: Command::Cbor,
            length: data.len() as u16,
            data: &data,
        };

        let mut report = [0u8; 64];
        init.serialize(&mut report).unwrap();

        let event = ctaphid.process_report_bytes(&report).unwrap();
        assert_eq!(event, Some((channel, Command::Cbor, data)));
    }

    #[test]
    fn test_process_report_multi_packet_assembly() {
        let mut ctaphid = make_test_ctaphid();
        let channel = Channel::from([0xAA, 0xBB, 0xCC, 0xDD]);
        let full_data: Vec<u8> = (0..100).collect();

        let message = Message {
            channel,
            command: Command::Cbor,
            data: full_data.clone(),
        };

        let fragments: Vec<_> = message.fragments(64).unwrap().collect();
        assert_eq!(fragments.len(), 2); // 1 init (57 bytes) + 1 cont (43 bytes)

        // Packet 1: Init packet
        let mut report1 = [0u8; 64];
        fragments[0].serialize(&mut report1).unwrap();
        let event1 = ctaphid.process_report_bytes(&report1).unwrap();
        assert_eq!(event1, None); // Should be accumulating

        // Packet 2: Cont packet
        let mut report2 = [0u8; 64];
        fragments[1].serialize(&mut report2).unwrap();
        let event2 = ctaphid.process_report_bytes(&report2).unwrap();
        assert_eq!(event2, Some((channel, Command::Cbor, full_data)));
    }

    #[test]
    fn test_process_report_sequence_mismatch() {
        let mut ctaphid = make_test_ctaphid();
        let channel = Channel::from([0x01, 0x02, 0x03, 0x04]);

        // Send init packet declaring length 100
        let init = InitializationPacket {
            channel,
            command: Command::Cbor,
            length: 100,
            data: &[0u8; 57],
        };
        let mut report1 = [0u8; 64];
        init.serialize(&mut report1).unwrap();
        let _ = ctaphid.process_report_bytes(&report1).unwrap();

        // Send cont packet with wrong sequence number (3 instead of 0)
        let cont = ContinuationPacket {
            channel,
            sequence: 3,
            data: &[0u8; 43],
        };
        let mut report2 = [0u8; 64];
        cont.serialize(&mut report2).unwrap();
        let event = ctaphid.process_report_bytes(&report2).unwrap();

        // Must drop and return None
        assert_eq!(event, None);
        assert!(!ctaphid.payload_stack.contains_key(&u32::from(channel)));
    }

    #[test]
    fn test_handle_init_allocates_channel() {
        let mut ctaphid = make_test_ctaphid();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let res = ctaphid.handle_init(Channel::BROADCAST, &nonce);
        assert!(res.is_ok());

        // Verify that data was written to the underlying device
        let written = ctaphid.hid.into_inner().into_inner();
        assert!(!written.is_empty());
    }

    #[test]
    fn test_process_report_multi_packet_assembly_with_excess_capacity() {
        let mut ctaphid = make_test_ctaphid();
        let channel = Channel::from([0xAA, 0xBB, 0xCC, 0xDD]);
        let total_len = 70; // 57 in init + 13 in cont
        let full_data = vec![0x42; total_len];

        // Packet 1: Init packet
        let init = InitializationPacket {
            channel,
            command: Command::Cbor,
            length: total_len as u16,
            data: &full_data[..57],
        };
        let mut report1 = [0u8; 64];
        init.serialize(&mut report1).unwrap();
        let event1 = ctaphid.process_report_bytes(&report1).unwrap();
        assert_eq!(event1, None);

        // Intentionally simulate allocator allocating a larger capacity (e.g. 256)
        if let Some(payload) = ctaphid.payload_stack.get_mut(&u32::from(channel)) {
            payload.data.reserve(200);
            assert!(payload.data.capacity() > total_len);
        }

        // Packet 2: Cont packet with remaining 13 bytes
        let cont = ContinuationPacket {
            channel,
            sequence: 0,
            data: &full_data[57..],
        };
        let mut report2 = [0u8; 64];
        cont.serialize(&mut report2).unwrap();
        let event2 = ctaphid.process_report_bytes(&report2).unwrap();

        // Must complete successfully even when capacity > total_len!
        assert_eq!(event2, Some((channel, Command::Cbor, full_data)));
    }

    #[test]
    fn test_handle_init_sync_preserves_existing_channel() {
        let mut ctaphid = make_test_ctaphid();
        let existing_channel = Channel::from([0x12, 0x34, 0x56, 0x78]);
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];

        let res = ctaphid.handle_init(existing_channel, &nonce);
        assert!(res.is_ok());

        let written = ctaphid.hid.into_inner().into_inner();
        // UHID buffer contains UHID_CREATE2 followed by UHID_INPUT2 containing the packet
        assert!(written.windows(4).any(|w| w == &[0x12, 0x34, 0x56, 0x78]));
    }
}
