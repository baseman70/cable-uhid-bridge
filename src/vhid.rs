#![allow(clippy::all, unused)]
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, prelude::*};
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::slice;

use enumflags2::{bitflags, BitFlags};
use uhidrs_sys as sys;

#[derive(Debug)]
pub enum StreamError {
    Io(std::io::Error),
    UnknownEventType(u32),
}

#[bitflags]
#[derive(Copy, Clone, PartialEq)]
#[repr(u64)]
pub enum DevFlags {
    FeatureReportsNumbered = 0b0000_0001,
    OutputReportsNumbered = 0b0000_0010,
    InputReportsNumbered = 0b0000_0100,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ReportType {
    Feature = 0,
    Output = 1,
    Input = 2,
}

impl TryFrom<u8> for ReportType {
    type Error = StreamError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(ReportType::Feature),
            1 => Ok(ReportType::Output),
            2 => Ok(ReportType::Input),
            _ => Err(StreamError::UnknownEventType(v as u32)),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Bus {
    PCI = 1,
    ISAPNP = 2,
    USB = 3,
    HIL = 4,
    BLUETOOTH = 5,
    VIRTUAL = 6,
    ISA = 16,
    I8042 = 17,
    XTKBD = 18,
    RS232 = 19,
    GAMEPORT = 20,
    PARPORT = 21,
    AMIGA = 22,
    ADB = 23,
    I2C = 24,
    HOST = 25,
    GSC = 26,
    ATARI = 27,
    SPI = 28,
    RMI = 29,
    CEC = 30,
    INTEL_ISHTP = 31,
}

pub const UHID_EVENT_SIZE: usize = mem::size_of::<sys::uhid_event>();

#[derive(Debug, Clone, PartialEq)]
pub struct CreateParams {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub bus: Bus,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub rd_data: Vec<u8>,
}

pub enum InputEvent<'a> {
    Create(CreateParams),
    Destroy,
    Input {
        data: &'a [u8],
    },
    Output {
        data: Vec<u8>,
    },
    GetReportReply {
        id: u32,
        err: u16,
        data: Vec<u8>,
    },
    SetReportReply {
        id: u32,
        err: u16,
    },
}

impl<'a> From<InputEvent<'a>> for sys::uhid_event {
    fn from(input: InputEvent<'a>) -> Self {
        let mut event: sys::uhid_event = unsafe { mem::zeroed() };

        match input {
            InputEvent::Create(CreateParams {
                name,
                phys,
                uniq,
                bus,
                vendor,
                product,
                version,
                country,
                rd_data,
            }) => {
                event.type_ = sys::uhid_event_type_UHID_CREATE2;
                let payload = unsafe { &mut event.u.create2 };

                let name_bytes = name.as_bytes();
                let name_len = name_bytes.len().min(payload.name.len());
                payload.name[..name_len].copy_from_slice(&name_bytes[..name_len]);

                let phys_bytes = phys.as_bytes();
                let phys_len = phys_bytes.len().min(payload.phys.len());
                payload.phys[..phys_len].copy_from_slice(&phys_bytes[..phys_len]);

                let uniq_bytes = uniq.as_bytes();
                let uniq_len = uniq_bytes.len().min(payload.uniq.len());
                payload.uniq[..uniq_len].copy_from_slice(&uniq_bytes[..uniq_len]);

                let rd_len = rd_data.len().min(payload.rd_data.len());
                payload.rd_data[..rd_len].copy_from_slice(&rd_data[..rd_len]);
                payload.rd_size = rd_len as u16;

                payload.bus = bus as u16;
                payload.vendor = vendor;
                payload.product = product;
                payload.version = version;
                payload.country = country;
            }
            InputEvent::Destroy => {
                event.type_ = sys::uhid_event_type_UHID_DESTROY;
            }
            InputEvent::Input { data } => {
                event.type_ = sys::uhid_event_type_UHID_INPUT2;
                let payload = unsafe { &mut event.u.input2 };
                let len = data.len().min(payload.data.len());
                payload.data[..len].copy_from_slice(&data[..len]);
                payload.size = len as u16;
            }
            InputEvent::Output { data } => {
                event.type_ = sys::uhid_event_type_UHID_OUTPUT;
                let payload = unsafe { &mut event.u.output };
                let len = data.len().min(payload.data.len());
                payload.data[..len].copy_from_slice(&data[..len]);
                payload.size = len as u16;
                payload.rtype = sys::hid_report_type_HID_OUTPUT_REPORT as u8;
            }
            InputEvent::GetReportReply { err, id, data, .. } => {
                event.type_ = sys::uhid_event_type_UHID_GET_REPORT_REPLY;
                let payload = unsafe { &mut event.u.get_report_reply };
                payload.err = err;
                let len = data.len().min(payload.data.len());
                payload.data[..len].copy_from_slice(&data[..len]);
                payload.size = len as u16;
                payload.id = id;
            }
            InputEvent::SetReportReply { err, id, .. } => {
                event.type_ = sys::uhid_event_type_UHID_SET_REPORT_REPLY;
                let payload = unsafe { &mut event.u.set_report_reply };
                payload.err = err;
                payload.id = id;
            }
        };

        event
    }
}

pub enum OutputEvent {
    Start { dev_flags: Vec<DevFlags> },
    Stop,
    Open,
    Close,
    Output { data: Vec<u8> },
    GetReport { id: u32, report_number: u8, report_type: ReportType },
    SetReport { id: u32, report_number: u8, report_type: ReportType, data: Vec<u8> },
}

fn to_uhid_event_type(value: u32) -> Option<sys::uhid_event_type> {
    let last_valid_value = sys::uhid_event_type_UHID_SET_REPORT_REPLY;
    if value <= last_valid_value {
        Some(value)
    } else {
        None
    }
}

impl TryFrom<sys::uhid_event> for OutputEvent {
    type Error = StreamError;
    fn try_from(event: sys::uhid_event) -> Result<Self, Self::Error> {
        if let Some(event_type) = to_uhid_event_type(event.type_) {
            match event_type {
                sys::uhid_event_type_UHID_START => Ok(unsafe {
                    OutputEvent::Start {
                        dev_flags: BitFlags::from_bits_truncate(event.u.start.dev_flags)
                            .iter()
                            .collect(),
                    }
                }),
                sys::uhid_event_type_UHID_STOP => Ok(OutputEvent::Stop),
                sys::uhid_event_type_UHID_OPEN => Ok(OutputEvent::Open),
                sys::uhid_event_type_UHID_CLOSE => Ok(OutputEvent::Close),
                sys::uhid_event_type_UHID_OUTPUT => {
                    let payload = unsafe { &event.u.output };
                    let max_len = payload.data.len();
                    let size = (payload.size as usize).min(max_len);
                    Ok(OutputEvent::Output {
                        data: payload.data[..size].to_vec(),
                    })
                }
                sys::uhid_event_type_UHID_GET_REPORT => {
                    let payload = unsafe { &event.u.get_report };
                    Ok(OutputEvent::GetReport {
                        id: payload.id,
                        report_number: payload.rnum,
                        report_type: ReportType::try_from(payload.rtype)?,
                    })
                }
                sys::uhid_event_type_UHID_SET_REPORT => {
                    let payload = unsafe { &event.u.set_report };
                    let max_len = payload.data.len();
                    let size = (payload.size as usize).min(max_len);
                    Ok(OutputEvent::SetReport {
                        id: payload.id,
                        report_number: payload.rnum,
                        report_type: ReportType::try_from(payload.rtype)?,
                        data: payload.data[..size].to_vec(),
                    })
                }
                _ => Err(StreamError::UnknownEventType(event.type_)),
            }
        } else {
            Err(StreamError::UnknownEventType(event.type_))
        }
    }
}

impl TryFrom<[u8; UHID_EVENT_SIZE]> for OutputEvent {
    type Error = StreamError;
    fn try_from(src: [u8; UHID_EVENT_SIZE]) -> Result<Self, Self::Error> {
        let event: sys::uhid_event = unsafe { std::ptr::read_unaligned(src.as_ptr() as *const sys::uhid_event) };
        OutputEvent::try_from(event)
    }
}

impl<'a> From<InputEvent<'a>> for [u8; UHID_EVENT_SIZE] {
    fn from(input: InputEvent<'a>) -> Self {
        let event: sys::uhid_event = input.into();
        unsafe { mem::transmute_copy(&event) }
    }
}

pub struct UHIDDevice<T: Read + Write> {
    handle: T,
}

impl<T: Read + Write> UHIDDevice<T> {
    pub fn from_handle(handle: T) -> Self {
        Self { handle }
    }

    pub fn into_inner(self) -> T {
        self.handle
    }

    pub fn handle(&self) -> &T {
        &self.handle
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data }.into();
        self.handle.write_all(&event)?;
        Ok(event.len())
    }

    pub fn read(&mut self) -> Result<OutputEvent, StreamError> {
        let mut event = [0u8; UHID_EVENT_SIZE];
        self.handle
            .read_exact(&mut event)
            .map_err(StreamError::Io)?;
        OutputEvent::try_from(event)
    }

    pub fn destroy(&mut self) -> io::Result<usize> {
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Destroy.into();
        self.handle.write_all(&event)?;
        Ok(event.len())
    }
}

impl UHIDDevice<File> {
    pub fn create(params: CreateParams) -> io::Result<UHIDDevice<File>> {
        UHIDDevice::create_with_path(params, Path::new("/dev/uhid"))
    }

    pub fn create_with_path(params: CreateParams, path: &Path) -> io::Result<UHIDDevice<File>> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(true);
        if cfg!(unix) {
            options.custom_flags(libc::O_RDWR | libc::O_CLOEXEC);
        }
        let mut handle = options.open(path)?;
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();
        handle.write_all(&event)?;
        Ok(UHIDDevice { handle })
    }
}

impl AsRawFd for UHIDDevice<File> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.handle.as_raw_fd()
    }
}

pub fn fido_report_descriptor() -> Vec<u8> {
    // Standard FIDO U2FHID report descriptor (64-byte IN/OUT reports)
    vec![
        0x06, 0xD0, 0xF1, /* Usage Page (FIDO Alliance) */
        0x09, 0x01,       /* Usage (U2F HID Auth. Device) */
        0xA1, 0x01,       /* Collection (Application) */
        0x09, 0x20,       /* Usage (Input Report Data) */
        0x15, 0x00,       /* Logical Minimum (0) */
        0x26, 0xFF, 0x00, /* Logical Maximum (255) */
        0x75, 0x08,       /* Report Size (8 bits) */
        0x95, 0x40,       /* Report Count (64 bytes) */
        0x81, 0x02,       /* Input (Data, Var, Abs) */
        0x09, 0x21,       /* Usage (Output Report Data) */
        0x15, 0x00,       /* Logical Minimum (0) */
        0x26, 0xFF, 0x00, /* Logical Maximum (255) */
        0x75, 0x08,       /* Report Size (8 bits) */
        0x95, 0x40,       /* Report Count (64 bytes) */
        0x91, 0x02,       /* Output (Data, Var, Abs) */
        0xC0,             /* End Collection */
    ]
}

pub fn create_fido_hid() -> io::Result<UHIDDevice<File>> {
    UHIDDevice::create(CreateParams {
        name: "caBLE Virtual Passkey Token".into(),
        phys: "cable-passkey".into(),
        uniq: "cable-bridge-01".into(),
        bus: Bus::USB,
        vendor: 0x1209, // OpenMoko
        product: 0x0001,
        version: 0x0001,
        country: 0,
        rd_data: fido_report_descriptor(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_type_try_from() {
        assert_eq!(ReportType::try_from(0).unwrap(), ReportType::Feature);
        assert_eq!(ReportType::try_from(1).unwrap(), ReportType::Output);
        assert_eq!(ReportType::try_from(2).unwrap(), ReportType::Input);
        assert!(ReportType::try_from(3).is_err());
        assert!(ReportType::try_from(255).is_err());
    }

    #[test]
    fn test_input_event_oversized_string_does_not_panic() {
        let huge_name = "A".repeat(500);
        let huge_phys = "B".repeat(500);
        let huge_uniq = "C".repeat(500);
        let huge_rd = vec![0xFF; 10000];

        let event: sys::uhid_event = InputEvent::Create(CreateParams {
            name: huge_name,
            phys: huge_phys,
            uniq: huge_uniq,
            bus: Bus::USB,
            vendor: 0x1234,
            product: 0x5678,
            version: 1,
            country: 0,
            rd_data: huge_rd,
        }).into();

        let ev_type = event.type_;
        assert_eq!(ev_type, sys::uhid_event_type_UHID_CREATE2);
        unsafe {
            let rd_size = event.u.create2.rd_size;
            assert_eq!(rd_size, 4096);
        }
    }

    #[test]
    fn test_input_event_oversized_data_does_not_panic() {
        let huge_data = vec![0x42; 8000];
        let event: sys::uhid_event = InputEvent::Input { data: &huge_data }.into();
        let ev_type = event.type_;
        assert_eq!(ev_type, sys::uhid_event_type_UHID_INPUT2);
        unsafe {
            let sz = event.u.input2.size;
            assert_eq!(sz, 4096);
        }
    }

    #[test]
    fn test_output_event_from_raw_bytes_unaligned() {
        let mut raw = [0u8; UHID_EVENT_SIZE];
        // Set type to UHID_OPEN
        let type_bytes = sys::uhid_event_type_UHID_OPEN.to_ne_bytes();
        raw[..type_bytes.len()].copy_from_slice(&type_bytes);

        let event = OutputEvent::try_from(raw).unwrap();
        assert!(matches!(event, OutputEvent::Open));
    }

    #[test]
    fn test_output_event_clamps_oversized_payload_size() {
        let mut raw = [0u8; UHID_EVENT_SIZE];
        // Set type to UHID_OUTPUT
        let type_bytes = sys::uhid_event_type_UHID_OUTPUT.to_ne_bytes();
        raw[..type_bytes.len()].copy_from_slice(&type_bytes);

        // In sys::uhid_event, u.output is at offset 4 (or 8 depending on arch alignment)
        let mut event: sys::uhid_event = unsafe { std::mem::zeroed() };
        event.type_ = sys::uhid_event_type_UHID_OUTPUT;
        unsafe {
            event.u.output.size = 60000; // Far larger than payload.data (4096)
            event.u.output.data[0] = 0xAA;
            event.u.output.data[4095] = 0xBB;
        }

        let parsed = OutputEvent::try_from(event).unwrap();
        match parsed {
            OutputEvent::Output { data } => {
                // Must be clamped to max data len (4096) without memory error!
                assert_eq!(data.len(), 4096);
                assert_eq!(data[0], 0xAA);
                assert_eq!(data[4095], 0xBB);
            }
            _ => panic!("Expected OutputEvent::Output"),
        }
    }
}
