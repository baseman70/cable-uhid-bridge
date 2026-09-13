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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ReportType {
    Feature = 0,
    Output = 1,
    Input = 2,
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
                name.as_bytes()
                    .iter()
                    .enumerate()
                    .for_each(|(i, x)| payload.name[i] = *x);
                phys.as_bytes()
                    .iter()
                    .enumerate()
                    .for_each(|(i, x)| payload.phys[i] = *x);
                uniq.as_bytes()
                    .iter()
                    .enumerate()
                    .for_each(|(i, x)| payload.uniq[i] = *x);
                rd_data
                    .iter()
                    .enumerate()
                    .for_each(|(i, x)| payload.rd_data[i] = *x);
                payload.rd_size = rd_data.len() as u16;
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
                data.iter()
                    .enumerate()
                    .for_each(|(i, x)| payload.data[i] = *x);
                payload.size = data.len() as u16;
            }
            InputEvent::Output { data } => {
                event.type_ = sys::uhid_event_type_UHID_OUTPUT;
                let payload = unsafe { &mut event.u.output };
                data.iter()
                    .enumerate()
                    .for_each(|(i, x)| payload.data[i] = *x);
                payload.size = data.len() as u16;
                payload.rtype = sys::hid_report_type_HID_OUTPUT_REPORT as u8;
            }
            InputEvent::GetReportReply { err, id, data, .. } => {
                event.type_ = sys::uhid_event_type_UHID_GET_REPORT_REPLY;
                let payload = unsafe { &mut event.u.get_report_reply };
                payload.err = err;
                data.iter()
                    .enumerate()
                    .for_each(|(i, x)| payload.data[i] = *x);
                payload.size = data.len() as u16;
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
                sys::uhid_event_type_UHID_OUTPUT => Ok(unsafe {
                    let payload: &sys::uhid_output_req = &event.u.output;
                    OutputEvent::Output {
                        data: slice::from_raw_parts(
                            &payload.data[0] as *const u8,
                            payload.size as usize,
                        )
                        .to_vec(),
                    }
                }),
                sys::uhid_event_type_UHID_GET_REPORT => Ok(unsafe {
                    let payload = &event.u.get_report;
                    OutputEvent::GetReport {
                        id: payload.id,
                        report_number: payload.rnum,
                        report_type: mem::transmute::<u8, ReportType>(payload.rtype),
                    }
                }),
                sys::uhid_event_type_UHID_SET_REPORT => Ok(unsafe {
                    let payload = &event.u.set_report;
                    OutputEvent::SetReport {
                        id: payload.id,
                        report_number: payload.rnum,
                        report_type: mem::transmute::<u8, ReportType>(payload.rtype),
                        data: slice::from_raw_parts(
                            &payload.data[0] as *const u8,
                            payload.size as usize,
                        )
                        .to_vec(),
                    }
                }),
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
        OutputEvent::try_from(unsafe { *(src.as_ptr() as *const sys::uhid_event) })
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
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data }.into();
        self.handle.write(&event)
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
        self.handle.write(&event)
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
