use std::{
  cmp::Ordering,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use bitflags::bitflags;
use thiserror::Error;

use crate::MacAddress;

pub(crate) const LLDP_TLV_END: u8 = 0;
pub(crate) const LLDP_TLV_CHASSIS_ID: u8 = 1;
pub(crate) const LLDP_TLV_PORT_ID: u8 = 2;
pub(crate) const LLDP_TLV_TTL: u8 = 3;
pub(crate) const LLDP_TLV_PORT_DESCR: u8 = 4;
pub(crate) const LLDP_TLV_SYSTEM_NAME: u8 = 5;
pub(crate) const LLDP_TLV_SYSTEM_DESCR: u8 = 6;
pub(crate) const LLDP_TLV_SYSTEM_CAP: u8 = 7;
pub(crate) const LLDP_TLV_MGMT_ADDR: u8 = 8;

const LLDP_CHASSISID_SUBTYPE_CHASSIS: u8 = 1;
const LLDP_CHASSISID_SUBTYPE_IFALIAS: u8 = 2;
const LLDP_CHASSISID_SUBTYPE_PORT: u8 = 3;
const LLDP_CHASSISID_SUBTYPE_LLADDR: u8 = 4;
const LLDP_CHASSISID_SUBTYPE_ADDR: u8 = 5;
const LLDP_CHASSISID_SUBTYPE_IFNAME: u8 = 6;
const LLDP_CHASSISID_SUBTYPE_LOCAL: u8 = 7;

const LLDP_PORTID_SUBTYPE_UNKNOWN: u8 = 0;
const LLDP_PORTID_SUBTYPE_IFALIAS: u8 = 1;
const LLDP_PORTID_SUBTYPE_PORT: u8 = 2;
const LLDP_PORTID_SUBTYPE_LLADDR: u8 = 3;
const LLDP_PORTID_SUBTYPE_ADDR: u8 = 4;
const LLDP_PORTID_SUBTYPE_IFNAME: u8 = 5;
const LLDP_PORTID_SUBTYPE_AGENTCID: u8 = 6;
const LLDP_PORTID_SUBTYPE_LOCAL: u8 = 7;

const LLDP_MGMT_ADDR_NONE: u8 = 0;
const LLDP_MGMT_ADDR_IP4: u8 = 1;
const LLDP_MGMT_ADDR_IP6: u8 = 2;

const LLDP_MGMT_IFACE_UNKNOWN: u8 = 1;
const LLDP_MGMT_IFACE_IFINDEX: u8 = 2;
const LLDP_MGMT_IFACE_SYSPORT: u8 = 3;

#[derive(Debug, Clone, Default)]
pub struct TlvList {
  pub tlvs: Vec<Tlv>,
  pub errors: Vec<TlvDecodeError>,
  pub end_len: usize,
  pub critical_error: Option<RawTlvError>,
}

impl TlvList {
  pub fn decode(mut buf: &[u8]) -> Self {
    let mut list = Self::default();

    while !buf.is_empty() {
      match RawTlv::decode(buf) {
        Ok(raw) => {
          list.end_len += raw.total_len();
          buf = &buf[raw.total_len()..];
          match Tlv::decode(raw) {
            Ok(tlv) => list.tlvs.push(tlv),
            Err(err) => list.errors.push(err),
          }
        }

        Err(err) => {
          list.critical_error = Some(err);
          return list;
        }
      }
    }

    list
  }
}

struct RawTlv<'a> {
  ty: u8,
  payload: &'a [u8],
}

impl<'a> RawTlv<'a> {
  fn total_len(&self) -> usize {
    self.payload.len() + 2
  }

  fn decode(buf: &'a [u8]) -> Result<Self, RawTlvError> {
    if buf.len() < 2 {
      return Err(RawTlvError::BufferTooShort);
    }

    let payload_ty = buf[0] >> 1;
    let payload_len = (((buf[0] & 1) as usize) << 8) + buf[1] as usize;
    let tlv_len = payload_len + 2;

    if buf.len() < tlv_len {
      return Err(RawTlvError::BufferTooShort);
    }

    let payload = &buf[2..2 + payload_len];

    Ok(Self {
      ty: payload_ty,
      payload,
    })
  }
}

#[derive(Debug, Clone)]
pub enum Tlv {
  End,
  ChassisId(ChassisId),
  PortId(PortId),
  TimeToLive(u16),
  PortDescription(String),
  SystemName(String),
  SystemDescription(String),
  Capabilities(Capabilities),
  ManagementAddress(ManagementAddress),
}

#[derive(Debug, Clone, Error)]
pub enum RawTlvError {
  #[error("buffer too short")]
  BufferTooShort,
}

#[derive(Debug, Clone, Error)]
pub enum TlvDecodeError {
  #[error("buffer too short")]
  BufferTooShort,
  #[error("buffer too long")]
  BufferTooLong,
  #[error("bytes after end")]
  BytesAfterEnd,
  #[error("unknown tlv '{0}'")]
  UnknownTlv(u8),
  #[error("unknown chassis id subtype '{0}'")]
  UnknownChassisIdSubtype(u8),
  #[error("unknown port id subtype '{0}'")]
  UnknownPortIdSubtype(u8),
  #[error(transparent)]
  FromStringError(#[from] std::string::FromUtf8Error),
}

impl Tlv {
  fn decode(raw: RawTlv) -> Result<Self, TlvDecodeError> {
    match raw.ty {
      LLDP_TLV_END => {
        if raw.payload.len() > 2 {
          Err(TlvDecodeError::BytesAfterEnd)
        } else {
          Ok(Tlv::End)
        }
      }

      LLDP_TLV_CHASSIS_ID => ChassisId::decode(raw.payload).map(Tlv::ChassisId),
      LLDP_TLV_PORT_ID => PortId::decode(raw.payload).map(Tlv::PortId),

      LLDP_TLV_TTL => match raw.payload.len().cmp(&2) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => Ok(Tlv::TimeToLive(u16::from_be_bytes(raw.payload.try_into().unwrap()))),
      },

      LLDP_TLV_PORT_DESCR => Ok(String::from_utf8(raw.payload.into()).map(Tlv::PortDescription)?),
      LLDP_TLV_SYSTEM_NAME => Ok(String::from_utf8(raw.payload.into()).map(Tlv::SystemName)?),
      LLDP_TLV_SYSTEM_DESCR => Ok(String::from_utf8(raw.payload.into()).map(Tlv::SystemDescription)?),

      LLDP_TLV_SYSTEM_CAP => match raw.payload.len().cmp(&4) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => {
          let capabilities = u16::from_be_bytes(raw.payload[0..2].try_into().unwrap());
          let capabilities = CapabilityFlags::from_bits_retain(capabilities);
          let enabled_capabilities = u16::from_be_bytes(raw.payload[2..4].try_into().unwrap());
          let enabled_capabilities = CapabilityFlags::from_bits_retain(enabled_capabilities);
          Ok(Tlv::Capabilities(Capabilities {
            capabilities,
            enabled_capabilities,
          }))
        }
      },

      LLDP_TLV_MGMT_ADDR => {
        if raw.payload.is_empty() {
          return Err(TlvDecodeError::BufferTooShort);
        }

        let addr_str_length = raw.payload[0] as usize;

        if raw.payload.len() < 1 + addr_str_length {
          return Err(TlvDecodeError::BufferTooShort);
        }

        let addr_family = raw.payload[1];
        let addr_length = addr_str_length - 1;
        let addr_bytes: Vec<u8> = raw.payload[2..2 + addr_length].into();

        let address = match addr_family {
          LLDP_MGMT_ADDR_IP4 => Address::Ip(IpAddr::V4(Ipv4Addr::new(
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
          ))),
          LLDP_MGMT_ADDR_IP6 => {
            let arr: [u8; 16] = addr_bytes[0..16].try_into().unwrap();
            Address::Ip(IpAddr::V6(Ipv6Addr::from(arr)))
          }

          _ => Address::Other(addr_bytes),
        };

        dbg!(raw.payload.len());
        dbg!(addr_str_length);

        match raw.payload.len().cmp(&(1 + addr_str_length + 6)) {
          Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
          Ordering::Less => Err(TlvDecodeError::BufferTooShort),
          Ordering::Equal => {
            let interface_subtype = raw.payload[1 + addr_str_length];
            let interface_number = raw.payload[1 + addr_str_length + 1..1 + addr_str_length + 5]
              .try_into()
              .unwrap();
            Ok(Tlv::ManagementAddress(ManagementAddress {
              address,
              interface_subtype,
              interface_number: u32::from_be_bytes(interface_number),
            }))
          }
        }
      }

      x => Err(TlvDecodeError::UnknownTlv(x)),
    }
  }
}

#[derive(Debug, Clone)]
pub enum ChassisId {
  MacAddress(MacAddress),
}

impl ChassisId {
  fn decode(buf: &[u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0];
    match subtype {
      LLDP_CHASSISID_SUBTYPE_LLADDR => match buf.len().cmp(&7) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => {
          let mac = buf[1..7].try_into().unwrap();
          Ok(ChassisId::MacAddress(MacAddress(mac)))
        }
      },

      x => Err(TlvDecodeError::UnknownChassisIdSubtype(x)),
    }
  }
}

#[derive(Debug, Clone)]
pub enum PortId {
  MacAddress(MacAddress),
  InterfaceName(String),
}

impl PortId {
  fn decode(buf: &[u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0];
    match subtype {
      LLDP_PORTID_SUBTYPE_IFNAME => Ok(PortId::InterfaceName(String::from_utf8(buf[1..].into())?)),

      LLDP_PORTID_SUBTYPE_LLADDR => match buf.len().cmp(&7) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => {
          let mac = buf[1..7].try_into().unwrap();
          Ok(PortId::MacAddress(MacAddress(mac)))
        }
      },

      x => Err(TlvDecodeError::UnknownPortIdSubtype(x)),
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
  pub capabilities: CapabilityFlags,
  pub enabled_capabilities: CapabilityFlags,
}

bitflags! {
  #[repr(transparent)]
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct CapabilityFlags: u16 {
      const OTHER             = 0b00000001;
      const REPEATER          = 0b00000010;
      const BRIDGE            = 0b00000100;
      const WLAN_ACCESS_POINT = 0b00001000;
      const ROUTER            = 0b00010000;
      const TELEPHONE         = 0b00100000;
      const DOCSIS            = 0b01000000;
      const STATION           = 0b10000000;
  }
}

#[derive(Debug, Clone)]
pub struct ManagementAddress {
  pub address: Address,
  pub interface_subtype: u8,
  pub interface_number: u32,
}

#[derive(Debug, Clone)]
pub enum Address {
  Ip(IpAddr),
  Other(Vec<u8>),
}
