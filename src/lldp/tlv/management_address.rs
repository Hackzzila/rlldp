use std::{
  cmp::Ordering,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use super::TlvDecodeError;

pub enum ManagementAddressKind {
  Ipv4,
  Ipv6,
}

impl TryFrom<u8> for ManagementAddressKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::Ipv4),
      2 => Ok(Self::Ipv6),
      x => Err(x),
    }
  }
}

impl From<ManagementAddressKind> for u8 {
  fn from(value: ManagementAddressKind) -> Self {
    match value {
      ManagementAddressKind::Ipv4 => 1,
      ManagementAddressKind::Ipv6 => 2,
    }
  }
}

pub enum ManagementInterfaceKind {
  IfIndex,
  SysPort,
}

impl TryFrom<u8> for ManagementInterfaceKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      2 => Ok(Self::IfIndex),
      3 => Ok(Self::SysPort),
      x => Err(x),
    }
  }
}

impl From<ManagementInterfaceKind> for u8 {
  fn from(value: ManagementInterfaceKind) -> Self {
    match value {
      ManagementInterfaceKind::IfIndex => 2,
      ManagementInterfaceKind::SysPort => 3,
    }
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

impl ManagementAddress {
  pub(super) fn decode(buf: &[u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let addr_str_length = buf[0] as usize;

    if buf.len() < 1 + addr_str_length {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let addr_family = buf[1];
    let addr_length = addr_str_length - 1;
    let addr_bytes: Vec<u8> = buf[2..2 + addr_length].into();

    let address = match addr_family.try_into() {
      Ok(ManagementAddressKind::Ipv4) => Address::Ip(IpAddr::V4(Ipv4Addr::new(
        addr_bytes[0],
        addr_bytes[1],
        addr_bytes[2],
        addr_bytes[3],
      ))),

      Ok(ManagementAddressKind::Ipv6) => {
        let arr: [u8; 16] = addr_bytes[0..16].try_into().unwrap();
        Address::Ip(IpAddr::V6(Ipv6Addr::from(arr)))
      }

      Err(_) => Address::Other(addr_bytes),
    };

    dbg!(buf.len());
    dbg!(addr_str_length);

    match buf.len().cmp(&(1 + addr_str_length + 6)) {
      Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
      Ordering::Less => Err(TlvDecodeError::BufferTooShort),
      Ordering::Equal => {
        let interface_subtype = buf[1 + addr_str_length];
        let interface_number = buf[1 + addr_str_length + 1..1 + addr_str_length + 5]
          .try_into()
          .unwrap();
        Ok(ManagementAddress {
          address,
          interface_subtype,
          interface_number: u32::from_be_bytes(interface_number),
        })
      }
    }
  }
}
