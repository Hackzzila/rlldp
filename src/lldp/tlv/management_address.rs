use std::{borrow::Cow, cmp::Ordering};

use crate::lldp::tlv::NetworkAddress;

use super::TlvDecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManagementInterfaceKind {
  Unknown,
  IfIndex,
  SysPort,
}

impl TryFrom<u8> for ManagementInterfaceKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::Unknown),
      2 => Ok(Self::IfIndex),
      3 => Ok(Self::SysPort),
      x => Err(x),
    }
  }
}

impl From<ManagementInterfaceKind> for u8 {
  fn from(value: ManagementInterfaceKind) -> Self {
    match value {
      ManagementInterfaceKind::Unknown => 1,
      ManagementInterfaceKind::IfIndex => 2,
      ManagementInterfaceKind::SysPort => 3,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ManagementAddress<'a> {
  pub address: NetworkAddress<'a>,
  pub interface_subtype: ManagementInterfaceKind,
  pub interface_number: u32,
  pub oid: Cow<'a, str>,
}

impl<'a> ManagementAddress<'a> {
  pub fn to_static(self) -> ManagementAddress<'static> {
    ManagementAddress {
      address: self.address.to_static(),
      interface_subtype: self.interface_subtype,
      interface_number: self.interface_number,
      oid: Cow::Owned(self.oid.into_owned()),
    }
  }

  pub(super) fn decode(buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let addr_str_length = buf[0] as usize;

    if buf.len() < 1 + addr_str_length {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let address = NetworkAddress::decode(&buf[1..1 + addr_str_length])?;

    let buf = &buf[1 + addr_str_length..];

    if buf.len() < 6 {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let interface_subtype = buf[0]
      .try_into()
      .map_err(TlvDecodeError::UnknownManagementInterfaceSubtype)?;

    let interface_number = buf[1..5].try_into().unwrap();

    let oid_len = buf[5] as usize;
    let buf = &buf[6..];

    match buf.len().cmp(&oid_len) {
      Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
      Ordering::Less => Err(TlvDecodeError::BufferTooShort),
      Ordering::Equal => Ok(ManagementAddress {
        address,
        interface_subtype,
        interface_number: u32::from_be_bytes(interface_number),
        oid: String::from_utf8_lossy(buf),
      }),
    }
  }

  pub(super) fn encoded_size(&self) -> usize {
    self.address.encoded_size() + self.oid.len() + 7
  }

  pub(super) fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.address.encoded_size() as _);
    self.address.encode(buf);
    buf.push(self.interface_subtype.into());
    buf.extend(self.interface_number.to_be_bytes());
    buf.push(self.oid.len() as _);
    buf.extend(self.oid.as_bytes());
  }
}

#[test]
fn basic_encode_decode() {
  use super::Tlv;
  use std::net::{IpAddr, Ipv4Addr};

  super::test_encode_decode(Tlv::ManagementAddress(ManagementAddress {
    address: NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 4, 4))),
    interface_subtype: ManagementInterfaceKind::IfIndex,
    interface_number: 1234,
    oid: Cow::Borrowed("foobarbaz"),
  }));
}
