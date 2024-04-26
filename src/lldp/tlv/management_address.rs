use std::cmp::Ordering;

use crate::lldp::tlv::NetworkAddress;

use super::TlvDecodeError;

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
pub struct ManagementAddress<'a> {
  pub address: NetworkAddress<'a>,
  pub interface_subtype: u8,
  pub interface_number: u32,
}

impl<'a> ManagementAddress<'a> {
  pub fn to_static(self) -> ManagementAddress<'static> {
    ManagementAddress {
      address: self.address.to_static(),
      interface_subtype: self.interface_subtype,
      interface_number: self.interface_number,
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

    let addr_length = addr_str_length - 1;
    let address = NetworkAddress::parse(&buf[1..2 + addr_length])?;

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
