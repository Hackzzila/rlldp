use std::{
  borrow::Cow,
  cmp::Ordering,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use super::TlvDecodeError;

pub enum AddressKind {
  Ipv4,
  Ipv6,
  Unknown(u8),
}

impl From<u8> for AddressKind {
  fn from(value: u8) -> Self {
    match value {
      1 => Self::Ipv4,
      2 => Self::Ipv6,
      x => Self::Unknown(x),
    }
  }
}

impl From<AddressKind> for u8 {
  fn from(value: AddressKind) -> Self {
    match value {
      AddressKind::Ipv4 => 1,
      AddressKind::Ipv6 => 2,
      AddressKind::Unknown(x) => x,
    }
  }
}

#[derive(Debug, Clone)]
pub enum Address<'a> {
  Ip(IpAddr),
  Other(u8, Cow<'a, [u8]>),
}

impl<'a> Address<'a> {
  pub fn kind(&self) -> AddressKind {
    match self {
      Self::Ip(IpAddr::V4(_)) => AddressKind::Ipv4,
      Self::Ip(IpAddr::V6(_)) => AddressKind::Ipv6,
      Self::Other(kind, _) => AddressKind::Unknown(*kind),
    }
  }

  pub fn to_static(self) -> Address<'static> {
    match self {
      Self::Ip(x) => Address::Ip(x),
      Self::Other(x, y) => Address::Other(x, Cow::Owned(y.into_owned())),
    }
  }

  pub(super) fn parse(buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0].into();
    let buf = &buf[1..];

    match subtype {
      AddressKind::Ipv4 => match buf.len().cmp(&4) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => Ok(Address::Ip(IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])))),
      },

      AddressKind::Ipv6 => match buf.len().cmp(&16) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => {
          let arr: [u8; 16] = buf[0..16].try_into().unwrap();
          Ok(Address::Ip(IpAddr::V6(Ipv6Addr::from(arr))))
        }
      },

      AddressKind::Unknown(x) => Ok(Address::Other(x, Cow::Borrowed(buf))),
    }
  }
}
