use std::{
  borrow::Cow,
  cmp::Ordering,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use super::TlvDecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkAddressKind {
  Ipv4,
  Ipv6,
  Unknown(u8),
}

impl From<u8> for NetworkAddressKind {
  fn from(value: u8) -> Self {
    match value {
      1 => Self::Ipv4,
      2 => Self::Ipv6,
      x => Self::Unknown(x),
    }
  }
}

impl From<NetworkAddressKind> for u8 {
  fn from(value: NetworkAddressKind) -> Self {
    match value {
      NetworkAddressKind::Ipv4 => 1,
      NetworkAddressKind::Ipv6 => 2,
      NetworkAddressKind::Unknown(x) => x,
    }
  }
}

#[derive(Debug, Clone)]
pub enum NetworkAddress<'a> {
  Ip(IpAddr),
  Other(u8, Cow<'a, [u8]>),
}

impl<'a> NetworkAddress<'a> {
  pub fn kind(&self) -> NetworkAddressKind {
    match self {
      Self::Ip(IpAddr::V4(_)) => NetworkAddressKind::Ipv4,
      Self::Ip(IpAddr::V6(_)) => NetworkAddressKind::Ipv6,
      Self::Other(kind, _) => NetworkAddressKind::Unknown(*kind),
    }
  }

  pub fn to_static(self) -> NetworkAddress<'static> {
    match self {
      Self::Ip(x) => NetworkAddress::Ip(x),
      Self::Other(x, y) => NetworkAddress::Other(x, Cow::Owned(y.into_owned())),
    }
  }

  pub(super) fn parse(buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0].into();
    let buf = &buf[1..];

    match subtype {
      NetworkAddressKind::Ipv4 => match buf.len().cmp(&4) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => Ok(NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(
          buf[0], buf[1], buf[2], buf[3],
        )))),
      },

      NetworkAddressKind::Ipv6 => match buf.len().cmp(&16) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => {
          let arr: [u8; 16] = buf[0..16].try_into().unwrap();
          Ok(NetworkAddress::Ip(IpAddr::V6(Ipv6Addr::from(arr))))
        }
      },

      NetworkAddressKind::Unknown(x) => Ok(NetworkAddress::Other(x, Cow::Borrowed(buf))),
    }
  }
}
