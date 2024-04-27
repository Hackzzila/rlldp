use std::{borrow::Cow, cmp::Ordering};

use super::{NetworkAddress, TlvDecodeError};
use crate::MacAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortIdKind {
  IfAlias,
  Port,
  LlAddr,
  Addr,
  IfName,
  AgentCid,
  Local,
}

impl TryFrom<u8> for PortIdKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::IfAlias),
      2 => Ok(Self::Port),
      3 => Ok(Self::LlAddr),
      4 => Ok(Self::Addr),
      5 => Ok(Self::IfName),
      6 => Ok(Self::AgentCid),
      7 => Ok(Self::Local),
      x => Err(x),
    }
  }
}

impl From<PortIdKind> for u8 {
  fn from(value: PortIdKind) -> Self {
    match value {
      PortIdKind::IfAlias => 1,
      PortIdKind::Port => 2,
      PortIdKind::LlAddr => 3,
      PortIdKind::Addr => 4,
      PortIdKind::IfName => 5,
      PortIdKind::AgentCid => 6,
      PortIdKind::Local => 7,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortId<'a> {
  InterfaceAlias(Cow<'a, str>),
  PortComponent(Cow<'a, str>),
  MacAddress(MacAddress),
  NetworkAddress(NetworkAddress<'a>),
  InterfaceName(Cow<'a, str>),
  AgentCircuitId(Cow<'a, [u8]>),
  Local(Cow<'a, str>),
}

impl<'a> PortId<'a> {
  pub fn kind(&self) -> PortIdKind {
    match self {
      Self::InterfaceAlias(_) => PortIdKind::IfAlias,
      Self::PortComponent(_) => PortIdKind::Port,
      Self::MacAddress(_) => PortIdKind::LlAddr,
      Self::NetworkAddress(_) => PortIdKind::Addr,
      Self::InterfaceName(_) => PortIdKind::IfName,
      Self::AgentCircuitId(_) => PortIdKind::AgentCid,
      Self::Local(_) => PortIdKind::Local,
    }
  }

  pub fn to_static(self) -> PortId<'static> {
    match self {
      Self::InterfaceAlias(x) => PortId::InterfaceAlias(Cow::Owned(x.into_owned())),
      Self::PortComponent(x) => PortId::PortComponent(Cow::Owned(x.into_owned())),
      Self::MacAddress(x) => PortId::MacAddress(x),
      Self::NetworkAddress(x) => PortId::NetworkAddress(x.to_static()),
      Self::InterfaceName(x) => PortId::InterfaceName(Cow::Owned(x.into_owned())),
      Self::AgentCircuitId(x) => PortId::AgentCircuitId(Cow::Owned(x.into_owned())),
      Self::Local(x) => PortId::Local(Cow::Owned(x.into_owned())),
    }
  }

  pub(super) fn decode(buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0].try_into().map_err(TlvDecodeError::UnknownPortIdSubtype)?;
    let buf = &buf[1..];
    match subtype {
      PortIdKind::IfName => Ok(PortId::InterfaceName(String::from_utf8_lossy(buf))),
      PortIdKind::IfAlias => Ok(PortId::InterfaceAlias(String::from_utf8_lossy(buf))),
      PortIdKind::Port => Ok(PortId::PortComponent(String::from_utf8_lossy(buf))),
      PortIdKind::Local => Ok(PortId::Local(String::from_utf8_lossy(buf))),

      PortIdKind::AgentCid => Ok(PortId::AgentCircuitId(Cow::Borrowed(buf))),

      PortIdKind::Addr => Ok(PortId::NetworkAddress(NetworkAddress::decode(buf)?)),

      PortIdKind::LlAddr => match buf.len().cmp(&6) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => {
          let mac = buf[0..6].try_into().unwrap();
          Ok(PortId::MacAddress(MacAddress(mac)))
        }
      },
    }
  }

  pub(super) fn encoded_size(&self) -> usize {
    let size = match self {
      Self::InterfaceAlias(x) | Self::PortComponent(x) | Self::InterfaceName(x) | Self::Local(x) => x.len(),

      Self::MacAddress(_) => 6,
      Self::NetworkAddress(x) => x.encoded_size(),
      Self::AgentCircuitId(x) => x.len(),
    };
    size + 1
  }

  pub(super) fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.kind().into());

    match self {
      Self::InterfaceAlias(x) | Self::PortComponent(x) | Self::InterfaceName(x) | Self::Local(x) => {
        buf.extend(x.as_bytes())
      }

      Self::MacAddress(mac) => buf.extend(mac.0),
      Self::NetworkAddress(x) => x.encode(buf),
      Self::AgentCircuitId(x) => buf.extend(x.iter()),
    }
  }
}

#[test]
fn basic_encode_decode() {
  use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

  use super::Tlv;

  let cow = Cow::Borrowed("foobarbaz");

  super::test_encode_decode(Tlv::PortId(PortId::InterfaceAlias(cow.clone())));
  super::test_encode_decode(Tlv::PortId(PortId::InterfaceName(cow.clone())));
  super::test_encode_decode(Tlv::PortId(PortId::PortComponent(cow.clone())));
  super::test_encode_decode(Tlv::PortId(PortId::Local(cow.clone())));
  super::test_encode_decode(Tlv::PortId(PortId::MacAddress(MacAddress([12, 34, 56, 78, 90, 12]))));
  super::test_encode_decode(Tlv::PortId(PortId::AgentCircuitId(vec![1, 2, 3, 4].into())));

  super::test_encode_decode(Tlv::PortId(PortId::NetworkAddress(NetworkAddress::Ip(IpAddr::V4(
    Ipv4Addr::new(1, 2, 3, 4),
  )))));

  super::test_encode_decode(Tlv::PortId(PortId::NetworkAddress(NetworkAddress::Ip(IpAddr::V6(
    Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
  )))));

  super::test_encode_decode(Tlv::PortId(PortId::NetworkAddress(NetworkAddress::Other(
    44,
    vec![11, 22, 33, 44, 55].into(),
  ))));
}
