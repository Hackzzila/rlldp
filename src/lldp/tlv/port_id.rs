use std::{borrow::Cow, cmp::Ordering};

use crate::MacAddress;

use super::{NetworkAddress, TlvDecodeError};

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

#[derive(Debug, Clone)]
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

      PortIdKind::Addr => Ok(PortId::NetworkAddress(NetworkAddress::parse(buf)?)),

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
}
