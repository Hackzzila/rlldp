use std::{borrow::Cow, cmp::Ordering};

use crate::MacAddress;

use super::TlvDecodeError;

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
  MacAddress(MacAddress),
  InterfaceName(Cow<'a, str>),
}

impl<'a> PortId<'a> {
  pub fn kind(&self) -> PortIdKind {
    match self {
      Self::MacAddress(_) => PortIdKind::LlAddr,
      Self::InterfaceName(_) => PortIdKind::IfName,
    }
  }

  pub fn to_static(self) -> PortId<'static> {
    match self {
      Self::MacAddress(x) => PortId::MacAddress(x),
      Self::InterfaceName(x) => PortId::InterfaceName(Cow::Owned(x.into_owned())),
    }
  }

  pub(super) fn decode(buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0].try_into().map_err(TlvDecodeError::UnknownPortIdSubtype)?;
    match subtype {
      PortIdKind::IfName => Ok(PortId::InterfaceName(String::from_utf8_lossy(buf[1..].into()))),

      PortIdKind::LlAddr => match buf.len().cmp(&7) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => {
          let mac = buf[1..7].try_into().unwrap();
          Ok(PortId::MacAddress(MacAddress(mac)))
        }
      },

      x => Err(TlvDecodeError::UnknownPortIdSubtype(x.into())),
    }
  }
}
