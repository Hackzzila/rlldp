use std::{borrow::Cow, cmp::Ordering};

use crate::MacAddress;

use super::{NetworkAddress, TlvDecodeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChassisIdKind {
  Chassis,
  IfAlias,
  Port,
  LlAddr,
  Addr,
  IfName,
  Local,
}

impl TryFrom<u8> for ChassisIdKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::Chassis),
      2 => Ok(Self::IfAlias),
      3 => Ok(Self::Port),
      4 => Ok(Self::LlAddr),
      5 => Ok(Self::Addr),
      6 => Ok(Self::IfName),
      7 => Ok(Self::Local),
      x => Err(x),
    }
  }
}

impl From<ChassisIdKind> for u8 {
  fn from(value: ChassisIdKind) -> Self {
    match value {
      ChassisIdKind::Chassis => 1,
      ChassisIdKind::IfAlias => 2,
      ChassisIdKind::Port => 3,
      ChassisIdKind::LlAddr => 4,
      ChassisIdKind::Addr => 5,
      ChassisIdKind::IfName => 6,
      ChassisIdKind::Local => 7,
    }
  }
}

#[derive(Debug, Clone)]
pub enum ChassisId<'a> {
  Chassis(Cow<'a, str>),
  InterfaceAlias(Cow<'a, str>),
  PortComponent(Cow<'a, str>),
  MacAddress(MacAddress),
  NetworkAddress(NetworkAddress<'a>),
  InterfaceName(Cow<'a, str>),
  Local(Cow<'a, str>),
}

impl<'a> ChassisId<'a> {
  pub fn kind(&self) -> ChassisIdKind {
    match self {
      Self::Chassis(_) => ChassisIdKind::Chassis,
      Self::InterfaceAlias(_) => ChassisIdKind::IfAlias,
      Self::PortComponent(_) => ChassisIdKind::Port,
      Self::MacAddress(_) => ChassisIdKind::LlAddr,
      Self::NetworkAddress(_) => ChassisIdKind::Addr,
      Self::InterfaceName(_) => ChassisIdKind::IfName,
      Self::Local(_) => ChassisIdKind::Local,
    }
  }

  pub fn to_static(self) -> ChassisId<'static> {
    match self {
      Self::Chassis(x) => ChassisId::Chassis(Cow::Owned(x.into_owned())),
      Self::InterfaceAlias(x) => ChassisId::InterfaceAlias(Cow::Owned(x.into_owned())),
      Self::PortComponent(x) => ChassisId::PortComponent(Cow::Owned(x.into_owned())),
      Self::MacAddress(x) => ChassisId::MacAddress(x),
      Self::NetworkAddress(x) => ChassisId::NetworkAddress(x.to_static()),
      Self::InterfaceName(x) => ChassisId::InterfaceAlias(Cow::Owned(x.into_owned())),
      Self::Local(x) => ChassisId::Local(Cow::Owned(x.into_owned())),
    }
  }

  pub(super) fn decode(buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0].try_into().map_err(TlvDecodeError::UnknownChassisIdSubtype)?;
    let buf = &buf[1..];
    match subtype {
      ChassisIdKind::Chassis => Ok(ChassisId::Chassis(String::from_utf8_lossy(buf))),
      ChassisIdKind::IfAlias => Ok(ChassisId::InterfaceAlias(String::from_utf8_lossy(buf))),
      ChassisIdKind::Port => Ok(ChassisId::PortComponent(String::from_utf8_lossy(buf))),
      ChassisIdKind::IfName => Ok(ChassisId::InterfaceName(String::from_utf8_lossy(buf))),
      ChassisIdKind::Local => Ok(ChassisId::Local(String::from_utf8_lossy(buf))),

      ChassisIdKind::Addr => Ok(ChassisId::NetworkAddress(NetworkAddress::parse(buf)?)),

      ChassisIdKind::LlAddr => match buf.len().cmp(&6) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => {
          let mac = buf[0..6].try_into().unwrap();
          Ok(ChassisId::MacAddress(MacAddress(mac)))
        }
      },
    }
  }
}
