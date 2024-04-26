use std::cmp::Ordering;

use crate::MacAddress;

use super::TlvDecodeError;

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
pub enum ChassisId {
  MacAddress(MacAddress),
}

impl ChassisId {
  pub fn kind(&self) -> ChassisIdKind {
    match self {
      Self::MacAddress(_) => ChassisIdKind::LlAddr,
    }
  }

  pub(super) fn decode(buf: &[u8]) -> Result<Self, TlvDecodeError> {
    if buf.is_empty() {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let subtype = buf[0].try_into().map_err(TlvDecodeError::UnknownChassisIdSubtype)?;
    match subtype {
      ChassisIdKind::LlAddr => match buf.len().cmp(&7) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => {
          let mac = buf[1..7].try_into().unwrap();
          Ok(ChassisId::MacAddress(MacAddress(mac)))
        }
      },

      x => Err(TlvDecodeError::UnknownChassisIdSubtype(x.into())),
    }
  }
}
