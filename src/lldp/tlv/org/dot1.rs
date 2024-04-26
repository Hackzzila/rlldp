use std::cmp::Ordering;

use crate::lldp::tlv::TlvDecodeError;

pub enum TlvKind {
  Pvid,
  Ppvid,
  VlanName,
  Pi,
}

impl TryFrom<u8> for TlvKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::Pvid),
      2 => Ok(Self::Ppvid),
      3 => Ok(Self::VlanName),
      4 => Ok(Self::Pi),
      x => Err(x),
    }
  }
}

impl From<TlvKind> for u8 {
  fn from(value: TlvKind) -> Self {
    match value {
      TlvKind::Pvid => 1,
      TlvKind::Ppvid => 2,
      TlvKind::VlanName => 3,
      TlvKind::Pi => 4,
    }
  }
}

#[derive(Debug, Clone)]
pub enum Tlv {
  PortVlanId(u16),
}

impl Tlv {
  pub fn kind(&self) -> TlvKind {
    match self {
      Self::PortVlanId(_) => TlvKind::Pvid,
    }
  }

  pub(super) fn decode(subtype: u8, buf: &[u8]) -> Result<Self, TlvDecodeError> {
    let kind = subtype.try_into().map_err(TlvDecodeError::UnknownTlv)?;
    match kind {
      TlvKind::Pvid => match buf.len().cmp(&2) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => Ok(Tlv::PortVlanId(u16::from_be_bytes(buf[0..2].try_into().unwrap()))),
      },

      x => Err(TlvDecodeError::UnknownTlv(x.into())),
    }
  }
}
