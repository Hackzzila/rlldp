use crate::lldp::tlv::TlvDecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlvKind {
  Mac,
  Power,
  La,
  Mfs,
}

impl TryFrom<u8> for TlvKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::Mac),
      2 => Ok(Self::Power),
      3 => Ok(Self::La),
      4 => Ok(Self::Mfs),
      x => Err(x),
    }
  }
}

impl From<TlvKind> for u8 {
  fn from(value: TlvKind) -> Self {
    match value {
      TlvKind::Mac => 1,
      TlvKind::Power => 2,
      TlvKind::La => 3,
      TlvKind::Mfs => 4,
    }
  }
}

#[derive(Debug, Clone)]
pub enum Tlv {}

impl Tlv {
  pub fn kind(&self) -> TlvKind {
    todo!()
  }

  pub(super) fn decode(subtype: u8, buf: &[u8]) -> Result<Self, TlvDecodeError> {
    let kind: TlvKind = subtype.try_into().map_err(TlvDecodeError::UnknownTlv)?;
    match kind {
      x => Err(TlvDecodeError::UnknownTlv(x.into())),
    }
  }
}
