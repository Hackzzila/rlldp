use std::{borrow::Cow, cmp::Ordering};

use crate::lldp::tlv::TlvDecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlvKind {
  PortVlanId,
  PortAndProtocolVlanId,
  VlanName,
  ProtocolIdentity,
}

impl TryFrom<u8> for TlvKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::PortVlanId),
      2 => Ok(Self::PortAndProtocolVlanId),
      3 => Ok(Self::VlanName),
      4 => Ok(Self::ProtocolIdentity),
      x => Err(x),
    }
  }
}

impl From<TlvKind> for u8 {
  fn from(value: TlvKind) -> Self {
    match value {
      TlvKind::PortVlanId => 1,
      TlvKind::PortAndProtocolVlanId => 2,
      TlvKind::VlanName => 3,
      TlvKind::ProtocolIdentity => 4,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tlv<'a> {
  PortVlanId(u16),
  VlanName(u16, Cow<'a, str>),
}

impl<'a> Tlv<'a> {
  pub fn kind(&self) -> TlvKind {
    match self {
      Self::PortVlanId(_) => TlvKind::PortVlanId,
      Self::VlanName(..) => TlvKind::VlanName,
    }
  }

  pub fn to_static(self) -> Tlv<'static> {
    match self {
      Self::PortVlanId(x) => Tlv::PortVlanId(x),
      Self::VlanName(x, y) => Tlv::VlanName(x, Cow::Owned(y.into_owned())),
    }
  }

  pub(super) fn decode(subtype: u8, buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    let kind = subtype.try_into().map_err(TlvDecodeError::UnknownTlv)?;
    match kind {
      TlvKind::PortVlanId => match buf.len().cmp(&2) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => Ok(Tlv::PortVlanId(u16::from_be_bytes(buf[0..2].try_into().unwrap()))),
      },

      TlvKind::VlanName => {
        if buf.len() < 3 {
          return Err(TlvDecodeError::BufferTooShort);
        }

        let vlan = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let name_len = buf[2] as usize;
        let buf = &buf[3..];

        match buf.len().cmp(&name_len) {
          Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
          Ordering::Less => Err(TlvDecodeError::BufferTooShort),
          Ordering::Equal => Ok(Tlv::VlanName(vlan, String::from_utf8_lossy(buf))),
        }
      }

      x => Err(TlvDecodeError::UnknownTlv(x.into())),
    }
  }

  pub(super) fn encoded_size(&self) -> usize {
    let size = match self {
      Self::PortVlanId(_) => 2,
      Self::VlanName(_, x) => 3 + x.len(),
    };
    size + 1
  }

  pub(super) fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.kind().into());
    match self {
      Self::PortVlanId(x) => buf.extend(x.to_be_bytes()),
      Self::VlanName(id, name) => {
        buf.extend(id.to_be_bytes());
        buf.push(name.len() as _);
        buf.extend(name.as_bytes());
      }
    }
  }
}

#[test]
fn test_encode_decode() {
  use crate::lldp::tlv::{org::OrgTlv, test_encode_decode, Tlv as BaseTlv};

  test_encode_decode(BaseTlv::Org(OrgTlv::Dot1(Tlv::PortVlanId(1234))));
  test_encode_decode(BaseTlv::Org(OrgTlv::Dot1(Tlv::VlanName(1234, "foobarbaz".into()))));
}
