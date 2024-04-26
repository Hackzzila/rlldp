use std::{borrow::Cow, cmp::Ordering};

use thiserror::Error;
use tracing::warn;

mod address;
pub use address::*;

mod chassis_id;
pub use chassis_id::*;

mod port_id;
pub use port_id::*;

mod system_capabilities;
pub use system_capabilities::*;

mod management_address;
pub use management_address::*;

pub mod org;
pub use org::{CustomOrgTlv, OrgTlv};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlvKind {
  End,
  ChassisId,
  PortId,
  TimeToLive,
  PortDescription,
  SystemName,
  SystemDescription,
  Capabilities,
  ManagementAddress,
  Org,
}

impl TryFrom<u8> for TlvKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      0 => Ok(Self::End),
      1 => Ok(Self::ChassisId),
      2 => Ok(Self::PortId),
      3 => Ok(Self::TimeToLive),
      4 => Ok(Self::PortDescription),
      5 => Ok(Self::SystemName),
      6 => Ok(Self::SystemDescription),
      7 => Ok(Self::Capabilities),
      8 => Ok(Self::ManagementAddress),
      127 => Ok(Self::Org),
      x => Err(x),
    }
  }
}

impl From<TlvKind> for u8 {
  fn from(value: TlvKind) -> Self {
    match value {
      TlvKind::End => 0,
      TlvKind::ChassisId => 1,
      TlvKind::PortId => 2,
      TlvKind::TimeToLive => 3,
      TlvKind::PortDescription => 4,
      TlvKind::SystemName => 5,
      TlvKind::SystemDescription => 6,
      TlvKind::Capabilities => 7,
      TlvKind::ManagementAddress => 8,
      TlvKind::Org => 127,
    }
  }
}

pub fn decode_list(mut buf: &[u8]) -> Result<Vec<Tlv>, RawTlvError> {
  let mut out = Vec::new();

  while !buf.is_empty() {
    let raw = RawTlv::decode(buf)?;
    buf = &buf[raw.total_len()..];
    match Tlv::decode(raw) {
      Ok(tlv) => out.push(tlv),
      Err(err) => warn!(%err, "failed to decode tlv"),
    }
  }

  Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawTlv<'a> {
  pub ty: u8,
  pub payload: &'a [u8],
}

impl<'a> RawTlv<'a> {
  fn total_len(&self) -> usize {
    self.payload.len() + 2
  }

  fn decode(buf: &'a [u8]) -> Result<Self, RawTlvError> {
    if buf.len() < 2 {
      return Err(RawTlvError::BufferTooShort);
    }

    let payload_ty = buf[0] >> 1;
    let payload_len = (((buf[0] & 1) as usize) << 8) + buf[1] as usize;
    let tlv_len = payload_len + 2;

    if buf.len() < tlv_len {
      return Err(RawTlvError::BufferTooShort);
    }

    let payload = &buf[2..2 + payload_len];

    Ok(Self {
      ty: payload_ty,
      payload,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tlv<'a> {
  End,
  ChassisId(ChassisId<'a>),
  PortId(PortId<'a>),
  TimeToLive(u16),
  PortDescription(Cow<'a, str>),
  SystemName(Cow<'a, str>),
  SystemDescription(Cow<'a, str>),
  Capabilities(Capabilities),
  ManagementAddress(ManagementAddress<'a>),
  Org(OrgTlv<'a>),
}

impl<'a> Tlv<'a> {
  pub fn to_static(self) -> Tlv<'static> {
    match self {
      Self::End => Tlv::End,
      Self::ChassisId(x) => Tlv::ChassisId(x.to_static()),
      Self::PortId(x) => Tlv::PortId(x.to_static()),
      Self::TimeToLive(x) => Tlv::TimeToLive(x),
      Self::PortDescription(x) => Tlv::PortDescription(Cow::Owned(x.into_owned())),
      Self::SystemName(x) => Tlv::SystemName(Cow::Owned(x.into_owned())),
      Self::SystemDescription(x) => Tlv::SystemDescription(Cow::Owned(x.into_owned())),
      Self::Capabilities(x) => Tlv::Capabilities(x),
      Self::ManagementAddress(x) => Tlv::ManagementAddress(x.to_static()),
      Self::Org(x) => Tlv::Org(x.to_static()),
    }
  }

  pub fn kind(&self) -> TlvKind {
    match self {
      Self::End => TlvKind::End,
      Self::ChassisId(_) => TlvKind::ChassisId,
      Self::PortId(_) => TlvKind::PortId,
      Self::TimeToLive(_) => TlvKind::TimeToLive,
      Self::PortDescription(_) => TlvKind::PortDescription,
      Self::SystemName(_) => TlvKind::SystemName,
      Self::SystemDescription(_) => TlvKind::SystemDescription,
      Self::Capabilities(_) => TlvKind::Capabilities,
      Self::ManagementAddress(_) => TlvKind::ManagementAddress,
      Self::Org(_) => TlvKind::Org,
    }
  }
}

#[derive(Debug, Clone, Error)]
pub enum RawTlvError {
  #[error("buffer too short")]
  BufferTooShort,
}

#[derive(Debug, Clone, Error)]
pub enum TlvDecodeError {
  #[error("buffer too short")]
  BufferTooShort,
  #[error("buffer too long")]
  BufferTooLong,
  #[error("bytes after end")]
  BytesAfterEnd,
  #[error("unknown chassis id subtype '{0}'")]
  UnknownChassisIdSubtype(u8),
  #[error("unknown port id subtype '{0}'")]
  UnknownPortIdSubtype(u8),
  #[error("unknown management interface subtype '{0}'")]
  UnknownManagementInterfaceSubtype(u8),
  #[error("unknown tlv '{0}'")]
  UnknownTlv(u8),
}

impl<'a> Tlv<'a> {
  fn decode(raw: RawTlv<'a>) -> Result<Self, TlvDecodeError> {
    let kind = raw.ty.try_into().map_err(TlvDecodeError::UnknownTlv)?;
    match kind {
      TlvKind::End => {
        if raw.payload.len() > 2 {
          Err(TlvDecodeError::BytesAfterEnd)
        } else {
          Ok(Tlv::End)
        }
      }

      TlvKind::ChassisId => ChassisId::decode(raw.payload).map(Tlv::ChassisId),
      TlvKind::PortId => PortId::decode(raw.payload).map(Tlv::PortId),

      TlvKind::TimeToLive => match raw.payload.len().cmp(&2) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => Ok(Tlv::TimeToLive(u16::from_be_bytes(raw.payload.try_into().unwrap()))),
      },

      TlvKind::PortDescription => Ok(Tlv::PortDescription(String::from_utf8_lossy(raw.payload))),
      TlvKind::SystemName => Ok(Tlv::SystemName(String::from_utf8_lossy(raw.payload))),
      TlvKind::SystemDescription => Ok(Tlv::SystemDescription(String::from_utf8_lossy(raw.payload))),
      TlvKind::Capabilities => Capabilities::decode(raw.payload).map(Tlv::Capabilities),
      TlvKind::ManagementAddress => ManagementAddress::decode(raw.payload).map(Tlv::ManagementAddress),
      TlvKind::Org => OrgTlv::decode(raw.payload).map(Tlv::Org),
    }
  }

  pub fn encoded_size(&self) -> usize {
    match self {
      Self::ChassisId(x) => x.encoded_size(),
      Self::PortId(x) => x.encoded_size(),
      Self::TimeToLive(_) => 2,
      Self::PortDescription(x) | Self::SystemName(x) | Self::SystemDescription(x) => x.len(),
      Self::Capabilities(x) => x.encoded_size(),
      Self::ManagementAddress(x) => x.encoded_size(),
      Self::Org(x) => x.encoded_size(),
      Self::End => 0,
    }
  }

  pub fn encode(&self, buf: &mut Vec<u8>) {
    let ty: u8 = self.kind().into();
    let len = self.encoded_size();
    buf.reserve(len + 2);

    let ty = (ty as u16) << 9;
    let len = (len as u16) & 0b00000001_11111111;
    let hdr = ty + len;
    buf.extend(hdr.to_be_bytes());

    match self {
      Self::ChassisId(x) => x.encode(buf),
      Self::PortId(x) => x.encode(buf),
      Self::TimeToLive(x) => buf.extend(x.to_be_bytes()),
      Self::PortDescription(x) | Self::SystemName(x) | Self::SystemDescription(x) => buf.extend(x.as_bytes()),
      Self::Capabilities(x) => x.encode(buf),
      Self::ManagementAddress(x) => x.encode(buf),
      Self::Org(x) => x.encode(buf),
      Self::End => {}
    }
  }
}

#[cfg(test)]
fn test_encode_decode(tlv: Tlv) {
  let mut buf = Vec::new();
  tlv.encode(&mut buf);

  let raw_tlv = RawTlv::decode(&buf).unwrap();
  let parsed_tlv = Tlv::decode(raw_tlv).unwrap();
  assert_eq!(parsed_tlv, tlv);
}

#[test]
fn encode_decode_ttl() {
  test_encode_decode(Tlv::TimeToLive(1234));
}

#[test]
fn encode_decode_string_tlv() {
  let cow = Cow::Borrowed("foobarbaz");
  test_encode_decode(Tlv::PortDescription(cow.clone()));
  test_encode_decode(Tlv::SystemName(cow.clone()));
  test_encode_decode(Tlv::SystemDescription(cow.clone()));
}

#[test]
fn encode_decode_end_tlv() {
  test_encode_decode(Tlv::End);
}
