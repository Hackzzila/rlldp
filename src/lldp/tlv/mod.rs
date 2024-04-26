use std::{borrow::Cow, cmp::Ordering};

use thiserror::Error;
use tracing::warn;

mod chassis_id;
pub use chassis_id::*;

mod port_id;
pub use port_id::*;

mod system_capabilities;
pub use system_capabilities::*;

mod management_address;
pub use management_address::*;

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

const LLDP_TLV_DOT1_PVID: u8 = 1;
const LLDP_TLV_DOT1_PPVID: u8 = 2;
const LLDP_TLV_DOT1_VLANNAME: u8 = 3;
const LLDP_TLV_DOT1_PI: u8 = 4;

const LLDP_TLV_DOT3_MAC: u8 = 1;
const LLDP_TLV_DOT3_POWER: u8 = 2;
const LLDP_TLV_DOT3_LA: u8 = 3;
const LLDP_TLV_DOT3_MFS: u8 = 4;

const LLDP_TLV_ORG_DOT1: [u8; 3] = [0x00, 0x80, 0xc2];
const LLDP_TLV_ORG_DOT3: [u8; 3] = [0x00, 0x12, 0x0f];

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

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone)]
pub enum Tlv<'a> {
  End,
  ChassisId(ChassisId),
  PortId(PortId),
  TimeToLive(u16),
  PortDescription(Cow<'a, str>),
  SystemName(Cow<'a, str>),
  SystemDescription(Cow<'a, str>),
  Capabilities(Capabilities),
  ManagementAddress(ManagementAddress),
  Org(OrgTlv),
}

impl<'a> Tlv<'a> {
  pub fn into_static(self) -> Tlv<'static> {
    match self {
      Self::End => Tlv::End,
      Self::ChassisId(x) => Tlv::ChassisId(x),
      Self::PortId(x) => Tlv::PortId(x),
      Self::TimeToLive(x) => Tlv::TimeToLive(x),
      Self::PortDescription(x) => Tlv::PortDescription(Cow::Owned(x.into_owned())),
      Self::SystemName(x) => Tlv::SystemName(Cow::Owned(x.into_owned())),
      Self::SystemDescription(x) => Tlv::SystemDescription(Cow::Owned(x.into_owned())),
      Self::Capabilities(x) => Tlv::Capabilities(x),
      Self::ManagementAddress(x) => Tlv::ManagementAddress(x),
      Self::Org(x) => Tlv::Org(x),
    }
  }

  pub fn to_static(&self) -> Tlv<'static> {
    match self {
      Self::End => Tlv::End,
      Self::ChassisId(x) => Tlv::ChassisId(x.clone()),
      Self::PortId(x) => Tlv::PortId(x.clone()),
      Self::TimeToLive(x) => Tlv::TimeToLive(*x),
      Self::PortDescription(x) => Tlv::PortDescription(Cow::Owned(x.clone().into_owned())),
      Self::SystemName(x) => Tlv::SystemName(Cow::Owned(x.clone().into_owned())),
      Self::SystemDescription(x) => Tlv::SystemDescription(Cow::Owned(x.clone().into_owned())),
      Self::Capabilities(x) => Tlv::Capabilities(*x),
      Self::ManagementAddress(x) => Tlv::ManagementAddress(x.clone()),
      Self::Org(x) => Tlv::Org(x.clone()),
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

#[derive(Debug, Clone)]
pub enum OrgTlv {
  Ieee802Dot1(Ieee802Dot1Tlv),
  Ieee802Dot3(Ieee802Dot3Tlv),
}

#[derive(Debug, Clone)]
pub enum Ieee802Dot1Tlv {
  PortVlanId(u16),
}

#[derive(Debug, Clone)]
pub enum Ieee802Dot3Tlv {}

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
  #[error(transparent)]
  FromStringError(#[from] std::string::FromUtf8Error),
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

      TlvKind::Org => {
        if raw.payload.len() < 3 {
          return Err(TlvDecodeError::BufferTooShort);
        }

        match raw.payload[0..3].try_into().unwrap() {
          LLDP_TLV_ORG_DOT1 => {
            if raw.payload.len() < 4 {
              return Err(TlvDecodeError::BufferTooShort);
            }

            match raw.payload[3] {
              LLDP_TLV_DOT1_PVID => match raw.payload.len().cmp(&6) {
                Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
                Ordering::Less => Err(TlvDecodeError::BufferTooShort),
                Ordering::Equal => Ok(Tlv::Org(OrgTlv::Ieee802Dot1(Ieee802Dot1Tlv::PortVlanId(
                  u16::from_be_bytes(raw.payload[4..6].try_into().unwrap()),
                )))),
              },

              _ => Err(TlvDecodeError::UnknownTlv(255)),
            }
          }

          // LLDP_TLV_ORG_DOT3 => {
          //   todo!("dot3")
          // }
          _ => Err(TlvDecodeError::UnknownTlv(255)),
        }
      }
    }
  }
}
