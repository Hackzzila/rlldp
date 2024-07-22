use std::{borrow::Cow, cmp::Ordering};

use thiserror::Error;

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
  #[error("unknown tlv '{0}'")]
  UnknownTlv(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlvKind {
  DeviceId,
  PortId,
  SoftwareVersion,
  Platform,
  NativeVlan,
  Duplex,
}

impl TryFrom<u16> for TlvKind {
  type Error = u16;
  fn try_from(value: u16) -> Result<Self, u16> {
    match value {
      0x0001 => Ok(Self::DeviceId),
      0x0003 => Ok(Self::PortId),
      0x0005 => Ok(Self::SoftwareVersion),
      0x0006 => Ok(Self::Platform),
      0x000a => Ok(Self::NativeVlan),
      0x000b => Ok(Self::Duplex),
      x => Err(x),
    }
  }
}

impl From<TlvKind> for u16 {
  fn from(value: TlvKind) -> Self {
    match value {
      TlvKind::DeviceId => 0x0001,
      TlvKind::PortId => 0x0003,
      TlvKind::SoftwareVersion => 0x0005,
      TlvKind::Platform => 0x0006,
      TlvKind::NativeVlan => 0x000a,
      TlvKind::Duplex => 0x000b,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawTlv<'a> {
  pub ty: u16,
  pub payload: &'a [u8],
}

impl<'a> RawTlv<'a> {
  pub(super) fn total_len(&self) -> usize {
    self.payload.len() + 4
  }

  pub(super) fn decode(buf: &'a [u8]) -> Result<Self, RawTlvError> {
    if buf.len() < 4 {
      return Err(RawTlvError::BufferTooShort);
    }

    let ty = u16::from_be_bytes(buf[0..2].try_into().unwrap());
    let len = u16::from_be_bytes(buf[2..4].try_into().unwrap());
    let len = (len as usize) - 4;

    if buf.len() < len {
      return Err(RawTlvError::BufferTooShort);
    }

    let payload = &buf[4..4 + len];

    Ok(Self { ty, payload })
  }
}

#[derive(Debug, Clone)]
pub enum Tlv<'a> {
  DeviceId(Cow<'a, str>),
  PortId(Cow<'a, str>),
  SoftwareVersion(Cow<'a, str>),
  Platform(Cow<'a, str>),
  NativeVlan(u16),
  Duplex(Duplex),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Duplex {
  Half,
  Full,
}

impl<'a> Tlv<'a> {
  pub(super) fn decode(raw: RawTlv<'a>) -> Result<Self, TlvDecodeError> {
    let kind = raw.ty.try_into().map_err(TlvDecodeError::UnknownTlv)?;
    match kind {
      TlvKind::DeviceId => Ok(Self::DeviceId(String::from_utf8_lossy(raw.payload))),
      TlvKind::PortId => Ok(Self::PortId(String::from_utf8_lossy(raw.payload))),
      TlvKind::SoftwareVersion => Ok(Self::SoftwareVersion(String::from_utf8_lossy(raw.payload))),
      TlvKind::Platform => Ok(Self::Platform(String::from_utf8_lossy(raw.payload))),
      TlvKind::NativeVlan => match raw.payload.len().cmp(&2) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => Ok(Self::NativeVlan(u16::from_be_bytes(raw.payload.try_into().unwrap()))),
      },
      TlvKind::Duplex => match raw.payload.len().cmp(&1) {
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Equal => {
          if raw.payload[0] == 0 {
            Ok(Self::Duplex(Duplex::Half))
          } else {
            Ok(Self::Duplex(Duplex::Full))
          }
        }
      },
    }
  }
}
