use std::borrow::Cow;

use thiserror::Error;
use tracing::warn;

use self::tlv::{Duplex, RawTlvError};
use crate::cdp::tlv::{RawTlv, Tlv};

pub mod tlv;

#[derive(Debug, Clone, Error)]
pub enum DataUnitError {
  #[error("buffer too short")]
  BufferTooShort,
  #[error("unknown cdp version '{0}'")]
  UnknownCdpVersion(u8),
  #[error("failed to decode tlv: '{0}'")]
  RawTlvError(#[from] RawTlvError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataUnit<'a> {
  pub time_to_live: u8,
  pub device_id: Option<Cow<'a, str>>,
  pub software_version: Option<Cow<'a, str>>,
  pub platform: Option<Cow<'a, str>>,
  pub port_id: Option<Cow<'a, str>>,
  pub duplex: Option<Duplex>,
  pub native_vlan: Option<u16>,
}

impl<'a> DataUnit<'a> {
  pub fn to_static(self) -> DataUnit<'static> {
    DataUnit {
      time_to_live: self.time_to_live,
      device_id: self.device_id.map(|x| Cow::Owned(x.into_owned())),
      software_version: self.software_version.map(|x| Cow::Owned(x.into_owned())),
      platform: self.platform.map(|x| Cow::Owned(x.into_owned())),
      port_id: self.port_id.map(|x| Cow::Owned(x.into_owned())),
      duplex: self.duplex,
      native_vlan: self.native_vlan,
    }
  }

  pub fn decode(buf: &'a [u8]) -> Result<Self, DataUnitError> {
    if buf.len() < 4 {
      return Err(DataUnitError::BufferTooShort);
    }

    let version = buf[0];
    if version != 2 {
      return Err(DataUnitError::UnknownCdpVersion(version));
    }

    let time_to_live = buf[1];

    let checksum: u16 = u16::from_be_bytes(buf[2..4].try_into().unwrap());

    let mut du = Self {
      time_to_live,
      device_id: None,
      software_version: None,
      platform: None,
      port_id: None,
      duplex: None,
      native_vlan: None,
    };

    let mut buf = &buf[4..];
    while !buf.is_empty() {
      let raw = RawTlv::decode(buf)?;
      buf = &buf[raw.total_len()..];
      match Tlv::decode(raw) {
        Ok(Tlv::DeviceId(new)) => {
          if let Some(old) = du.device_id.take() {
            warn!(?old, ?new, "duplicate device id");
          }
          du.device_id = Some(new);
        }

        Ok(Tlv::PortId(new)) => {
          if let Some(old) = du.port_id.take() {
            warn!(?old, ?new, "duplicate port id");
          }
          du.port_id = Some(new);
        }

        Ok(Tlv::Platform(new)) => {
          if let Some(old) = du.platform.take() {
            warn!(?old, ?new, "duplicate platform");
          }
          du.platform = Some(new);
        }

        Ok(Tlv::SoftwareVersion(new)) => {
          if let Some(old) = du.software_version.take() {
            warn!(?old, ?new, "duplicate software version");
          }
          du.software_version = Some(new);
        }

        Ok(Tlv::NativeVlan(new)) => {
          if let Some(old) = du.native_vlan.take() {
            warn!(?old, ?new, "duplicate native vlan");
          }
          du.native_vlan = Some(new);
        }

        Ok(Tlv::Duplex(new)) => {
          if let Some(old) = du.duplex.take() {
            warn!(?old, ?new, "duplicate duplex");
          }
          du.duplex = Some(new);
        }

        Err(err) => warn!(%err, "failed to decode tlv"),
      }
    }

    Ok(du)
  }
}
