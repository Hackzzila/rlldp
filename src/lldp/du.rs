use thiserror::Error;

use crate::lldp::tlv::{
  TlvList, LLDP_TLV_CHASSIS_ID, LLDP_TLV_PORT_DESCR, LLDP_TLV_PORT_ID, LLDP_TLV_SYSTEM_DESCR, LLDP_TLV_SYSTEM_NAME,
  LLDP_TLV_TTL,
};

use super::tlv::{
  Capabilities, ChassisId, ManagementAddress, PortId, RawTlvError, Tlv, TlvDecodeError, LLDP_TLV_SYSTEM_CAP,
};

#[derive(Debug, Clone, Error)]
pub enum DataUnitError {
  #[error("missing chassis id")]
  MissingChassisId,
  #[error("missing port id")]
  MissingPortId,
  #[error("missing time to live")]
  MissingTimeToLive,
  #[error("duplicate TLV")]
  DuplicateTlv(u8),
}

#[derive(Debug, Clone)]
pub struct DataUnit {
  pub chassis_id: ChassisId,
  pub port_id: PortId,
  pub time_to_live: u16,
  pub port_description: Option<String>,
  pub system_name: Option<String>,
  pub system_description: Option<String>,
  pub capabilities: Option<Capabilities>,
  pub management_address: Vec<ManagementAddress>,
}

impl DataUnit {
  pub fn decode(buf: &[u8]) -> (Result<Self, DataUnitError>, Vec<TlvDecodeError>, Option<RawTlvError>) {
    let list = TlvList::decode(buf);
    (Self::decode_inner(list.tlvs), list.errors, list.critical_error)
  }

  fn decode_inner(tlvs: Vec<Tlv>) -> Result<Self, DataUnitError> {
    let mut chassis_id = None;
    let mut port_id = None;
    let mut time_to_live = None;
    let mut port_description = None;
    let mut system_name = None;
    let mut system_description = None;
    let mut capabilities = None;
    let mut management_address = Vec::new();

    for tlv in tlvs {
      match tlv {
        Tlv::End => {}

        Tlv::ChassisId(x) => {
          if chassis_id.replace(x).is_some() {
            return Err(DataUnitError::DuplicateTlv(LLDP_TLV_CHASSIS_ID));
          }
        }

        Tlv::PortId(x) => {
          if port_id.replace(x).is_some() {
            return Err(DataUnitError::DuplicateTlv(LLDP_TLV_PORT_ID));
          }
        }

        Tlv::TimeToLive(x) => {
          if time_to_live.replace(x).is_some() {
            return Err(DataUnitError::DuplicateTlv(LLDP_TLV_TTL));
          }
        }

        Tlv::PortDescription(x) => {
          if port_description.replace(x).is_some() {
            return Err(DataUnitError::DuplicateTlv(LLDP_TLV_PORT_DESCR));
          }
        }

        Tlv::SystemName(x) => {
          if system_name.replace(x).is_some() {
            return Err(DataUnitError::DuplicateTlv(LLDP_TLV_SYSTEM_NAME));
          }
        }

        Tlv::SystemDescription(x) => {
          if system_description.replace(x).is_some() {
            return Err(DataUnitError::DuplicateTlv(LLDP_TLV_SYSTEM_DESCR));
          }
        }

        Tlv::Capabilities(x) => {
          if capabilities.replace(x).is_some() {
            return Err(DataUnitError::DuplicateTlv(LLDP_TLV_SYSTEM_CAP));
          }
        }

        Tlv::ManagementAddress(x) => management_address.push(x),
      }
    }

    Ok(Self {
      chassis_id: chassis_id.ok_or(DataUnitError::MissingChassisId)?,
      port_id: port_id.ok_or(DataUnitError::MissingPortId)?,
      time_to_live: time_to_live.ok_or(DataUnitError::MissingTimeToLive)?,
      port_description,
      system_name,
      system_description,
      capabilities,
      management_address,
    })
  }
}
