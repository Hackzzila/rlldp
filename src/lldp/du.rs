use std::borrow::Cow;

use thiserror::Error;
use tracing::warn;

use super::tlv::{decode_list, Capabilities, ChassisId, ManagementAddress, PortId, RawTlvError, Tlv};

#[derive(Debug, Clone, Error)]
pub enum DataUnitError {
  #[error("missing chassis id")]
  MissingChassisId,
  #[error("missing port id")]
  MissingPortId,
  #[error("missing time to live")]
  MissingTimeToLive,
  #[error("failed to decode tlv: '{0}'")]
  RawTlvError(#[from] RawTlvError),
}

#[derive(Debug, Clone)]
pub struct DataUnit<'a> {
  pub chassis_id: ChassisId<'a>,
  pub port_id: PortId<'a>,
  pub time_to_live: u16,
  pub port_description: Option<Cow<'a, str>>,
  pub system_name: Option<Cow<'a, str>>,
  pub system_description: Option<Cow<'a, str>>,
  pub capabilities: Option<Capabilities>,
  pub management_address: Vec<ManagementAddress<'a>>,
}

#[derive(Debug, Clone, Default)]
pub struct DataUnitOrg {
  pub ieee802_1: DataUnitIeee802Dot1,
}

#[derive(Debug, Clone, Default)]
pub struct DataUnitIeee802Dot1 {
  pub port_vlan_id: Option<u16>,
}

impl<'a> DataUnit<'a> {
  pub fn decode(buf: &'a [u8]) -> Result<Self, DataUnitError> {
    let list = decode_list(buf)?;

    let mut chassis_id = None;
    let mut port_id = None;
    let mut time_to_live = None;
    let mut port_description = None;
    let mut system_name = None;
    let mut system_description = None;
    let mut capabilities = None;
    let mut management_address = Vec::new();
    // let mut ieee802_1_port_vlan_id = None;

    for tlv in list {
      match tlv {
        Tlv::End => {}

        Tlv::ChassisId(new) => {
          if let Some(old) = chassis_id.take() {
            warn!(?old, ?new, "duplicate chassis id");
          }
          chassis_id = Some(new);
        }

        Tlv::PortId(new) => {
          if let Some(old) = port_id.take() {
            warn!(?old, ?new, "duplicate port id");
          }
          port_id = Some(new);
        }

        Tlv::TimeToLive(new) => {
          if let Some(old) = time_to_live.take() {
            warn!(?old, ?new, "duplicate time to live");
          }
          time_to_live = Some(new);
        }

        Tlv::PortDescription(new) => {
          if let Some(old) = port_description.take() {
            warn!(?old, ?new, "duplicate port description");
          }
          port_description = Some(new);
        }

        Tlv::SystemName(new) => {
          if let Some(old) = system_name.take() {
            warn!(?old, ?new, "duplicate system name");
          }
          system_name = Some(new);
        }

        Tlv::SystemDescription(new) => {
          if let Some(old) = system_description.take() {
            warn!(?old, ?new, "duplicate system description");
          }
          system_description = Some(new);
        }

        Tlv::Capabilities(new) => {
          if let Some(old) = capabilities.take() {
            warn!(?old, ?new, "duplicate system capabilities");
          }
          capabilities = Some(new);
        }

        Tlv::ManagementAddress(x) => management_address.push(x),

        // Tlv::Org(OrgTlv::Ieee802Dot1(Ieee802Dot1Tlv::PortVlanId(new))) => {
        //   if let Some(old) = ieee802_1_port_vlan_id.take() {
        //     ieee802_1_port_vlan_id =
        //       Some(cx.handle_duplicate_tlv(old, Tlv::Org(OrgTlv::Ieee802Dot1(Ieee802Dot1Tlv::PortVlanId(new))))?);
        //   } else {
        //     ieee802_1_port_vlan_id = Some(Tlv::Org(OrgTlv::Ieee802Dot1(Ieee802Dot1Tlv::PortVlanId(new))));
        //   }
        // }
        _ => {}
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
