use std::borrow::Cow;

use thiserror::Error;
use tracing::warn;

use super::tlv::{
  decode_list,
  org::{dot1, dot3},
  Capabilities, ChassisId, ManagementAddress, OrgTlv, PortId, RawTlvError, Tlv,
};

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
  pub org: Org<'a>,
}

#[derive(Debug, Clone, Default)]
pub struct Org<'a> {
  pub dot1: Dot1<'a>,
  pub dot3: Dot3,
}

impl<'a> Org<'a> {
  pub fn to_static(self) -> Org<'static> {
    Org {
      dot1: self.dot1.to_static(),
      dot3: self.dot3,
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct Dot1<'a> {
  pub port_vlan_id: Option<u16>,
  pub vlan_name: Vec<(u16, Cow<'a, str>)>,
}

impl<'a> Dot1<'a> {
  pub fn to_static(self) -> Dot1<'static> {
    Dot1 {
      port_vlan_id: self.port_vlan_id,
      vlan_name: self
        .vlan_name
        .into_iter()
        .map(|(x, y)| (x, Cow::Owned(y.into_owned())))
        .collect(),
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct Dot3 {
  pub mac_phy_status: Option<dot3::MacPhyStatus>,
}

impl<'a> DataUnit<'a> {
  pub fn to_static(self) -> DataUnit<'static> {
    DataUnit {
      chassis_id: self.chassis_id.to_static(),
      port_id: self.port_id.to_static(),
      time_to_live: self.time_to_live,
      port_description: self.port_description.map(|x| Cow::Owned(x.into_owned())),
      system_name: self.system_name.map(|x| Cow::Owned(x.into_owned())),
      system_description: self.system_description.map(|x| Cow::Owned(x.into_owned())),
      capabilities: self.capabilities,
      management_address: self
        .management_address
        .into_iter()
        .map(ManagementAddress::to_static)
        .collect(),
      org: self.org.to_static(),
    }
  }

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
    let mut org = Org::default();

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

        Tlv::Org(OrgTlv::Dot1(dot1::Tlv::PortVlanId(new))) => {
          if let Some(old) = org.dot1.port_vlan_id.take() {
            warn!(?old, ?new, "duplicate vlan id");
          }
          org.dot1.port_vlan_id = Some(new);
        }

        Tlv::Org(OrgTlv::Dot1(dot1::Tlv::VlanName(x, y))) => org.dot1.vlan_name.push((x, y)),

        Tlv::Org(OrgTlv::Dot3(dot3::Tlv::MacPhyStatus(new))) => {
          if let Some(old) = org.dot3.mac_phy_status.take() {
            warn!(?old, ?new, "duplicate mac/phy status");
          }
          org.dot3.mac_phy_status = Some(new);
        }

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
      org,
    })
  }
}
