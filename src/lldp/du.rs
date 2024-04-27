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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
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

  pub fn encode(self, buf: &mut Vec<u8>) {
    let chassis_id = Tlv::ChassisId(self.chassis_id);
    let port_id = Tlv::PortId(self.port_id);
    let ttl = Tlv::TimeToLive(self.time_to_live);
    let port_description = self.port_description.map(Tlv::PortDescription);
    let system_name = self.system_name.map(Tlv::SystemName);
    let system_description = self.system_description.map(Tlv::SystemDescription);
    let capabilities = self.capabilities.map(Tlv::Capabilities);
    let management_address: Vec<_> = self
      .management_address
      .into_iter()
      .map(Tlv::ManagementAddress)
      .collect();

    let org_dot1_vlan_id = self
      .org
      .dot1
      .port_vlan_id
      .map(|x| Tlv::Org(OrgTlv::Dot1(dot1::Tlv::PortVlanId(x))));

    let org_dot1_vlan_name: Vec<_> = self
      .org
      .dot1
      .vlan_name
      .into_iter()
      .map(|(x, y)| Tlv::Org(OrgTlv::Dot1(dot1::Tlv::VlanName(x, y))))
      .collect();

    let org_dot3_phy = self
      .org
      .dot3
      .mac_phy_status
      .map(|x| Tlv::Org(OrgTlv::Dot3(dot3::Tlv::MacPhyStatus(x))));

    let total_size = chassis_id.encoded_size()
      + port_id.encoded_size()
      + ttl.encoded_size()
      + port_description.as_ref().map(|x| x.encoded_size()).unwrap_or_default()
      + system_description
        .as_ref()
        .map(|x| x.encoded_size())
        .unwrap_or_default()
      + system_name.as_ref().map(|x| x.encoded_size()).unwrap_or_default()
      + capabilities.as_ref().map(|x| x.encoded_size()).unwrap_or_default()
      + management_address.iter().fold(0, |acc, x| acc + x.encoded_size())
      + org_dot1_vlan_id.as_ref().map(|x| x.encoded_size()).unwrap_or_default()
      + org_dot1_vlan_name.iter().fold(0, |acc, x| acc + x.encoded_size())
      + org_dot3_phy.as_ref().map(|x| x.encoded_size()).unwrap_or_default();

    buf.reserve(total_size);

    chassis_id.encode(buf);
    port_id.encode(buf);
    ttl.encode(buf);

    if let Some(x) = port_description {
      x.encode(buf);
    }

    if let Some(x) = system_name {
      x.encode(buf);
    }

    if let Some(x) = system_description {
      x.encode(buf);
    }

    if let Some(x) = capabilities {
      x.encode(buf);
    }

    for x in management_address.into_iter() {
      x.encode(buf);
    }

    if let Some(x) = org_dot1_vlan_id {
      x.encode(buf);
    }

    for x in org_dot1_vlan_name {
      x.encode(buf);
    }

    if let Some(x) = org_dot3_phy {
      x.encode(buf);
    }
  }
}

#[cfg(test)]
fn test_encode_decode(du: DataUnit) {
  let mut buf = Vec::new();
  du.clone().encode(&mut buf);

  let parsed_du = DataUnit::decode(&buf).unwrap();
  assert_eq!(parsed_du, du);
}

#[test]
fn basic_encode_decode() {
  use std::net::{IpAddr, Ipv4Addr};

  use crate::lldp::tlv::{
    org::dot3::{AutoNegotiationCapability, AutoNegotiationStatus, MacPhyStatus, MauType},
    ManagementInterfaceKind, NetworkAddress,
  };

  test_encode_decode(DataUnit {
    chassis_id: ChassisId::Local("chassis".into()),
    port_id: PortId::Local("port".into()),
    time_to_live: 1234,
    port_description: Some("port_description".into()),
    system_name: Some("system_name".into()),
    system_description: Some("system_description".into()),
    capabilities: None,
    management_address: vec![
      ManagementAddress {
        address: NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        interface_subtype: ManagementInterfaceKind::IfIndex,
        interface_number: 123456,
        oid: "oid".into(),
      },
      ManagementAddress {
        address: NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))),
        interface_subtype: ManagementInterfaceKind::SysPort,
        interface_number: 567890,
        oid: "".into(),
      },
    ],
    org: Org {
      dot1: Dot1 {
        port_vlan_id: Some(1234),
        vlan_name: vec![(1234, "vlan1".into()), (5678, "vlan2".into())],
      },
      dot3: Dot3 {
        mac_phy_status: Some(MacPhyStatus {
          status: AutoNegotiationStatus::ENABLED,
          advertised: AutoNegotiationCapability::OTHER | AutoNegotiationCapability::B_1000_BASE_T_FD,
          mau: MauType::B1000BaseTFD,
        }),
      },
    },
  })
}
