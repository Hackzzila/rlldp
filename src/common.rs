use std::borrow::Cow;

use crate::cdp::DataUnit as CdpDu;
use crate::lldp::du::DataUnit as LLdpDu;
use crate::lldp::tlv::PortId;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataUnit<'a> {
  Cdp(CdpDu<'a>),
  Lldp(LLdpDu<'a>),
}

impl<'a> DataUnit<'a> {
  pub fn time_to_live(&self) -> u16 {
    match self {
      Self::Cdp(x) => x.time_to_live as _,
      Self::Lldp(x) => x.time_to_live,
    }
  }

  pub fn system_name(&self) -> Option<&Cow<'a, str>> {
    match self {
      Self::Cdp(x) => x.device_id.as_ref(),
      Self::Lldp(x) => x.system_name.as_ref(),
    }
  }

  pub fn port_vlan_id(&self) -> Option<u16> {
    match self {
      Self::Cdp(x) => x.native_vlan,
      Self::Lldp(x) => x.org.dot1.port_vlan_id,
    }
  }

  pub fn port_id(&self) -> Option<PortId> {
    match self {
      Self::Cdp(x) => {
        let port_id = x.port_id.clone()?;
        Some(PortId::InterfaceName(port_id))
      }
      Self::Lldp(x) => Some(x.port_id.clone()),
    }
  }
}

impl<'a> From<LLdpDu<'a>> for DataUnit<'a> {
  fn from(value: LLdpDu<'a>) -> Self {
    Self::Lldp(value)
  }
}

impl<'a> From<CdpDu<'a>> for DataUnit<'a> {
  fn from(value: CdpDu<'a>) -> Self {
    Self::Cdp(value)
  }
}
