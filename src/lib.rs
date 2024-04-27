use std::fmt::{Debug, Display};

pub mod cdp;
pub mod lldp;

#[derive(Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct MacAddress(pub [u8; 6]);

impl Display for MacAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
      self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
    )
  }
}

impl Debug for MacAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    Display::fmt(self, f)
  }
}

pub const LLDP_TYPE: u16 = 0x88CCu16.to_be();

#[repr(C)]
#[derive(Debug)]
pub struct MacHeader {
  pub destination_mac: MacAddress,
  pub source_mac: MacAddress,
  pub ether_type: u16,
}
