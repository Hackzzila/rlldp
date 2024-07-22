use std::cmp::Ordering;

use bitflags::bitflags;

use super::TlvDecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capabilities {
  pub capabilities: CapabilityFlags,
  pub enabled_capabilities: CapabilityFlags,
}

bitflags! {
  #[repr(transparent)]
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct CapabilityFlags: u16 {
    const OTHER              = 0b00000001;
    const REPEATER           = 0b00000010;
    const BRIDGE             = 0b00000100;
    const WLAN_ACCESS_POINT  = 0b00001000;
    const ROUTER             = 0b00010000;
    const TELEPHONE          = 0b00100000;
    const DOCSIS             = 0b01000000;
    const STATION            = 0b10000000;
    const C_VLAN             = 0b00000001_00000000;
    const S_VLAN             = 0b00000010_00000000;
    const TWO_PORT_MAC_RELAY = 0b00000100_00000000;
  }
}

impl Capabilities {
  pub(super) fn decode(buf: &[u8]) -> Result<Self, TlvDecodeError> {
    match buf.len().cmp(&4) {
      Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
      Ordering::Less => Err(TlvDecodeError::BufferTooShort),
      Ordering::Equal => {
        let capabilities = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let capabilities = CapabilityFlags::from_bits_retain(capabilities);
        let enabled_capabilities = u16::from_be_bytes(buf[2..4].try_into().unwrap());
        let enabled_capabilities = CapabilityFlags::from_bits_retain(enabled_capabilities);
        Ok(Capabilities {
          capabilities,
          enabled_capabilities,
        })
      }
    }
  }

  pub(super) fn encoded_size(&self) -> usize {
    4
  }

  pub(super) fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend(self.capabilities.bits().to_be_bytes());
    buf.extend(self.enabled_capabilities.bits().to_be_bytes());
  }
}

#[test]
fn basic_encode_decode() {
  use super::Tlv;

  let capabilities = CapabilityFlags::OTHER | CapabilityFlags::TWO_PORT_MAC_RELAY;
  let enabled_capabilities = CapabilityFlags::REPEATER | CapabilityFlags::S_VLAN;
  super::test_encode_decode(Tlv::Capabilities(Capabilities {
    capabilities,
    enabled_capabilities,
  }))
}
