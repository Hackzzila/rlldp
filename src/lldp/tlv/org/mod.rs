use std::borrow::Cow;

use super::TlvDecodeError;

pub mod dot1;
pub mod dot3;

pub const LLDP_TLV_ORG_DOT1: [u8; 3] = [0x00, 0x80, 0xc2];
pub const LLDP_TLV_ORG_DOT3: [u8; 3] = [0x00, 0x12, 0x0f];

#[derive(Debug, Clone)]
pub enum OrgTlv<'a> {
  Dot1(dot1::Tlv<'a>),
  Dot3(dot3::Tlv),
  Custom(CustomOrgTlv<'a>),
}

impl<'a> OrgTlv<'a> {
  pub fn to_static(self) -> OrgTlv<'static> {
    match self {
      Self::Dot1(x) => OrgTlv::Dot1(x.to_static()),
      Self::Dot3(x) => OrgTlv::Dot3(x),
      Self::Custom(x) => OrgTlv::Custom(x.to_static()),
    }
  }

  pub(super) fn decode(buf: &'a [u8]) -> Result<Self, TlvDecodeError> {
    if buf.len() < 4 {
      return Err(TlvDecodeError::BufferTooShort);
    }

    let org = buf[0..3].try_into().unwrap();
    let subtype = buf[3];

    match org {
      LLDP_TLV_ORG_DOT1 => dot1::Tlv::decode(subtype, &buf[4..]).map(OrgTlv::Dot1),
      LLDP_TLV_ORG_DOT3 => dot3::Tlv::decode(subtype, &buf[4..]).map(OrgTlv::Dot3),

      _ => Ok(OrgTlv::Custom(CustomOrgTlv {
        org,
        subtype,
        data: Cow::Borrowed(&buf[4..]),
      })),
    }
  }
}

#[derive(Debug, Clone)]
pub struct CustomOrgTlv<'a> {
  pub org: [u8; 3],
  pub subtype: u8,
  pub data: Cow<'a, [u8]>,
}

impl<'a> CustomOrgTlv<'a> {
  pub fn to_static(self) -> CustomOrgTlv<'static> {
    CustomOrgTlv {
      org: self.org,
      subtype: self.subtype,
      data: Cow::Owned(self.data.into_owned()),
    }
  }
}
