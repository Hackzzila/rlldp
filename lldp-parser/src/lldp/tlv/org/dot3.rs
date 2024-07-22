use std::{
  cmp::Ordering,
  fmt::{self, Debug},
};

use bitflags::bitflags;

use crate::lldp::tlv::TlvDecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlvKind {
  MacPhyStatus,
  Power,
  LinkAggregation,
  MaximumFrameSize,
}

impl TryFrom<u8> for TlvKind {
  type Error = u8;
  fn try_from(value: u8) -> Result<Self, u8> {
    match value {
      1 => Ok(Self::MacPhyStatus),
      2 => Ok(Self::Power),
      3 => Ok(Self::LinkAggregation),
      4 => Ok(Self::MaximumFrameSize),
      x => Err(x),
    }
  }
}

impl From<TlvKind> for u8 {
  fn from(value: TlvKind) -> Self {
    match value {
      TlvKind::MacPhyStatus => 1,
      TlvKind::Power => 2,
      TlvKind::LinkAggregation => 3,
      TlvKind::MaximumFrameSize => 4,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tlv {
  MacPhyStatus(MacPhyStatus),
}

impl Tlv {
  pub fn kind(&self) -> TlvKind {
    match self {
      Self::MacPhyStatus(_) => TlvKind::MacPhyStatus,
    }
  }

  pub(super) fn decode(subtype: u8, buf: &[u8]) -> Result<Self, TlvDecodeError> {
    let kind: TlvKind = subtype.try_into().map_err(TlvDecodeError::UnknownTlv)?;
    match kind {
      TlvKind::MacPhyStatus => match buf.len().cmp(&5) {
        Ordering::Greater => Err(TlvDecodeError::BufferTooLong),
        Ordering::Less => Err(TlvDecodeError::BufferTooShort),
        Ordering::Equal => {
          let status = AutoNegotiationStatus::from_bits_retain(buf[0]);
          let advertised =
            AutoNegotiationCapability::from_bits_retain(u16::from_le_bytes(buf[1..3].try_into().unwrap()));
          let mau = MauType::from(u16::from_be_bytes(buf[3..5].try_into().unwrap()));

          Ok(Tlv::MacPhyStatus(MacPhyStatus {
            status,
            advertised,
            mau,
          }))
        }
      },

      x => Err(TlvDecodeError::UnknownTlv(x.into())),
    }
  }

  pub(super) fn encoded_size(&self) -> usize {
    let size = match self {
      Self::MacPhyStatus(_) => 5,
    };
    size + 1
  }

  pub(super) fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.kind().into());
    match self {
      Self::MacPhyStatus(x) => {
        buf.push(x.status.bits());
        buf.extend(x.advertised.bits().to_le_bytes());
        let mau: u16 = x.mau.into();
        buf.extend(mau.to_be_bytes());
      }
    }
  }
}

#[test]
fn test_encode_decode() {
  use crate::lldp::tlv::{org::OrgTlv, test_encode_decode, Tlv as BaseTlv};

  test_encode_decode(BaseTlv::Org(OrgTlv::Dot3(Tlv::MacPhyStatus(MacPhyStatus {
    status: AutoNegotiationStatus::ENABLED,
    advertised: AutoNegotiationCapability::OTHER | AutoNegotiationCapability::B_1000_BASE_T_FD,
    mau: MauType::B1000BaseTFD,
  }))));
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MacPhyStatus {
  pub status: AutoNegotiationStatus,
  pub advertised: AutoNegotiationCapability,
  pub mau: MauType,
}

bitflags! {
  #[repr(transparent)]
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct AutoNegotiationStatus: u8 {
    const SUPPORTED = 0b00000001;
    const ENABLED   = 0b00000010;
  }
}

bitflags! {
  #[repr(transparent)]
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct AutoNegotiationCapability: u16 {
    const OTHER            = 0b00000001;
    const B_10_BASE_T      = 0b00000010;
    const B_10_BASE_T_FD   = 0b00000100;
    const B_100_BASE_T4    = 0b00001000;
    const B_100_BASE_TX    = 0b00010000;
    const B_100_BASE_TX_FD = 0b00100000;
    const B_100_BASE_T2    = 0b01000000;
    const B_100_BASE_T2_FD = 0b10000000;
    const FDX_PAUSE        = 0b00000001_00000000;
    const FDX_A_PAUSE      = 0b00000010_00000000;
    const FDX_S_PAUSE      = 0b00000100_00000000;
    const FDX_B_PAUSE      = 0b00001000_00000000;
    const B_1000_BASE_X    = 0b00010000_00000000;
    const B_1000_BASE_X_FD = 0b00100000_00000000;
    const B_1000_BASE_T    = 0b01000000_00000000;
    const B_1000_BASE_T_FD = 0b10000000_00000000;
  }
}

// https://datatracker.ietf.org/doc/html/rfc4836
// dot3MauType
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MauType {
  Aui = 1,
  B10Base5 = 2,
  Foirl = 3,
  B10Base2 = 4,
  B10BaseT = 5,
  B10BaseFP = 6,
  B10BaseFB = 7,
  B10BaseFL = 8,
  B10Broad36 = 9,
  B10BaseTHD = 10,
  B10BaseTFD = 11,
  B10BaseFLHD = 12,
  B10BaseFLFD = 13,
  B100BaseT4 = 14,
  B100BaseTXHD = 15,
  B100BaseTXFD = 16,
  B100BaseFXHD = 17,
  B100BaseFXFD = 18,
  B100BaseT2HD = 19,
  B100BaseT2FD = 20,
  B1000BaseXHD = 21,
  B1000BaseXFD = 22,
  B1000BaseLXHD = 23,
  B1000BaseLXFD = 24,
  B1000BaseSXHD = 25,
  B1000BaseSXFD = 26,
  B1000BaseCXHD = 27,
  B1000BaseCXFD = 28,
  B1000BaseTHD = 29,
  B1000BaseTFD = 30,
  B10GigBaseX = 31,
  B10GigBaseLX4 = 32,
  B10GigBaseR = 33,
  B10GigBaseER = 34,
  B10GigBaseLR = 35,
  B10GigBaseSR = 36,
  B10GigBaseW = 37,
  B10GigBaseEW = 38,
  B10GigBaseLW = 39,
  B10GigBaseSW = 40,
  B10GigBaseCX4 = 41,
  B2BaseTL = 42,
  B10PassTS = 43,
  B100BaseBX10D = 44,
  B100BaseBX10U = 45,
  B100BaseLX10 = 46,
  B1000BaseBX10D = 47,
  B1000BaseBX10U = 48,
  B1000BaseLX10 = 49,
  B1000BasePX10D = 50,
  B1000BasePX10U = 51,
  B1000BasePX20D = 52,
  B1000BasePX20U = 53,
  Unknown(u16),
}

impl From<u16> for MauType {
  fn from(value: u16) -> Self {
    match value {
      1 => Self::Aui,
      2 => Self::B10Base5,
      3 => Self::Foirl,
      4 => Self::B10Base2,
      5 => Self::B10BaseT,
      6 => Self::B10BaseFP,
      7 => Self::B10BaseFB,
      8 => Self::B10BaseFL,
      9 => Self::B10Broad36,
      10 => Self::B10BaseTHD,
      11 => Self::B10BaseTFD,
      12 => Self::B10BaseFLHD,
      13 => Self::B10BaseFLFD,
      14 => Self::B100BaseT4,
      15 => Self::B100BaseTXHD,
      16 => Self::B100BaseTXFD,
      17 => Self::B100BaseFXHD,
      18 => Self::B100BaseFXFD,
      19 => Self::B100BaseT2HD,
      20 => Self::B100BaseT2FD,
      21 => Self::B1000BaseXHD,
      22 => Self::B1000BaseXFD,
      23 => Self::B1000BaseLXHD,
      24 => Self::B1000BaseLXFD,
      25 => Self::B1000BaseSXHD,
      26 => Self::B1000BaseSXFD,
      27 => Self::B1000BaseCXHD,
      28 => Self::B1000BaseCXFD,
      29 => Self::B1000BaseTHD,
      30 => Self::B1000BaseTFD,
      31 => Self::B10GigBaseX,
      32 => Self::B10GigBaseLX4,
      33 => Self::B10GigBaseR,
      34 => Self::B10GigBaseER,
      35 => Self::B10GigBaseLR,
      36 => Self::B10GigBaseSR,
      37 => Self::B10GigBaseW,
      38 => Self::B10GigBaseEW,
      39 => Self::B10GigBaseLW,
      40 => Self::B10GigBaseSW,
      41 => Self::B10GigBaseCX4,
      42 => Self::B2BaseTL,
      43 => Self::B10PassTS,
      44 => Self::B100BaseBX10D,
      45 => Self::B100BaseBX10U,
      46 => Self::B100BaseLX10,
      47 => Self::B1000BaseBX10D,
      48 => Self::B1000BaseBX10U,
      49 => Self::B1000BaseLX10,
      50 => Self::B1000BasePX10D,
      51 => Self::B1000BasePX10U,
      52 => Self::B1000BasePX20D,
      53 => Self::B1000BasePX20U,
      x => Self::Unknown(x),
    }
  }
}

impl From<MauType> for u16 {
  fn from(value: MauType) -> Self {
    match value {
      MauType::Aui => 1,
      MauType::B10Base5 => 2,
      MauType::Foirl => 3,
      MauType::B10Base2 => 4,
      MauType::B10BaseT => 5,
      MauType::B10BaseFP => 6,
      MauType::B10BaseFB => 7,
      MauType::B10BaseFL => 9,
      MauType::B10Broad36 => 9,
      MauType::B10BaseTHD => 10,
      MauType::B10BaseTFD => 11,
      MauType::B10BaseFLHD => 12,
      MauType::B10BaseFLFD => 13,
      MauType::B100BaseT4 => 14,
      MauType::B100BaseTXHD => 15,
      MauType::B100BaseTXFD => 16,
      MauType::B100BaseFXHD => 17,
      MauType::B100BaseFXFD => 18,
      MauType::B100BaseT2HD => 19,
      MauType::B100BaseT2FD => 20,
      MauType::B1000BaseXHD => 21,
      MauType::B1000BaseXFD => 22,
      MauType::B1000BaseLXHD => 23,
      MauType::B1000BaseLXFD => 24,
      MauType::B1000BaseSXHD => 25,
      MauType::B1000BaseSXFD => 26,
      MauType::B1000BaseCXHD => 27,
      MauType::B1000BaseCXFD => 28,
      MauType::B1000BaseTHD => 29,
      MauType::B1000BaseTFD => 30,
      MauType::B10GigBaseX => 31,
      MauType::B10GigBaseLX4 => 32,
      MauType::B10GigBaseR => 33,
      MauType::B10GigBaseER => 34,
      MauType::B10GigBaseLR => 35,
      MauType::B10GigBaseSR => 36,
      MauType::B10GigBaseW => 37,
      MauType::B10GigBaseEW => 38,
      MauType::B10GigBaseLW => 39,
      MauType::B10GigBaseSW => 40,
      MauType::B10GigBaseCX4 => 41,
      MauType::B2BaseTL => 42,
      MauType::B10PassTS => 43,
      MauType::B100BaseBX10D => 44,
      MauType::B100BaseBX10U => 45,
      MauType::B100BaseLX10 => 46,
      MauType::B1000BaseBX10D => 47,
      MauType::B1000BaseBX10U => 48,
      MauType::B1000BaseLX10 => 49,
      MauType::B1000BasePX10D => 50,
      MauType::B1000BasePX10U => 51,
      MauType::B1000BasePX20D => 52,
      MauType::B1000BasePX20U => 53,
      MauType::Unknown(x) => x,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Duplex {
  Full,
  Half,
}

impl MauType {
  pub fn speed(&self) -> Option<u16> {
    match self {
      Self::Unknown(_) => None,
      Self::Aui
      | Self::Foirl
      | Self::B10Base5
      | Self::B10Base2
      | Self::B10BaseT
      | Self::B10BaseFP
      | Self::B10BaseFB
      | Self::B10BaseFL
      | Self::B10Broad36
      | Self::B10BaseTHD
      | Self::B10BaseTFD
      | Self::B10BaseFLHD
      | Self::B10BaseFLFD
      | Self::B10PassTS => Some(10),
      Self::B100BaseT4
      | Self::B100BaseTXHD
      | Self::B100BaseTXFD
      | Self::B100BaseFXHD
      | Self::B100BaseFXFD
      | Self::B100BaseT2HD
      | Self::B100BaseT2FD
      | Self::B100BaseBX10D
      | Self::B100BaseBX10U
      | Self::B100BaseLX10 => Some(100),
      Self::B1000BaseXHD
      | Self::B1000BaseXFD
      | Self::B1000BaseLXHD
      | Self::B1000BaseLXFD
      | Self::B1000BaseSXHD
      | Self::B1000BaseSXFD
      | Self::B1000BaseCXHD
      | Self::B1000BaseCXFD
      | Self::B1000BaseTHD
      | Self::B1000BaseTFD
      | Self::B1000BaseBX10D
      | Self::B1000BaseBX10U
      | Self::B1000BaseLX10
      | Self::B1000BasePX10D
      | Self::B1000BasePX10U
      | Self::B1000BasePX20D
      | Self::B1000BasePX20U => Some(1000),
      Self::B10GigBaseX
      | Self::B10GigBaseLX4
      | Self::B10GigBaseLR
      | Self::B10GigBaseSR
      | Self::B10GigBaseW
      | Self::B10GigBaseEW
      | Self::B10GigBaseLW
      | Self::B10GigBaseSW
      | Self::B10GigBaseCX4
      | Self::B10GigBaseR
      | Self::B10GigBaseER => Some(10000),
      Self::B2BaseTL => Some(2),
    }
  }

  pub fn duplex(&self) -> Option<Duplex> {
    match self {
      Self::Aui
      | Self::Foirl
      | Self::Unknown(_)
      | Self::B10Base5
      | Self::B10Base2
      | Self::B10BaseT
      | Self::B10BaseFP
      | Self::B10BaseFB
      | Self::B10BaseFL
      | Self::B10Broad36
      | Self::B1000BaseBX10D
      | Self::B1000BaseBX10U
      | Self::B1000BaseLX10
      | Self::B1000BasePX10D
      | Self::B1000BasePX10U
      | Self::B1000BasePX20D
      | Self::B1000BasePX20U
      | Self::B100BaseT4
      | Self::B2BaseTL
      | Self::B10PassTS
      | Self::B100BaseBX10D
      | Self::B100BaseBX10U
      | Self::B100BaseLX10 => None,
      Self::B10BaseTHD
      | Self::B10BaseFLHD
      | Self::B100BaseTXHD
      | Self::B100BaseFXHD
      | Self::B100BaseT2HD
      | Self::B1000BaseXHD
      | Self::B1000BaseLXHD
      | Self::B1000BaseSXHD
      | Self::B1000BaseCXHD
      | Self::B1000BaseTHD => Some(Duplex::Half),
      Self::B10BaseTFD
      | Self::B10BaseFLFD
      | Self::B100BaseTXFD
      | Self::B100BaseFXFD
      | Self::B100BaseT2FD
      | Self::B1000BaseXFD
      | Self::B1000BaseLXFD
      | Self::B1000BaseSXFD
      | Self::B1000BaseCXFD
      | Self::B1000BaseTFD
      | Self::B10GigBaseX
      | Self::B10GigBaseLX4
      | Self::B10GigBaseR
      | Self::B10GigBaseER
      | Self::B10GigBaseLR
      | Self::B10GigBaseSR
      | Self::B10GigBaseW
      | Self::B10GigBaseEW
      | Self::B10GigBaseLW
      | Self::B10GigBaseSW
      | Self::B10GigBaseCX4 => Some(Duplex::Full),
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      MauType::Aui => "Aui",
      MauType::B10Base5 => "B10Base5",
      MauType::Foirl => "Foirl",
      MauType::B10Base2 => "B10Base2",
      MauType::B10BaseT => "B10BaseT",
      MauType::B10BaseFP => "B10BaseFP",
      MauType::B10BaseFB => "B10BaseFB",
      MauType::B10BaseFL => "B10BaseFL",
      MauType::B10Broad36 => "B10Broad36",
      MauType::B10BaseTHD => "B10BaseTHD",
      MauType::B10BaseTFD => "B10BaseTFD",
      MauType::B10BaseFLHD => "B10BaseFLHD",
      MauType::B10BaseFLFD => "B10BaseFLFD",
      MauType::B100BaseT4 => "B100BaseT4",
      MauType::B100BaseTXHD => "B100BaseTXHD",
      MauType::B100BaseTXFD => "B100BaseTXFD",
      MauType::B100BaseFXHD => "B100BaseFXHD",
      MauType::B100BaseFXFD => "B100BaseFXFD",
      MauType::B100BaseT2HD => "B100BaseT2HD",
      MauType::B100BaseT2FD => "B100BaseT2FD",
      MauType::B1000BaseXHD => "B1000BaseXHD",
      MauType::B1000BaseXFD => "B1000BaseXFD",
      MauType::B1000BaseLXHD => "B1000BaseLXHD",
      MauType::B1000BaseLXFD => "B1000BaseLXFD",
      MauType::B1000BaseSXHD => "B1000BaseSXHD",
      MauType::B1000BaseSXFD => "B1000BaseSXFD",
      MauType::B1000BaseCXHD => "B1000BaseCXHD",
      MauType::B1000BaseCXFD => "B1000BaseCXFD",
      MauType::B1000BaseTHD => "B1000BaseTHD",
      MauType::B1000BaseTFD => "B1000BaseTFD",
      MauType::B10GigBaseX => "B10GigBaseX",
      MauType::B10GigBaseLX4 => "B10GigBaseLX4",
      MauType::B10GigBaseR => "B10GigBaseR",
      MauType::B10GigBaseER => "B10GigBaseER",
      MauType::B10GigBaseLR => "B10GigBaseLR",
      MauType::B10GigBaseSR => "B10GigBaseSR",
      MauType::B10GigBaseW => "B10GigBaseW",
      MauType::B10GigBaseEW => "B10GigBaseEW",
      MauType::B10GigBaseLW => "B10GigBaseLW",
      MauType::B10GigBaseSW => "B10GigBaseSW",
      MauType::B10GigBaseCX4 => "B10GigBaseCX4",
      MauType::B2BaseTL => "B2BaseTL",
      MauType::B10PassTS => "B10PassTS",
      MauType::B100BaseBX10D => "B100BaseBX10D",
      MauType::B100BaseBX10U => "B100BaseBX10U",
      MauType::B100BaseLX10 => "B100BaseLX10",
      MauType::B1000BaseBX10D => "B1000BaseBX10D",
      MauType::B1000BaseBX10U => "B1000BaseBX10U",
      MauType::B1000BaseLX10 => "B1000BaseLX10",
      MauType::B1000BasePX10D => "B1000BasePX10D",
      MauType::B1000BasePX10U => "B1000BasePX10U",
      MauType::B1000BasePX20D => "B1000BasePX20D",
      MauType::B1000BasePX20U => "B1000BasePX20U",
      MauType::Unknown(_) => "Unknown",
    }
  }
}

impl fmt::Debug for MauType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let name = format!("MauType::{}", self.as_str());
    f.debug_struct(&name)
      .field("speed", &self.speed())
      .field("duplex", &self.duplex())
      .finish()
  }
}
