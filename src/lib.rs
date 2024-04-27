use std::{
  collections::HashMap,
  fmt::{Debug, Display},
  io,
  sync::Arc,
  time::{Duration, Instant, SystemTime},
};

use common::{DataUnit, Protocol};
use rawsocket::{bpf::bpf_program, bpf_filter, bsd::tokio::BpfSocket, EthernetPacket};
use tokio::{sync::RwLock, task::AbortHandle};
use tracing::{debug, info, instrument, span, warn, Instrument, Level};

pub mod cdp;
pub mod common;
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
#[derive(Debug, Clone)]
pub struct MacHeader {
  pub destination_mac: MacAddress,
  pub source_mac: MacAddress,
  pub ether_type: u16,
}

#[derive(Debug, Clone, Default)]
pub struct Interface {
  inner: Arc<InterfaceInner>,
}

#[derive(Debug, Default)]
struct InterfaceInner {
  neighbors: RwLock<HashMap<NeighborKey, Neighbor>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NeighborKey {
  protocol: Protocol,
  source: MacAddress,
}

#[derive(Debug)]
struct Neighbor {
  first_detection_time: Instant,
  last_detection_time: Instant,
  timeout_handle: AbortHandle,
  du: DataUnit<'static>,
}

impl Interface {
  pub async fn insert_du(&self, source: MacAddress, du: DataUnit<'static>) {
    let key = NeighborKey {
      source,
      protocol: du.protocol(),
    };

    let mut first_detection_time = Instant::now();
    let last_detection_time = first_detection_time;

    let mut inner = self.inner.neighbors.write().await;
    if let Some(entry) = inner.remove(&key) {
      first_detection_time = entry.first_detection_time;
      entry.timeout_handle.abort();
      debug!(protocol = ?key.protocol, source = %key.source, "received update for existing neighbor");
    } else {
      info!(protocol = ?key.protocol, source = %key.source, "discovered new neighbor");
    }

    let ttl = du.time_to_live();
    let interface = self.clone();
    let key_clone = key.clone();
    let span = span!(Level::DEBUG, "neighbor_timeout");
    let timeout = tokio::task::spawn(
      async move {
        tokio::time::sleep(Duration::from_secs(ttl as _)).await;
        info!(protocol = ?key_clone.protocol, source = %key_clone.source, "neighbor timed out");
        interface.inner.neighbors.write().await.remove(&key_clone);
      }
      .instrument(span),
    );

    inner.insert(
      key,
      Neighbor {
        first_detection_time,
        last_detection_time,
        timeout_handle: timeout.abort_handle(),
        du,
      },
    );
  }

  #[instrument(skip_all, fields(interface = intf))]
  pub async fn start_socket(&self, intf: &str, lldp: bool, cdp: bool) -> io::Result<()> {
    let filter = if cdp && lldp {
      bpf_filter!(
        { 0x20, 0, 0, 0x00000002 },
        { 0x15, 0, 2, 0x0ccccccc },
        { 0x28, 0, 0, 0x00000000 },
        { 0x15, 2, 0, 0x00000100 },
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 1, 0x000088cc },
        { 0x6, 0, 0, 0x00080000 },
        { 0x6, 0, 0, 0x00000000 },
      )
    } else if cdp {
      bpf_filter!(
        { 0x20, 0, 0, 0x00000002 },
        { 0x15, 0, 3, 0x0ccccccc },
        { 0x28, 0, 0, 0x00000000 },
        { 0x15, 0, 1, 0x00000100 },
        { 0x6, 0, 0, 0x00080000 },
        { 0x6, 0, 0, 0x00000000 },
      )
    } else if lldp {
      bpf_filter!(
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 1, 0x000088cc },
        { 0x6, 0, 0, 0x00080000 },
        { 0x6, 0, 0, 0x00000000 },
      )
    } else {
      return Ok(());
    };

    let mut buf = [0; 1500];
    let sock = BpfSocket::open(intf, Some(buf.len() as _))?;
    sock.set_immediate(true)?;
    sock.set_read_filter(filter)?;

    loop {
      for packet in sock.read_iter(&mut buf).await.unwrap() {
        let eth = EthernetPacket::try_decode(packet.capture).unwrap();
        let du: DataUnit = if eth.header.ether_type == 0xcc88 {
          match lldp::du::DataUnit::decode(eth.payload) {
            Ok(x) => x.into(),
            Err(err) => {
              warn!(%err, "failed to decode lldp du");
              continue;
            }
          }
        } else if eth.header.ether_type == 49665 {
          match cdp::DataUnit::decode(&eth.payload[8..]) {
            Ok(x) => x.into(),
            Err(err) => {
              warn!(%err, "failed to decode cdp du");
              continue;
            }
          }
        } else {
          continue;
        };

        self
          .insert_du(MacAddress(eth.header.source_mac.0), du.to_static())
          .await;
      }
    }
  }
}
