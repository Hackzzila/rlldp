use std::{
    collections::{hash_map::Entry, BTreeMap, BinaryHeap, HashMap},
    fmt::{Debug, Display},
    time::Instant,
};

use lldp_parser::{DataUnit, Protocol};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Default)]
pub struct Interface {
    neighbors: HashMap<(Protocol, MacAddress), Neighbor>,
    timers: BTreeMap<Instant, Timer>,
}

#[derive(Debug)]
pub struct Neighbor {
    first_detection_time: Instant,
    last_detection_time: Instant,
    du: DataUnit<'static>,
}

#[derive(Debug)]
pub enum Timer {
    Timeout {
        protocol: Protocol,
        source: MacAddress,
    },
}

impl Interface {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert_du(&mut self, source: MacAddress, du: DataUnit<'static>, now: Instant) {
        self.timers.insert(
            now,
            Timer::Timeout {
                source,
                protocol: du.protocol(),
            },
        );

        match self.neighbors.entry((du.protocol(), source)) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().last_detection_time = now;
                entry.get_mut().du = du;
            }

            Entry::Vacant(entry) => {
                entry.insert(Neighbor {
                    first_detection_time: now,
                    last_detection_time: now,
                    du,
                });
            }
        };
    }
}

// pub const LLDP_TYPE: u16 = 0x88CCu16.to_be();
//
// #[repr(C)]
// #[derive(Debug, Clone)]
// pub struct MacHeader {
//   pub destination_mac: MacAddress,
//   pub source_mac: MacAddress,
//   pub ether_type: u16,
// }
//
// pub struct Instance {
//   interfaces: HashMap<K, InterfaceInner>,
// }
//
// #[derive(Debug, Default)]
// struct InterfaceInner {
//   neighbors: HashMap<NeighborKey, Neighbor>,
// }
//
// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// struct NeighborKey {
//   protocol: Protocol,
//   source: MacAddress,
// }
//
// #[derive(Debug)]
// struct Neighbor {
//   first_detection_time: Instant,
//   last_detection_time: Instant,
//   du: DataUnit<'static>,
// }
//
// impl Instance
// where
//   K: Hash + Eq,
// {
//   pub fn insert_du(&self, interface: &K, source: MacAddress, du: DataUnit<'static>) {
//     let key = NeighborKey {
//       source,
//       protocol: du.protocol(),
//     };
//
//     let mut first_detection_time = Instant::now();
//     let last_detection_time = first_detection_time;
//
//     if let Some(entry) = inner.remove(&key) {
//       first_detection_time = entry.first_detection_time;
//       entry.timeout_handle.abort();
//       debug!(protocol = ?key.protocol, source = %key.source, "received update for existing neighbor");
//     } else {
//       info!(protocol = ?key.protocol, source = %key.source, "discovered new neighbor");
//     }
//
//     let ttl = du.time_to_live();
//     let interface = self.clone();
//     let key_clone = key.clone();
//     let span = span!(Level::DEBUG, "neighbor_timeout");
//     let timeout = tokio::task::spawn(
//       async move {
//         tokio::time::sleep(Duration::from_secs(ttl as _)).await;
//         info!(protocol = ?key_clone.protocol, source = %key_clone.source, "neighbor timed out");
//         interface.inner.neighbors.write().await.remove(&key_clone);
//       }
//       .instrument(span),
//     );
//
//     inner.insert(
//       key,
//       Neighbor {
//         first_detection_time,
//         last_detection_time,
//         timeout_handle: timeout.abort_handle(),
//         du,
//       },
//     );
//   }
// }
