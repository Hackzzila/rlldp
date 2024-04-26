use std::error::Error;

use rawsocket::{bsd::sync::BpfSocket, rustix::net::Protocol, EthernetPacket, MacAddress};
use rlldp::{lldp::du::DataUnit, MacHeader, LLDP_TYPE};

const LLDP_MAC_1: MacAddress = MacAddress([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
const LLDP_MAC_2: MacAddress = MacAddress([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
const LLDP_MAC_3: MacAddress = MacAddress([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);

fn main() {
  tracing_subscriber::fmt::init();
  // let packet = include_bytes!("../lldp.1.raw");
  // let parsed: MacHeader = unsafe { std::ptr::read(packet.as_ptr() as *const _) };
  // println!("{parsed:#?}");

  // assert!(parsed.ether_type == LLDP_TYPE);

  const ETH_P_LLDP: u16 = 0x88CC;

  // let sock = RawSocket::open(Some(Protocol::from_raw(
  //   ((ETH_P_LLDP as u16).to_be() as u32).try_into().unwrap(),
  // )))
  // .unwrap();

  // sock.bind_to_interface("eth0").unwrap();
  // sock.set_multicast_membership("eth0", LLDP_MAC_1, true).unwrap();
  // sock.set_multicast_membership("eth0", LLDP_MAC_2, true).unwrap();
  // sock.set_multicast_membership("eth0", LLDP_MAC_3, true).unwrap();
  let sock = BpfSocket::open("en8", Some(1500)).unwrap();
  sock.set_immediate(true).unwrap();
  sock
    .set_read_filter(rawsocket::bpf_filter!(
      { 0x28, 0, 0, 0x0000000c },
      { 0x15, 0, 1, 0x000088cc },
      { 0x6, 0, 0, 0x00080000 },
      { 0x6, 0, 0, 0x00000000 },
    ))
    .unwrap();

  loop {
    let mut buf = [0; 1500];
    for packet in sock.read_iter(&mut buf).unwrap() {
      let eth = EthernetPacket::try_decode(packet.capture).unwrap();
      dbg!(DataUnit::decode(eth.payload));
    }
  }
}
