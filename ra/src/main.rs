extern crate getopts;
extern crate pnet;
use getopts::Options;
use std::env;
use pnet::datalink::{self, NetworkInterface, MacAddr};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::ndp;
use pnet::packet::icmpv6::ndp::{MutableRouterAdvertPacket, RouterAdvert};
use pnet::packet::icmpv6::ndp::NdpOption;

// MacAddr::from_str();
fn build_ndpopt_src_link_addr(link_addr: MacAddr) -> NdpOption {
    let MacAddr(a1, a2, a3, a4, a5, a6) = link_addr;
    let data = vec![a1, a2, a3, a4, a5, a6];

    NdpOption {
        option_type: ndp::NdpOptionTypes::SourceLLAddr,
        length: 0, // TODO: auto-complete or not?
        data: data,
    }
}

fn build_ndpopt_prefix() -> NdpOption {
    NdpOption {
        option_type: ndp::NdpOptionTypes::PrefixInformation,
        length: 0,
        data: Vec::new(),
    }
}

fn build_ndpopt_mtu() -> NdpOption {
    NdpOption {
        option_type: ndp::NdpOptionTypes::MTU,
        length: 0,
        data: Vec::new(),
    }
}

// research
fn build_ndpopt_rdnss() -> NdpOption {
    let rdnss = ndp::NdpOptionType::new(0x19);

    NdpOption {
        option_type: rdnss,
        length: 0,
        data: Vec::new(),
    }
}

fn main() {
    let interface_name = env::args().nth(1).unwrap(); // interface name
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx), // tx = sender, rx = receiver
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            )
        }
    };

    let mut buf = [0; 1024];
    let mut mut_router_advertisement = MutableRouterAdvertPacket::new(&mut buf).unwrap();
    let rt_advt = RouterAdvert {
        icmpv6_type: icmpv6::Icmpv6Types::RouterAdvert,
        icmpv6_code: icmpv6::Icmpv6Code(0),
        checksum: 0,
        hop_limit: 0,
        flags: 0,
        lifetime: 0,
        reachable_time: 0,
        retrans_time: 0,
        options: Vec::new(),
        payload: Vec::new(),
    };


    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                // Constructs a single packet, the same length as the the one received,
                // using the provided closure. This allows the packet to be constructed
                // directly in the write buffer, without copying. If copying is not a
                // problem, you could also use send_to.
                //
                // The packet is sent once the closure has finished executing.
                tx.build_and_send(1, packet.packet().len(), &mut |mut new_packet| {
                    let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                    // Create a clone of the original packet
                    new_packet.clone_from(&packet);

                    // Switch the source and destination
                    new_packet.set_source(packet.get_destination());
                    new_packet.set_destination(packet.get_source());
                });
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}