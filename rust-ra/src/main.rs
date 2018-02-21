// TODO: Fix libpnet
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate pnet;
extern crate ra;
use getopts::Options;
use std::env;
use std::net::Ipv6Addr;
use std::str::FromStr;
use pnet::datalink::{self, MacAddr};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::Packet;
use pnet::packet::icmpv6::ndp;

use ra::packet_builder::*;

fn main() {
    env_logger::init();

    let interface_name = env::args().nth(1).unwrap(); // interface name
    let interface = get_interface(&interface_name);

    // Create a new channel, dealing with layer 2 packets
    let mut tx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => tx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            )
        }
    };

    // create router advert packet
    let mut ndp_opts = Vec::new();
    ndp_opts.push(build_ndpopt_mtu(64));
    ndp_opts.push(build_ndpopt_prefix(
        64,
        true,
        true,
        1800,
        3600,
        Ipv6Addr::from_str("2001:db8:1::1").unwrap(),
    ));
    ndp_opts.push(build_ndpopt_src_link_addr(
        MacAddr::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
    ));
    ndp_opts.push(build_ndpopt_rdnss(
        1800,
        vec![
            Ipv6Addr::from_str("2001:db8:3::1").unwrap(),
            Ipv6Addr::from_str("2001:db8:3::2").unwrap(),
        ],
    ));

    let ip_src = Ipv6Addr::from_str("2001:db8:10::1").unwrap();
    let ip_dst = Ipv6Addr::from_str("2001:db8:5::1").unwrap();

    let rt_advt = build_router_advert(
        64,
        ndp::RouterAdvertFlags::OtherConf,
        1800,
        1800,
        1800,
        ndp_opts,
        ip_src,
        ip_dst,
    );

    // create ipv6 packet, L3
    let ipv6 = build_ipv6_of_rt_advt(ip_src, ip_dst, rt_advt.packet());

    // L2 ether
    let ether = build_ether_packet(
        MacAddr::from_str("BB:BB:BB:BB:BB:BB").unwrap(),
        MacAddr::from_str("AA:AA:AA:AA:AA:AA").unwrap(),
        EtherType::new(0x86dd),
        ipv6.packet(),
    );

    tx.send_to(ether.packet(), Some(interface))
        .unwrap()
        .unwrap();
}
