// TODO: Fix libpnet
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate pnet;
extern crate ra;
use clap::App;
use std::net::Ipv6Addr;
use std::str::FromStr;
use pnet::datalink::{self, MacAddr};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::Packet;

use ra::packet_builder::*;
use ra::packet_config::*;


fn main() {
    env_logger::init(); // logger setting

    // arg parse
    let yaml = load_yaml!("opt.yml");
    let app = App::from_yaml(yaml)
        .name(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!());

    let args = app.get_matches();

    let interface_name = args.value_of("INTERFACE").unwrap();
    let interface = get_interface(&interface_name);

    // TODO: extract function
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

    let ip_src = if let Some(sip) = args.value_of("src-ip") {
        Ipv6Addr::from_str(sip).unwrap()
    } else {
        // TODO: get interface's IP address
        Ipv6Addr::from_str("::1").unwrap()
    };
    let ip_dst = Ipv6Addr::from_str(args.value_of("DST-IP").unwrap()).unwrap();

    let rt_advt = set_router_advt(ip_src, ip_dst, &args);

    // create ipv6 packet, L3
    let ipv6 = build_ipv6_of_rt_advt(ip_src, ip_dst, rt_advt.packet());

    // L2 ether
    let ether = build_ether_packet(
        MacAddr::from_str("BB:BB:BB:BB:BB:BB").unwrap(),
        MacAddr::from_str("08:00:27:d1:fc:38").unwrap(),
        EtherType::new(0x86dd),
        ipv6.packet(),
    );

    tx.send_to(ether.packet(), Some(interface))
        .unwrap()
        .unwrap();
}
