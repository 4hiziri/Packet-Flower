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
use std::net::IpAddr;
use pnet::datalink::MacAddr;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::Packet;

use ra::packet_builder::*;
use ra::packet_config::*;
use ra::packet_sender::*;


fn main() {
    env_logger::init();

    let yaml = load_yaml!("opt.yml");
    let app = App::from_yaml(yaml)
        .name(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!());

    let args = app.get_matches();

    let interface_name = args.value_of("INTERFACE").unwrap();
    let interface = get_interface(&interface_name);

    // Create a new channel, dealing with layer 2 packets
    let mut tx = match get_connection(&interface) {
        Ethernet(tx, _) => tx,
        _ => panic!("get_connection: failed to get connection"),
    };

    // can get Ipv4/6 address and netmask info
    // which one use?
    debug!("{:?}", interface.ips);
    debug!("{:?}", interface.ips[1]);
    let ips = interface.ips.clone();
    let ips: Vec<Ipv6Addr> = ips.iter()
        .map(|ip| ip.ip())
        .filter(|ip| ip.is_ipv6())
        .map(|ipv6| match ipv6 {
            IpAddr::V6(addr) => addr,
            _ => panic!("can't get ipv6 address: {:?}", ipv6),
        })
        .collect();

    let ipv6: Ipv6Addr = ips[0];
    debug!("{:?}", ipv6);
    debug!("{:?}", ips);

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

    // TODO: can get mac addr via interface
    let src_mac = if args.is_present("src-mac") {
        MacAddr::from_str(args.value_of("src-mac").unwrap()).unwrap()
    } else {
        interface.mac_address()
    };

    // L2 ether
    let ether = build_ether_packet(
        src_mac,
        // MacAddr::from_str("08:00:27:d1:fc:38").unwrap(),
        MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        EtherType::new(0x86dd),
        ipv6.packet(),
    );

    tx.send_to(ether.packet(), Some(interface))
        .unwrap()
        .unwrap();
}
