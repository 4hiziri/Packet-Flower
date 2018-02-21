// TODO: Fix libpnet
extern crate getopts;
extern crate pnet;
use getopts::Options;
use std::env;
use std::net::Ipv6Addr;
use std::str::FromStr;
use pnet::datalink::{self, NetworkInterface, MacAddr};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{MutableEthernetPacket, EtherType};
use pnet::packet::Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::icmpv6;
use pnet::packet::FromPacket;
use pnet::packet::icmpv6::ndp;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::ndp::{MutableRouterAdvertPacket, MutableNdpOptionPacket,
                                RouterAdvertPacket};
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::packet::ethernet;
use pnet::packet::ethernet::EtherTypes;
use pnet::util::Octets;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::transport_channel;
use pnet::transport::TransportProtocol::Ipv6;
use std::iter::FromIterator;

/// Return IPv6 NDP option source link address
/// #Arguments
/// `link_addr` - Source address that is  L2 link, only support MAC address
/// # Example
/// ```
/// let src_addr_opt = build_ndpopt_src_link_addr(MacAddr::from_str("aa:bb:cc:dd:ee:ff"));
/// ```
fn build_ndpopt_src_link_addr(link_addr: MacAddr) -> NdpOption {
    const LENGTH: u8 = 1;
    let mut buf = [0; LENGTH as usize * 8];
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();
    let MacAddr(a1, a2, a3, a4, a5, a6) = link_addr;

    ndpopt.set_option_type(ndp::NdpOptionTypes::SourceLLAddr);
    ndpopt.set_length(LENGTH);
    ndpopt.set_data(&[a1, a2, a3, a4, a5, a6]);

    ndpopt.from_packet()
}

/// Return IPv6 NDP prefix option
/// # Arguments
/// `prefix_len` - Length of prefix part of address, exp.) 2001:db8:1::/64 => prefix_len 64
/// `l_flag` -
/// `a_flag` -
/// `valid_time` - Time when prefix is valid
/// `ref_time` - Time when prefix is referable(?)
/// `prefix` - Prefix IPv6 address
/// # Example
/// ```
/// let prefix = build_ndpopt_prefix(64, False, True, 1800, 3600, Ipv6Addr::from_str("2001:db8::1"))
/// ```
fn build_ndpopt_prefix(
    prefix_len: u8,
    l_flag: bool,
    a_flag: bool,
    valid_time: u32,
    ref_time: u32,
    prefix: Ipv6Addr,
) -> NdpOption {
    const LENGTH: u8 = 4;
    let mut buf = [0; LENGTH as usize * 8];
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();
    let mut data: Vec<u8> = Vec::new();
    let flag = if l_flag { 0x80 } else { 0 } | if a_flag { 0x40 } else { 0 };

    data.push(prefix_len);
    data.push(flag);
    data.append(&mut valid_time.octets().iter().cloned().collect());
    data.append(&mut ref_time.octets().iter().cloned().collect());
    // reserved
    data.push(0);
    data.push(0);
    data.push(0);
    data.push(0);
    data.append(&mut prefix.octets().iter().cloned().collect());

    ndpopt.set_option_type(ndp::NdpOptionTypes::PrefixInformation);
    ndpopt.set_length(LENGTH);
    ndpopt.set_data(&data);

    ndpopt.from_packet()
}

/// Return IPv6 NDP MTU option
/// # Arguments
/// `mtu` - MTU
/// # Example
/// ```
/// let mtu = build_ndpopt_mtu(64);
/// ```
fn build_ndpopt_mtu(mtu: u32) -> NdpOption {
    const LENGTH: u8 = 1;
    let mut buf = [0; LENGTH as usize * 8];
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();
    let mut data = Vec::new();

    // reserved
    data.push(0);
    data.push(0);

    data.append(&mut mtu.octets().iter().cloned().collect());

    ndpopt.set_option_type(ndp::NdpOptionTypes::MTU);
    ndpopt.set_length(LENGTH);
    ndpopt.set_data(&data);

    ndpopt.from_packet()
}

/// Return IPv6 NDP RDNSS option
/// # Arguments
/// `lifetime` - Lifetime of name servers
/// `dns-servers` - Vector of name servers which notify host
///
/// # Example
/// ```
/// let dns = Vec::new();
/// dns.push(Ipv6Addr::from_str("2001:db8:2::2"));
/// let rdnss = build_ndpopt_rdnss(dns, 1800);
/// ```
fn build_ndpopt_rdnss(lifetime: u32, dns_servers: Vec<Ipv6Addr>) -> NdpOption {
    let length: u8 = 1 + 2 * dns_servers.len() as u8;
    let mut buf = Vec::new();
    buf.resize(length as usize * 8, 0);
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();
    let rdnss = ndp::NdpOptionType::new(0x19);
    let mut data: Vec<u8> = Vec::new();

    ndpopt.set_option_type(rdnss);
    ndpopt.set_length(length);

    // reserved
    data.append(&mut [0u8; 2].iter().cloned().collect());
    data.append(&mut lifetime.octets().iter().cloned().collect());

    for server in dns_servers {
        data.append(&mut server.octets().iter().cloned().collect());
    }

    ndpopt.set_data(data.as_slice());

    ndpopt.from_packet()
}

/// Find the network interface with the provided name
///
/// #Arguments
/// `interface_name` - interface name. exp.) enp1s0, wlan1
fn get_interface(interface_name: &str) -> NetworkInterface {
    datalink::interfaces()
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .unwrap()
}

fn build_router_advert(
    rt_advt: &mut MutableRouterAdvertPacket,
    hop_limit: u8,
    flag: u8,
    lifetime: u16,
    reachable_time: u32,
    retrans_time: u32,
    ndp_opts: Vec<NdpOption>,
) {
    rt_advt.set_icmpv6_type(icmpv6::Icmpv6Types::RouterAdvert);
    rt_advt.set_icmpv6_code(ndp::Icmpv6Codes::NoCode);
    rt_advt.set_hop_limit(hop_limit);
    rt_advt.set_flags(flag);
    rt_advt.set_lifetime(lifetime);
    rt_advt.set_reachable_time(reachable_time);
    rt_advt.set_retrans_time(retrans_time);
    rt_advt.set_options(&ndp_opts);
}

fn convert_rtadvt_icmpv6(rt_advt_packet: &[u8]) -> Icmpv6Packet {
    Icmpv6Packet::new(rt_advt_packet).unwrap()
}

fn main() {
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

    // let protocol = Layer4(Ipv6(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6));
    // let (mut tx, _) = transport_channel(4096, protocol).unwrap();

    // create router advert packet
    let mut payload_len: u16 = MutableRouterAdvertPacket::minimum_packet_size() as u16;
    println!("advt_min: {}", payload_len); // => 16

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

    payload_len += ndp_opts[0].length as u16 * 8;
    payload_len += ndp_opts[1].length as u16 * 8;
    payload_len += ndp_opts[2].length as u16 * 8;
    payload_len += ndp_opts[3].length as u16 * 8;

    let mut buf = Vec::new();
    buf.resize(payload_len as usize, 0);
    let mut rt_advt = MutableRouterAdvertPacket::owned(buf).unwrap();
    build_router_advert(
        &mut rt_advt,
        64,
        ndp::RouterAdvertFlags::OtherConf,
        1800,
        1800,
        1800,
        ndp_opts,
    );

    // let ipv6_payload = rt_advt.packet();

    // create ipv6 packet, L3
    let ip_src = Ipv6Addr::from_str("2001:db8:10::1").unwrap();
    let ip_dst = Ipv6Addr::from_str("2001:db8:5::1").unwrap();
    let advt_packet = rt_advt.packet();
    let cp_advt_packet = Vec::from_iter(advt_packet.to_owned());
    let mut advt_packet = Vec::from_iter(advt_packet.to_owned());
    let icmpv6_packet = convert_rtadvt_icmpv6(cp_advt_packet.as_slice());
    let mut rt_advt = MutableRouterAdvertPacket::new(&mut advt_packet).unwrap();

    rt_advt.set_checksum(icmpv6::checksum(&icmpv6_packet, ip_src, ip_dst));
    let ipv6_payload = rt_advt.packet();
    let mut buf = Vec::new();
    buf.resize(
        ipv6_payload.len() + MutableIpv6Packet::minimum_packet_size(),
        0,
    );
    let mut ipv6 = MutableIpv6Packet::new(&mut buf).unwrap();

    ipv6.set_version(0x6);
    ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6.set_destination(ip_dst);
    ipv6.set_source(ip_src);
    ipv6.set_payload_length(ipv6_payload.len() as u16);
    ipv6.set_payload(&ipv6_payload);

    // L2 ether
    let length = MutableEthernetPacket::minimum_packet_size() + ipv6.packet().len();
    let mut buf = Vec::new();
    buf.resize(length as usize, 0);
    let mut ether = MutableEthernetPacket::new(&mut buf).unwrap();

    ether.set_ethertype(EtherType::new(0x86dd)); // IPv6
    ether.set_destination(MacAddr::from_str("AA:AA:AA:AA:AA:AA").unwrap());
    ether.set_source(MacAddr::from_str("BB:BB:BB:BB:BB:BB").unwrap());
    ether.set_payload(ipv6.packet());

    tx.send_to(ether.packet(), Some(interface))
        .unwrap()
        .unwrap();
}
