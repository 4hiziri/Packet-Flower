extern crate getopts;
extern crate pnet;
use getopts::Options;
use std::env;
use std::net::Ipv6Addr;
use std::str::FromStr;
use pnet::datalink::{self, NetworkInterface, MacAddr};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::icmpv6;
use pnet::packet::FromPacket;
use pnet::packet::icmpv6::ndp;
use pnet::packet::icmpv6::ndp::{MutableRouterAdvertPacket, MutableNdpOptionPacket};
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::util::Octets;


/// Return IPv6 NDP option source link address
/// #Arguments
/// `link_addr` - Source address that is  L2 link, only support MAC address
/// # Example
/// ```
/// let src_addr_opt = build_ndpopt_src_link_addr(MacAddr::from_str("aa:bb:cc:dd:ee:ff"));
/// ```
fn build_ndpopt_src_link_addr(link_addr: MacAddr) -> NdpOption {
    let mut buf = [0; 16];
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();
    let MacAddr(a1, a2, a3, a4, a5, a6) = link_addr;

    ndpopt.set_option_type(ndp::NdpOptionTypes::SourceLLAddr);
    ndpopt.set_length(1);
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
    let mut buf = [0; 40];
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();
    let mut data: Vec<u8> = Vec::new();
    let flag = if l_flag { 0x80 } else { 0 } | if a_flag { 0x40 } else { 0 };

    data.push(prefix_len);
    data.push(flag);
    data.append(&mut valid_time.octets().iter().cloned().collect());
    data.append(&mut ref_time.octets().iter().cloned().collect());
    data.append(&mut prefix.octets().iter().cloned().collect());

    ndpopt.set_option_type(ndp::NdpOptionTypes::PrefixInformation);
    ndpopt.set_length(4);
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
    let mut buf = [0; 16];
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();

    ndpopt.set_option_type(ndp::NdpOptionTypes::MTU);
    ndpopt.set_length(1);
    ndpopt.set_data(&mtu.octets());

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
    let mut buf = [0; 80];
    // assert, limited size
    let mut ndpopt = MutableNdpOptionPacket::new(&mut buf).unwrap();
    let rdnss = ndp::NdpOptionType::new(0x19);
    let length: u8 = 3 + dns_servers.len() as u8;
    let mut data: Vec<u8> = Vec::new();

    ndpopt.set_option_type(rdnss);
    ndpopt.set_length(length);

    data.append(&mut lifetime.octets().iter().cloned().collect());

    for server in dns_servers {
        data.append(&mut server.octets().iter().cloned().collect());
    }

    ndpopt.set_data(data.as_slice());

    ndpopt.from_packet()
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
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
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
    let mut rt_advt = MutableRouterAdvertPacket::new(&mut buf).unwrap();
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

    rt_advt.set_icmpv6_type(icmpv6::Icmpv6Types::RouterAdvert);
    rt_advt.set_icmpv6_code(ndp::Icmpv6Codes::NoCode);
    rt_advt.set_hop_limit(64);
    rt_advt.set_flags(ndp::RouterAdvertFlags::OtherConf);
    rt_advt.set_lifetime(1800);
    rt_advt.set_reachable_time(1800);
    rt_advt.set_retrans_time(1800);
    rt_advt.set_options(&ndp_opts);

    let mut buf = [0; 1024];
    let mut ipv6 = MutableIpv6Packet::new(&mut buf).unwrap();
    ipv6.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6.set_destination(Ipv6Addr::from_str("2001:db8:5::1").unwrap());
    ipv6.set_payload(rt_advt.packet());

    tx.send_to(ipv6.packet(), Some(interface)).unwrap();
}
