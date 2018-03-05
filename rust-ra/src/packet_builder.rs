extern crate pnet;
use std::net::Ipv6Addr;
use pnet::datalink::{self, NetworkInterface, MacAddr};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherType};
use pnet::packet::Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::icmpv6;
use pnet::packet::FromPacket;
use pnet::packet::icmpv6::ndp;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::ndp::{MutableRouterAdvertPacket, MutableNdpOptionPacket};
use pnet::packet::icmpv6::ndp::NdpOption;
use pnet::util::Octets;
use std::iter::FromIterator;

/// Return IPv6 NDP option source link address
/// #Arguments
/// `link_addr` - Source address that is  L2 link, only support MAC address
/// # Example
/// ```
/// let src_addr_opt = build_ndpopt_src_link_addr(MacAddr::from_str("aa:bb:cc:dd:ee:ff"));
/// ```
pub fn build_ndpopt_src_link_addr(link_addr: MacAddr) -> NdpOption {
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
pub fn build_ndpopt_prefix(
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
    // reserved field
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
pub fn build_ndpopt_mtu(mtu: u32) -> NdpOption {
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
pub fn build_ndpopt_rdnss(lifetime: u32, dns_servers: Vec<Ipv6Addr>) -> NdpOption {
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
pub fn get_interface(interface_name: &str) -> NetworkInterface {
    datalink::interfaces()
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .unwrap()
}

pub fn build_router_advert<'a>(
    hop_limit: u8,
    flag: u8,
    lifetime: u16,
    reachable_time: u32,
    retrans_time: u32,
    ndp_opts: Vec<NdpOption>,
    source: Ipv6Addr,
    destination: Ipv6Addr,
) -> MutableRouterAdvertPacket<'a> {
    let payload_len: usize = ndp_opts
        .as_slice()
        .into_iter()
        .map(|opt| opt.length as usize)
        .fold(
            MutableRouterAdvertPacket::minimum_packet_size() as usize,
            |acc, len| acc + len * 8,
        );

    let mut buf = Vec::with_capacity(payload_len);
    buf.resize(payload_len, 0);
    let mut rt_advt = MutableRouterAdvertPacket::owned(buf).unwrap();
    debug!("build_router_advert: advert payload len is {}", payload_len);

    rt_advt.set_icmpv6_type(icmpv6::Icmpv6Types::RouterAdvert);
    rt_advt.set_icmpv6_code(ndp::Icmpv6Codes::NoCode);
    rt_advt.set_hop_limit(hop_limit);
    rt_advt.set_flags(flag);
    rt_advt.set_lifetime(lifetime);
    rt_advt.set_reachable_time(reachable_time);
    rt_advt.set_retrans_time(retrans_time);
    rt_advt.set_options(&ndp_opts);

    let advt_packet = Vec::from_iter(rt_advt.packet().to_owned());
    rt_advt.set_checksum(icmpv6::checksum(
        &convert_rtadvt_icmpv6(advt_packet.as_slice()),
        source,
        destination,
    ));

    rt_advt
}

pub fn build_ipv6_packet(
    next_header: pnet::packet::ip::IpNextHeaderProtocol,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    payload: &[u8],
) -> MutableIpv6Packet {
    let packet_len = payload.len() + MutableIpv6Packet::minimum_packet_size();
    let mut buf = Vec::with_capacity(packet_len);
    buf.resize(packet_len, 0);
    let mut ipv6 = MutableIpv6Packet::owned(buf).unwrap();

    ipv6.set_version(0x6);
    ipv6.set_next_header(next_header);
    ipv6.set_source(source);
    ipv6.set_destination(destination);
    ipv6.set_payload_length(payload.len() as u16);
    ipv6.set_payload(&payload);

    ipv6
}

pub fn build_ipv6_of_rt_advt(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    payload: &[u8],
) -> MutableIpv6Packet {
    build_ipv6_packet(
        pnet::packet::ip::IpNextHeaderProtocols::Icmpv6,
        source,
        destination,
        payload,
    )
}

pub fn convert_rtadvt_icmpv6(rt_advt_packet: &[u8]) -> Icmpv6Packet {
    Icmpv6Packet::new(rt_advt_packet).unwrap()
}

pub fn build_ether_packet(
    source: MacAddr,
    destination: MacAddr,
    ether_type: EtherType,
    payload: &[u8],
) -> MutableEthernetPacket {
    let packet_len: usize = MutableEthernetPacket::minimum_packet_size() + payload.len();
    let mut buf = Vec::new();
    buf.resize(packet_len, 0);
    let mut ether = MutableEthernetPacket::owned(buf).unwrap();

    ether.set_ethertype(ether_type);
    ether.set_source(source);
    ether.set_destination(destination);
    ether.set_payload(payload);

    ether
}
