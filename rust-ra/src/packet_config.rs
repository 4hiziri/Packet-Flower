use clap::ArgMatches;
use pnet::datalink::MacAddr;
use pnet::packet::icmpv6::ndp;
use pnet::packet::icmpv6::ndp::MutableRouterAdvertPacket;
use std::net::Ipv6Addr;
use std::str::FromStr;

use packet_builder::*;

pub fn set_mtu_opt(opts: &mut Vec<ndp::NdpOption>, args: &ArgMatches) {
    if let Some(mtu_str) = args.value_of("mtu") {
        let mtu = if mtu_str == "" {
            64
        } else {
            mtu_str.parse::<u32>().unwrap()
        };

        let mtu_opt = build_ndpopt_mtu(mtu);
        opts.push(mtu_opt);
    }
}

pub fn set_src_opt(opts: &mut Vec<ndp::NdpOption>, args: &ArgMatches) {
    if let Some(src_link) = args.value_of("source-link") {
        // FIXME: only accept MAC addr now
        let mac = MacAddr::from_str(src_link).unwrap();
        let src_opt = build_ndpopt_src_link_addr(mac);
        opts.push(src_opt);
    }
}

pub fn set_prefix_opt(opts: &mut Vec<ndp::NdpOption>, args: &ArgMatches) {
    if let Some(prefix) = args.value_of("prefix") {
        let prefix_addr: Ipv6Addr = Ipv6Addr::from_str(prefix).unwrap();

        // TODO: prefix length setting
        let length = match args.value_of("prefix-length") {
            Some(p_len) => p_len.parse::<u8>().unwrap(),
            None => 64,
        };

        let on_link = args.is_present("prefix-on-link");
        let addr_conf = args.is_present("prefix-addr-conf");

        let valid = match args.value_of("prefix-valid") {
            Some(valid) => valid.parse::<u32>().unwrap(),
            None => 1800,
        };

        let prefer = match args.value_of("prefix-prefer") {
            Some(prefer) => prefer.parse::<u32>().unwrap(),
            None => 3600,
        };

        let prefix_opt =
            build_ndpopt_prefix(length, on_link, addr_conf, valid, prefer, prefix_addr);

        opts.push(prefix_opt);
    }
}

pub fn set_rdnss_opt(opts: &mut Vec<ndp::NdpOption>, args: &ArgMatches) {
    if let Some(rdnss) = args.values_of("rdnss") {
        let rdnss: Vec<_> = rdnss
            .map(|addr| Ipv6Addr::from_str(addr).unwrap())
            .collect();

        let lifetime = match args.value_of("dns-lifetime") {
            Some(lifetime) => lifetime.parse::<u32>().unwrap(),
            None => 1800,
        };

        let rdnss_opt = build_ndpopt_rdnss(lifetime, rdnss);
        opts.push(rdnss_opt);
    }
}

pub fn set_router_advt<'a>(
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    args: &ArgMatches,
) -> MutableRouterAdvertPacket<'a> {
    // create router advert packete
    let mut ndp_opts = Vec::new();

    set_mtu_opt(&mut ndp_opts, &args);
    set_prefix_opt(&mut ndp_opts, &args);
    set_src_opt(&mut ndp_opts, &args);
    set_rdnss_opt(&mut ndp_opts, &args);

    let hop_limit = match args.value_of("hop-limit") {
        Some(hop) => hop.parse::<u8>().unwrap(),
        None => 64,
    };
    let m_flag = if args.is_present("managed-flag") {
        ndp::RouterAdvertFlags::ManagedAddressConf
    } else {
        0
    };
    let o_flag = if args.is_present("other-flag") {
        ndp::RouterAdvertFlags::OtherConf
    } else {
        0
    };
    let flag = m_flag | o_flag;
    let lifetime = match args.value_of("lifetime") {
        Some(lifetime) => lifetime.parse::<u16>().unwrap(),
        None => 1800,
    };
    let reachable = match args.value_of("reachable-time") {
        Some(reachable) => reachable.parse::<u32>().unwrap(),
        None => 1800,
    };
    let retrans = match args.value_of("retrans-time") {
        Some(retrans) => retrans.parse::<u32>().unwrap(),
        None => 1800,
    };

    build_router_advert(
        hop_limit,
        flag,
        lifetime,
        reachable,
        retrans,
        ndp_opts,
        ip_src,
        ip_dst,
    )
}
