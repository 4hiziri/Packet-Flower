#/usr/bin/python3

import gi
gi.require_version('NM', '1.0')
from gi.repository import NM
import dpkt
from scapy.all import sr1, IP, IPv6, UDP, DNS, DNSQR, ls


def info(interface):
    print("package test")
    
    test_domain = 'www.google.com'
    client = NM.Client.new(None)
    dev = client.get_device_by_iface(interface)
    ip4config = dev.get_ip4_config()
    ip6config = dev.get_ip6_config()
    name_servers4 = ip4config.get_nameservers()
    name_servers6 = ip6config.get_nameservers()

    print("IPv4 DNS servers: {}".format(name_servers4))
    print("DNS query to {}".format(name_servers4[0]))

    payload = IP(dst=name_servers4[0])
    payload /= UDP(dport=53)
    payload /= DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com'))
    dns_rep = sr1(payload, verbose=0)

    for i in range(dns_rep['DNS'].arcount):
        print("DNS reply: {}".format(dns_rep['DNS'].ar[i].rdata))

    print("IPv6 DNS servers: {}".format(name_servers6))
    print("DNS query to {}".format(name_servers6[0]))

    payload = IPv6(dst=name_servers6[0])
    payload /= UDP(dport=53)
    payload /= DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com'))
    dns_rep = sr1(payload, verbose=0)

    for i in range(dns_rep['DNS'].arcount):
        print("DNS reply: {}".format(dns_rep['DNS'].ar[i].rdata))


def dnsv6_request(nameserver, domain_name):
    payload = IPv6(dst=nameserver)
    payload /= UDP(dport=53)
    payload /= DNS(rd=1, qd=DNSQR(qname=domain_name))
    return sr1(payload, verbose=0)


def get_v6_nameservers(interface):
    client = NM.Client.new(None)
    dev = client.get_device_by_iface(interface)
    ip6config = dev.get_ip6_config()
    return ip6config.get_nameservers()


def check_ipv6(ips_list):
    sets = [set(ips) for ips in ips_list]
    head = sets.pop()

    for s in sets:
        if head != s:
            return False

    return True


def main(interface):
    nameservers = get_v6_nameservers(interface)
    results = []

    for nameserver in nameservers:
        rep = dnsv6_request(nameserver, 'www.google.com')
        tmp = []

        for i in range(rep['DNS'].arcount):
            tmp.append(rep['DNS'].ar[i].rdata)

        results.append(tmp)

    print(check_ipv6(results))


if __name__ == '__main__':
    info('wlp2s0')
    # main('wlp2s0')
