from scapy.all import sniff

dumped = sniff(filter='icmpv6.type == 134', count=10)

