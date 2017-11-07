# Usage
`CMD inteface source-address destination-address <options>`

+ interface
  - network interface name. ex) enp1s0, eth1
+ source-address
  - source adderss. ex) 2001:db8::1
+ destination-address
  - distination address. ex) 2001:db8::2

# router advertisement param
+ --hop-limit hop limit
+ -fo other flag
+ -fm managed flag
+ --lifetime lifetime
+ --reachable reachable time
+ --retrans retransmission time

# ra option param
+ RDNSS
- -r use rdnss option: dns address
- --r-lifetime rdnss lifetime
 
+ MTU
- -m use mtu option: mtu
 
+ target link address
- -l use link option: link address
 
+ Prefix
- -p use prefix option: prefix addr and length like 2001:db8::/64
- --p-l prefix L flag
- --p-a prefix A flag
- --p-valid prefix valid lifetime
- --p-prefer prefix prefered lifetime
