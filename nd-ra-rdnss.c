#include <stdio.h>
#include <libnet.h>

#define ND_RA_MANAGED_CONFIG_FLAG 0x0800000
#define ND_RA_OTHER_CONFIG_FLAG   0x0400000
#define ND_RA_HOP_LIMIT           0x1000000
#define ND_OPT_RDNSS              0x19
#define LIFETIME_INF              0xffffffff

typedef struct libnet_in6_addr libnet_in6_addr;

void build_icmpv6_rdnss_opt(libnet_t* l,
			    libnet_in6_addr *header,
			    uint8_t *payload,
			    uint32_t lifetime,
			    const char* dns_addr);

void build_icmpv6_src_link_addr_opt(libnet_t* l,
				    uint8_t *payload,
				    const char* link_addr);

void build_icmpv6_mtu_opt(libnet_t* l,
			  uint8_t *payload,
			  uint32_t mtu);

void build_icmpv6_prefix_opt(libnet_t* l,
			     uint8_t *payload,
			     uint8_t flag,
			     uint32_t valid_lifetime,
			     uint32_t prefered_lifetime,			     
			     const char* prefix);

int main(int argc, char** argv){
  if (argc != 4) {
    fprintf(stderr, "%s <interface> <src addr> <dns addr>\n", argv[0]);
    exit(1);
  }

  // set argv
  char *interface = argv[1];    
  char *dst_addr = "ff02::1";
  char *src_addr = argv[2];
  char *dns_addr = argv[3];

  libnet_t *l;
  libnet_in6_addr sip, dip, trg;
  char errbuf[LIBNET_ERRBUF_SIZE];

  /***************************************************************
    initialize libnet, this must be called before other function
   ***************************************************************/
  l = libnet_init(LIBNET_RAW6, interface, errbuf);
  if(l == NULL) {
    printf("libnet_init: %s\n", errbuf);
    exit(1);
  }

  // get ipv6-addr struct
  sip = libnet_name2addr6(l, src_addr, LIBNET_DONT_RESOLVE);
  dip = libnet_name2addr6(l, dst_addr, LIBNET_DONT_RESOLVE);

  /*********************************
   *   build router advertisement  *
   *********************************/
  uint32_t lt = LIFETIME_INF;
  uint8_t payload[16];
  build_icmpv6_rdnss_opt(l, &trg, payload, lt, dns_addr);

  // how to append another header? malloc?

  libnet_build_icmpv6_ndp_nadv(
			       ND_ROUTER_ADVERT,                               // uint8_t type
			       0,                                              // uint8_t code
			       0,                                              // uint16_t check_sum
			       64 * ND_RA_HOP_LIMIT + ND_RA_OTHER_CONFIG_FLAG, // uint32_t flags
			       trg,                                            // libnet_in6_addr target
			       payload,                                        // uint8_t* payload
			       16,                                             // uint32_t payload size
			       l,                                              // libnet_t* context
			       0                                               // libnet_ptag_t ptag, 0 means create new one
			       );

  /*********************************
   *       build ipv6 packet       *
   *********************************/
  libnet_build_ipv6(
		    0,                                        // uint8_t traffic class
		    0,                                        // uint32_t flow label
		    LIBNET_IPV6_H,                            // uint16_t len
		    IPPROTO_ICMP6,                            // uint8_t nh -> next header
		    64,                                       // uint8_t hl -> hop limit
		    sip,                                      // libnet_in6_addr src
		    dip,                                      // libnet_in6_addr dst
		    NULL,                                     // uint8_t* payload
		    0,                                        // uint32_t payload_s
		    l,                                        // libnet_t* l
		    0                                         // libnet_ptag_t ptag
		    );

  while(1){
    if(libnet_write(l) == -1) {
      printf("libnet_write: %s\n", libnet_geterror(l));
      exit(1);
    }

    sleep(0.01);
  }

  libnet_destroy(l);

  return 0;
}

/**
 * set config value to header and payload.
 * @param l libnet context
 * @param header header of RDNSS, set some value into this
 * @param payload dns address is set here
 * @param lifetime lifetime of dns server
 * @param dns_addr address of dns server, like "2001:db8::1"
 */
void build_icmpv6_rdnss_opt(libnet_t* l,
			    libnet_in6_addr *header,
			    uint8_t *payload,
			    uint32_t lifetime,
			    const char* dns_addr){
  // copy address, builder funciton accepts only uint8_t*
  for (int i = 0; i < 16; i++)
    payload[i] = libnet_name2addr6(l, dns_addr, LIBNET_DONT_RESOLVE).__u6_addr.__u6_addr8[i];

  header->__u6_addr.__u6_addr8[8] = ND_OPT_RDNSS; // type num RDNSS
  // TODO: check size is whether correct or not.
  // this is strange, too strange
  header->__u6_addr.__u6_addr8[9] = 0x2 + 0x1; // 0x2 + number_of_dns_addr, this means size?
  header->__u6_addr.__u6_addr32[3] = lifetime; // what life time?

  return;
}

/**
 * This sets 'link_addr' and payload-len to 'payload'
 *
 * @param l libnet context
 * @param payload actual return val
 * @param link_addr MAC-addr
 */
void build_icmpv6_src_link_addr_opt(libnet_t* l,				    
				    uint8_t *payload,
				    const char* link_addr){
  // if RA, 0x01 only. But NA or Redirect can use 0x02
  payload[0] = ND_OPT_SOURCE_LINKADDR; // == 0x01
  // if ethernet is used, length should be 1. MAC addr is 48 bit len.

  payload[1] = 1;

  // use link_addr like "\x12\x34\x56\xab\xcd\xef"?
  for(int i = 0; i < 6; i++) // if MAC addr is 42(6 bytes), this is ok.
    payload[2 + i] = link_addr[i];
  
  return;
}

/**
 * This sets mtu to payload
 * @param l libnet context
 * @param payload actual ret val 
 * @param mtu mtu
 */
void build_icmpv6_mtu_opt(libnet_t* l,
			  uint8_t *payload,
			  uint32_t mtu){
  payload[0] = ND_OPT_MTU;
  payload[1] = 1;

  union len32{
    uint8_t u8[4];
    uint32_t u32[1];
  } tmp;
  tmp.u32[0] = mtu;  
  for(int i = 0; i < 4; i++)
    payload[2 + i] = tmp.u8[i];  
  
  return;
}

void build_icmpv6_prefix_opt(libnet_t* l,
			     uint8_t *payload,
			     uint8_t flag,
			     uint32_t valid_lifetime,
			     uint32_t prefered_lifetime,			     
			     const char* prefix){  
  return;
}
