#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libnet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// macro for icmpv6 flags
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

int main(int argc, char** argv){
  if (argc != 5) {
    fprintf(stderr, "%s <interface> <src addr> <dist addr> <dns addr>\n", argv[0]);
    return 1;
  }

  // set argv
  char *interface = argv[1];
  char *dist_addr = argv[2];
  char *src_addr = argv[3];
  char *dns_addr = argv[4];
  
  libnet_t *l;
  int id, seq;
  libnet_in6_addr sip, dip, trg, dns;
  char errbuf[LIBNET_ERRBUF_SIZE];

  /***************************************************************
    initialize libnet, this must be called before other functionsn
   ***************************************************************/
  l = libnet_init(LIBNET_RAW6, interface, errbuf);
  if(l == NULL) {
    printf("libnet_init: %s\n", errbuf);
    exit(1);
  }  

  // get rand val for session.
  libnet_seed_prand(l);
  id = libnet_get_prand(LIBNET_PRu32);
  seq = libnet_get_prand(LIBNET_PRu32);

  // get ipv6-addr struct
  sip = libnet_name2addr6(l, src_addr, LIBNET_DONT_RESOLVE);   
  dip = libnet_name2addr6(l, dist_addr, LIBNET_DONT_RESOLVE);

  /********************************* 
   *   build router advertisement  *
   *********************************/  
  uint32_t lt = LIFETIME_INF;
  uint8_t payload[16];
  build_icmpv6_rdnss_opt(l, &trg, payload, lt, dns_addr);
  
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
  
  // build ipv6 packet
  libnet_build_ipv6(
		    0,                                        // uint8_t traffic class
		    0,                                        // uint32_t flow label
		    LIBNET_IPV6_H + LIBNET_ICMPV6_NDP_NADV_H, //uint16_t len
		    IPPROTO_ICMP6,                            //uint8_t nh -> next header
		    64,                                       //uint8_t hl -> hop limit
		    sip,                                      //libnet_in6_addr src
		    dip,                                      //libnet_in6_addr dst
		    NULL,                                     //uint8_t* payload
		    0,                                        //uint32_t payload_s
		    l,                                        //libnet_t* l
		    0                                         //libnet_ptag_t ptag
		    );
    
  if(libnet_write(l) == -1) {
    printf("libnet_write: %s\n", libnet_geterror(l));
    exit(1);
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
  
  header->__u6_addr.__u6_addr8[8] = 0x19; // type num RDNSS
  header->__u6_addr.__u6_addr8[9] = 0x2 + 0x1; // 0x2 + number_of_dns_addr
  header->__u6_addr.__u6_addr32[3] = lifetime;
  
  return;
}
