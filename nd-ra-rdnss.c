#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>

#define ND_RA_MANAGED_CONFIG_FLAG 0x0800000
#define ND_RA_OTHER_CONFIG_FLAG   0x0400000
#define ND_RA_HOP_LIMIT           0x1000000
#define ND_OPT_RDNSS              0x19
#define LIFETIME_INF              0xffffffff

#define ND_OPT_ON_LINK_FLAG       0x80
#define ND_OPT_AUTO_CONFIG_FLAG   0x40

typedef struct libnet_in6_addr libnet_in6_addr;

int build_icmpv6_rdnss_opt(libnet_t* l,
			   libnet_in6_addr *header,
			   uint8_t **payload,
			   uint32_t lifetime,
			   const char* dns_addr);

int build_icmpv6_src_link_addr_opt(libnet_t* l,
				   uint8_t **payload,
				   const char* link_addr);

int build_icmpv6_mtu_opt(libnet_t* l,
			 uint8_t **payload,
			 uint32_t mtu);

int build_icmpv6_prefix_opt(libnet_t* l,
			    uint8_t **payload,
			    uint8_t prefix_len,
			    uint8_t flag,
			    uint32_t valid_lifetime,
			    uint32_t prefered_lifetime,			     
			    const char* prefix);

uint8_t* payload_malloc(int len);

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

  /*****************************************************************
   * Initialize libnet, this must be called before other function. *
   *****************************************************************/
  l = libnet_init(LIBNET_RAW6, interface, errbuf);
  if(l == NULL) {
    printf("libnet_init: %s\n", errbuf);
    exit(1);
  }

  // get ipv6-addr struct
  sip = libnet_name2addr6(l, src_addr, LIBNET_DONT_RESOLVE);
  dip = libnet_name2addr6(l, dst_addr, LIBNET_DONT_RESOLVE);

  /*********************************
   *   Build router advertisement  *
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
    break;

    sleep(1);
  }

  libnet_destroy(l);

  return 0;
}

/**
 * Set config value to header and payload.
 * 128 bits, If addr is one.
 * 
 * @param l libnet context
 * @param header header of RDNSS, set some value into this
 * @param payload dns address is set here
 * @param lifetime lifetime of dns server
 * @param dns_addr address of dns server, like "2001:db8::1"
 * @return bytes size of payload
 */
int build_icmpv6_rdnss_opt(libnet_t* l,
			   libnet_in6_addr *header,
			   uint8_t **payload,
			   uint32_t lifetime,
			   const char* dns_addr){
  int len = 2 + 1;
  *payload = payload_malloc(len); // this must be error.
  
  // copy address, builder funciton accepts only uint8_t*
  for (int i = 0; i < 16; i++)
    *payload[i] = libnet_name2addr6(l, dns_addr, LIBNET_DONT_RESOLVE).__u6_addr.__u6_addr8[i];

  header->__u6_addr.__u6_addr8[8] = ND_OPT_RDNSS; // type num RDNSS
  // TODO: check size is whether correct or not.
  // this is strange, too strange
  header->__u6_addr.__u6_addr8[9] = 0x2 + 0x1; // 0x2 + number_of_dns_addr, this means size?
  header->__u6_addr.__u6_addr32[3] = lifetime; // what life time?

  return len * 8;
}

/**
 * This sets 'link_addr' and payload-len to 'payload'
 * If ethernet, 64 bits
 *
 * @param l libnet context
 * @param payload actual return val
 * @param link_addr MAC-addr
 * @return bytes size of payload
 */
int build_icmpv6_src_link_addr_opt(libnet_t* l,				    
				   uint8_t **payload,
				   const char* link_addr){
  int len = 1;
  *payload = payload_malloc(len);
  
  // if RA, 0x01 only. But NA or Redirect can use 0x02
  *payload[0] = ND_OPT_SOURCE_LINKADDR; // == 0x01
  // if ethernet is used, length should be 1. MAC addr is 48 bit len.

  *payload[1] = len;

  // use link_addr like "\x12\x34\x56\xab\xcd\xef"?
  // if MAC addr is 42(6 bytes), this is ok.
  for(int i = 0; i < 6; i++) *payload[2 + i] = link_addr[i];
  
  return len * 8;
}

/**
 * This sets mtu to payload
 * 64 bits
 * 
 * @param l libnet context
 * @param payload actual ret val 
 * @param mtu mtu
 * @return bytes size of payload
 */
int build_icmpv6_mtu_opt(libnet_t* l,
			 uint8_t **payload,
			 uint32_t mtu){
  int len = 1;
  *payload = payload_malloc(len);
  
  *payload[0] = ND_OPT_MTU;
  *payload[1] = len;

  union len32{
    uint8_t u8[4];
    uint32_t u32[1];
  } tmp;
  tmp.u32[0] = mtu;  
  for(int i = 0; i < 4; i++) *payload[2 + i] = tmp.u8[i];  
  
  return len * 8;
}

/**
 * This sets prefix option payloads.
 * 256 bits
 *
 * @param l : Libnet context
 * @param payload : Data is set here
 * @param prefix_len : Prefix addr's network part length
 * @param flag : Flag, only L and A flag. Others are reserved
 * @param valid_lifetime : In this span, prefix can be used to judge whether such addr is on link or not.
 * @param prefered_lifetime : This span means addr generating by this prefix is recomended in this span.
 * @param prefix : Just prefix, length is defined by prefix_len.
 * @return bytes size of payload
 */
int build_icmpv6_prefix_opt(libnet_t* l,
			    uint8_t **payload,
			    uint8_t prefix_len,
			    uint8_t flag, // L|A|Reserved
			    uint32_t valid_lifetime, // valid
			    uint32_t prefered_lifetime, // able to refer?
			    const char* prefix){
  int len = 4;
  *payload = payload_malloc(len);
  
  *payload[0] = ND_OPT_PREFIX_INFORMATION;
  *payload[1] = len;
  *payload[2] = prefix_len;
  // L flag and A flag is available.
  // L is on-link flag. This is 1, the same prefixes means they are on same link.
  // A is Address Auto config flag. This is 1, this prefix can be used for gen global address
  *payload[3] = flag & 0xc0;

  union len32{
    uint8_t u8[4];
    uint32_t u32[1];
  } tmp;

  tmp.u32[0] = valid_lifetime;
  for(int i = 0; i < 4; i++) *payload[4 + i] = tmp.u8[i];

  tmp.u32[0] = prefered_lifetime;
  for(int i = 0; i < 4; i++) *payload[8 + i] = tmp.u8[i];

  for(int i = 0; i < 4; i++) *payload[12 + i] = 0; // reserved. sould be 0.

  unsigned char buf[sizeof(struct in6_addr)];  
  if (inet_pton(AF_INET6, prefix, buf)){
    for(int i = 0; i < 16; i++) *payload[16 + i] = buf[i];
  }
  else{
    fprintf(stderr, "Prefix is invalid: %s", prefix);
    exit(1);
  }
    
  return len * 8;
}

uint8_t* payload_malloc(int len){
  return (uint8_t*)malloc(len * 8);
}
