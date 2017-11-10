#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <getopt.h>

#define ND_RA_MANAGED_CONFIG_FLAG 0x80
#define ND_RA_OTHER_CONFIG_FLAG   0x40
#define ND_OPT_RDNSS              0x19
#define ND_OPT_PREFIX_L_FLAG      0x80
#define ND_OPT_PREFIX_A_FLAG      0x40

#define max(A, B) (A) > (B) ? A : B

typedef struct libnet_in6_addr libnet_in6_addr;

int build_icmpv6_rdnss_opt(libnet_t* l,
			   uint8_t **payload,
			   uint32_t lifetime,
			   const char* dns_addr);

libnet_ptag_t build_icmpv6_ndp_ra(uint8_t type,
				  uint8_t code,
				  uint16_t checksum,
				  uint8_t hop_limit,
				  uint8_t flags,
				  uint16_t lifetime,
				  uint32_t reachable_time,
				  uint32_t retransmission_time,
				  uint8_t* payload,
				  uint32_t payload_s,
				  libnet_t* l,
				  libnet_ptag_t ptag);

int build_icmpv6_trg_link_addr_opt(libnet_t* l,
				   uint8_t **payload,
				   const uint8_t* link_addr);

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

// for option
#define ICMPV6        0x00 // unnecessary?
#define ICMPV6_HL     0x01 // hop limit
#define ICMPV6_OF     0x02 // o flag
#define ICMPV6_MF     0x03 // m flag
#define ICMPV6_LT     0x04 // life time
#define ICMPV6_RT     0x05 // reachable time
#define ICMPV6_RE     0x06 // retransmission time
#define OPT_LINK      0x10
#define OPT_MTU       0x20
#define OPT_PREFIX    0x40
#define OPT_PREFIX_LF 0x41 // L flag
#define OPT_PREFIX_AF 0x42 // A flag
#define OPT_PREFIX_VT 0x43 // valid time
#define OPT_PREFIX_PT 0x44 // prefered time
#define OPT_RDNSS     0x80
#define OPT_RDNSS_LT  0x81 // life time
#define COUNT         0x100
#define INTERVAL      0x200
int options = 0;

/**
 * CMD inteface dst src <options>
 * interface: NIC
 * src: source adderss
 * dst: destination address
 *
 * router advertisement param
 * --hop-limit hop limit
 * -of other flag
 * -mf managed flag
 * --lifetime lifetime
 * --reachable reachable time
 * --retrans retransmission time
 *
 * ra option param
 *
 * rdnss
 * -r use rdnss option: dns address
 * --r-lifetime rdnss lifetime
 *
 * mtu
 * -m use mtu option: mtu
 *
 * link
 * -l use link option: link address
 *
 * prefix
 * -p use prefix option: prefix addr and length like 2001:db8::/64
 * --pl prefix l flag
 * --pa prefix a flag
 * --p-valid prefix valid lifetime
 * --p-prefer prefix prefered lifetime
 */
int main(int argc, char** argv){
  int count = -1;
  int interval = 1000000; // this mean mili sec.
  uint8_t  icmpv6_hop_limit = 0; // 0 means this ra doesn't have hop limit.
  uint8_t  icmpv6_flags     = 0;
  uint16_t icmpv6_lifetime  = 0; // 0 - 9000
  uint32_t icmpv6_reachable = 0;
  uint32_t icmpv6_retrans   = 0;

  char*    rdnss_dns_addr = NULL;
  uint32_t rdnss_lifetime = 0xffffffff;

  uint32_t mtu_mtu = 0;

  uint8_t link_addr[6];

  char*    prefix_prefix            = NULL;
  uint8_t  prefix_prefix_len        = 0;
  uint8_t  prefix_flags             = 0;
  uint32_t prefix_valid_lifetime    = 0xffffffff;
  uint32_t prefix_prefered_lifetime = 0xffffffff;

  /**********
   * option *
   **********/
  // analyze arg
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"c",          required_argument, 0,  COUNT         },
      {"i",          required_argument, 0,  INTERVAL     },
      {"hop-limit",  required_argument, 0,  ICMPV6_HL     },
      {"of",         no_argument,       0,  ICMPV6_OF     }, // make this return macro val
      {"mf",         no_argument,       0,  ICMPV6_MF     },
      {"lifetime",   required_argument, 0,  ICMPV6_LT     },
      {"reachable",  required_argument, 0,  ICMPV6_RT     },
      {"retrans",    required_argument, 0,  ICMPV6_RE     },
      {"r",          required_argument, 0,  OPT_RDNSS     },
      {"r-lifetime", required_argument, 0,  OPT_RDNSS_LT  },
      {"m",          required_argument, 0,  OPT_MTU       },
      {"l",          required_argument, 0,  OPT_LINK      },
      {"p",          required_argument, 0,  OPT_PREFIX    },
      {"pl",         no_argument,       0,  OPT_PREFIX_LF },
      {"pa",         no_argument,       0,  OPT_PREFIX_AF },
      {"p-valid",    required_argument, 0,  OPT_PREFIX_VT },
      {"p-prefer",   required_argument, 0,  OPT_PREFIX_PT },
      {0,            0,                 0,  0             }
    };

    int c = getopt_long_only(argc, argv, "", long_options, &option_index);
    if (c == -1)
      break;

    switch(c) {
    case ICMPV6_HL:
      icmpv6_hop_limit = atoi(optarg);
      break;
    case ICMPV6_OF:
      icmpv6_flags |= ND_RA_OTHER_CONFIG_FLAG;
      break;
    case ICMPV6_MF:
      icmpv6_flags |= ND_RA_MANAGED_CONFIG_FLAG;
      break;
    case ICMPV6_LT:
      icmpv6_lifetime = atoi(optarg);
      break;
    case ICMPV6_RT:
      icmpv6_reachable = atoi(optarg);
      break;
    case ICMPV6_RE:
      icmpv6_retrans = atoi(optarg);
      break;
    case OPT_RDNSS:
      options |= OPT_RDNSS;
      rdnss_dns_addr = optarg; // Is this error? I think optarg points argv address, this may not be error.
      break;
    case OPT_RDNSS_LT:
      rdnss_lifetime = atoi(optarg);
      break;
    case OPT_MTU:
      options |= OPT_MTU;
      mtu_mtu = atoi(optarg);
      break;
    case OPT_LINK:
      options |= OPT_LINK;

      char* addr = strtok(optarg, ":");
      link_addr[0] = strtol(addr, NULL, 16);;

      for (int i = 1; i < 6; i++){
	link_addr[i] = strtol(strtok(NULL, ":"), NULL, 16);
      }

      break;
    case OPT_PREFIX:
      options |= OPT_PREFIX;

      char* prefix_str = strtok(optarg, "/");
      if (prefix_str == NULL) {
	fprintf(stderr, "Prefix option error: Prefix address is invalid, length is missig. ex) 2001:db8::/64");
	exit(1);
      }
      char* len = strtok(NULL, "/");

      prefix_prefix = prefix_str;
      prefix_prefix_len = atoi(len);
      break;
    case OPT_PREFIX_LF:
      prefix_flags |= ND_OPT_PREFIX_L_FLAG;
      break;
    case OPT_PREFIX_AF:
      prefix_flags |= ND_OPT_PREFIX_A_FLAG;
      break;
    case OPT_PREFIX_VT:
      prefix_valid_lifetime = atoi(optarg);
      break;
    case OPT_PREFIX_PT:
      prefix_prefered_lifetime = atoi(optarg);
      break;
    case COUNT:
      count = atoi(optarg);
      break;
    case INTERVAL:
      interval = atof(optarg);
      break;
    default:
      fprintf(stderr, "Invalid option val: %d\n", c);
      exit(1);
    }
  }

  if ((argc - optind) != 3) {
    fprintf(stderr, "%s interface dst-addr src-addr <options>\n", argv[0]);
    exit(1);
  }

  // set argv
  char *interface = argv[optind];
  // char *dst_addr = "ff02::1";
  char *dst_addr = argv[optind+ 1];
  char *src_addr = argv[optind+ 2];
  libnet_t *l;
  libnet_in6_addr sip, dip;
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
  // make opion payload
  uint8_t* rdnss = NULL;
  int rdnss_len = 0;
  if (options & OPT_RDNSS) rdnss_len = build_icmpv6_rdnss_opt(l, &rdnss, rdnss_lifetime, rdnss_dns_addr);

  uint8_t* mtu = NULL;
  int mtu_len = 0;
  if (options & OPT_MTU) mtu_len = build_icmpv6_mtu_opt(l, &mtu, mtu_mtu);

  uint8_t* link = NULL;
  int link_len = 0;
  if (options & OPT_LINK) link_len = build_icmpv6_trg_link_addr_opt(l, &link, link_addr);

  uint8_t* prefix = NULL;
  int prefix_len = 0;
  if (options & OPT_PREFIX) prefix_len = build_icmpv6_prefix_opt(l,
								 &prefix,
								 prefix_prefix_len,
								 prefix_flags,
								 prefix_valid_lifetime, // 2592000,
								 prefix_prefered_lifetime, // 604800,
								 prefix_prefix);// "2001:db8:ffff::");

  // concat options to payload
  uint8_t* payload = (uint8_t*)malloc(rdnss_len + mtu_len + link_len + prefix_len);
  int payload_s = 0;

  for (int i = 0; i < rdnss_len; i++) payload[payload_s + i] = rdnss[i];
  payload_s += rdnss_len;

  for (int i = 0; i < mtu_len; i++) payload[payload_s + i] = mtu[i];
  payload_s += mtu_len;

  for (int i = 0; i < link_len; i++) payload[payload_s + i] = link[i];
  payload_s += link_len;

  for (int i = 0; i < prefix_len; i++) payload[payload_s + i] = prefix[i];
  payload_s += prefix_len;

  free(rdnss); free(mtu); free(link); free(prefix); // ok? free(NULL);

  build_icmpv6_ndp_ra(ND_ROUTER_ADVERT, // type
		      0,                // code
		      0,                // checksum
		      icmpv6_hop_limit, // hop limit
		      icmpv6_flags,     // flags
		      icmpv6_lifetime,  // lifetime
		      icmpv6_reachable, // reachable time
		      icmpv6_retrans,   // retransmission
		      payload,          // payload
		      payload_s,        // payload_s
		      l,
		      0
		      );


  /*********************************
   *       build ipv6 packet       *
   *********************************/
  libnet_build_ipv6(
		    0,                // uint8_t traffic class
		    0,                // uint32_t flow label
		    16 + payload_s,   // uint16_t len
		    IPPROTO_ICMP6,    // uint8_t nh -> next header
		    255,              // uint8_t hl -> hop limit
		    sip,              // libnet_in6_addr src
		    dip,              // libnet_in6_addr dst
		    NULL,             // uint8_t* payload
		    0,                // uint32_t payload_s
		    l,                // libnet_t* l
		    0                 // libnet_ptag_t ptag
		    );

  for (int i = 0; i != count; i++) {
    if (libnet_write(l) == -1) {
      printf("libnet_write: %s\n", libnet_geterror(l));
      exit(1);
    }
    usleep(interval);
  }

  free(payload);
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
			   uint8_t** payload,
			   uint32_t lifetime,
			   const char* dns_addr){
  int len = 2 + 1;

  // copy address, builder funciton accepts only uint8_t*
  *payload = (uint8_t*)malloc(len * 8);

  (*payload)[0] = ND_OPT_RDNSS;
  (*payload)[1] = len;
  (*payload)[2] = 0;
  (*payload)[3] = 0;

  union {
    uint8_t u8[4];
    uint32_t u32[1];
  } tmp;

  tmp.u32[0] = lifetime;

  for(int i = 0; i < 4; i++) (*payload)[4 + i] = tmp.u8[i];

  for (int i = 0; i < 16; i++)
    (*payload)[8 + i] = libnet_name2addr6(l, dns_addr, LIBNET_DONT_RESOLVE).__u6_addr.__u6_addr8[i];

  return len * 8;
}

libnet_ptag_t build_icmpv6_ndp_ra(uint8_t type,
				  uint8_t code,
				  uint16_t checksum,
				  uint8_t hop_limit,
				  uint8_t flags,
				  uint16_t lifetime,
				  uint32_t reachable_time,
				  uint32_t retransmission_time,
				  uint8_t* payload,
				  uint32_t payload_s,
				  libnet_t* l,
				  libnet_ptag_t ptag){
  union {
    uint8_t u8[4];
    uint16_t u16[2];
    uint32_t u32[1];
  } hop_flag_life, tmp;

  // costruct hop , flag and lifetime
  hop_flag_life.u8[3] = hop_limit;
  hop_flag_life.u8[2] = flags;
  hop_flag_life.u16[0] = lifetime;

  // HACK: What is correct way?
  libnet_in6_addr trg;
  tmp.u32[0] = reachable_time;
  for (int i = 0; i < 4; i++)
    trg.__u6_addr.__u6_addr8[3 - i] = tmp.u8[i]; // must extract?

  tmp.u32[0] = retransmission_time;
  for (int i = 0; i < 4; i++)
    trg.__u6_addr.__u6_addr8[3 - i + 4] = tmp.u8[i];

  // set overlaped part to trg
  for (int i = 0; i < 4; i++) tmp.u8[i] = payload[i];
  trg.__u6_addr.__u6_addr32[2] = tmp.u32[0];

  for (int i = 0; i < 4; i++) tmp.u8[i] = payload[4 + i];
  trg.__u6_addr.__u6_addr32[3] = tmp.u32[0];

  return libnet_build_icmpv6_ndp_nadv(
				      type,                      // uint8_t type
				      code,                      // uint8_t code
				      checksum,                  // uint16_t check_sum
				      hop_flag_life.u32[0],      // uint32_t flags, this is
				      trg,                       // libnet_in6_addr target
				      payload + 8,               // uint8_t* payload
				      max(payload_s - 8, 0),     // uint32_t payload size
				      l,                         // libnet_t* context
				      ptag                       // libnet_ptag_t ptag, 0 means create new one
				      );
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
int build_icmpv6_trg_link_addr_opt(libnet_t* l,
				   uint8_t **payload,
				   const uint8_t* link_addr){
  int len = 1;
  *payload = (uint8_t*)malloc(len * 8);

  // if RA, 0x01 only. But NA or Redirect can use 0x02
  (*payload)[0] = ND_OPT_SOURCE_LINKADDR; // == 0x01

  // if ethernet is used, length should be 1. MAC addr is 48 bit len.
  (*payload)[1] = len;

  for(int i = 0; i < 6; i++) // if MAC addr is 42(6 bytes), this is ok.
    (*payload)[2 + i] = link_addr[i];

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
  *payload = (uint8_t*)malloc(len * 8);

  (*payload)[0] = ND_OPT_MTU;
  (*payload)[1] = len;
  (*payload)[2] = 0;
  (*payload)[3] = 0;

  union len32{
    uint8_t u8[4];
    uint32_t u32[1];
  } tmp;
  tmp.u32[0] = mtu;
  for(int i = 0; i < 4; i++)
    (*payload)[4 + 3 - i] = tmp.u8[i];

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
  *payload = (uint8_t*)malloc(len * 8);

  (*payload)[0] = ND_OPT_PREFIX_INFORMATION;
  (*payload)[1] = len;
  (*payload)[2] = prefix_len;
  // L flag and A flag is available.
  // L is on-link flag. This is 1, the same prefixes means they are on same link.
  // A is Address Auto config flag. This is 1, this prefix can be used for gen global address
  (*payload)[3] = flag & 0xc0;

  union len32{
    uint8_t u8[4];
    uint32_t u32[1];
  } tmp;

  tmp.u32[0] = valid_lifetime;
  for(int i = 0; i < 4; i++) (*payload)[4 + 3 - i] = tmp.u8[i];

  tmp.u32[0] = prefered_lifetime;
  for(int i = 0; i < 4; i++) (*payload)[8 + 3 - i] = tmp.u8[i];

  for(int i = 0; i < 4; i++) (*payload)[12 + i] = 0; // reserved. sould be 0.

  unsigned char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET6, prefix, buf)){
    for(int i = 0; i < 16; i++) (*payload)[16 + i] = buf[i];
  }
  else{
    fprintf(stderr, "Prefix is invalid: %s", prefix);
    exit(1);
  }

  return len * 8;
}
