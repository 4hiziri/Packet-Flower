#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libnet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc, char** argv){
  if (argc != 2) {
    fprintf(stderr, "%s <interface>\n", argv[0]);
    return 1;
  }
  
  char *interface = argv[1];  
  libnet_t *l;
  int id, seq;
  struct libnet_in6_addr sip, dip;
  char errbuf[LIBNET_ERRBUF_SIZE];

  // initialize libnet, this must be called before other functions
  l = libnet_init(LIBNET_RAW6, interface, errbuf);
  if(l == NULL) {
    printf("libnet_init: %s\n", errbuf);
    exit(1);
  }

  libnet_seed_prand(l);
  id = libnet_get_prand(LIBNET_PRu32);
  seq = libnet_get_prand(LIBNET_PRu32);
  
  libnet_build_icmpv6_echo(			   
			   ICMP6_ECHO_REQUEST,  //u_int8_t type
			   0,          //u_int8_t code
			   0,          //u_int16_t sum
			   1,          //u_int16_t id
			   seq,        //u_int16_t seq
			   NULL,       //u_int8_t* payload
			   0,          //u_int32_t payload_s
			   l,          //libnet_t* l
			   0           //libnte_ptag_t ptag
			   );

  char* host = "1::1";
  sip = libnet_name2addr6(l, host, LIBNET_DONT_RESOLVE); 
  //test  
  //inet_pton(AF_INET6, host, )
  
  dip = libnet_name2addr6(l, "1::21", LIBNET_DONT_RESOLVE);
  //dip = libnet_name2addr6(l, "ffe0:bd8::aaaa/64", LIBNET_DONT_RESOLVE);

  libnet_build_ipv6(
		    0, // uint8_t traffic class
		    0, // uint32_t flow label
		    LIBNET_IPV6_H + LIBNET_ICMPV6_ECHO_H, //uint16_t len
		    IPPROTO_ICMP6,   //uint8_t nh -> next header
		    64,              //uint8_t hl -> hop limit
		    sip,             //libnet_in6_addr src
		    dip,             //libnet_in6_addr dst
		    NULL,            //uint8_t* payload
		    0,               //uint32_t payload_s
		    l,               //libnet_t* l
		    0                //libnet_ptag_t ptag
		    );

    
  if(libnet_write(l) == -1) {
    printf("libnet_write: %s\n", libnet_geterror(l));
    exit(1);
  }

  libnet_destroy(l);
 
  return 0;
}
