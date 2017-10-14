#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

int main(int argc, char** argv){
  libnet_t *l;
  int id, seq;
  u_int32_t sip, dip;
  char errbuf[LIBNET_ERRBUF_SIZE];
  char *interface = "wlp2s0";  

  l = libnet_init(LIBNET_RAW4, interface, errbuf);
  if(l == NULL) {
    printf("libnet_init: %s\n", errbuf);
    exit(1);
  }
    
  libnet_seed_prand(l);
  id = libnet_get_prand(LIBNET_PRu32);
  seq = libnet_get_prand(LIBNET_PRu32);
  libnet_build_icmpv4_echo(
			   ICMP_ECHO,  //u_int8_t type
			   0,          //u_int8_t code
			   0,          //u_int16_t sum
			   1,          //u_int16_t id
			   seq,        //u_int16_t seq
			   NULL,       //u_int8_t* payload
			   0,          //u_int32_t payload_s
			   l,          //libnet_t* l
			   0           //libnte_ptag_t ptag
			   );
    
  sip = libnet_name2addr4(l, "192.168.1.5", LIBNET_DONT_RESOLVE);
  dip = libnet_name2addr4(l, "192.168.1.1", LIBNET_DONT_RESOLVE);

  libnet_build_ipv4(
		    LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, //u_int16_t ip_len
		    0,               //u_int8_t tos
		    id,              //u_int16_t id
		    0,               //u_int16_t frag
		    64,              //u_int8_t ttl
		    IPPROTO_ICMP,    //u_int8_t prot
		    0,               //u_int16_t sum
		    sip,             //u_int32_t src
		    dip,             //u_int32_t dst
		    NULL,            //u_int8_t* payload
		    0,               //u_int32_t payload_s
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
