#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* uri2query(char* dst, char* src) {
  char cp_src[1024];
  char *delimiter = ".";
  char *headp = NULL;
  strcpy(cp_src, src);

  headp = strtok(cp_src, delimiter);
  while(headp){
    dst[0] = (char)(strlen(headp) & 0xff);
    dst++;
    strcpy(dst, headp);
    dst += strlen(headp);
    headp = strtok(NULL, delimiter);
  }

  return dst;
}

int main(int argc, char** argv){
  char *interface = "wlp2s0";
  libnet_t *l;
  char* dns_addr_str = "133.6.1.2";
  char payload[1024];
  int payload_s = 0;
  uint32_t dns_addr;
  char errbuf[LIBNET_ERRBUF_SIZE];
  char query[1024];
  uri2query(query, "www.google.com");

  /*****************************************************************
   * Initialize libnet, this must be called before other function. *
   *****************************************************************/
  l = libnet_init(LIBNET_RAW4, interface, errbuf);
  if(l == NULL) {
    printf("libnet_init: %s\n", errbuf);
    exit(1);
  }  

  // get addr
  dns_addr = libnet_name2addr4(l, dns_addr_str, LIBNET_DONT_RESOLVE);

  payload_s = snprintf(payload, sizeof(payload), "%s%c%c%c%c%c", query, 0, 0, 1, 0, 1);
  
  libnet_build_dnsv4(LIBNET_DNS_H, // h_len
		     0, // id
		     0x0100, // flags, recur
		     1, // num_q
		     0, // num_anws_rr
		     0, // num_auth_rr
		     0, // num_addi_rr
		     (uint8_t *)payload, // payload
		     payload_s, // payload_s
		     l, // l
		     0 // ptag
		     );

  libnet_build_udp(51001, // sp
		   53, // dp
		   LIBNET_UDP_H + LIBNET_DNS_H + payload_s, // len
		   0, // sum
		   NULL, // payload
		   0, // payload_s
		   l, // l
		   0 // ptag
		   );

  libnet_build_ipv4(
  		    LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + payload_s, // ip_len
  		    0, // tos
  		    0, // id
  		    0, // flag, dont fragment
  		    253, // ttl
  		    IPPROTO_UDP, // prot, UDP?
  		    0, // sum
  		    libnet_name2addr4(l, "192.168.6.101", LIBNET_DONT_RESOLVE), // src
  		    dns_addr, // dst
  		    NULL, // payload
  		    0, // payload_s
  		    l, // l
  		    0 // ptag
  		    );

  if (libnet_write(l) == -1) {
      printf("libnet_write: %s\n", libnet_geterror(l));
      exit(1);
  }

  libnet_destroy(l);
  
  return 0;
}
