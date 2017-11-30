#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

int main(int argc, char** argv){
  char* dev = argv[1];
  char err_buf[1024];
  struct bpf_program fp;
  bpf_u_int32 net, mask; // ip addr? mask

  if ( pcap_lookupnet(dev, &net, &mask, err_buf) == -1 ) {
    fprintf(stderr, "can't get mask error\n");
    net = 0;
    mask = 0;
  }

  pcap_t *handle = pcap_open_live(dev, // device
				  200, // packet len
				  1,  // promisc
				  1000, // to_ms
				  err_buf // error buf
				  );
  if(handle == NULL) {
    fprintf(stderr, "Init error\n");
    exit(1);
  }

  if ( pcap_compile(handle, // pcap_t
		    &fp, // compiled_exp
		    "icmpv6.type == 134",
		    0, // optimized_p
		    net // netmask
		    ) == -1 ) {
    fprintf(stderr, "can't compile\n");
    exit(1);
  }

  if ( pcap_setfilter(handle, &fp) == -1 ) {
    fprintf(stderr, "can't filter\n");
    exit(1);
  }
  
  return 0;
}
